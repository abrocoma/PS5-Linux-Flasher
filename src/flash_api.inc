/* ---------- flasher API (included by usbprobe.c) ---------- */
#include <pthread.h>
#include "flash.h"
#include "download.h"
#include "net.h"

static flash_job_t job;
static pthread_t job_thread;

static int job_busy(void) {
  return job.state == FLASH_WRITING || job.state == FLASH_VERIFYING;
}
static int dl_busy(void) { return dl.state == DL_RUNNING; }

static void url_decode(char *s) {
  char *o = s;
  for (; *s; s++) {
    if (*s == '%' && isxdigit((unsigned char)s[1]) && isxdigit((unsigned char)s[2])) {
      char h[3] = {s[1], s[2], 0};
      *o++ = (char)strtol(h, NULL, 16);
      s += 2;
    } else if (*s == '+') {
      *o++ = ' ';
    } else {
      *o++ = *s;
    }
  }
  *o = 0;
}

/* "/dev/da1p3" -> "da1" (whole disk of a partition) */
static void disk_of(const char *from, char *out, size_t ol) {
  out[0] = 0;
  if (strncmp(from, "/dev/", 5) != 0)
    return;
  const char *n = from + 5;
  size_t i = 0;
  while (n[i] && !isdigit((unsigned char)n[i]))
    i++;
  while (isdigit((unsigned char)n[i]))
    i++;
  snprintf(out, ol, "%.*s", (int)i, n);
}

/* whole disk that holds file <path>, e.g. "da1" */
static void disk_of_file(const char *path, char *out, size_t ol) {
  struct statfs sf;
  out[0] = 0;
  if (statfs(path, &sf) == 0)
    disk_of(sf.f_mntfromname, out, ol);
}

static int is_image_name(const char *n) {
  size_t l = strlen(n);
  if (n[0] == '.')
    return 0;
  return (l > 4 && (strcasecmp(n + l - 4, ".img") == 0 || strcasecmp(n + l - 4, ".iso") == 0)) ||
         (l > 7 && (strcasecmp(n + l - 7, ".img.xz") == 0 || strcasecmp(n + l - 7, ".iso.xz") == 0));
}

static int img_count;
static void add_image(buf_t *out, const char *path) {
  struct stat st;
  char disk[16], side[65];
  if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
    return;
  disk_of_file(path, disk, sizeof(disk));
  if (img_count++)
    bputs(out, ",");
  bputs(out, "{\"path\":");
  bjson(out, path);
  bprintf(out, ",\"size\":%lld,\"unpacked\":%llu,\"xz\":%s,\"sha256_file\":%s,\"disk\":",
          (long long)st.st_size, (unsigned long long)flash_image_size(path),
          flash_is_xz(path) ? "true" : "false",
          flash_read_sidecar(path, side) == 0 ? "true" : "false");
  bjson(out, disk);
  bputs(out, "}");
}

/* only images downloaded with the Flasher (on the PS5 itself); files on USB drives are not listed */
static void api_images(buf_t *out) {
  img_count = 0;
  bputs(out, "{\"images\":[");
  /* images downloaded to the PS5 itself */
  DIR *dd = opendir(DL_DIR);
  if (dd) {
    struct dirent *e;
    while ((e = readdir(dd)) && img_count < 64) {
      if (!is_image_name(e->d_name))
        continue;
      char p[1100];
      snprintf(p, sizeof(p), "%s/%s", DL_DIR, e->d_name);
      add_image(out, p);
    }
    closedir(dd);
  }
  bputs(out, "],\"partial\":[");
  /* unfinished downloads (resumable) */
  int np = 0;
  dd = opendir(DL_DIR);
  if (dd) {
    struct dirent *e;
    while ((e = readdir(dd))) {
      size_t l = strlen(e->d_name);
      if (l < 6 || strcmp(e->d_name + l - 5, ".part") != 0)
        continue;
      char p[1100], u[1024] = "";
      struct stat st;
      snprintf(p, sizeof(p), "%s/%s", DL_DIR, e->d_name);
      if (stat(p, &st) != 0)
        continue;
      snprintf(p, sizeof(p), "%s/%s.url", DL_DIR, e->d_name);
      int f = open(p, O_RDONLY);
      if (f >= 0) {
        ssize_t k = read(f, u, sizeof(u) - 1);
        u[k > 0 ? k : 0] = 0;
        close(f);
      }
      if (np++)
        bputs(out, ",");
      bputs(out, "{\"name\":");
      bjson(out, e->d_name);
      bprintf(out, ",\"size\":%lld,\"url\":", (long long)st.st_size);
      bjson(out, u);
      bputs(out, "}");
    }
    closedir(dd);
  }
  bprintf(out, "],\"free\":%llu}", (unsigned long long)dl_free_bytes());
}

static void job_json(buf_t *out) {
  static const char *names[] = {"idle", "writing", "verifying", "done", "failed", "cancelled"};
  double now = flash_now();
  double el = job.t_start ? ((job.state == FLASH_WRITING || job.state == FLASH_VERIFYING) ? now : job.t_done) - job.t_start : 0;
  bprintf(out, "{\"state\":\"%s\",\"total\":%llu,\"written\":%llu,\"verified\":%llu,"
          "\"read\":%llu,\"img_size\":%llu,\"elapsed\":%.1f,\"write_secs\":%.1f,\"sidecar\":%d,\"msg\":",
          names[job.state], (unsigned long long)job.total, (unsigned long long)job.written,
          (unsigned long long)job.verified, (unsigned long long)job.read_bytes,
          (unsigned long long)job.img_size, el,
          job.t_written ? job.t_written - job.t_start : (job.state == FLASH_WRITING ? el : 0),
          job.sidecar);
  bjson(out, job.msg);
  bputs(out, ",\"img\":");
  bjson(out, job.img);
  bputs(out, ",\"dev\":");
  bjson(out, job.dev);
  bputs(out, ",\"label\":");
  bjson(out, job.label);
  bputs(out, ",\"sha_written\":");
  bjson(out, job.sha_written);
  bputs(out, ",\"sha_readback\":");
  bjson(out, job.sha_readback);
  bputs(out, ",\"sha_image_file\":");
  bjson(out, job.sha_image_file);
  bputs(out, "}");
}

static void *job_main(void *arg) {
  char name[16];
  snprintf(name, sizeof(name), "%s", job.dev + 5);
  creds_t orig;
  creds_save(&orig);
  apply_level(4, &orig);
  buf_t log = {0};
  unmount_disk(name, &log);
  creds_restore(&orig);
  free(log.p);

  flash_run(&job);

  buf_t r = {0};
  job_json(&r);
  save_report("FLASH RESULT", &r);
  free(r.p);
  if (job.state == FLASH_DONE)
    notify("Linux Flasher: done\n%s written and verified.\nYou can unplug it.", job.label);
  else
    notify("Linux Flasher: %s\n%s", job.state == FLASH_CANCELLED ? "cancelled" : "FAILED", job.msg);
  return NULL;
}

static void api_flash(const char *img, const char *dev, buf_t *out) {
  char d[256];
  if (job_busy() || dl_busy()) {
    result(out, 0, "flash", EBUSY, "A flash or download is already running.");
    return;
  }
  if (!is_writable_name(dev)) {
    result(out, 0, "refused", EPERM, "Only USB drives (da<N>) can be flashed.");
    return;
  }
  if (is_payload_drive(dev)) {
    result(out, 0, "refused", EPERM, "That is your payload drive (it holds Linux_Flasher.elf). It is never written.");
    return;
  }
  if (strncmp(img, DL_DIR "/", sizeof(DL_DIR)) != 0 || strstr(img, "..") || !is_image_name(strrchr(img, '/') ? strrchr(img, '/') + 1 : img)) {
    result(out, 0, "refused", EINVAL, "Pick an image (.img, .iso, .img.xz or .iso.xz) from the list.");
    return;
  }
  char idisk[16];
  disk_of_file(img, idisk, sizeof(idisk));
  if (strcmp(idisk, dev) == 0) {
    result(out, 0, "refused", EINVAL, "The image is on the drive you want to write to. Put it on another drive.");
    return;
  }
  struct stat st;
  if (stat(img, &st) != 0) {
    result(out, 0, "image", errno, img);
    return;
  }
  snprintf(d, sizeof(d), "/dev/%s", dev);
  off_t dsize = 0;
  int fd = open(d, O_RDONLY);
  if (fd >= 0) {
    ioctl(fd, DIOCGMEDIASIZE, &dsize);
    close(fd);
  }
  uint64_t need = flash_image_size(img);
  if (need && dsize && need > (uint64_t)dsize) {
    char m[200];
    snprintf(m, sizeof(m), "The image needs %.2f GB but the drive has %.2f GB. Use a bigger drive.",
             need / 1e9, dsize / 1e9);
    result(out, 0, "too small", ENOSPC, m);
    return;
  }
  memset(&job, 0, sizeof(job));
  snprintf(job.img, sizeof(job.img), "%s", img);
  snprintf(job.dev, sizeof(job.dev), "%s", d);
  char descr[DISK_IDENT_SIZE] = "";
#ifdef DIOCGDESCR
  fd = open(d, O_RDONLY);
  if (fd >= 0) {
    ioctl(fd, DIOCGDESCR, descr);
    close(fd);
  }
#endif
  snprintf(job.label, sizeof(job.label), "%.1f GB %s", dsize / 1e9, descr);
  job.total = need;
  job.img_size = (uint64_t)st.st_size;
  job.state = FLASH_WRITING;
  snprintf(job.msg, sizeof(job.msg), "Starting");
  if (pthread_create(&job_thread, NULL, job_main, NULL) != 0) {
    job.state = FLASH_FAILED;
    result(out, 0, "flash", errno, "could not start the flash thread");
    return;
  }
  pthread_detach(job_thread);
  result(out, 1, "flash started", 0, job.label);
}

/* ---------- downloads ---------- */
static pthread_t dl_thread;
static void *dl_main(void *a) {
  dl_run();
  if (dl.state == DL_DONE)
    notify("Linux Flasher: download finished\n%s", strrchr(dl.path, '/') + 1);
  else if (dl.state == DL_FAILED)
    notify("Linux Flasher: download failed\n%s", dl.msg);
  buf_t r = {0};
  bprintf(&r, "{\"state\":%d,\"url\":", dl.state);
  bjson(&r, dl.url);
  bprintf(&r, ",\"got\":%llu,\"total\":%llu,\"sha\":\"%s\",\"msg\":",
          (unsigned long long)dl.got, (unsigned long long)dl.total, dl.sha);
  bjson(&r, dl.msg);
  bputs(&r, ",\"log\":");
  bjson(&r, net_log);
  bputs(&r, "}");
  save_report("DOWNLOAD RESULT", &r);
  free(r.p);
  return NULL;
}

static void api_download(const char *url, const char *sha, buf_t *out) {
  char name[256];
  if (job_busy() || dl_busy()) {
    result(out, 0, "download", EBUSY, "A flash or download is already running.");
    return;
  }
  if (strncmp(url, "https://", 8) != 0 && strncmp(url, "http://", 7) != 0) {
    result(out, 0, "download", EINVAL, "Paste a full link starting with https://");
    return;
  }
  if (dl_name_from_url(url, name, sizeof(name)) != 0) {
    result(out, 0, "download", EINVAL,
           "The link must point straight at an .img, .iso, .img.xz or .iso.xz file.");
    return;
  }
  memset(&dl, 0, sizeof(dl));
  snprintf(dl.url, sizeof(dl.url), "%s", url);
  snprintf(dl.path, sizeof(dl.path), "%s/%s", DL_DIR, name);
  if (strlen(sha) == 64 && strspn(sha, "0123456789abcdef") == 64)
    snprintf(dl.expect, sizeof(dl.expect), "%s", sha);
  struct stat st;
  if (stat(dl.path, &st) == 0) {
    result(out, 0, "download", EEXIST, "Already downloaded: it's in the image list. Delete it first to download again.");
    return;
  }
  dl.state = DL_RUNNING;
  snprintf(dl.msg, sizeof(dl.msg), "Starting");
  if (pthread_create(&dl_thread, NULL, dl_main, NULL) != 0) {
    dl.state = DL_FAILED;
    result(out, 0, "download", errno, "could not start the download thread");
    return;
  }
  pthread_detach(dl_thread);
  result(out, 1, "download started", 0, name);
}

static void dl_json(buf_t *out) {
  static const char *names[] = {"idle", "running", "done", "failed", "paused"};
  double el = dl.t_start ? (dl.state == DL_RUNNING ? flash_now() : dl.t_done) - dl.t_start : 0;
  bprintf(out, "{\"state\":\"%s\",\"got\":%llu,\"total\":%llu,\"resumed_from\":%llu,"
               "\"elapsed\":%.1f,\"sidecar\":%d,\"msg\":",
          names[dl.state], (unsigned long long)dl.got, (unsigned long long)dl.total,
          (unsigned long long)dl.resumed_from, el, dl.has_sidecar);
  bjson(out, dl.msg);
  bputs(out, ",\"name\":");
  bjson(out, dl.path[0] ? strrchr(dl.path, '/') + 1 : "");
  bputs(out, ",\"url\":");
  bjson(out, dl.url);
  bputs(out, ",\"log\":");
  bjson(out, net_log);
  bprintf(out, ",\"pinned\":%s,\"expect\":\"%s\"}", dl.expect[0] ? "true" : "false", dl.expect);
}

/* delete a downloaded image (and its .sha256 / unfinished parts) */
static void api_delimg(const char *img, buf_t *out) {
  if (strncmp(img, DL_DIR "/", sizeof(DL_DIR)) != 0 || strstr(img, "..") ||
      strchr(img + sizeof(DL_DIR), '/')) {
    result(out, 0, "delete", EPERM, "Only images downloaded to the PS5 can be deleted here.");
    return;
  }
  if ((dl_busy() && strncmp(dl.path, img, strlen(dl.path)) == 0) ||
      (job_busy() && strcmp(job.img, img) == 0)) {
    result(out, 0, "delete", EBUSY, "That image is in use right now.");
    return;
  }
  char p[1200];
  int r = unlink(img), e = errno;
  const char *suf[] = {".sha256", ".part", ".part.url"};
  char base[1100];
  snprintf(base, sizeof(base), "%s", img);
  size_t l = strlen(base);
  if (l > 5 && strcmp(base + l - 5, ".part") == 0)
    base[l - 5] = 0; /* deleting an unfinished download */
  for (int i = 0; i < 3; i++) {
    snprintf(p, sizeof(p), "%s%s", base, suf[i]);
    unlink(p);
  }
  result(out, r == 0 || e == ENOENT, "delete", r == 0 ? 0 : e, img);
}
