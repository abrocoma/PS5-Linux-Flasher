/* Image downloader (PS5 only): HTTPS via libSceHttp, DNS-independent (net.c).
 * Saves to /data/LinuxFlasher/<name>, resumes from <name>.part, fetches an
 * optional <url>.sha256 and checks it. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>

#include "download.h"
#include "flash.h"
#include "sha256.h"
#include "net.h"

dl_job_t dl;
static hc_t *volatile cur_hc = NULL;

uint64_t dl_free_bytes(void) {
  struct statfs sf;
  if (statfs(DL_DIR, &sf) != 0 && statfs("/data", &sf) != 0)
    return 0;
  return (uint64_t)sf.f_bavail * sf.f_bsize;
}

/* last path part of the URL, safe for a file name; "" if not an image */
int dl_name_from_url(const char *url, char *out, size_t ol) {
  const char *e = url + strcspn(url, "?#");
  const char *s = e;
  while (s > url && s[-1] != '/')
    s--;
  size_t n = 0;
  for (const char *p = s; p < e && n + 1 < ol; p++) {
    char c = *p;
    if (c == '%' && p + 2 < e) { /* %20 etc: keep it simple */
      c = '_';
      p += 2;
    }
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
          c == '.' || c == '-' || c == '_' || c == '+'))
      c = '_';
    out[n++] = c;
  }
  out[n] = 0;
  const char *ok[] = {".img", ".iso", ".img.xz", ".iso.xz"};
  for (int i = 0; i < 4; i++) {
    size_t l = strlen(ok[i]);
    if (n > l && strcasecmp(out + n - l, ok[i]) == 0)
      return 0;
  }
  out[0] = 0;
  return -1;
}

static void dfail(const char *fmt, const char *a) {
  snprintf(dl.msg, sizeof(dl.msg), fmt, a);
  dl.state = DL_FAILED;
}

/* small text file (the .sha256): returns 64-hex in out or -1 */
static int fetch_sidecar(const char *url, char out[65]) {
  char u[1200], err[160];
  snprintf(u, sizeof(u), "%s.sha256", url);
  hc_t h;
  hc_init(&h);
  int st = 0, known = 0;
  uint64_t len = 0;
  out[0] = 0;
  if (hc_get(&h, u, 0, &st, &len, &known, err, sizeof(err)) != 0) {
    hc_close(&h);
    return -1;
  }
  char b[256];
  int n = 0, k;
  if (st == 200)
    while (n < (int)sizeof(b) - 1 && (k = hc_read(&h, b + n, sizeof(b) - 1 - n)) > 0)
      n += k;
  hc_close(&h);
  if (st != 200 || n < 64)
    return -1;
  for (int i = 0; i < 64; i++) {
    char c = b[i];
    if (c >= 'A' && c <= 'F')
      c += 32;
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
      return -1;
    out[i] = c;
  }
  out[64] = 0;
  return 0;
}

static int hash_file_prefix(const char *path, uint64_t n, sha256_t *s) {
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return -1;
  static uint8_t b[1 << 20];
  uint64_t done = 0;
  while (done < n) {
    size_t want = n - done < sizeof(b) ? (size_t)(n - done) : sizeof(b);
    ssize_t k = read(fd, b, want);
    if (k <= 0) {
      close(fd);
      return -1;
    }
    sha256_update(s, b, (size_t)k);
    done += (uint64_t)k;
    dl.got = done;
  }
  close(fd);
  return 0;
}

void dl_run(void) {
  char err[200], part[1100], urlf[1100], side[1100];
  int fd = -1, st = 0, known = 0;
  hc_t h;
  hc_init(&h);
  net_log[0] = 0;
  uint64_t len = 0, from = 0;
  sha256_t sh;
  static uint8_t buf[1 << 20];

  dl.state = DL_RUNNING;
  dl.got = dl.total = 0;
  dl.t_start = flash_now();
  snprintf(dl.msg, sizeof(dl.msg), "Connecting");
  mkdir("/data", 0755);
  mkdir(DL_DIR, 0755);
  snprintf(part, sizeof(part), "%s.part", dl.path);
  snprintf(urlf, sizeof(urlf), "%s.part.url", dl.path);
  snprintf(side, sizeof(side), "%s.sha256", dl.path);

  /* resume an unfinished download of the same link */
  struct stat ps;
  if (stat(part, &ps) == 0 && ps.st_size > 0) {
    char old[1024] = "";
    int uf = open(urlf, O_RDONLY);
    if (uf >= 0) {
      ssize_t k = read(uf, old, sizeof(old) - 1);
      old[k > 0 ? k : 0] = 0;
      close(uf);
    }
    if (strcmp(old, dl.url) == 0)
      from = (uint64_t)ps.st_size;
  }
  int uf = open(urlf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (uf >= 0) {
    write(uf, dl.url, strlen(dl.url));
    close(uf);
  }

  /* expected checksum: built in for known images, else a published .sha256 */
  char want[65];
  if (dl.expect[0]) {
    snprintf(want, sizeof(want), "%s", dl.expect);
    dl.has_sidecar = 1;
  } else {
    dl.has_sidecar = fetch_sidecar(dl.url, want) == 0;
  }

  if (hc_get(&h, dl.url, from, &st, &len, &known, err, sizeof(err)) != 0) {
    dfail("Download failed: %s", err);
    goto done;
  }
  cur_hc = &h;
  if (st == 200 && from) {
    from = 0; /* server ignored the resume request: start over */
  } else if (st != 200 && st != 206) {
    char m[64];
    snprintf(m, sizeof(m), "%d", st);
    dfail(st == 404 ? "Not found (HTTP %s). Check the link."
                    : "The server answered HTTP %s instead of the file.", m);
    goto done;
  }
  dl.total = known ? from + len : 0;
  if (dl.total) {
    uint64_t freeb = dl_free_bytes();
    if (freeb && dl.total - from > freeb) {
      char m[96];
      snprintf(m, sizeof(m), "%.2f GB, but only %.2f GB is free",
               (dl.total - from) / 1e9, freeb / 1e9);
      dfail("Not enough space on the PS5: the download needs %s.", m);
      goto done;
    }
  }

  sha256_init(&sh);
  if (from) {
    snprintf(dl.msg, sizeof(dl.msg), "Checking the part already downloaded");
    if (hash_file_prefix(part, from, &sh)) {
      from = 0;
      sha256_init(&sh);
    }
  }
  fd = open(part, O_WRONLY | O_CREAT | (from ? 0 : O_TRUNC), 0644);
  if (fd < 0) {
    dfail("Can't save to the PS5: %s", strerror(errno));
    goto done;
  }
  dl.got = from;
  dl.resumed_from = from;
  dl.t_start = flash_now();
  snprintf(dl.msg, sizeof(dl.msg), from ? "Resuming" : "Downloading");
  for (;;) {
    if (dl.cancel) {
      snprintf(dl.msg, sizeof(dl.msg), "Paused. Press Resume to continue.");
      dl.state = DL_CANCELLED;
      goto done;
    }
    int k = hc_read(&h, buf, sizeof(buf));
    if (k < 0 && dl.cancel) { /* Pause aborts the read: not an error */
      snprintf(dl.msg, sizeof(dl.msg), "Paused at %.1f MB. Press Resume to continue.", dl.got / 1e6);
      dl.state = DL_CANCELLED;
      goto done;
    }
    if (k < 0) {
      snprintf(dl.msg, sizeof(dl.msg),
               "Connection lost at %.1f MB (0x%08x). Start it again to resume.",
               dl.got / 1e6, (unsigned)k);
      dl.state = DL_FAILED;
      goto done;
    }
    if (k == 0)
      break;
    if (pwrite(fd, buf, (size_t)k, (off_t)dl.got) != k) {
      dfail("Saving failed: %s (PS5 storage full?)", strerror(errno));
      goto done;
    }
    sha256_update(&sh, buf, (size_t)k);
    dl.got += (uint64_t)k;
  }
  fsync(fd);
  close(fd);
  fd = -1;
  if (dl.total && dl.got != dl.total) {
    snprintf(dl.msg, sizeof(dl.msg),
             "Download ended early (%.1f of %.1f MB). Start it again to resume.",
             dl.got / 1e6, dl.total / 1e6);
    dl.state = DL_FAILED;
    goto done;
  }
  sha256_hex(&sh, dl.sha);
  if (dl.has_sidecar && strcmp(want, dl.sha) != 0) {
    unlink(part);
    unlink(urlf);
    dfail("%s", "The download is corrupt (checksum doesn't match). It was deleted, please download again.");
    goto done;
  }
  if (rename(part, dl.path) != 0) {
    dfail("Couldn't finish the file: %s", strerror(errno));
    goto done;
  }
  unlink(urlf);
  if (dl.has_sidecar) {
    int sf = open(side, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (sf >= 0) {
      char line[1200];
      const char *base = strrchr(dl.path, '/') + 1;
      int n = snprintf(line, sizeof(line), "%s  %s\n", dl.sha, base);
      write(sf, line, (size_t)n);
      close(sf);
    }
  }
  dl.t_done = flash_now();
  snprintf(dl.msg, sizeof(dl.msg), "Downloaded%s. It's now in the image list.",
           dl.has_sidecar ? " and checked against its .sha256" : " (no .sha256 published, not checked)");
  dl.state = DL_DONE;

done:
  cur_hc = NULL;
  if (fd >= 0)
    close(fd);
  hc_close(&h);
  if (!dl.t_done)
    dl.t_done = flash_now();
}

void dl_cancel(void) {
  dl.cancel = 1;
  hc_t *h = cur_hc;
  if (h)
    hc_abort(h);
}
