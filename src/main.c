/* Linux Flasher (by abrocoma): flash Linux images to USB drives from the PS5 OS.
 *
 * Answers one question: can a payload on the PS5 OS open a USB drive as a
 * raw block device, read it, and write it?  Serves a small page on port 9077
 * (PS5 browser: http://127.0.0.1:9077, phone: http://<ps5-ip>:9077).
 *
 * Nothing is ever erased: the write test reads the first 1 MiB of the drive,
 * writes the same bytes back, and reads them again to compare.
 * Writes are only allowed on da<N> devices (USB mass storage on FreeBSD).
 */
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <time.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "drivename.h"
#ifdef WITH_LOADER
int boot_linux(char *src, size_t sl, char *err, size_t el);
#endif

#define VERSION "1.6.2"
#define PORT 9077
#define TEST_BYTES (1024 * 1024)

int sceKernelSendNotificationRequest(int, void *, size_t, int);
int sceUserServiceInitialize(void *);
int sceSystemServiceLaunchWebBrowser(const char *uri, void *);
int tile_install(void);
typedef struct {
  char reserved[45];
  char message[3075];
} notify_t;

static void notify(const char *fmt, ...) {
  notify_t req;
  va_list ap;
  memset(&req, 0, sizeof(req));
  va_start(ap, fmt);
  vsnprintf(req.message, sizeof(req.message), fmt, ap);
  va_end(ap);
  sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

/* ---------- growable string buffer ---------- */
typedef struct {
  char *p;
  size_t len, cap;
} buf_t;

static void bputs(buf_t *b, const char *s) {
  size_t n = strlen(s);
  if (b->len + n + 1 > b->cap) {
    size_t cap = b->cap ? b->cap : 4096;
    while (b->len + n + 1 > cap)
      cap *= 2;
    char *np = realloc(b->p, cap);
    if (!np)
      return;
    b->p = np;
    b->cap = cap;
  }
  memcpy(b->p + b->len, s, n + 1);
  b->len += n;
}

static void bprintf(buf_t *b, const char *fmt, ...) {
  char tmp[4096];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(tmp, sizeof(tmp), fmt, ap);
  va_end(ap);
  bputs(b, tmp);
}

/* JSON string literal (escapes quotes, backslashes, control chars) */
static void bjson(buf_t *b, const char *s) {
  char tmp[8];
  bputs(b, "\"");
  for (; s && *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') {
      tmp[0] = '\\';
      tmp[1] = (char)c;
      tmp[2] = 0;
    } else if (c < 0x20) {
      snprintf(tmp, sizeof(tmp), "\\u%04x", c);
    } else {
      tmp[0] = (char)c;
      tmp[1] = 0;
    }
    bputs(b, tmp);
  }
  bputs(b, "\"");
}

/* ---------- device helpers ---------- */

/* Only whole USB mass-storage disks may be written: da0, da1, ... */
static int is_writable_name(const char *n) {
  if (strncmp(n, "da", 2) != 0 || !n[2])
    return 0;
  for (const char *p = n + 2; *p; p++)
    if (!isdigit((unsigned char)*p))
      return 0;
  return 1;
}

static int valid_devname(const char *n) {
  if (!n[0] || strlen(n) > 32 || strstr(n, ".."))
    return 0;
  for (const char *p = n; *p; p++)
    if (!isalnum((unsigned char)*p) && *p != '.' && *p != '_' && *p != '-')
      return 0;
  return 1;
}

/* Mount points whose source is /dev/<name> or a slice/partition of it. */
static void mounts_of(const char *name, buf_t *out) {
  struct statfs *m;
  int n = getmntinfo(&m, MNT_NOWAIT);
  char dev[64];
  size_t dl;
  snprintf(dev, sizeof(dev), "/dev/%s", name);
  dl = strlen(dev);
  int first = 1;
  bputs(out, "[");
  for (int i = 0; i < n; i++) {
    const char *f = m[i].f_mntfromname;
    if (strncmp(f, dev, dl) == 0 &&
        (f[dl] == 0 || f[dl] == 's' || f[dl] == 'p')) {
      if (!first)
        bputs(out, ",");
      first = 0;
      bputs(out, "{\"from\":");
      bjson(out, f);
      bputs(out, ",\"on\":");
      bjson(out, m[i].f_mntonname);
      bputs(out, ",\"fs\":");
      bjson(out, m[i].f_fstypename);
      bputs(out, "}");
    }
  }
  bputs(out, "]");
}

/* True when a partition of /dev/<name> is mounted somewhere that holds
 * Linux_Flasher.elf in its root: that is the drive we run from (and usually
 * the user's Linux drive). It must never be written or unmounted. */
static int is_payload_drive(const char *name) {
  struct statfs *m;
  int n = getmntinfo(&m, MNT_NOWAIT);
  char dev[64], f[1100];
  struct stat st;
  snprintf(dev, sizeof(dev), "/dev/%s", name);
  size_t dl = strlen(dev);
  for (int i = 0; i < n; i++) {
    const char *fr = m[i].f_mntfromname;
    if (strncmp(fr, dev, dl) == 0 && (fr[dl] == 0 || fr[dl] == 's' || fr[dl] == 'p')) {
      snprintf(f, sizeof(f), "%s/Linux_Flasher.elf", m[i].f_mntonname);
      if (stat(f, &st) == 0)
        return 1;
      snprintf(f, sizeof(f), "%s/Linux_Flasher_personal.elf", m[i].f_mntonname);
      if (stat(f, &st) == 0)
        return 1;
      snprintf(f, sizeof(f), "%s/USB_Flasher.elf", m[i].f_mntonname);
      if (stat(f, &st) == 0)
        return 1;
    }
  }
  return 0;
}

/* Unmount every partition of /dev/<name> (needs raised rights). */
static int unmount_disk(const char *name, buf_t *log) {
  struct statfs *m;
  int n = getmntinfo(&m, MNT_NOWAIT);
  char dev[64];
  snprintf(dev, sizeof(dev), "/dev/%s", name);
  size_t dl = strlen(dev);
  int fails = 0;
  for (int i = 0; i < n; i++) {
    const char *fr = m[i].f_mntfromname;
    if (strncmp(fr, dev, dl) == 0 && (fr[dl] == 0 || fr[dl] == 's' || fr[dl] == 'p')) {
      int r = unmount(m[i].f_mntonname, 0);
      if (r != 0 && errno == EBUSY)
        r = unmount(m[i].f_mntonname, MNT_FORCE);
      if (log)
        bprintf(log, "unmount %s (%s): %s\n", m[i].f_mntonname, fr,
                r == 0 ? "ok" : strerror(errno));
      if (r != 0)
        fails++;
    }
  }
  return fails;
}

static void disk_info(const char *name, buf_t *out) {
  char path[64];
  off_t size = 0;
  u_int sector = 0;
  char descr[DISK_IDENT_SIZE] = "", ident[DISK_IDENT_SIZE] = "";
  int fd, open_errno = 0;

  snprintf(path, sizeof(path), "/dev/%s", name);
  fd = open(path, O_RDONLY);
  if (fd < 0) {
    open_errno = errno;
  } else {
    ioctl(fd, DIOCGMEDIASIZE, &size);
    ioctl(fd, DIOCGSECTORSIZE, &sector);
#ifdef DIOCGDESCR
    ioctl(fd, DIOCGDESCR, descr);
#endif
    ioctl(fd, DIOCGIDENT, ident);
    close(fd);
  }
  bputs(out, "{\"name\":");
  bjson(out, name);
  int payload = is_payload_drive(name);
  bprintf(out, ",\"size\":%lld,\"sector\":%u,\"writable_name\":%s,\"payload_drive\":%s",
          (long long)size, sector,
          (is_writable_name(name) && !payload) ? "true" : "false",
          payload ? "true" : "false");
  bputs(out, ",\"descr\":");
  bjson(out, descr);
  char product[128], labels[256];
  drive_product(name, product, sizeof(product));
  drive_labels(path, labels, sizeof(labels));
  bputs(out, ",\"product\":");
  bjson(out, product);
  bputs(out, ",\"labels\":");
  bjson(out, labels);
  bputs(out, ",\"ident\":");
  bjson(out, ident);
  bprintf(out, ",\"open_errno\":%d,\"open_error\":", open_errno);
  bjson(out, open_errno ? strerror(open_errno) : "");
  bputs(out, ",\"mounts\":");
  mounts_of(name, out);
  bputs(out, "}");
}

static int cmpstr(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}

/* ---------- API handlers ---------- */

static void api_info(buf_t *out) {
  char disks[1024] = "";
  size_t dl = sizeof(disks) - 1;
  int kd = sysctlbyname("kern.disks", disks, &dl, NULL, 0);
  int kd_errno = kd ? errno : 0;
  if (kd == 0)
    disks[dl] = 0;
  else
    disks[0] = 0;

#ifdef WITH_LOADER
  bputs(out, "{\"boot\":true,");
#else
  bputs(out, "{");
#endif
  bprintf(out, "\"version\":\"%s\",\"uid\":%d,\"euid\":%d,\"gid\":%d",
          VERSION, getuid(), geteuid(), getgid());
  bprintf(out, ",\"authid\":\"0x%016llx\"",
          (unsigned long long)kernel_get_ucred_authid(getpid()));
  bprintf(out, ",\"kern_disks_errno\":%d,\"kern_disks\":", kd_errno);
  bjson(out, disks);

  /* every /dev entry, so unknown device names show up */
  char *names[1024];
  int nn = 0;
  DIR *d = opendir("/dev");
  struct dirent *e;
  if (d) {
    while ((e = readdir(d)) && nn < 1024)
      if (e->d_name[0] != '.')
        names[nn++] = strdup(e->d_name);
    closedir(d);
  }
  qsort(names, nn, sizeof(char *), cmpstr);
  bputs(out, ",\"dev\":[");
  for (int i = 0; i < nn; i++) {
    if (i)
      bputs(out, ",");
    bjson(out, names[i]);
  }
  bputs(out, "]");

  /* candidate disks: kern.disks entries + /dev entries that look like disks */
  bputs(out, ",\"disks\":[");
  int first = 1;
  char seen[2048] = " ";
  char tmp[sizeof(disks)];
  strcpy(tmp, disks);
  for (char *t = strtok(tmp, " "); t; t = strtok(NULL, " ")) {
    if (!valid_devname(t))
      continue;
    if (!first)
      bputs(out, ",");
    first = 0;
    disk_info(t, out);
    strncat(seen, t, sizeof(seen) - strlen(seen) - 2);
    strcat(seen, " ");
  }
  for (int i = 0; i < nn; i++) {
    const char *n = names[i];
    char key[48];
    snprintf(key, sizeof(key), " %s ", n);
    /* whole USB disks only (da0, da1, ...): /dev/usb, usbc, usbctl are
     * controller nodes, not drives */
    int looks = is_writable_name(n);
    if (looks && !strstr(seen, key) && valid_devname(n)) {
      if (!first)
        bputs(out, ",");
      first = 0;
      disk_info(n, out);
    }
  }
  bputs(out, "]");

  /* all mounts */
  struct statfs *m;
  int mn = getmntinfo(&m, MNT_NOWAIT);
  bputs(out, ",\"mounts\":[");
  for (int i = 0; i < mn; i++) {
    if (i)
      bputs(out, ",");
    bputs(out, "[");
    bjson(out, m[i].f_mntfromname);
    bputs(out, ",");
    bjson(out, m[i].f_mntonname);
    bputs(out, ",");
    bjson(out, m[i].f_fstypename);
    bputs(out, "]");
  }
  bputs(out, "]}");
  for (int i = 0; i < nn; i++)
    free(names[i]);
}

static void hexdump(buf_t *out, const unsigned char *p, size_t n) {
  for (size_t i = 0; i < n; i += 16) {
    bprintf(out, "%04zx ", i);
    for (size_t j = 0; j < 16; j++)
      bprintf(out, " %02x", p[i + j]);
    bputs(out, "  ");
    for (size_t j = 0; j < 16; j++) {
      char c[2] = {isprint(p[i + j]) ? (char)p[i + j] : '.', 0};
      bputs(out, c);
    }
    bputs(out, "\n");
  }
}

static void result(buf_t *out, int ok, const char *step, int err,
                   const char *extra) {
  bprintf(out, "{\"ok\":%s,\"step\":", ok ? "true" : "false");
  bjson(out, step);
  bprintf(out, ",\"errno\":%d,\"error\":", err);
  bjson(out, err ? strerror(err) : "");
  bputs(out, ",\"detail\":");
  bjson(out, extra ? extra : "");
  bputs(out, "}");
}

static void api_read(const char *name, buf_t *out) {
  char path[64];
  snprintf(path, sizeof(path), "/dev/%s", name);
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    result(out, 0, "open (read-only)", errno, path);
    return;
  }
  unsigned char *b = NULL;
  if (posix_memalign((void **)&b, 4096, 4096)) {
    close(fd);
    result(out, 0, "alloc", ENOMEM, NULL);
    return;
  }
  ssize_t n = pread(fd, b, 4096, 0);
  int err = errno;
  close(fd);
  if (n != 4096) {
    char d[64];
    snprintf(d, sizeof(d), "read returned %zd", n);
    result(out, 0, "read first 4 KiB", n < 0 ? err : 0, d);
    free(b);
    return;
  }
  buf_t hx = {0};
  bprintf(&hx, "First 512 bytes of %s (MBR signature %s):\n", path,
          (b[510] == 0x55 && b[511] == 0xaa) ? "55 aa present" : "absent");
  hexdump(&hx, b, 512);
  result(out, 1, "read first 4 KiB", 0, hx.p);
  free(hx.p);
  free(b);
}

/* Read 1 MiB, write the same bytes back, read again, compare. */
/* ---------- privilege ladder for the read-write open ---------- */
typedef struct {
  uint64_t authid;
  uint8_t caps[16], attrs[32];
  uid_t uid, ruid, svuid;
  gid_t rgid;
  intptr_t rootdir, jaildir;
  int have_attrs;
} creds_t;

static void creds_save(creds_t *c) {
  pid_t p = getpid();
  c->authid = kernel_get_ucred_authid(p);
  kernel_get_ucred_caps(p, c->caps);
  c->have_attrs = kernel_get_ucred_attrs(p, c->attrs) == 0;
  c->uid = geteuid();
  c->ruid = getuid();
  c->svuid = geteuid();
  c->rgid = getgid();
  c->rootdir = kernel_get_proc_rootdir(p);
  c->jaildir = kernel_get_proc_jaildir(p);
}

static void creds_restore(const creds_t *c) {
  pid_t p = getpid();
  kernel_set_ucred_authid(p, c->authid);
  kernel_set_ucred_caps(p, c->caps);
  if (c->have_attrs)
    kernel_set_ucred_attrs(p, c->attrs);
  kernel_set_ucred_uid(p, c->uid);
  kernel_set_ucred_ruid(p, c->ruid);
  kernel_set_ucred_svuid(p, c->svuid);
  kernel_set_ucred_rgid(p, c->rgid);
  if (c->rootdir)
    kernel_set_proc_rootdir(p, c->rootdir);
  kernel_set_proc_jaildir(p, c->jaildir);
}

static const uint8_t ALL_CAPS[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                     0xff, 0xff, 0xff, 0xff};

/* level 0 = as loaded; each higher level adds more rights */
static const char *LEVELS[] = {
    "as loaded",
    "all capability bits",
    "all caps + authid 0x4800000000010003 (SDK debug/ptrace)",
    "all caps + authid 0x4801000000000013 (AppInstUtil)",
    "full jailbreak (uid 0, root dir, no jail) + all caps + authid 0x48000..10003",
    "full jailbreak + all caps + authid 0x48000..10003 + attrs[0]=0x80",
    "level 5 + kern.geom.debugflags=16 (allow writing to a drive in use)",
};
#define NLEVELS (int)(sizeof(LEVELS) / sizeof(LEVELS[0]))

static void apply_level(int lvl, const creds_t *orig) {
  pid_t p = getpid();
  if (lvl >= 1)
    kernel_set_ucred_caps(p, ALL_CAPS);
  if (lvl == 2 || lvl >= 4)
    kernel_set_ucred_authid(p, 0x4800000000010003ULL);
  if (lvl == 3)
    kernel_set_ucred_authid(p, 0x4801000000000013ULL);
  if (lvl >= 4) {
    kernel_set_ucred_uid(p, 0);
    kernel_set_ucred_ruid(p, 0);
    kernel_set_ucred_svuid(p, 0);
    kernel_set_ucred_rgid(p, 0);
    intptr_t root = kernel_get_root_vnode();
    if (root)
      kernel_set_proc_rootdir(p, root);
    kernel_set_proc_jaildir(p, 0);
  }
  if (lvl >= 5 && orig->have_attrs) {
    uint8_t a[32];
    memcpy(a, orig->attrs, 32);
    a[0] |= 0x80;
    kernel_set_ucred_attrs(p, a);
  }
}

static void api_write(const char *name, buf_t *out) {
  char path[64];
  if (!is_writable_name(name)) {
    result(out, 0, "refused", EPERM, "write test only allowed on da<N>");
    return;
  }
  if (is_payload_drive(name)) {
    result(out, 0, "refused", EPERM,
           "This drive holds Linux_Flasher.elf (the drive you run payloads from). It is never written.");
    return;
  }
  snprintf(path, sizeof(path), "/dev/%s", name);

  creds_t orig;
  creds_save(&orig);
  buf_t log = {0};
  /* a mounted partition blocks opening the whole disk for writing */
  apply_level(4, &orig);
  if (unmount_disk(name, &log))
    bputs(&log, "(some partitions could not be unmounted)\n");
  creds_restore(&orig);
  int fd = -1, lvl;
  int geom_old = 0, geom_set = 0;
  size_t gl = sizeof(geom_old);
  sysctlbyname("kern.geom.debugflags", &geom_old, &gl, NULL, 0);
  for (lvl = 0; lvl < NLEVELS; lvl++) {
    if (lvl)
      apply_level(lvl, &orig);
    if (lvl == NLEVELS - 1) {
      int v = geom_old | 16;
      if (sysctlbyname("kern.geom.debugflags", NULL, NULL, &v, sizeof(v)) == 0)
        geom_set = 1;
      else
        bprintf(&log, "   (setting kern.geom.debugflags failed: %s)\n",
                strerror(errno));
    }
    fd = open(path, O_RDWR);
    int e = errno;
    bprintf(&log, "%d. %s: %s\n", lvl, LEVELS[lvl],
            fd >= 0 ? "OPENED" : strerror(e));
    if (fd >= 0)
      break;
    creds_restore(&orig);
  }
  if (fd < 0) {
    if (geom_set) {
      apply_level(5, &orig);
      sysctlbyname("kern.geom.debugflags", NULL, NULL, &geom_old, sizeof(geom_old));
      creds_restore(&orig);
    }
    bputs(&log, "\nNo level could open the drive for writing.\nUSB mounts right now:\n");
    struct statfs *m;
    int mn = getmntinfo(&m, MNT_NOWAIT);
    for (int i = 0; i < mn; i++)
      if (strncmp(m[i].f_mntonname, "/mnt/usb", 8) == 0 || strncmp(m[i].f_mntfromname, "/dev/da", 7) == 0)
        bprintf(&log, "  %s on %s (%s)\n", m[i].f_mntfromname, m[i].f_mntonname, m[i].f_fstypename);
    result(out, 0, "open (read-write), all levels", EPERM, log.p);
    free(log.p);
    return;
  }
  /* keep the working rights for the test itself; restore at the end */
  unsigned char *a = NULL, *b = NULL;
  if (posix_memalign((void **)&a, 4096, TEST_BYTES) ||
      posix_memalign((void **)&b, 4096, TEST_BYTES)) {
    close(fd);
    result(out, 0, "alloc", ENOMEM, NULL);
    free(log.p);
    creds_restore(&orig);
    return;
  }
  const char *step = "read 1 MiB";
  ssize_t n = pread(fd, a, TEST_BYTES, 0);
  if (n == TEST_BYTES) {
    step = "write the same 1 MiB back";
    n = pwrite(fd, a, TEST_BYTES, 0);
  }
  if (n == TEST_BYTES) {
    step = "flush";
    n = fsync(fd) == 0 ? TEST_BYTES : -1;
  }
  if (n == TEST_BYTES) {
    step = "read back";
    n = pread(fd, b, TEST_BYTES, 0);
  }
  int err = errno;
  close(fd);
  if (n != TEST_BYTES) {
    bprintf(&log, "\nOpened, but '%s' returned %zd", step, n);
    result(out, 0, step, n < 0 ? err : 0, log.p);
  } else if (memcmp(a, b, TEST_BYTES) != 0) {
    bputs(&log, "\nData read back differs!");
    result(out, 0, "compare", 0, log.p);
  } else {
    bputs(&log, "\nWrote 1 MiB and read it back identical. RAW WRITING WORKS.");
    result(out, 1, "write test", 0, log.p);
  }
  free(a);
  free(b);
  free(log.p);
  if (geom_set)
    sysctlbyname("kern.geom.debugflags", NULL, NULL, &geom_old, sizeof(geom_old));
  creds_restore(&orig);
}

/* unmount one /mnt/usb* mount point, whatever device it comes from */
static void api_unmount_path(const char *path, buf_t *out) {
  if (strncmp(path, "/mnt/usb", 8) != 0 || strstr(path, "..")) {
    result(out, 0, "refused", EPERM, "only /mnt/usb* mount points");
    return;
  }
  creds_t orig;
  creds_save(&orig);
  apply_level(4, &orig);
  int r = unmount(path, 0);
  int e = errno;
  if (r != 0 && e == EBUSY) {
    r = unmount(path, MNT_FORCE);
    e = errno;
  }
  creds_restore(&orig);
  result(out, r == 0, "unmount", r == 0 ? 0 : e, path);
}

static void api_unmount(const char *name, int force, buf_t *out) {
  if (!is_writable_name(name) || is_payload_drive(name)) {
    result(out, 0, "refused", EPERM, "only da<N> drives");
    return;
  }
  struct statfs *m;
  int n = getmntinfo(&m, MNT_NOWAIT);
  char dev[64], done[512] = "";
  snprintf(dev, sizeof(dev), "/dev/%s", name);
  size_t dl = strlen(dev);
  int err = 0, count = 0;
  for (int i = 0; i < n; i++) {
    const char *f = m[i].f_mntfromname;
    if (strncmp(f, dev, dl) == 0 &&
        (f[dl] == 0 || f[dl] == 's' || f[dl] == 'p')) {
      if (unmount(m[i].f_mntonname, force ? MNT_FORCE : 0) != 0)
        err = errno;
      else {
        count++;
        strncat(done, m[i].f_mntonname, sizeof(done) - strlen(done) - 2);
        strcat(done, " ");
      }
    }
  }
  char d[600];
  snprintf(d, sizeof(d), "unmounted %d: %s", count, done);
  result(out, err == 0, "unmount", err, d);
}

/* ---------- HTTP ---------- */

static const char page[] =
#include "page.html.h"
    ;

static void reply(int fd, int status, const char *type, const char *body,
                  size_t len) {
  char hdr[256];
  int n = snprintf(hdr, sizeof(hdr),
                   "HTTP/1.1 %d %s\r\nContent-Type: %s\r\n"
                   "Content-Length: %zu\r\nCache-Control: no-store\r\n"
                   "Connection: close\r\n\r\n",
                   status, status == 200 ? "OK" : "Error", type, len);
  send(fd, hdr, (size_t)n, 0);
  while (len > 0) {
    ssize_t w = send(fd, body, len, 0);
    if (w <= 0)
      break;
    body += w;
    len -= (size_t)w;
  }
}

static void query_param(const char *q, const char *key, char *val, size_t vl) {
  size_t kl = strlen(key);
  val[0] = 0;
  while (q && *q) {
    if (strncmp(q, key, kl) == 0 && q[kl] == '=') {
      size_t i = 0;
      q += kl + 1;
      while (*q && *q != '&' && *q != ' ' && i + 1 < vl)
        val[i++] = *q++;
      val[i] = 0;
      return;
    }
    q = strchr(q, '&');
    if (q)
      q++;
  }
}

/* Append each API result to Linux_Flasher_report.txt on every USB drive that
 * has Linux_Flasher.elf in its root (= the drive the payload is kept on). */
static void save_report(const char *req, const buf_t *out) {
  char p[96];
  struct stat st;
  for (int i = 0; i < 8; i++) {
    snprintf(p, sizeof(p), "/mnt/usb%d/Linux_Flasher.elf", i);
    if (stat(p, &st) != 0)
      snprintf(p, sizeof(p), "/mnt/usb%d/Linux_Flasher_personal.elf", i);
    if (stat(p, &st) != 0) {
      snprintf(p, sizeof(p), "/mnt/usb%d/USB_Flasher.elf", i);
      if (stat(p, &st) != 0)
        continue;
    }
    snprintf(p, sizeof(p), "/mnt/usb%d/Linux_Flasher_report.txt", i);
    int f = open(p, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (f < 0)
      continue;
    char hdr[300];
    int n = snprintf(hdr, sizeof(hdr), "=== %ld v" VERSION " %s\n", (long)time(NULL), req);
    write(f, hdr, (size_t)n);
    write(f, out->p, out->len);
    write(f, "\n\n", 2);
    fsync(f);
    close(f);
  }
}

#include "flash_api.inc"

static int handle(int fd) {
  char req[2048];
  ssize_t n = recv(fd, req, sizeof(req) - 1, 0);
  if (n <= 0)
    return 0;
  req[n] = 0;
  char reqline[200];
  snprintf(reqline, sizeof(reqline), "%.*s", (int)strcspn(req, "\r\n"), req);
  if (strncmp(req, "GET ", 4) != 0) {
    reply(fd, 405, "text/plain", "GET only\n", 9);
    return 0;
  }
  char *path = req + 4, *sp = strchr(path, ' ');
  if (sp)
    *sp = 0;
  char *q = strchr(path, '?');
  if (q)
    *q++ = 0;

  char dev[40], authid[24], force[4], mpath[64], img[1024];
  query_param(q, "img", img, sizeof(img));
  url_decode(img);
  char url[1024], sha[80];
  query_param(q, "url", url, sizeof(url));
  url_decode(url);
  query_param(q, "sha", sha, sizeof(sha));
  query_param(q, "path", mpath, sizeof(mpath));
  query_param(q, "dev", dev, sizeof(dev));
  query_param(q, "authid", authid, sizeof(authid));
  query_param(q, "force", force, sizeof(force));

  /* optional experiment: run this request with a different authid */
  uint64_t old_authid = 0;
  int swapped = 0;
  if (authid[0]) {
    old_authid = kernel_get_ucred_authid(getpid());
    if (kernel_set_ucred_authid(getpid(), strtoull(authid, NULL, 16)) == 0)
      swapped = 1;
  }

  buf_t out = {0};
  int quit = 0;
  if (strcmp(path, "/") == 0) {
    reply(fd, 200, "text/html; charset=utf-8", page, sizeof(page) - 1);
  } else if (strcmp(path, "/api/info") == 0) {
    api_info(&out);
  } else if (strcmp(path, "/api/read") == 0 && valid_devname(dev)) {
    api_read(dev, &out);
  } else if (strcmp(path, "/api/write") == 0 && valid_devname(dev)) {
    api_write(dev, &out);
  } else if (strcmp(path, "/api/unmount") == 0 && valid_devname(dev)) {
    api_unmount(dev, force[0] == '1', &out);
  } else if (strcmp(path, "/api/umountpath") == 0) {
    api_unmount_path(mpath, &out);
  } else if (strcmp(path, "/api/images") == 0) {
    api_images(&out);
  } else if (strcmp(path, "/api/flash") == 0 && valid_devname(dev)) {
    api_flash(img, dev, &out);
  } else if (strcmp(path, "/api/download") == 0) {
    api_download(url, sha, &out);
  } else if (strcmp(path, "/api/dlprogress") == 0) {
    dl_json(&out);
  } else if (strcmp(path, "/api/dlcancel") == 0) {
    dl_cancel();
    result(&out, 1, "download paused", 0, "");
  } else if (strcmp(path, "/api/delimg") == 0) {
    api_delimg(img, &out);
  } else if (strcmp(path, "/api/progress") == 0) {
    job_json(&out);
  } else if (strcmp(path, "/api/cancel") == 0) {
    job.cancel = 1;
    result(&out, 1, "cancel requested", 0, "");
#ifdef WITH_LOADER
  } else if (strcmp(path, "/api/bootlinux") == 0) {
    char src[128], err[160];
    if (job_busy() || dl_busy()) {
      result(&out, 0, "boot", EBUSY, "A flash or download is running.");
    } else if (boot_linux(src, sizeof(src), err, sizeof(err)) == 0) {
      result(&out, 1, "boot", 0, src);
      notify("Starting Linux...\n%s", src);
    } else {
      result(&out, 0, "boot", EIO, err);
    }
#endif
  } else if (strcmp(path, "/api/quit") == 0) {
    if (job_busy() || dl_busy()) {
      result(&out, 0, "quit", EBUSY, "A flash or download is running. Cancel it first.");
    } else {
      result(&out, 1, "quit", 0, "Linux Flasher stopped");
      quit = 1;
    }
  } else {
    reply(fd, 404, "text/plain", "not found\n", 10);
  }
  if (out.p) {
    reply(fd, 200, "application/json", out.p, out.len);
    if (strcmp(path, "/api/progress") != 0 && strcmp(path, "/api/images") != 0 &&
        strcmp(path, "/api/dlprogress") != 0 &&
        strcmp(path, "/api/info") != 0)
      save_report(reqline, &out);
  }
  free(out.p);

  if (swapped)
    kernel_set_ucred_authid(getpid(), old_authid);
  return quit;
}

static void local_ip(char *ip, size_t len) {
  struct ifaddrs *ifa, *i;
  snprintf(ip, len, "<ps5-ip>");
  if (getifaddrs(&ifa) != 0)
    return;
  for (i = ifa; i; i = i->ifa_next) {
    if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET)
      continue;
    struct sockaddr_in *s = (struct sockaddr_in *)i->ifa_addr;
    if (ntohl(s->sin_addr.s_addr) >> 24 == 127)
      continue;
    inet_ntop(AF_INET, &s->sin_addr, ip, (socklen_t)len);
    break;
  }
  freeifaddrs(ifa);
}

int main(void) {
  signal(SIGPIPE, SIG_IGN);
  int s = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in a = {0};
  a.sin_family = AF_INET;
  a.sin_port = htons(PORT);
  a.sin_addr.s_addr = htonl(INADDR_ANY);
  sceUserServiceInitialize(NULL);
  char url[64];
  snprintf(url, sizeof(url), "http://127.0.0.1:%d/", PORT);

  if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(s, 8) != 0) {
    /* already running: just show its page again */
    close(s);
    notify("Linux Flasher is already running - opening it");
    sceSystemServiceLaunchWebBrowser(url, NULL);
    return 0;
  }

  int tile = tile_install();
  char ip[64];
  local_ip(ip, sizeof(ip));
  notify("Linux Flasher " VERSION " ready%s\nPhone: http://%s:%d",
         tile == 0 ? "\nOpen it from Media on the home screen" : "",
         ip, PORT);

  if (sceSystemServiceLaunchWebBrowser(url, NULL) != 0)
    notify("Linux Flasher: could not open the browser.\nOpen %s yourself.", url);

  for (;;) {
    int c = accept(s, NULL, NULL);
    if (c < 0)
      continue;
    int quit = handle(c);
    close(c);
    if (quit)
      break;
  }
  close(s);
  notify("Linux Flasher stopped");
  return 0;
}
