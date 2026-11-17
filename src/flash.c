/* Flash engine: writes an .img or .img.xz to a raw device (or file) and
 * verifies it by reading back.  Portable: builds for the PS5 payload and
 * for Linux (host test).  Device preparation (unmount, rights) is done by
 * the caller. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "flash.h"
#include "sha256.h"
#define XZ_USE_CRC64 /* must match xz/xz_config.h */
#include "xz/xz.h"

#define CHUNK (4u << 20)   /* write size: 4 MiB */
#define INBUF (1u << 20)   /* compressed read size */
#define DICT_MAX (64u << 20)

double flash_now(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec / 1e6;
}

static int ends_with(const char *s, const char *suf) {
  size_t a = strlen(s), b = strlen(suf);
  return a >= b && strcasecmp(s + a - b, suf) == 0;
}

int flash_is_xz(const char *path) { return ends_with(path, ".xz"); }

static int vli(const uint8_t *b, size_t n, size_t *i, uint64_t *v) {
  *v = 0;
  for (int s = 0; s < 63 && *i < n; s += 7) {
    uint8_t x = b[(*i)++];
    *v |= (uint64_t)(x & 0x7f) << s;
    if (!(x & 0x80))
      return 0;
  }
  return -1;
}

/* Uncompressed size of an .xz file from its index (single stream, optional
 * stream padding).  Returns 0 if unknown. */
uint64_t flash_xz_size(const char *path) {
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return 0;
  struct stat st;
  uint64_t total = 0;
  uint8_t f[12];
  off_t end;
  if (fstat(fd, &st) != 0 || st.st_size < 32)
    goto out;
  end = st.st_size;
  /* skip stream padding (zero bytes, multiple of 4) */
  for (;;) {
    uint8_t z[4];
    if (end < 32 || pread(fd, z, 4, end - 4) != 4)
      goto out;
    if (z[0] | z[1] | z[2] | z[3])
      break;
    end -= 4;
  }
  if (pread(fd, f, 12, end - 12) != 12 || f[10] != 'Y' || f[11] != 'Z')
    goto out;
  uint32_t bs = (uint32_t)f[4] | f[5] << 8 | f[6] << 16 | (uint32_t)f[7] << 24;
  size_t isz = ((size_t)bs + 1) * 4;
  if (isz > (64u << 20) || (off_t)isz + 12 > end)
    goto out;
  uint8_t *idx = malloc(isz);
  if (!idx)
    goto out;
  if (pread(fd, idx, isz, end - 12 - (off_t)isz) == (ssize_t)isz &&
      idx[0] == 0) {
    size_t i = 1;
    uint64_t n, u, c;
    if (vli(idx, isz, &i, &n) == 0) {
      for (uint64_t k = 0; k < n; k++) {
        if (vli(idx, isz, &i, &u) || vli(idx, isz, &i, &c)) {
          total = 0;
          break;
        }
        total += c;
      }
    }
  }
  free(idx);
out:
  close(fd);
  return total;
}

uint64_t flash_image_size(const char *path) {
  if (flash_is_xz(path))
    return flash_xz_size(path);
  struct stat st;
  return stat(path, &st) == 0 ? (uint64_t)st.st_size : 0;
}

/* Read "<64 hex>" from <image>.sha256 if present. */
int flash_read_sidecar(const char *img, char out[65]) {
  char p[1100];
  snprintf(p, sizeof(p), "%s.sha256", img);
  int fd = open(p, O_RDONLY);
  out[0] = 0;
  if (fd < 0)
    return -1;
  char b[128];
  ssize_t n = read(fd, b, sizeof(b) - 1);
  close(fd);
  if (n < 64)
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

static void fail(flash_job_t *j, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(j->msg, sizeof(j->msg), fmt, ap);
  va_end(ap);
  j->state = FLASH_FAILED;
}

/* write one chunk, padding the tail to a whole sector */
static int put(flash_job_t *j, int dfd, uint8_t *buf, size_t len, sha256_t *sw) {
  sha256_update(sw, buf, len);
  size_t wl = (len + 511) & ~(size_t)511;
  if (wl != len)
    memset(buf + len, 0, wl - len);
  ssize_t w = pwrite(dfd, buf, wl, (off_t)j->written);
  if (w != (ssize_t)wl) {
    if (w >= 0 || errno == ENOSPC)
      fail(j, "The drive is full after %.1f MB: the image doesn't fit on it",
           j->written / 1e6);
    else
      fail(j, "Write failed at %.1f MB: %s", j->written / 1e6, strerror(errno));
    return -1;
  }
  j->written += len;
  return 0;
}

void flash_run(flash_job_t *j) {
  int ifd = -1, dfd = -1;
  uint8_t *in = NULL, *out = NULL;
  struct xz_dec *xz = NULL;
  sha256_t sw, sf, sr;
  char hw[65], hf[65], hr[65];

  j->written = j->verified = 0;
  j->t_start = flash_now();
  j->state = FLASH_WRITING;
  snprintf(j->msg, sizeof(j->msg), "Writing");

  ifd = open(j->img, O_RDONLY);
  if (ifd < 0) {
    fail(j, "Can't open the image: %s", strerror(errno));
    goto done;
  }
  dfd = open(j->dev, O_RDWR);
  if (dfd < 0) {
    fail(j, "Can't open %s for writing: %s", j->dev, strerror(errno));
    goto done;
  }
  in = malloc(INBUF);
  if (posix_memalign((void **)&out, 4096, CHUNK) || !in) {
    fail(j, "Out of memory");
    goto done;
  }
  sha256_init(&sw);
  sha256_init(&sf);

  if (flash_is_xz(j->img)) {
    xz_crc32_init();
    xz_crc64_init();
    xz = xz_dec_init(XZ_DYNALLOC, DICT_MAX);
    if (!xz) {
      fail(j, "Out of memory (xz)");
      goto done;
    }
    struct xz_buf b = {.in = in, .in_pos = 0, .in_size = 0,
                       .out = out, .out_pos = 0, .out_size = CHUNK};
    int eof = 0;
    for (;;) {
      if (j->cancel) {
        fail(j, "Cancelled");
        j->state = FLASH_CANCELLED;
        goto done;
      }
      if (b.in_pos == b.in_size && !eof) {
        ssize_t n = read(ifd, in, INBUF);
        if (n < 0) {
          fail(j, "Reading the image failed: %s", strerror(errno));
          goto done;
        }
        if (n == 0)
          eof = 1;
        sha256_update(&sf, in, (size_t)n);
        j->read_bytes += (uint64_t)n;
        b.in_size = (size_t)n;
        b.in_pos = 0;
      }
      enum xz_ret r = xz_dec_catrun(xz, &b, eof);
      if (b.out_pos == b.out_size || (r == XZ_STREAM_END && b.out_pos)) {
        if (put(j, dfd, out, b.out_pos, &sw))
          goto done;
        b.out_pos = 0;
      }
      if (r == XZ_STREAM_END)
        break;
      if (r != XZ_OK) {
        fail(j, "The image is damaged or not a valid .xz (xz error %d at %.1f MB)",
             (int)r, j->written / 1e6);
        goto done;
      }
    }
  } else {
    for (;;) {
      if (j->cancel) {
        fail(j, "Cancelled");
        j->state = FLASH_CANCELLED;
        goto done;
      }
      ssize_t n = read(ifd, out, CHUNK);
      if (n < 0) {
        fail(j, "Reading the image failed: %s", strerror(errno));
        goto done;
      }
      if (n == 0)
        break;
      sha256_update(&sf, out, (size_t)n);
      j->read_bytes += (uint64_t)n;
      if (put(j, dfd, out, (size_t)n, &sw))
        goto done;
    }
  }
  if (fsync(dfd) != 0 && errno != ENODEV && errno != EINVAL) {
    fail(j, "Flushing the drive failed: %s", strerror(errno));
    goto done;
  }
  sha256_hex(&sw, hw);
  sha256_hex(&sf, hf);
  snprintf(j->sha_image_file, sizeof(j->sha_image_file), "%s", hf);
  snprintf(j->sha_written, sizeof(j->sha_written), "%s", hw);
  j->t_written = flash_now();

  /* image file checksum against the .sha256 next to it */
  char side[65];
  if (flash_read_sidecar(j->img, side) == 0) {
    j->sidecar = strcmp(side, hf) == 0 ? 1 : -1;
    if (j->sidecar < 0) {
      fail(j, "The image file doesn't match its .sha256 (corrupt download?)");
      goto done;
    }
  }

  /* verify: read back what was written */
  j->state = FLASH_VERIFYING;
  snprintf(j->msg, sizeof(j->msg), "Verifying");
  sha256_init(&sr);
  while (j->verified < j->written) {
    if (j->cancel) {
      fail(j, "Verify cancelled (the drive was written)");
      j->state = FLASH_CANCELLED;
      goto done;
    }
    uint64_t left = j->written - j->verified;
    size_t want = left < CHUNK ? (size_t)left : CHUNK;
    size_t rl = (want + 511) & ~(size_t)511;
    ssize_t n = pread(dfd, out, rl, (off_t)j->verified);
    if (n < (ssize_t)want) {
      fail(j, "Reading back failed at %.1f MB: %s", j->verified / 1e6,
           n < 0 ? strerror(errno) : "short read");
      goto done;
    }
    sha256_update(&sr, out, want);
    j->verified += want;
  }
  sha256_hex(&sr, hr);
  snprintf(j->sha_readback, sizeof(j->sha_readback), "%s", hr);
  if (strcmp(hr, hw) != 0) {
    fail(j, "VERIFY FAILED: the drive doesn't hold what was written. Try another drive or port.");
    goto done;
  }
  j->t_done = flash_now();
  snprintf(j->msg, sizeof(j->msg), "Done: %.2f GB written and verified",
           j->written / 1e9);
  j->state = FLASH_DONE;

done:
  if (xz)
    xz_dec_end(xz);
  free(in);
  free(out);
  if (ifd >= 0)
    close(ifd);
  if (dfd >= 0)
    close(dfd);
  if (!j->t_done)
    j->t_done = flash_now();
}
