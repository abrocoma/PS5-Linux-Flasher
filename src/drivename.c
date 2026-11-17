/* Friendlier drive names: the USB product description (when the console's
 * sysctl tree has it) and the volume labels found on the drive itself
 * (FAT, exFAT, ext2/3/4), read through the raw disk. */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if defined(__FreeBSD__) || defined(__PROSPERO__)
#include <sys/sysctl.h>
#include <sys/types.h>
#endif

#include "drivename.h"

#define SECT 512

static int rd(int fd, uint64_t off, void *buf, size_t n) {
  return pread(fd, buf, n, (off_t)off) == (ssize_t)n ? 0 : -1;
}

static uint32_t le32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t le64(const uint8_t *p) { return le32(p) | (uint64_t)le32(p + 4) << 32; }

/* trim trailing spaces/NULs, keep printable ASCII */
static void clean(char *s) {
  size_t n = strlen(s);
  for (size_t i = 0; i < n; i++)
    if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] > 0x7e)
      s[i] = '?';
  while (n && (s[n - 1] == ' ' || s[n - 1] == '?'))
    s[--n] = 0;
}

/* label of the file system that starts at byte offset off (or "") */
static void fs_label(int fd, uint64_t off, char *out, size_t ol) {
  uint8_t b[SECT * 3];
  out[0] = 0;
  if (rd(fd, off, b, SECT))
    return;
  /* exFAT */
  if (memcmp(b + 3, "EXFAT   ", 8) == 0) {
    uint32_t heap = le32(b + 88), root = le32(b + 96);
    unsigned bps = 1u << b[108], spc = 1u << b[109];
    uint64_t pos = off + ((uint64_t)heap + (uint64_t)(root - 2) * spc) * bps;
    uint8_t *c = malloc((size_t)bps * spc > 65536 ? 65536 : (size_t)bps * spc);
    size_t cl = (size_t)bps * spc > 65536 ? 65536 : (size_t)bps * spc;
    if (c && rd(fd, pos, c, cl) == 0) {
      for (size_t i = 0; i + 32 <= cl; i += 32) {
        if (c[i] == 0x83) { /* volume label entry */
          int n = c[i + 1] > 11 ? 11 : c[i + 1];
          size_t k = 0;
          for (int j = 0; j < n && k + 1 < ol; j++) {
            uint16_t ch = c[i + 2 + 2 * j] | c[i + 3 + 2 * j] << 8;
            out[k++] = ch < 0x80 ? (char)ch : '?';
          }
          out[k] = 0;
          break;
        }
        if (c[i] == 0)
          break;
      }
    }
    free(c);
    clean(out);
    return;
  }
  /* FAT32 / FAT16 */
  if (b[510] == 0x55 && b[511] == 0xaa) {
    int at = -1;
    if (memcmp(b + 82, "FAT32   ", 8) == 0)
      at = 71;
    else if (memcmp(b + 54, "FAT1", 4) == 0 || memcmp(b + 54, "FAT  ", 5) == 0)
      at = 43;
    if (at > 0) {
      snprintf(out, ol, "%.11s", (char *)b + at);
      clean(out);
      if (strcmp(out, "NO NAME") == 0)
        out[0] = 0;
      return;
    }
  }
  /* ISO 9660 (hybrid ISO images): primary volume descriptor at +32768 */
  if (rd(fd, off + 32768, b, SECT) == 0 && b[0] == 1 && memcmp(b + 1, "CD001", 5) == 0) {
    snprintf(out, ol, "%.32s", (char *)b + 40);
    clean(out);
    return;
  }
  /* ext2/3/4: superblock at +1024, magic 0xEF53 at 0x38, label at 0x78 */
  if (rd(fd, off + 1024, b, SECT) == 0 && b[0x38] == 0x53 && b[0x39] == 0xef) {
    snprintf(out, ol, "%.16s", (char *)b + 0x78);
    clean(out);
  }
}

/* partition start offsets (bytes) from GPT or MBR; returns count */
static int partitions(int fd, uint64_t *st, int max) {
  uint8_t m[SECT], g[SECT];
  int n = 0;
  if (rd(fd, 0, m, SECT) || m[510] != 0x55 || m[511] != 0xaa)
    return 0;
  if (m[450] == 0xee && rd(fd, SECT, g, SECT) == 0 && memcmp(g, "EFI PART", 8) == 0) {
    uint64_t lba = le64(g + 72);
    uint32_t cnt = le32(g + 80), sz = le32(g + 84);
    if (sz < 128 || sz > 512 || cnt > 256)
      return 0;
    uint8_t *e = malloc((size_t)cnt * sz);
    if (e && rd(fd, lba * SECT, e, (size_t)cnt * sz) == 0)
      for (uint32_t i = 0; i < cnt && n < max; i++) {
        uint8_t *p = e + (size_t)i * sz;
        int used = 0;
        for (int j = 0; j < 16; j++)
          used |= p[j];
        if (used)
          st[n++] = le64(p + 32) * SECT;
      }
    free(e);
    return n;
  }
  for (int i = 0; i < 4 && n < max; i++) {
    uint8_t *p = m + 446 + 16 * i;
    uint32_t s = le32(p + 8);
    if (p[4] && s)
      st[n++] = (uint64_t)s * SECT;
  }
  if (n == 0) /* no partition table: file system on the whole disk */
    st[n++] = 0;
  return n;
}

void drive_labels(const char *dev, char *out, size_t ol) {
  uint64_t st[16];
  out[0] = 0;
  int fd = open(dev, O_RDONLY);
  if (fd < 0)
    return;
  int n = partitions(fd, st, 15);
  st[n++] = 0; /* whole disk last: catches hybrid ISOs */
  for (int i = 0; i < n; i++) {
    char l[64];
    fs_label(fd, st[i], l, sizeof(l));
    if (!l[0] || strstr(out, l))
      continue;
    size_t len = strlen(out);
    snprintf(out + len, ol - len, "%s%s", len ? ", " : "", l);
  }
  close(fd);
}

/* USB product description of daN via dev.da.N.%parent -> dev.umass.M.%desc */
void drive_product(const char *name, char *out, size_t ol) {
  out[0] = 0;
#if defined(__FreeBSD__) || defined(__PROSPERO__)
  if (strncmp(name, "da", 2))
    return;
  char key[64], parent[64], desc[256];
  size_t l = sizeof(parent) - 1;
  snprintf(key, sizeof(key), "dev.da.%s.%%parent", name + 2);
  if (sysctlbyname(key, parent, &l, NULL, 0) != 0)
    return;
  parent[l] = 0;
  /* "umass0" -> dev.umass.0.%desc */
  char *d = parent;
  while (*d && (*d < '0' || *d > '9'))
    d++;
  if (!*d)
    return;
  snprintf(key, sizeof(key), "dev.%.*s.%s.%%desc", (int)(d - parent), parent, d);
  l = sizeof(desc) - 1;
  if (sysctlbyname(key, desc, &l, NULL, 0) != 0)
    return;
  desc[l] = 0;
  char *comma = strchr(desc, ',');
  if (comma)
    *comma = 0;
  snprintf(out, ol, "%s", desc);
  clean(out);
#else
  (void)name;
#endif
}
