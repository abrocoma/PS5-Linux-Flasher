/* Personal build only (-DWITH_LOADER): "Boot Linux" sends ps5-linux-loader
 * to the ELF loader on 127.0.0.1:9021, like sending it from a PC.
 * Loader: ps5-linux-loader.elf on a USB drive (root or PS5/Linux/) if present,
 * else the newest release of soniciso1/ps5-linux-loader from GitHub,
 * else the copy downloaded last time (saved on the PS5). */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "download.h"
#include "net.h"

#define REPO_API "https://api.github.com/repos/soniciso1/ps5-linux-loader/releases/latest"
#define CACHE DL_DIR "/ps5-linux-loader.elf"
#define CACHE_TAG DL_DIR "/ps5-linux-loader.tag"
#define MAXELF (16u << 20)

static uint8_t *readfile(const char *p, size_t *n) {
  struct stat st;
  if (stat(p, &st) || st.st_size < 64 || st.st_size > (off_t)MAXELF)
    return NULL;
  uint8_t *b = malloc((size_t)st.st_size);
  int fd = open(p, O_RDONLY);
  if (!b || fd < 0) {
    free(b);
    if (fd >= 0)
      close(fd);
    return NULL;
  }
  ssize_t r = read(fd, b, (size_t)st.st_size);
  close(fd);
  if (r != st.st_size || memcmp(b, "\x7f" "ELF", 4)) {
    free(b);
    return NULL;
  }
  *n = (size_t)st.st_size;
  return b;
}

/* GET url into memory (max bytes); returns buffer or NULL */
static uint8_t *fetch(const char *url, size_t max, size_t *n) {
  hc_t h;
  hc_init(&h);
  int st = 0, known = 0;
  uint64_t len = 0;
  char err[160];
  uint8_t *b = NULL;
  *n = 0;
  if (hc_get(&h, url, 0, &st, &len, &known, err, sizeof(err)) == 0 && st == 200) {
    b = malloc(max + 1);
    while (b && *n < max) {
      int k = hc_read(&h, b + *n, max - *n);
      if (k <= 0)
        break;
      *n += (size_t)k;
    }
    if (b)
      b[*n] = 0;
  }
  hc_close(&h);
  return b;
}

/* copy the JSON string value after "key": into out */
static int json_str(const char *j, const char *key, const char *from, char *out, size_t ol) {
  char k[64];
  snprintf(k, sizeof(k), "\"%s\"", key);
  const char *p = strstr(from ? from : j, k);
  if (!p || !(p = strchr(p + strlen(k), '"')))
    return -1;
  p++;
  size_t i = 0;
  while (*p && *p != '"' && i + 1 < ol)
    out[i++] = *p++;
  out[i] = 0;
  return 0;
}

/* newest release .elf from GitHub; saves it as the cached copy */
static uint8_t *latest(size_t *n, char *tag, size_t tl) {
  size_t jn;
  char *j = (char *)fetch(REPO_API, 256 * 1024, &jn);
  if (!j)
    return NULL;
  char url[512] = "";
  tag[0] = 0;
  json_str(j, "tag_name", NULL, tag, tl);
  for (const char *p = j; (p = strstr(p, "\"browser_download_url\"")); p++) {
    if (json_str(j, "browser_download_url", p, url, sizeof(url)) == 0) {
      size_t l = strlen(url);
      if (l > 4 && strcmp(url + l - 4, ".elf") == 0)
        break;
    }
    url[0] = 0;
  }
  free(j);
  if (!url[0])
    return NULL;
  uint8_t *elf = fetch(url, MAXELF, n);
  if (!elf || *n < 64 || memcmp(elf, "\x7f" "ELF", 4)) {
    free(elf);
    return NULL;
  }
  mkdir("/data", 0755);
  mkdir(DL_DIR, 0755);
  int fd = open(CACHE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) {
    write(fd, elf, *n);
    close(fd);
  }
  fd = open(CACHE_TAG, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) {
    write(fd, tag, strlen(tag));
    close(fd);
  }
  return elf;
}

/* returns 0 when sent; src says which loader was used */
int boot_linux(char *src, size_t sl, char *err, size_t el) {
  static const char *sub[] = {"", "PS5/Linux/"};
  uint8_t *elf = NULL;
  size_t n = 0;
  char tag[96];
  for (int j = 0; j < 2 && !elf; j++)
    for (int i = 0; i < 8 && !elf; i++) {
      char p[96];
      snprintf(p, sizeof(p), "/mnt/usb%d/%sps5-linux-loader.elf", i, sub[j]);
      if ((elf = readfile(p, &n)))
        snprintf(src, sl, "%s", p);
    }
  if (!elf && (elf = latest(&n, tag, sizeof(tag))))
    snprintf(src, sl, "soniciso1 %s (downloaded)", tag[0] ? tag : "latest");
  if (!elf && (elf = readfile(CACHE, &n))) {
    tag[0] = 0;
    int fd = open(CACHE_TAG, O_RDONLY);
    if (fd >= 0) {
      ssize_t k = read(fd, tag, sizeof(tag) - 1);
      tag[k > 0 ? k : 0] = 0;
      close(fd);
    }
    snprintf(src, sl, "soniciso1 %s (saved copy, offline)", tag[0] ? tag : "");
  }
  if (!elf) {
    snprintf(err, el, "No loader: no ps5-linux-loader.elf on USB, GitHub not reachable and no saved copy yet.");
    return -1;
  }
  int rc = -1, fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a = {0};
  a.sin_family = AF_INET;
  a.sin_port = htons(9021);
  a.sin_addr.s_addr = inet_addr("127.0.0.1");
  if (fd < 0 || connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
    snprintf(err, el, "The ELF loader isn't running (port 9021).");
  } else {
    size_t off = 0;
    while (off < n) {
      ssize_t w = send(fd, elf + off, n - off, 0);
      if (w <= 0)
        break;
      off += (size_t)w;
    }
    rc = off == n ? 0 : -1;
    if (rc)
      snprintf(err, el, "Sending the loader failed.");
  }
  if (fd >= 0)
    close(fd);
  free(elf);
  return rc;
}
