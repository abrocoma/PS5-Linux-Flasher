/* Home-screen (Media row) tile for Linux Flasher.
 *
 * The tile is a web link only: a Media-category title whose deeplink points
 * at this payload's HTTP server (http://127.0.0.1:9077/). No app is
 * installed or launched. Registration is adapted from PS-Play /
 * ProsperoPlayer's media launcher (https://github.com/MounirHero/PS-Play),
 * GPL-3.0-or-later, via our Hello Brother / PS5 Linux launchers.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ps5/kernel.h>

#define TILE_ID "USBF00001"
#define APP_ROOT "/user/app"
#define APP_DIR APP_ROOT "/" TILE_ID
#define APPINST_AUTHID UINT64_C(0x4801000000000013)

int sceAppInstUtilInitialize(void);
int sceAppInstUtilTerminate(void);
int sceAppInstUtilAppInstallAll(void *);
int sceAppInstUtilAppUnInstall(const char *, void *, void *);
typedef int (*install_title_dir_fn)(const char *, const char *, void *);

#define INCASSET(name, file)                                                   \
  __asm__(".section .rodata\n"                                                 \
          ".global " #name "\n" #name ":\n"                                    \
          ".incbin \"" file "\"\n" #name "_end:\n"                             \
          ".global " #name "_size\n" #name "_size:\n"                          \
          ".quad " #name "_end - " #name "\n");                                \
  extern const uint8_t name[];                                                 \
  extern const unsigned long name##_size

INCASSET(tile_param, "assets/param.json");
INCASSET(tile_icon, "assets/icon0.png");

static int mk(const char *p) {
  return (mkdir(p, 0755) == 0 || errno == EEXIST) ? 0 : -1;
}

static int write_file(const char *path, const uint8_t *d, size_t n) {
  int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  size_t off = 0;
  if (fd < 0)
    return -1;
  while (off < n) {
    ssize_t w = write(fd, d + off, n - off);
    if (w <= 0) {
      close(fd);
      return -1;
    }
    off += (size_t)w;
  }
  fsync(fd);
  close(fd);
  return 0;
}

/* Returns 0 when the tile is registered (or already was). */
int tile_install(void) {
  pid_t pid = getpid();
  uint64_t orig = kernel_get_ucred_authid(pid);
  int rc = -1;

  if (kernel_set_ucred_authid(pid, APPINST_AUTHID) != 0)
    return -1;
  if (sceAppInstUtilInitialize() != 0)
    goto out;
  if (mk(APP_ROOT) || mk(APP_DIR) || mk(APP_DIR "/sce_sys") ||
      write_file(APP_DIR "/sce_sys/param.json", tile_param, tile_param_size) ||
      write_file(APP_DIR "/sce_sys/icon0.png", tile_icon, tile_icon_size)) {
    sceAppInstUtilTerminate();
    goto out;
  }
  uint32_t h = 0;
  install_title_dir_fn install_dir = NULL;
  if (kernel_dynlib_handle(-1, "libSceAppInstUtil.sprx", &h) == 0)
    install_dir = (install_title_dir_fn)kernel_dynlib_resolve(-1, h, "Wudg3Xe3heE");
  int t = install_dir ? install_dir(TILE_ID, APP_ROOT "/", NULL) : -1;
  int a = t == 0 ? 0 : sceAppInstUtilAppInstallAll(NULL);
  rc = (t == 0 || a == 0) ? 0 : -1;
  sceAppInstUtilTerminate();
out:
  if (orig)
    kernel_set_ucred_authid(pid, orig);
  return rc;
}
