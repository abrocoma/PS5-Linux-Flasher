#pragma once
#include <stdarg.h>
#include <stdint.h>

enum {
  FLASH_IDLE = 0,
  FLASH_WRITING,
  FLASH_VERIFYING,
  FLASH_DONE,
  FLASH_FAILED,
  FLASH_CANCELLED,
};

typedef struct {
  volatile int state;
  volatile int cancel;
  char img[1024];
  char dev[256];
  char label[128];          /* "7.8 GB STORE N GO" for messages */
  uint64_t total;           /* expected bytes to write (0 = unknown) */
  uint64_t img_size;        /* image file size */
  volatile uint64_t read_bytes, written, verified;
  double t_start, t_written, t_done;
  int sidecar;              /* 0 none, 1 match, -1 mismatch */
  char sha_image_file[65], sha_written[65], sha_readback[65];
  char msg[512];
} flash_job_t;

double flash_now(void);
int flash_is_xz(const char *path);
uint64_t flash_xz_size(const char *path);
uint64_t flash_image_size(const char *path);
int flash_read_sidecar(const char *img, char out[65]);
void flash_run(flash_job_t *j);
