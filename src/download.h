#pragma once
#include <stdint.h>

#define DL_DIR "/data/LinuxFlasher"
#define DL_VERSION "1.4"

enum { DL_IDLE = 0, DL_RUNNING, DL_DONE, DL_FAILED, DL_CANCELLED };

typedef struct {
  volatile int state, cancel;
  char url[1024];
  char path[1100]; /* final file in DL_DIR */
  volatile uint64_t got, total, resumed_from;
  double t_start, t_done;
  int has_sidecar;
  char sha[65];
  char expect[65]; /* known-good sha256, or "" */
  char msg[400];
} dl_job_t;

extern dl_job_t dl;
void dl_run(void);
void dl_cancel(void);
uint64_t dl_free_bytes(void);
int dl_name_from_url(const char *url, char *out, size_t ol);
