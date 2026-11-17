#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct {
  int pool, ssl, http, tmpl, conn, req;
} hc_t;

extern char net_log[2048];
void hc_init(hc_t *h);
int hc_get(hc_t *h, const char *url, uint64_t from, int *status, uint64_t *len,
           int *len_known, char *err, size_t el);
int hc_read(hc_t *h, void *buf, size_t n);
void hc_abort(hc_t *h);
void hc_close(hc_t *h);
