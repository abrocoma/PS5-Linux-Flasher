#pragma once
#include <stddef.h>

/* "PS5DATA, boot, cachyos" style list of volume labels on a raw disk */
void drive_labels(const char *dev, char *out, size_t ol);
/* USB product description ("Samsung M3 Portable") or "" when unavailable */
void drive_product(const char *name, char *out, size_t ol);
