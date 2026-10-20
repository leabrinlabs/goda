/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FL_EXTRACTOR_H
#define FL_EXTRACTOR_H
#include <stddef.h>
#include <stdint.h>
#include <signal.h>
/* Writes only an exclusively created output directory below dest_root.
 * Failure/cancellation preserves the incomplete marker and partial output.
 * Output is the completed path on success, descriptive error on failure.
 * Caller serializes extraction jobs. Progress may be called on worker thread. */
int fl_extract_pkg(const char *source, const char *dest_root,
                   void (*progress)(const char *, uint64_t, uint64_t),
                   volatile sig_atomic_t *cancel, char *output, size_t output_cap);
/* Migration for outputs of early alpha that used 0644 for every inner file.
 * Accepts only completed outputs whose SFO and manifest match the source PKG. */
int fl_restore_permissions(const char *source,const char *target,
 void (*progress)(const char *,uint64_t,uint64_t),char *error,size_t error_cap);

#endif
