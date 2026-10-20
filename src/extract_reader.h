/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FL_EXTRACT_READER_H
#define FL_EXTRACT_READER_H
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
typedef struct fl_pkg_reader fl_pkg_reader;
typedef struct { const char *path; uint32_t inode; uint64_t size; } fl_pkg_file;
/* Source is opened read-only. Errors are descriptive; no output files are made. */
fl_pkg_reader *fl_pkg_open(const char *path, char *error, size_t error_size);
void fl_pkg_close(fl_pkg_reader *r);
int fl_pkg_source_stat(const fl_pkg_reader *r, struct stat *out);
const char *fl_pkg_error(const fl_pkg_reader *r);
const char *fl_pkg_content_id(const fl_pkg_reader *r);
size_t fl_pkg_file_count(const fl_pkg_reader *r);
const fl_pkg_file *fl_pkg_files(const fl_pkg_reader *r);
uint32_t fl_pkg_file_mode(const fl_pkg_reader *r,size_t index);
int fl_pkg_read(fl_pkg_reader *r, size_t index, uint64_t offset, void *out, size_t length);
/* Decrypted package metadata entries; caller frees result. */
int fl_pkg_metadata_present(const fl_pkg_reader *r, uint32_t id);
uint8_t *fl_pkg_metadata_entry(fl_pkg_reader *r, uint32_t id, size_t *length);
#endif
