/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FL_MODULE_ALIAS_H
#define FL_MODULE_ALIAS_H
#include "engine.h"
#define FL_MODULE_VIEWS 2
#define FL_MODULE_BASE_NAME ".ps4fl-original"
#ifdef FL_LINK_VIEWS
#define FL_MODULE_OWNED_ROOT "/system_data/ps4-folder-loader-links"
#else
#define FL_MODULE_OWNED_ROOT "/data/ps4-folder-loader/overlays"
#endif
struct fl_module_view { char source[FL_PATH]; char relative[32]; char base_source[FL_PATH]; };
/* Creates only loader-owned directory views; never mounts or edits game files. */
int fl_prepare_module_views(const struct fl_game *game,
 struct fl_module_view views[FL_MODULE_VIEWS], size_t *count, fl_progress progress);
#ifdef FL_HOST
void fl_module_views_host_root(const char *path);
#endif
#endif
