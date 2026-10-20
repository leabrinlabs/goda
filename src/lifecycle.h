/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FL_LIFECYCLE_H
#define FL_LIFECYCLE_H
#include "catalog.h"
/* One volatile session; never a persistent per-game compatibility database. */
int fl_lifecycle_busy(void);
/* 0 idle, 1 awaiting process, 2 watching process, 3 cleaning after exit. */
int fl_lifecycle_phase(void);
int fl_lifecycle_begin(const struct fl_game *game);
int fl_lifecycle_track(const char *source,const char *target);
void fl_lifecycle_dispatched(void);
#endif
