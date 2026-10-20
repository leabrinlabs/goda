/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FL_LAUNCH_GATE_H
#define FL_LAUNCH_GATE_H
#include "module_alias.h"
/* One synchronous pre-exec mount gate; exact selected title and thread only. */
int fl_gate_launch(const struct fl_game *,const struct fl_module_view *,size_t,int,fl_progress,int *);
#endif
