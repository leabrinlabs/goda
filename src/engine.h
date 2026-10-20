#ifndef FL_ENGINE_H
#define FL_ENGINE_H
#include "catalog.h"
typedef void (*fl_progress)(const char *message);
/* A process was observed and then exited during startup observation. This
 * does not identify user close versus crash, and must not reopen the UI. */
enum { FL_LAUNCH_OBSERVED_EXIT = 1 };
int fl_runtime_access(void);
int fl_private_metadata(const struct fl_game *game,const char *reg);
int fl_refresh_folder(const struct fl_game *game,fl_progress progress);
int fl_register_folder(const struct fl_game *game,fl_progress progress);
int fl_launch(const struct fl_game *game,fl_progress progress);
#endif
