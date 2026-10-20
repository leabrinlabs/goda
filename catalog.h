#ifndef FL_CATALOG_H
#define FL_CATALOG_H
#include <stddef.h>
#define FL_PATH 1024
#define FL_MAX_GAMES 512
struct fl_game {char id[10],title[256],version[32],path[FL_PATH];};
int fl_title_id(const char *s);
int fl_join(char *out,size_t cap,const char *a,const char *b);
int fl_sfo(const unsigned char *data,size_t n,struct fl_game *g,char *error,size_t cap);
int fl_inspect_game(const char *path,struct fl_game *g,char *error,size_t cap);
int fl_scan(const char *root,struct fl_game *games,size_t *count,char *error,size_t cap);
int fl_allowed_directory(const char *path,char resolved[FL_PATH]);
void fl_set_host_root(const char *path);
#endif
