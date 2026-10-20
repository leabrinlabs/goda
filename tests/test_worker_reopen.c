/* Regression: exercise the actual production worker when a user closes the
 * observed game before the 30-second startup check completes. No server,
 * console API, source game, or save file is opened. */
#define FL_HOST
void fl_browser_restore_after_failure(void);
void fl_browser_begin_request(void);
#define main unused_loader_server_main
#include "../src/main.c"
#undef main
#include <assert.h>
static int next_launch_result,launch_calls,reopen_calls,navigation_calls;
int fl_launch(const struct fl_game *game,fl_progress report){assert(game==&selected&&report);launch_calls++;return next_launch_result;}
/* Tripwire for the old worker's automatic reopen branch. */
void fl_browser_restore_after_failure(void){reopen_calls++;}
void fl_browser_begin_request(void){}
int fl_browser_before_launch(void){navigation_calls++;return 0;}
int fl_lifecycle_phase(void){return 0;}
int fl_lifecycle_busy(void){return 0;}
int fl_runtime_access(void){assert(0);return -1;}
int fl_extract_pkg(const char *a,const char *b,void(*p)(const char*,uint64_t,uint64_t),volatile sig_atomic_t *c,char *d,size_t e){(void)a;(void)b;(void)p;(void)c;(void)d;(void)e;assert(0);return -1;}
int fl_restore_permissions(const char *a,const char *b,void(*p)(const char*,uint64_t,uint64_t),char *d,size_t e){(void)a;(void)b;(void)p;(void)d;(void)e;assert(0);return -1;}
int main(void){
 const int outcomes[]={-1,FL_LAUNCH_OBSERVED_EXIT,0};
 for(size_t i=0;i<sizeof(outcomes)/sizeof(outcomes[0]);i++){
  next_launch_result=outcomes[i];job_kind=1;busy=1;unsigned before=job_serial;
  worker(NULL);assert(!busy&&job_serial==before+1&&job_result==outcomes[i]);
  assert(reopen_calls==0&&navigation_calls==0);
 }
 assert(launch_calls==3);
 puts("PASS: production worker never reopens UI after failed launch, observed early exit, or successful launch; distinct exit result preserved");
}
