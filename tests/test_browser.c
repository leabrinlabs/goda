/* Exercise the actual native navigation implementation with mocked Sony calls. */
#include "../src/browser.c"
#include <assert.h>
#include <stdarg.h>
#include <string.h>
static int back_calls,back_rc;
void fl_audit(const char *c,const char *format,...){(void)c;(void)format;}
int sceSystemServiceNavigateToGoBack(void){back_calls++;return back_rc;}
int main(void){back_rc=-1;assert(fl_browser_before_launch()<0&&back_calls==1);
 back_rc=0;assert(!fl_browser_before_launch()&&back_calls==2);
 puts("PASS: navigation rejection blocks dispatch; accepted request is sent exactly once; visual success not inferred");}
