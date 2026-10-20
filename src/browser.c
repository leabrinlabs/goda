/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "browser.h"
#ifdef FL_HOST
int fl_browser_before_launch(void){return 0;}
#else
#include <stdio.h>
#include <unistd.h>
#include "audit.h"
/* On the observed 13.60 SystemService mapping, this export jumps directly
 * to the zero-argument sceShellCoreUtilExitMiniApp implementation. GoHome
 * only changed the underlying navigation and left our browser in front.
 * Evidence: dist/browser-research-1360/native-exports-v2.json. No app IDs,
 * process termination, extra game launch, or ShellUI patching are used. */
extern int sceSystemServiceNavigateToGoBack(void);
int fl_browser_before_launch(void){
 fl_audit("browser","exit_own_browser_before_single_launch begin api=NavigateToGoBack");
 int rc=sceSystemServiceNavigateToGoBack();
 fl_audit("browser","exit_own_browser rc=0x%08x visual_result_requires_confirmation=1",(unsigned)rc);
 return rc<0?-1:0;
}
#endif
