/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FL_BROWSER_H
#define FL_BROWSER_H
/* Exit the browser mini app BEFORE the single game launch. Never terminate
 * its shared ShellUI application or re-launch a game to obtain focus.
 * Native return success alone is not a visual result. */
int fl_browser_before_launch(void);
#endif
