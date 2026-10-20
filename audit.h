/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FL_AUDIT_H
#define FL_AUDIT_H
void fl_audit(const char *component,const char *format,...) __attribute__((format(printf,2,3)));
#endif
