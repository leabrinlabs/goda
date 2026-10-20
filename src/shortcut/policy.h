#ifndef D3_REGISTRATION_POLICY_H
#define D3_REGISTRATION_POLICY_H
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
/* Caller serializes access. A ticket is consumed before the installer runs. */
struct reg_policy { bool armed, claimed, reported, success; uint64_t thread; };
static inline int reg_request(struct reg_policy *p, unsigned op,
                              const char title[32], uint64_t thread) {
    if (!p->armed || !thread || memcmp(title, "PFLD00001\0", 10)) return EPERM;
    if (op == 10) {
        if (p->claimed) return EBUSY;
        p->claimed = true; p->thread = thread;
        return 0;
    }
    if ((op == 11 || op == 12) && p->claimed && !p->reported && p->thread == thread) {
        p->reported = true; p->success = op == 11;
        return 0;
    }
    return EPERM;
}
#endif
