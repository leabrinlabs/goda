#ifndef D3_CAVE_SELECT_H
#define D3_CAVE_SELECT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Select only aligned, entirely zero bytes inside the caller's reserved range. */
static inline bool d3_select_zero_cave(const uint8_t *bytes, size_t size,
                                       size_t need, size_t *offset) {
    if (!bytes || !offset || !need || need > size) return false;
    for (size_t start = 0; start <= size - need; start += 16) {
        size_t i = 0;
        while (i < need && bytes[start + i] == 0) ++i;
        if (i == need) { *offset = start; return true; }
    }
    return false;
}
#endif
