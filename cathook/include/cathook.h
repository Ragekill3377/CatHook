#ifndef CATHOOK_H
#define CATHOOK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int ch_hook(void *target, void *replace, void **original);

int ch_unhook(void *target);

#ifdef __cplusplus
}
#endif

#endif
