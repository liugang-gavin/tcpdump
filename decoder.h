
#ifndef __DECODER_H__
#define __DECODER_H__

#include <stdint.h>

typedef int (*decoder_callback_t)(int8_t *passwd, int8_t *bssid, void *arg);
uint32_t
decoder_open(decoder_callback_t callback, void *arg);

uint32_t
decoder_close(void);

uint32_t
decoder_process_package(const uint8_t *src,
                        const uint8_t *dst,
                        const uint8_t *bssid);
#endif
