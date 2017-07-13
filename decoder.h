
#ifndef __DECODER_H__
#define __DECODER_H__

#include <stdint.h>
uint32_t
decoder_open(void);

uint32_t
decoder_close(void);

uint32_t
decoder_process_package(const uint8_t *src,
                        const uint8_t *dst,
                        const uint8_t *bssid);
#endif
