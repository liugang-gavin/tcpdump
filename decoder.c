#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "decoder.h"



#define DECODER_PREFIX_NUMBER 10
#define DECODER_MULTICAST_MAC0 0x01
#define DECODER_MULTICAST_MAC1 0x00
#define DECODER_MULTICAST_MAC2 0x5e

#define DECODER_PREFIX_MAC3 0x4e
#define DECODER_PREFIX_MAC4 0x58
#define DECODER_PREFIX_MAC5 0x50

#define DECODER_DATA_MAC3   0x5e
#define DECODER_LENGTH_MAC4 0xff


struct decoder_t{
	uint32_t prefix_num;
	uint8_t  src_mac[6];
	uint8_t  bssid[6];
	uint8_t  datalen;
	uint8_t  curlen;
	int8_t  *passwd;
	decoder_callback_t callback;
	void	  *callback_arg;
};

static struct decoder_t decoder; 

#define IS_PREFIX_MAC(mac) (mac[0] == DECODER_MULTICAST_MAC0 && \
									mac[1] == DECODER_MULTICAST_MAC1 && \
									mac[2] == DECODER_MULTICAST_MAC2 && \
									mac[3] == DECODER_PREFIX_MAC3 && \
									mac[4] == DECODER_PREFIX_MAC4 && \
									mac[5] == DECODER_PREFIX_MAC5)

#define IS_LENGTH_MAC(mac) (mac[0] == DECODER_MULTICAST_MAC0 && \
									mac[1] == DECODER_MULTICAST_MAC1 && \
									mac[2] == DECODER_MULTICAST_MAC2 && \
									mac[3] == DECODER_DATA_MAC3 && \
									mac[4] == DECODER_LENGTH_MAC4)

#define IS_DATA_MAC(mac) (mac[0] == DECODER_MULTICAST_MAC0 && \
									mac[1] == DECODER_MULTICAST_MAC1 && \
									mac[2] == DECODER_MULTICAST_MAC2 && \
									mac[3] == DECODER_DATA_MAC3 && \
									mac[4] != DECODER_LENGTH_MAC4)


uint32_t
decoder_process_package(const uint8_t *src,
								const uint8_t *dst,
								const uint8_t *bssid)
{
	if (IS_PREFIX_MAC(dst)) {
			if (memcmp(decoder.src_mac, src, 6) == 0) {
				decoder.prefix_num ++;
			} else {
				memcpy(decoder.src_mac, src, 6);
				memcpy(decoder.bssid, bssid, 6);
				decoder.prefix_num = 1;
			}
			return 0;
	}

	if (decoder.prefix_num > DECODER_PREFIX_NUMBER &&
				memcmp(decoder.src_mac, src, 6) == 0) {
			if (IS_LENGTH_MAC(dst) && decoder.passwd == NULL) {
				decoder.datalen = dst[5];
				decoder.passwd = malloc(decoder.datalen + 1);
				memset(decoder.passwd, 0, decoder.datalen + 1);
			}
			
			if (IS_DATA_MAC(dst) && dst[4] < decoder.datalen &&
					decoder.passwd[dst[4]] == 0) {
				decoder.passwd[dst[4]] = dst[5];
				decoder.curlen ++;
				if (decoder.curlen == decoder.datalen)
					decoder.callback(decoder.passwd, decoder.bssid,
										 decoder.callback_arg);
			}
	}
	return 0;
}

uint32_t
decoder_open(decoder_callback_t callback, void *arg)
{
	decoder.prefix_num = 0;
	decoder.datalen = 0;
	decoder.passwd = NULL;
	decoder.callback = callback;
	decoder.callback_arg = arg;
	return 0;
}

uint32_t
decoder_close()
{
   decoder.prefix_num = 0;
   decoder.datalen = 0;
   if (decoder.passwd != NULL)
		free(decoder.passwd);
	decoder.passwd = NULL;
	decoder.callback = NULL;
   return 0;
}

