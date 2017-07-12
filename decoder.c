#include<string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>



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
	uint8_t  currlen;
   int8_t  *passwd;
	void	(*callback)(int8_t  *passwd);
};

static struct decoder_t decoder; 

static inline uint32_t
decoder_is_prefix(const uint8_t *dst)
{
	if (dst[0] == DECODER_MULTICAST_MAC0 &&
       dst[1] == DECODER_MULTICAST_MAC1 &&
		 dst[2] == DECODER_MULTICAST_MAC2 &&
		 dst[3] == DECODER_PREFIX_MAC3 &&
		 dst[4] == DECODER_PREFIX_MAC4 &&
		 dst[5] == DECODER_PREFIX_MAC5)
		return 1;
	return 0;
}

static inline uint32_t
decoder_is_length(const uint8_t *dst)
{
   if (dst[0] == DECODER_MULTICAST_MAC0 &&
       dst[1] == DECODER_MULTICAST_MAC1 &&
       dst[2] == DECODER_MULTICAST_MAC2 &&
       dst[3] == DECODER_DATA_MAC3 &&
       dst[4] == DECODER_LENGTH_MAC4)
      return 1;
   return 0;
}

static inline uint32_t
decoder_is_data(const uint8_t *dst)
{
   if (dst[0] == DECODER_MULTICAST_MAC0 &&
       dst[1] == DECODER_MULTICAST_MAC1 &&
       dst[2] == DECODER_MULTICAST_MAC2 &&
       dst[3] == DECODER_DATA_MAC3 &&
       dst[4] != DECODER_LENGTH_MAC4)
      return 1;
   return 0;
}


uint32_t
decoder_process_package(const uint8_t *src,
								const uint8_t *dst,
								const uint8_t *bssid)
{
	if (decoder_is_prefix(dst)) {
			if (memcmp(decoder.src_mac, src, 6) == 0)
				decoder.prefix_num ++;
			else {
				memcpy(decoder.src_mac, src, 6);
				memcpy(decoder.bssid, bssid, 6);
				decoder.prefix_num = 1;
			}
			return 0;
	}

	if (decoder.prefix_num > DECODER_PREFIX_NUMBER &&
				memcmp(decoder.src_mac, src, 6) == 0) {
			if (decoder_is_length(dst) && decoder.passwd == NULL) {
				decoder.datalen = dst[5];
				decoder.passwd = malloc(decoder.datalen + 1);
				memset(decoder.passwd, 0, decoder.datalen + 1);
			}
			
			if (decoder_is_data(dst) && dst[4] < decoder.datalen &&
					decoder.passwd[dst[4]] == 0) {
				decoder.passwd[dst[4]] = dst[5];
				printf("get pass word %d,%c", dst[4], dst[5]);
			}
	}
}

uint32_t
decoder_init()
{
	decoder.prefix_num = 0;
	decoder.datalen = 0;
	decoder.passwd = NULL;
	return 0;
}
