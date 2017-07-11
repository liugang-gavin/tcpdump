/*
 * Copyright (c) 2001
 *	Fortress Technologies, Inc.  All rights reserved.
 *      Charlie Lenahan (clenahan@fortresstech.com)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* \summary: IEEE 802.11 printer */

#include <pcap.h>
//#include "netdissect-stdinc.h"
#include <stdint.h>

#include <stdlib.h>
#include <stdio.h>

#include "cpack.h"

#include <string.h>

#include "extract.h"


/* Lengths of 802.11 header components. */
#define	IEEE802_11_FC_LEN		2
#define	IEEE802_11_DUR_LEN		2
#define	IEEE802_11_DA_LEN		6
#define	IEEE802_11_SA_LEN		6
#define	IEEE802_11_BSSID_LEN		6
#define	IEEE802_11_RA_LEN		6
#define	IEEE802_11_TA_LEN		6
#define	IEEE802_11_ADDR1_LEN		6
#define	IEEE802_11_SEQ_LEN		2
#define	IEEE802_11_CTL_LEN		2
#define	IEEE802_11_CARRIED_FC_LEN	2
#define	IEEE802_11_HT_CONTROL_LEN	4
#define	IEEE802_11_IV_LEN		3
#define	IEEE802_11_KID_LEN		1

/* Frame check sequence length. */
#define	IEEE802_11_FCS_LEN		4

/* Lengths of beacon components. */
#define	IEEE802_11_TSTAMP_LEN		8
#define	IEEE802_11_BCNINT_LEN		2
#define	IEEE802_11_CAPINFO_LEN		2
#define	IEEE802_11_LISTENINT_LEN	2

#define	IEEE802_11_AID_LEN		2
#define	IEEE802_11_STATUS_LEN		2
#define	IEEE802_11_REASON_LEN		2

/* Length of previous AP in reassocation frame */
#define	IEEE802_11_AP_LEN		6

#define	T_MGMT 0x0  /* management */
#define	T_CTRL 0x1  /* control */
#define	T_DATA 0x2 /* data */
#define	T_RESV 0x3  /* reserved */

#define	ST_ASSOC_REQUEST   	0x0
#define	ST_ASSOC_RESPONSE 	0x1
#define	ST_REASSOC_REQUEST   	0x2
#define	ST_REASSOC_RESPONSE  	0x3
#define	ST_PROBE_REQUEST   	0x4
#define	ST_PROBE_RESPONSE   	0x5
/* RESERVED 			0x6  */
/* RESERVED 			0x7  */
#define	ST_BEACON   		0x8
#define	ST_ATIM			0x9
#define	ST_DISASSOC		0xA
#define	ST_AUTH			0xB
#define	ST_DEAUTH		0xC
#define	ST_ACTION		0xD
/* RESERVED 			0xE  */
/* RESERVED 			0xF  */

#define CTRL_CONTROL_WRAPPER	0x7
#define	CTRL_BAR	0x8
#define	CTRL_BA		0x9
#define	CTRL_PS_POLL	0xA
#define	CTRL_RTS	0xB
#define	CTRL_CTS	0xC
#define	CTRL_ACK	0xD
#define	CTRL_CF_END	0xE
#define	CTRL_END_ACK	0xF

#define	DATA_DATA			0x0
#define	DATA_DATA_CF_ACK		0x1
#define	DATA_DATA_CF_POLL		0x2
#define	DATA_DATA_CF_ACK_POLL		0x3
#define	DATA_NODATA			0x4
#define	DATA_NODATA_CF_ACK		0x5
#define	DATA_NODATA_CF_POLL		0x6
#define	DATA_NODATA_CF_ACK_POLL		0x7

#define DATA_QOS_DATA			0x8
#define DATA_QOS_DATA_CF_ACK		0x9
#define DATA_QOS_DATA_CF_POLL		0xA
#define DATA_QOS_DATA_CF_ACK_POLL	0xB
#define DATA_QOS_NODATA			0xC
#define DATA_QOS_CF_POLL_NODATA		0xE
#define DATA_QOS_CF_ACK_POLL_NODATA	0xF

/*
 * The subtype field of a data frame is, in effect, composed of 4 flag
 * bits - CF-Ack, CF-Poll, Null (means the frame doesn't actually have
 * any data), and QoS.
 */
#define DATA_FRAME_IS_CF_ACK(x)		((x) & 0x01)
#define DATA_FRAME_IS_CF_POLL(x)	((x) & 0x02)
#define DATA_FRAME_IS_NULL(x)		((x) & 0x04)
#define DATA_FRAME_IS_QOS(x)		((x) & 0x08)

/*
 * Bits in the frame control field.
 */
#define	FC_VERSION(fc)		((fc) & 0x3)
#define	FC_TYPE(fc)		(((fc) >> 2) & 0x3)
#define	FC_SUBTYPE(fc)		(((fc) >> 4) & 0xF)
#define	FC_TO_DS(fc)		((fc) & 0x0100)
#define	FC_FROM_DS(fc)		((fc) & 0x0200)
#define	FC_MORE_FLAG(fc)	((fc) & 0x0400)
#define	FC_RETRY(fc)		((fc) & 0x0800)
#define	FC_POWER_MGMT(fc)	((fc) & 0x1000)
#define	FC_MORE_DATA(fc)	((fc) & 0x2000)
#define	FC_PROTECTED(fc)	((fc) & 0x4000)
#define	FC_ORDER(fc)		((fc) & 0x8000)

struct mgmt_header_t {
	uint16_t	fc;
	uint16_t 	duration;
	uint8_t		da[IEEE802_11_DA_LEN];
	uint8_t		sa[IEEE802_11_SA_LEN];
	uint8_t		bssid[IEEE802_11_BSSID_LEN];
	uint16_t	seq_ctrl;
};

#define	MGMT_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
			 IEEE802_11_DA_LEN+IEEE802_11_SA_LEN+\
			 IEEE802_11_BSSID_LEN+IEEE802_11_SEQ_LEN)

#define	CAPABILITY_ESS(cap)	((cap) & 0x0001)
#define	CAPABILITY_IBSS(cap)	((cap) & 0x0002)
#define	CAPABILITY_CFP(cap)	((cap) & 0x0004)
#define	CAPABILITY_CFP_REQ(cap)	((cap) & 0x0008)
#define	CAPABILITY_PRIVACY(cap)	((cap) & 0x0010)

struct ssid_t {
	uint8_t		element_id;
	uint8_t		length;
	u_char		ssid[33];  /* 32 + 1 for null */
};

struct rates_t {
	uint8_t		element_id;
	uint8_t		length;
	uint8_t		rate[16];
};

struct challenge_t {
	uint8_t		element_id;
	uint8_t		length;
	uint8_t		text[254]; /* 1-253 + 1 for null */
};

struct fh_t {
	uint8_t		element_id;
	uint8_t		length;
	uint16_t	dwell_time;
	uint8_t		hop_set;
	uint8_t 	hop_pattern;
	uint8_t		hop_index;
};

struct ds_t {
	uint8_t		element_id;
	uint8_t		length;
	uint8_t		channel;
};

struct cf_t {
	uint8_t		element_id;
	uint8_t		length;
	uint8_t		count;
	uint8_t		period;
	uint16_t	max_duration;
	uint16_t	dur_remaing;
};

struct tim_t {
	uint8_t		element_id;
	uint8_t		length;
	uint8_t		count;
	uint8_t		period;
	uint8_t		bitmap_control;
	uint8_t		bitmap[251];
};

#define	E_SSID 		0
#define	E_RATES 	1
#define	E_FH	 	2
#define	E_DS 		3
#define	E_CF	 	4
#define	E_TIM	 	5
#define	E_IBSS 		6
/* reserved 		7 */
/* reserved 		8 */
/* reserved 		9 */
/* reserved 		10 */
/* reserved 		11 */
/* reserved 		12 */
/* reserved 		13 */
/* reserved 		14 */
/* reserved 		15 */
/* reserved 		16 */

#define	E_CHALLENGE 	16
/* reserved 		17 */
/* reserved 		18 */
/* reserved 		19 */
/* reserved 		16 */
/* reserved 		16 */


struct mgmt_body_t {
	uint8_t   	timestamp[IEEE802_11_TSTAMP_LEN];
	uint16_t  	beacon_interval;
	uint16_t 	listen_interval;
	uint16_t 	status_code;
	uint16_t 	aid;
	u_char		ap[IEEE802_11_AP_LEN];
	uint16_t	reason_code;
	uint16_t	auth_alg;
	uint16_t	auth_trans_seq_num;
	int		challenge_present;
	struct challenge_t  challenge;
	uint16_t	capability_info;
	int		ssid_present;
	struct ssid_t	ssid;
	int		rates_present;
	struct rates_t 	rates;
	int		ds_present;
	struct ds_t	ds;
	int		cf_present;
	struct cf_t	cf;
	int		fh_present;
	struct fh_t	fh;
	int		tim_present;
	struct tim_t	tim;
};

struct ctrl_control_wrapper_hdr_t {
	uint16_t	fc;
	uint16_t	duration;
	uint8_t		addr1[IEEE802_11_ADDR1_LEN];
	uint16_t	carried_fc[IEEE802_11_CARRIED_FC_LEN];
	uint16_t	ht_control[IEEE802_11_HT_CONTROL_LEN];
};

#define	CTRL_CONTROL_WRAPPER_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
					 IEEE802_11_ADDR1_LEN+\
					 IEEE802_11_CARRIED_FC_LEN+\
					 IEEE802_11_HT_CONTROL_LEN)

struct ctrl_rts_hdr_t {
	uint16_t	fc;
	uint16_t	duration;
	uint8_t		ra[IEEE802_11_RA_LEN];
	uint8_t		ta[IEEE802_11_TA_LEN];
};

#define	CTRL_RTS_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
			 IEEE802_11_RA_LEN+IEEE802_11_TA_LEN)

struct ctrl_cts_hdr_t {
	uint16_t	fc;
	uint16_t	duration;
	uint8_t		ra[IEEE802_11_RA_LEN];
};

#define	CTRL_CTS_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+IEEE802_11_RA_LEN)

struct ctrl_ack_hdr_t {
	uint16_t	fc;
	uint16_t	duration;
	uint8_t		ra[IEEE802_11_RA_LEN];
};

#define	CTRL_ACK_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+IEEE802_11_RA_LEN)

struct ctrl_ps_poll_hdr_t {
	uint16_t	fc;
	uint16_t	aid;
	uint8_t		bssid[IEEE802_11_BSSID_LEN];
	uint8_t		ta[IEEE802_11_TA_LEN];
};

#define	CTRL_PS_POLL_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_AID_LEN+\
				 IEEE802_11_BSSID_LEN+IEEE802_11_TA_LEN)

struct ctrl_end_hdr_t {
	uint16_t	fc;
	uint16_t	duration;
	uint8_t		ra[IEEE802_11_RA_LEN];
	uint8_t		bssid[IEEE802_11_BSSID_LEN];
};

#define	CTRL_END_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
			 IEEE802_11_RA_LEN+IEEE802_11_BSSID_LEN)

struct ctrl_end_ack_hdr_t {
	uint16_t	fc;
	uint16_t	duration;
	uint8_t		ra[IEEE802_11_RA_LEN];
	uint8_t		bssid[IEEE802_11_BSSID_LEN];
};

#define	CTRL_END_ACK_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
				 IEEE802_11_RA_LEN+IEEE802_11_BSSID_LEN)

struct ctrl_ba_hdr_t {
	uint16_t	fc;
	uint16_t	duration;
	uint8_t		ra[IEEE802_11_RA_LEN];
};

#define	CTRL_BA_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+IEEE802_11_RA_LEN)

struct ctrl_bar_hdr_t {
	uint16_t	fc;
	uint16_t	dur;
	uint8_t		ra[IEEE802_11_RA_LEN];
	uint8_t		ta[IEEE802_11_TA_LEN];
	uint16_t	ctl;
	uint16_t	seq;
};

#define	CTRL_BAR_HDRLEN		(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
				 IEEE802_11_RA_LEN+IEEE802_11_TA_LEN+\
				 IEEE802_11_CTL_LEN+IEEE802_11_SEQ_LEN)

struct meshcntl_t {
	uint8_t		flags;
	uint8_t		ttl;
	uint8_t		seq[4];
	uint8_t		addr4[6];
	uint8_t		addr5[6];
	uint8_t		addr6[6];
};

#define	IV_IV(iv)	((iv) & 0xFFFFFF)
#define	IV_PAD(iv)	(((iv) >> 24) & 0x3F)
#define	IV_KEYID(iv)	(((iv) >> 30) & 0x03)

static int
wep_print(const u_char *p)
{
	return 1;
}

/*
 *  Data Frame - Address field contents
 *
 *  To Ds  | From DS | Addr 1 | Addr 2 | Addr 3 | Addr 4
 *    0    |  0      |  DA    | SA     | BSSID  | n/a
 *    0    |  1      |  DA    | BSSID  | SA     | n/a
 *    1    |  0      |  BSSID | SA     | DA     | n/a
 *    1    |  1      |  RA    | TA     | DA     | SA
 */

/*
 * Function to get source and destination MAC addresses for a data frame.
 */
static void
get_data_src_dst_mac(uint16_t fc, const u_char *p, const uint8_t **srcp,
                     const uint8_t **dstp, const uint8_t **bssid)
{
#define ADDR1  (p + 4)
#define ADDR2  (p + 10)
#define ADDR3  (p + 16)
#define ADDR4  (p + 24)

	if (!FC_TO_DS(fc)) {
		if (!FC_FROM_DS(fc)) {
			/* not To DS and not From DS */
			*srcp = ADDR2;
			*dstp = ADDR1;
         *bssid = ADDR3;
		} else {
			/* not To DS and From DS */
			*srcp = ADDR3;
			*dstp = ADDR1;
         *bssid = ADDR2;
		}
	} else {
		if (!FC_FROM_DS(fc)) {
			/* From DS and not To DS */
			*srcp = ADDR2;
			*dstp = ADDR3;
         *bssid = ADDR1;
		} else {
			/* To DS and From DS */
			*srcp = ADDR4;
			*dstp = ADDR3;
         *bssid = NULL;
		}
	}

#undef ADDR1
#undef ADDR2
#undef ADDR3
#undef ADDR4
}

static void
get_mgmt_src_dst_mac(const u_char *p, const uint8_t **srcp, const uint8_t **dstp)
{
	const struct mgmt_header_t *hp = (const struct mgmt_header_t *) p;

	if (srcp != NULL)
		*srcp = hp->sa;
	if (dstp != NULL)
		*dstp = hp->da;
}

/*
 * Print Header funcs
 */

static void
data_header_print(uint16_t fc, const u_char *p)
{
	u_int subtype = FC_SUBTYPE(fc);

#define ADDR1  (p + 4)
#define ADDR2  (p + 10)
#define ADDR3  (p + 16)
#define ADDR4  (p + 24)

#if 0
	if (!FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
		printf("DA:%s SA:%s BSSID:%s ",
		    etheraddr_string(ADDR1), etheraddr_string(ADDR2),
		    etheraddr_string(ADDR3));
	} else if (!FC_TO_DS(fc) && FC_FROM_DS(fc)) {
		printf("DA:%s BSSID:%s SA:%s ",
		    etheraddr_string(ADDR1), etheraddr_string(ADDR2),
		    etheraddr_string(ADDR3));
	} else if (FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
		printf("BSSID:%s SA:%s DA:%s ",
		    etheraddr_string(ADDR1), etheraddr_string(ADDR2),
		    etheraddr_string(ADDR3));
	} else if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
		printf("RA:%s TA:%s DA:%s SA:%s ",
		    etheraddr_string(ADDR1), etheraddr_string(ADDR2),
		    etheraddr_string(ADDR3), etheraddr_string(ADDR4));
	}
#endif
#undef ADDR1
#undef ADDR2
#undef ADDR3
#undef ADDR4
}

static void
mgmt_header_print(const u_char *p)
{
}

static void
ctrl_header_print(uint16_t fc, const u_char *p)
{
}

static int
extract_header_length(uint16_t fc)
{
	int len;

	switch (FC_TYPE(fc)) {
	case T_MGMT:
		return MGMT_HDRLEN;
	case T_CTRL:
		switch (FC_SUBTYPE(fc)) {
		case CTRL_CONTROL_WRAPPER:
			return CTRL_CONTROL_WRAPPER_HDRLEN;
		case CTRL_BAR:
			return CTRL_BAR_HDRLEN;
		case CTRL_BA:
			return CTRL_BA_HDRLEN;
		case CTRL_PS_POLL:
			return CTRL_PS_POLL_HDRLEN;
		case CTRL_RTS:
			return CTRL_RTS_HDRLEN;
		case CTRL_CTS:
			return CTRL_CTS_HDRLEN;
		case CTRL_ACK:
			return CTRL_ACK_HDRLEN;
		case CTRL_CF_END:
			return CTRL_END_HDRLEN;
		case CTRL_END_ACK:
			return CTRL_END_ACK_HDRLEN;
		default:
			printf("unknown 802.11 ctrl frame subtype (%d)", FC_SUBTYPE(fc));
			return 0;
		}
	case T_DATA:
		len = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
		if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
			len += 2;
		return len;
	default:
		printf("unknown 802.11 frame type (%d)", FC_TYPE(fc));
		return 0;
	}
}

static int
extract_mesh_header_length(const u_char *p)
{
	return (p[0] &~ 3) ? 0 : 6*(1 + (p[0] & 3));
}

#ifndef roundup2
#define	roundup2(x, y)	(((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */
#endif

static const char tstr[] = "[|802.11]";

static u_int
ieee802_11_print(const u_char *p, u_int length, u_int orig_caplen, int pad,
                 u_int fcslen)
{
	uint16_t fc;
	u_int caplen, hdrlen, meshdrlen;
	const uint8_t *src, *dst, *bssid;
	int llc_hdrlen;

	caplen = orig_caplen;
	/* Remove FCS, if present */
	if (length < fcslen) {
		return caplen;
	}
	length -= fcslen;
	if (caplen > length) {
		/* Amount of FCS in actual packet data, if any */
		fcslen = caplen - length;
		caplen -= fcslen;
	}

	if (caplen < IEEE802_11_FC_LEN) {
		return orig_caplen;
	}

	fc = EXTRACT_LE_16BITS(p);
	hdrlen = extract_header_length(fc);
	if (hdrlen == 0) {
		/* Unknown frame type or control frame subtype; quit. */
		return (0);
	}
	if (pad)
		hdrlen = roundup2(hdrlen, 4);
	if (FC_TYPE(fc) == T_DATA &&
	    DATA_FRAME_IS_QOS(FC_SUBTYPE(fc))) {
		meshdrlen = extract_mesh_header_length(p+hdrlen);
		hdrlen += meshdrlen;
	} else
		meshdrlen = 0;

	if (caplen < hdrlen) {
		return hdrlen;
	}

	/*
	 * Go past the 802.11 header.
	 */
	length -= hdrlen;
	caplen -= hdrlen;
	p += hdrlen;

	switch (FC_TYPE(fc)) {
	case T_MGMT:
		get_mgmt_src_dst_mac(p - hdrlen, &src, &dst);
		break;
	case T_CTRL:
		break;
	case T_DATA:
		if (DATA_FRAME_IS_NULL(FC_SUBTYPE(fc)))
			return hdrlen;	/* no-data frame */
		/* There may be a problem w/ AP not having this bit set */
		if (FC_PROTECTED(fc)) {
			if (!wep_print(p)) {
				return hdrlen;
			}
		} else {
			get_data_src_dst_mac(fc, p - hdrlen, &src, &dst, &bssid);
         printf("src-mac:%02x:%02x:%02x:%02x:%02x:%02x\n", src[0], src[1],src[2],src[3],src[4],src[5]);
         printf("dst-mac:%02x:%02x:%02x:%02x:%02x:%02x\n", dst[0], dst[1],dst[2],dst[3],dst[4],dst[5]);
         if (bssid != NULL)
           printf("bssid  :%02x:%02x:%02x:%02x:%02x:%02x\n", dst[0], dst[1],dst[2],dst[3],dst[4],dst[5]);
#if 0
			llc_hdrlen = llc_print(p, length, caplen, &src, &dst);
			if (llc_hdrlen < 0) {
				/*
				 * Some kinds of LLC packet we cannot
				 * handle intelligently
				 */
				llc_hdrlen = -llc_hdrlen;
			}
#endif
			hdrlen += llc_hdrlen;
		}
		break;
	default:
		/* We shouldn't get here - we should already have quit */
		break;
	}

	return hdrlen;
}

/*
 * This is the top level routine of the printer.  'p' points
 * to the 802.11 header of the packet, 'h->ts' is the timestamp,
 * 'h->len' is the length of the packet off the wire, and 'h->caplen'
 * is the number of bytes actually captured.
 */
void
ieee802_11_if_print(u_char *arg, const struct pcap_pkthdr *h, const u_char *p)
{
	ieee802_11_print(p, h->len, h->caplen, 0, 0);
   return;
}


/*
 * The radio capture header precedes the 802.11 header.
 *
 * Note well: all radiotap fields are little-endian.
 */
struct ieee80211_radiotap_header {
	uint8_t		it_version;	/* Version 0. Only increases
					 * for drastic changes,
					 * introduction of compatible
					 * new fields does not count.
					 */
	uint8_t		it_pad;
	uint16_t	it_len;		/* length of the whole
					 * header in bytes, including
					 * it_version, it_pad,
					 * it_len, and data fields.
					 */
	uint32_t	it_present;	/* A bitmap telling which
					 * fields are present. Set bit 31
					 * (0x80000000) to extend the
					 * bitmap by another 32 bits.
					 * Additional extensions are made
					 * by setting bit 31.
					 */
};

enum ieee80211_radiotap_type {
	IEEE80211_RADIOTAP_TSFT = 0,
	IEEE80211_RADIOTAP_FLAGS = 1,
	IEEE80211_RADIOTAP_RATE = 2,
	IEEE80211_RADIOTAP_CHANNEL = 3,
	IEEE80211_RADIOTAP_FHSS = 4,
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	IEEE80211_RADIOTAP_ANTENNA = 11,
	IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	IEEE80211_RADIOTAP_RX_FLAGS = 14,
	/* NB: gap for netbsd definitions */
	IEEE80211_RADIOTAP_XCHANNEL = 18,
	IEEE80211_RADIOTAP_MCS = 19,
	IEEE80211_RADIOTAP_AMPDU_STATUS = 20,
	IEEE80211_RADIOTAP_VHT = 21,
	IEEE80211_RADIOTAP_NAMESPACE = 29,
	IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30,
	IEEE80211_RADIOTAP_EXT = 31
};

/* channel attributes */
#define	IEEE80211_CHAN_TURBO	0x00010	/* Turbo channel */
#define	IEEE80211_CHAN_CCK	0x00020	/* CCK channel */
#define	IEEE80211_CHAN_OFDM	0x00040	/* OFDM channel */
#define	IEEE80211_CHAN_2GHZ	0x00080	/* 2 GHz spectrum channel. */
#define	IEEE80211_CHAN_5GHZ	0x00100	/* 5 GHz spectrum channel */
#define	IEEE80211_CHAN_PASSIVE	0x00200	/* Only passive scan allowed */
#define	IEEE80211_CHAN_DYN	0x00400	/* Dynamic CCK-OFDM channel */
#define	IEEE80211_CHAN_GFSK	0x00800	/* GFSK channel (FHSS PHY) */
#define	IEEE80211_CHAN_GSM	0x01000	/* 900 MHz spectrum channel */
#define	IEEE80211_CHAN_STURBO	0x02000	/* 11a static turbo channel only */
#define	IEEE80211_CHAN_HALF	0x04000	/* Half rate channel */
#define	IEEE80211_CHAN_QUARTER	0x08000	/* Quarter rate channel */
#define	IEEE80211_CHAN_HT20	0x10000	/* HT 20 channel */
#define	IEEE80211_CHAN_HT40U	0x20000	/* HT 40 channel w/ ext above */
#define	IEEE80211_CHAN_HT40D	0x40000	/* HT 40 channel w/ ext below */

/* Useful combinations of channel characteristics, borrowed from Ethereal */
#define IEEE80211_CHAN_A \
        (IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define IEEE80211_CHAN_B \
        (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define IEEE80211_CHAN_G \
        (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)
#define IEEE80211_CHAN_TA \
        (IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_TURBO)
#define IEEE80211_CHAN_TG \
        (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN  | IEEE80211_CHAN_TURBO)


/* For IEEE80211_RADIOTAP_FLAGS */
#define	IEEE80211_RADIOTAP_F_CFP	0x01	/* sent/received
						 * during CFP
						 */
#define	IEEE80211_RADIOTAP_F_SHORTPRE	0x02	/* sent/received
						 * with short
						 * preamble
						 */
#define	IEEE80211_RADIOTAP_F_WEP	0x04	/* sent/received
						 * with WEP encryption
						 */
#define	IEEE80211_RADIOTAP_F_FRAG	0x08	/* sent/received
						 * with fragmentation
						 */
#define	IEEE80211_RADIOTAP_F_FCS	0x10	/* frame includes FCS */
#define	IEEE80211_RADIOTAP_F_DATAPAD	0x20	/* frame has padding between
						 * 802.11 header and payload
						 * (to 32-bit boundary)
						 */
#define	IEEE80211_RADIOTAP_F_BADFCS	0x40	/* does not pass FCS check */

/* For IEEE80211_RADIOTAP_RX_FLAGS */
#define IEEE80211_RADIOTAP_F_RX_BADFCS	0x0001	/* frame failed crc check */
#define IEEE80211_RADIOTAP_F_RX_PLCP_CRC	0x0002	/* frame failed PLCP CRC check */

/* For IEEE80211_RADIOTAP_MCS known */
#define IEEE80211_RADIOTAP_MCS_BANDWIDTH_KNOWN		0x01
#define IEEE80211_RADIOTAP_MCS_MCS_INDEX_KNOWN		0x02	/* MCS index field */
#define IEEE80211_RADIOTAP_MCS_GUARD_INTERVAL_KNOWN	0x04
#define IEEE80211_RADIOTAP_MCS_HT_FORMAT_KNOWN		0x08
#define IEEE80211_RADIOTAP_MCS_FEC_TYPE_KNOWN		0x10
#define IEEE80211_RADIOTAP_MCS_STBC_KNOWN		0x20
#define IEEE80211_RADIOTAP_MCS_NESS_KNOWN		0x40
#define IEEE80211_RADIOTAP_MCS_NESS_BIT_1		0x80

/* For IEEE80211_RADIOTAP_MCS flags */
#define IEEE80211_RADIOTAP_MCS_BANDWIDTH_MASK	0x03
#define IEEE80211_RADIOTAP_MCS_BANDWIDTH_20	0
#define IEEE80211_RADIOTAP_MCS_BANDWIDTH_40	1
#define IEEE80211_RADIOTAP_MCS_BANDWIDTH_20L	2
#define IEEE80211_RADIOTAP_MCS_BANDWIDTH_20U	3
#define IEEE80211_RADIOTAP_MCS_SHORT_GI		0x04 /* short guard interval */
#define IEEE80211_RADIOTAP_MCS_HT_GREENFIELD	0x08
#define IEEE80211_RADIOTAP_MCS_FEC_LDPC		0x10
#define IEEE80211_RADIOTAP_MCS_STBC_MASK	0x60
#define		IEEE80211_RADIOTAP_MCS_STBC_1	1
#define		IEEE80211_RADIOTAP_MCS_STBC_2	2
#define		IEEE80211_RADIOTAP_MCS_STBC_3	3
#define IEEE80211_RADIOTAP_MCS_STBC_SHIFT	5
#define IEEE80211_RADIOTAP_MCS_NESS_BIT_0	0x80

/* For IEEE80211_RADIOTAP_AMPDU_STATUS */
#define IEEE80211_RADIOTAP_AMPDU_REPORT_ZEROLEN		0x0001
#define IEEE80211_RADIOTAP_AMPDU_IS_ZEROLEN		0x0002
#define IEEE80211_RADIOTAP_AMPDU_LAST_KNOWN		0x0004
#define IEEE80211_RADIOTAP_AMPDU_IS_LAST		0x0008
#define IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_ERR		0x0010
#define IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_KNOWN	0x0020

/* For IEEE80211_RADIOTAP_VHT known */
#define IEEE80211_RADIOTAP_VHT_STBC_KNOWN			0x0001
#define IEEE80211_RADIOTAP_VHT_TXOP_PS_NA_KNOWN			0x0002
#define IEEE80211_RADIOTAP_VHT_GUARD_INTERVAL_KNOWN		0x0004
#define IEEE80211_RADIOTAP_VHT_SGI_NSYM_DIS_KNOWN		0x0008
#define IEEE80211_RADIOTAP_VHT_LDPC_EXTRA_OFDM_SYM_KNOWN	0x0010
#define IEEE80211_RADIOTAP_VHT_BEAMFORMED_KNOWN			0x0020
#define IEEE80211_RADIOTAP_VHT_BANDWIDTH_KNOWN			0x0040
#define IEEE80211_RADIOTAP_VHT_GROUP_ID_KNOWN			0x0080
#define IEEE80211_RADIOTAP_VHT_PARTIAL_AID_KNOWN		0x0100

/* For IEEE80211_RADIOTAP_VHT flags */
#define IEEE80211_RADIOTAP_VHT_STBC			0x01
#define IEEE80211_RADIOTAP_VHT_TXOP_PS_NA		0x02
#define IEEE80211_RADIOTAP_VHT_SHORT_GI			0x04
#define IEEE80211_RADIOTAP_VHT_SGI_NSYM_M10_9		0x08
#define IEEE80211_RADIOTAP_VHT_LDPC_EXTRA_OFDM_SYM	0x10
#define IEEE80211_RADIOTAP_VHT_BEAMFORMED		0x20

#define IEEE80211_RADIOTAP_VHT_BANDWIDTH_MASK	0x1f

#define IEEE80211_RADIOTAP_VHT_NSS_MASK		0x0f
#define IEEE80211_RADIOTAP_VHT_MCS_MASK		0xf0
#define IEEE80211_RADIOTAP_VHT_MCS_SHIFT	4

#define IEEE80211_RADIOTAP_CODING_LDPC_USERn			0x01

#define	IEEE80211_CHAN_FHSS \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_GFSK)
#define	IEEE80211_CHAN_A \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_B \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define	IEEE80211_CHAN_PUREG \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_G \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)

#define	IS_CHAN_FHSS(flags) \
	((flags & IEEE80211_CHAN_FHSS) == IEEE80211_CHAN_FHSS)
#define	IS_CHAN_A(flags) \
	((flags & IEEE80211_CHAN_A) == IEEE80211_CHAN_A)
#define	IS_CHAN_B(flags) \
	((flags & IEEE80211_CHAN_B) == IEEE80211_CHAN_B)
#define	IS_CHAN_PUREG(flags) \
	((flags & IEEE80211_CHAN_PUREG) == IEEE80211_CHAN_PUREG)
#define	IS_CHAN_G(flags) \
	((flags & IEEE80211_CHAN_G) == IEEE80211_CHAN_G)
#define	IS_CHAN_ANYG(flags) \
	(IS_CHAN_PUREG(flags) || IS_CHAN_G(flags))

static void
print_chaninfo(uint16_t freq, int flags, int presentflags)
{
}

static int
print_radiotap_field(struct cpack_state *s, uint32_t bit, uint8_t *flagsp,
                     uint32_t presentflags)
{
	u_int i;
	int rc;

	switch (bit) {

	case IEEE80211_RADIOTAP_TSFT: {
		uint64_t tsft;

		rc = cpack_uint64(s, &tsft);
		if (rc != 0)
			goto trunc;
		break;
		}

	case IEEE80211_RADIOTAP_FLAGS: {
		uint8_t flagsval;

		rc = cpack_uint8(s, &flagsval);
		if (rc != 0)
			goto trunc;
		*flagsp = flagsval;
		break;
		}

	case IEEE80211_RADIOTAP_RATE: {
		uint8_t rate;

		rc = cpack_uint8(s, &rate);
		if (rc != 0)
			goto trunc;
		break;
		}

	case IEEE80211_RADIOTAP_CHANNEL: {
		uint16_t frequency;
		uint16_t flags;

		rc = cpack_uint16(s, &frequency);
		if (rc != 0)
			goto trunc;
		rc = cpack_uint16(s, &flags);
		if (rc != 0)
			goto trunc;
		/*
		 * If CHANNEL and XCHANNEL are both present, skip
		 * CHANNEL.
		 */
		if (presentflags & (1 << IEEE80211_RADIOTAP_XCHANNEL))
			break;
		print_chaninfo(frequency, flags, presentflags);
		break;
		}

	case IEEE80211_RADIOTAP_FHSS: {
		uint8_t hopset;
		uint8_t hoppat;

		rc = cpack_uint8(s, &hopset);
		if (rc != 0)
			goto trunc;
		rc = cpack_uint8(s, &hoppat);
		if (rc != 0)
			goto trunc;
		break;
		}

	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL: {
		int8_t dbm_antsignal;

		rc = cpack_int8(s, &dbm_antsignal);
		if (rc != 0)
			goto trunc;
		break;
		}

	case IEEE80211_RADIOTAP_DBM_ANTNOISE: {
		int8_t dbm_antnoise;

		rc = cpack_int8(s, &dbm_antnoise);
		if (rc != 0)
			goto trunc;
		break;
		}

	case IEEE80211_RADIOTAP_LOCK_QUALITY: {
		uint16_t lock_quality;

		rc = cpack_uint16(s, &lock_quality);
		if (rc != 0)
			goto trunc;
		break;
		}

	case IEEE80211_RADIOTAP_TX_ATTENUATION: {
		uint16_t tx_attenuation;

		rc = cpack_uint16(s, &tx_attenuation);
		if (rc != 0)
			goto trunc;
		break;
		}

	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION: {
		uint8_t db_tx_attenuation;

		rc = cpack_uint8(s, &db_tx_attenuation);
		if (rc != 0)
			goto trunc;
		break;
		}

	case IEEE80211_RADIOTAP_DBM_TX_POWER: {
		int8_t dbm_tx_power;

		rc = cpack_int8(s, &dbm_tx_power);
		if (rc != 0)
			goto trunc;
		break;
		}

	case IEEE80211_RADIOTAP_ANTENNA: {
		uint8_t antenna;

		rc = cpack_uint8(s, &antenna);
		if (rc != 0)
			goto trunc;
		break;
		}

	case IEEE80211_RADIOTAP_DB_ANTSIGNAL: {
		uint8_t db_antsignal;

		rc = cpack_uint8(s, &db_antsignal);
		if (rc != 0)
			goto trunc;
		break;
		}

	case IEEE80211_RADIOTAP_DB_ANTNOISE: {
		uint8_t db_antnoise;

		rc = cpack_uint8(s, &db_antnoise);
		if (rc != 0)
			goto trunc;
		break;
		}

	case IEEE80211_RADIOTAP_RX_FLAGS: {
		uint16_t rx_flags;

		rc = cpack_uint16(s, &rx_flags);
		if (rc != 0)
			goto trunc;
		/* Do nothing for now */
		break;
		}

	case IEEE80211_RADIOTAP_XCHANNEL: {
		uint32_t flags;
		uint16_t frequency;
		uint8_t channel;
		uint8_t maxpower;

		rc = cpack_uint32(s, &flags);
		if (rc != 0)
			goto trunc;
		rc = cpack_uint16(s, &frequency);
		if (rc != 0)
			goto trunc;
		rc = cpack_uint8(s, &channel);
		if (rc != 0)
			goto trunc;
		rc = cpack_uint8(s, &maxpower);
		if (rc != 0)
			goto trunc;
		print_chaninfo(frequency, flags, presentflags);
		break;
		}

	case IEEE80211_RADIOTAP_MCS: {
		uint8_t known;
		uint8_t flags;
		uint8_t mcs_index;
		static const char *ht_bandwidth[4] = {
			"20 MHz",
			"40 MHz",
			"20 MHz (L)",
			"20 MHz (U)"
		};
		float htrate;

		rc = cpack_uint8(s, &known);
		if (rc != 0)
			goto trunc;
		rc = cpack_uint8(s, &flags);
		if (rc != 0)
			goto trunc;
		rc = cpack_uint8(s, &mcs_index);
		if (rc != 0)
			goto trunc;
		break;
		}

	case IEEE80211_RADIOTAP_AMPDU_STATUS: {
		uint32_t reference_num;
		uint16_t flags;
		uint8_t delim_crc;
		uint8_t reserved;

		rc = cpack_uint32(s, &reference_num);
		if (rc != 0)
			goto trunc;
		rc = cpack_uint16(s, &flags);
		if (rc != 0)
			goto trunc;
		rc = cpack_uint8(s, &delim_crc);
		if (rc != 0)
			goto trunc;
		rc = cpack_uint8(s, &reserved);
		if (rc != 0)
			goto trunc;
		/* Do nothing for now */
		break;
		}

	case IEEE80211_RADIOTAP_VHT: {
		uint16_t known;
		uint8_t flags;
		uint8_t bandwidth;
		uint8_t mcs_nss[4];
		uint8_t coding;
		uint8_t group_id;
		uint16_t partial_aid;
		static const char *vht_bandwidth[32] = {
			"20 MHz",
			"40 MHz",
			"20 MHz (L)",
			"20 MHz (U)",
			"80 MHz",
			"80 MHz (L)",
			"80 MHz (U)",
			"80 MHz (LL)",
			"80 MHz (LU)",
			"80 MHz (UL)",
			"80 MHz (UU)",
			"160 MHz",
			"160 MHz (L)",
			"160 MHz (U)",
			"160 MHz (LL)",
			"160 MHz (LU)",
			"160 MHz (UL)",
			"160 MHz (UU)",
			"160 MHz (LLL)",
			"160 MHz (LLU)",
			"160 MHz (LUL)",
			"160 MHz (UUU)",
			"160 MHz (ULL)",
			"160 MHz (ULU)",
			"160 MHz (UUL)",
			"160 MHz (UUU)",
			"unknown (26)",
			"unknown (27)",
			"unknown (28)",
			"unknown (29)",
			"unknown (30)",
			"unknown (31)"
		};

		rc = cpack_uint16(s, &known);
		if (rc != 0)
			goto trunc;
		rc = cpack_uint8(s, &flags);
		if (rc != 0)
			goto trunc;
		rc = cpack_uint8(s, &bandwidth);
		if (rc != 0)
			goto trunc;
		for (i = 0; i < 4; i++) {
			rc = cpack_uint8(s, &mcs_nss[i]);
			if (rc != 0)
				goto trunc;
		}
		rc = cpack_uint8(s, &coding);
		if (rc != 0)
			goto trunc;
		rc = cpack_uint8(s, &group_id);
		if (rc != 0)
			goto trunc;
		rc = cpack_uint16(s, &partial_aid);
		if (rc != 0)
			goto trunc;
		for (i = 0; i < 4; i++) {
			u_int nss, mcs;
			nss = mcs_nss[i] & IEEE80211_RADIOTAP_VHT_NSS_MASK;
			mcs = (mcs_nss[i] & IEEE80211_RADIOTAP_VHT_MCS_MASK) >> IEEE80211_RADIOTAP_VHT_MCS_SHIFT;

			if (nss == 0)
				continue;
		}
		break;
		}

	default:
		/* this bit indicates a field whose
		 * size we do not know, so we cannot
		 * proceed.  Just print the bit number.
		 */
		return -1;
	}

	return 0;

trunc:
	return rc;
}


static int
print_in_radiotap_namespace(struct cpack_state *s, uint8_t *flags,
                            uint32_t presentflags, int bit0)
{
#define	BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define	BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define	BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define	BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define	BITNO_2(x) (((x) & 2) ? 1 : 0)
	uint32_t present, next_present;
	int bitno;
	enum ieee80211_radiotap_type bit;
	int rc;

	for (present = presentflags; present; present = next_present) {
		/*
		 * Clear the least significant bit that is set.
		 */
		next_present = present & (present - 1);

		/*
		 * Get the bit number, within this presence word,
		 * of the remaining least significant bit that
		 * is set.
		 */
		bitno = BITNO_32(present ^ next_present);

		/*
		 * Stop if this is one of the "same meaning
		 * in all presence flags" bits.
		 */
		if (bitno >= IEEE80211_RADIOTAP_NAMESPACE)
			break;

		/*
		 * Get the radiotap bit number of that bit.
		 */
		bit = (enum ieee80211_radiotap_type)(bit0 + bitno);

		rc = print_radiotap_field(s, bit, flags, presentflags);
		if (rc != 0)
			return rc;
	}

	return 0;
}

static u_int
ieee802_11_radio_print(const u_char *p, u_int length, u_int caplen)
{
#define	BIT(n)	(1U << n)
#define	IS_EXTENDED(__p)	\
	    (EXTRACT_LE_32BITS(__p) & BIT(IEEE80211_RADIOTAP_EXT)) != 0

	struct cpack_state cpacker;
	const struct ieee80211_radiotap_header *hdr;
	uint32_t presentflags;
	const uint32_t *presentp, *last_presentp;
	int vendor_namespace;
	uint8_t vendor_oui[3];
	uint8_t vendor_subnamespace;
	uint16_t skip_length;
	int bit0;
	u_int len;
	uint8_t flags;
	int pad;
	u_int fcslen;

	if (caplen < sizeof(*hdr)) {
		return caplen;
	}

	hdr = (const struct ieee80211_radiotap_header *)p;

	len = EXTRACT_LE_16BITS(&hdr->it_len);

	/*
	 * If we don't have the entire radiotap header, just give up.
	 */
	if (caplen < len) {
		return caplen;
	}
	cpack_init(&cpacker, (const uint8_t *)hdr, len); /* align against header start */
	cpack_advance(&cpacker, sizeof(*hdr)); /* includes the 1st bitmap */
	for (last_presentp = &hdr->it_present;
	     (const u_char*)(last_presentp + 1) <= p + len &&
	     IS_EXTENDED(last_presentp);
	     last_presentp++)
	  cpack_advance(&cpacker, sizeof(hdr->it_present)); /* more bitmaps */

	/* are there more bitmap extensions than bytes in header? */
	if ((const u_char*)(last_presentp + 1) > p + len) {
		return caplen;
	}

	/*
	 * Start out at the beginning of the default radiotap namespace.
	 */
	bit0 = 0;
	vendor_namespace = 0;
	memset(vendor_oui, 0, 3);
	vendor_subnamespace = 0;
	skip_length = 0;
	/* Assume no flags */
	flags = 0;
	/* Assume no Atheros padding between 802.11 header and body */
	pad = 0;
	/* Assume no FCS at end of frame */
	fcslen = 0;
	for (presentp = &hdr->it_present; presentp <= last_presentp;
	    presentp++) {
		presentflags = EXTRACT_LE_32BITS(presentp);

		/*
		 * If this is a vendor namespace, we don't handle it.
		 */
		if (vendor_namespace) {
			/*
			 * Skip past the stuff we don't understand.
			 * If we add support for any vendor namespaces,
			 * it'd be added here; use vendor_oui and
			 * vendor_subnamespace to interpret the fields.
			 */
			if (cpack_advance(&cpacker, skip_length) != 0) {
				/*
				 * Ran out of space in the packet.
				 */
				break;
			}

			/*
			 * We've skipped it all; nothing more to
			 * skip.
			 */
			skip_length = 0;
		} else {
			if (print_in_radiotap_namespace(&cpacker,
			    &flags, presentflags, bit0) != 0) {
				/*
				 * Fatal error - can't process anything
				 * more in the radiotap header.
				 */
				break;
			}
		}

		/*
		 * Handle the namespace switch bits; we've already handled
		 * the extension bit in all but the last word above.
		 */
		switch (presentflags &
		    (BIT(IEEE80211_RADIOTAP_NAMESPACE)|BIT(IEEE80211_RADIOTAP_VENDOR_NAMESPACE))) {

		case 0:
			/*
			 * We're not changing namespaces.
			 * advance to the next 32 bits in the current
			 * namespace.
			 */
			bit0 += 32;
			break;

		case BIT(IEEE80211_RADIOTAP_NAMESPACE):
			/*
			 * We're switching to the radiotap namespace.
			 * Reset the presence-bitmap index to 0, and
			 * reset the namespace to the default radiotap
			 * namespace.
			 */
			bit0 = 0;
			vendor_namespace = 0;
			memset(vendor_oui, 0, 3);
			vendor_subnamespace = 0;
			skip_length = 0;
			break;

		case BIT(IEEE80211_RADIOTAP_VENDOR_NAMESPACE):
			/*
			 * We're switching to a vendor namespace.
			 * Reset the presence-bitmap index to 0,
			 * note that we're in a vendor namespace,
			 * and fetch the fields of the Vendor Namespace
			 * item.
			 */
			bit0 = 0;
			vendor_namespace = 1;
			if ((cpack_align_and_reserve(&cpacker, 2)) == NULL) {
				break;
			}
			if (cpack_uint8(&cpacker, &vendor_oui[0]) != 0) {
				break;
			}
			if (cpack_uint8(&cpacker, &vendor_oui[1]) != 0) {
				break;
			}
			if (cpack_uint8(&cpacker, &vendor_oui[2]) != 0) {
				break;
			}
			if (cpack_uint8(&cpacker, &vendor_subnamespace) != 0) {
				break;
			}
			if (cpack_uint16(&cpacker, &skip_length) != 0) {
				break;
			}
			break;

		default:
			/*
			 * Illegal combination.  The behavior in this
			 * case is undefined by the radiotap spec; we
			 * just ignore both bits.
			 */
			break;
		}
	}

	if (flags & IEEE80211_RADIOTAP_F_DATAPAD)
		pad = 1;	/* Atheros padding */
	if (flags & IEEE80211_RADIOTAP_F_FCS)
		fcslen = 4;	/* FCS at end of packet */
	return len + ieee802_11_print(p + len, length - len, caplen - len, pad,
	    fcslen);
#undef BITNO_32
#undef BITNO_16
#undef BITNO_8
#undef BITNO_4
#undef BITNO_2
#undef BIT
}

static u_int
ieee802_11_avs_radio_print(const u_char *p, u_int length, u_int caplen)
{
	uint32_t caphdr_len;

	if (caplen < 8) {
		return caplen;
	}

	caphdr_len = EXTRACT_32BITS(p + 4);
	if (caphdr_len < 8) {
		/*
		 * Yow!  The capture header length is claimed not
		 * to be large enough to include even the version
		 * cookie or capture header length!
		 */
		return caplen;
	}

	if (caplen < caphdr_len) {
		return caplen;
	}

	return caphdr_len + ieee802_11_print(p + caphdr_len,
	    length - caphdr_len, caplen - caphdr_len, 0, 0);
}

#define PRISM_HDR_LEN		144

#define WLANCAP_MAGIC_COOKIE_BASE 0x80211000
#define WLANCAP_MAGIC_COOKIE_V1	0x80211001
#define WLANCAP_MAGIC_COOKIE_V2	0x80211002

/*
 * For DLT_PRISM_HEADER; like DLT_IEEE802_11, but with an extra header,
 * containing information such as radio information, which we
 * currently ignore.
 *
 * If, however, the packet begins with WLANCAP_MAGIC_COOKIE_V1 or
 * WLANCAP_MAGIC_COOKIE_V2, it's really DLT_IEEE802_11_RADIO_AVS
 * (currently, on Linux, there's no ARPHRD_ type for
 * DLT_IEEE802_11_RADIO_AVS, as there is a ARPHRD_IEEE80211_PRISM
 * for DLT_PRISM_HEADER, so ARPHRD_IEEE80211_PRISM is used for
 * the AVS header, and the first 4 bytes of the header are used to
 * indicate whether it's a Prism header or an AVS header).
 */
u_int
prism_if_print(const struct pcap_pkthdr *h, const u_char *p)
{
	u_int caplen = h->caplen;
	u_int length = h->len;
	uint32_t msgcode;

	if (caplen < 4) {
		return caplen;
	}

	msgcode = EXTRACT_32BITS(p);
	if (msgcode == WLANCAP_MAGIC_COOKIE_V1 ||
	    msgcode == WLANCAP_MAGIC_COOKIE_V2)
		return ieee802_11_avs_radio_print(p, length, caplen);

	if (caplen < PRISM_HDR_LEN) {
		return caplen;
	}

	return PRISM_HDR_LEN + ieee802_11_print(p + PRISM_HDR_LEN,
	    length - PRISM_HDR_LEN, caplen - PRISM_HDR_LEN, 0, 0);
}

/*
 * For DLT_IEEE802_11_RADIO; like DLT_IEEE802_11, but with an extra
 * header, containing information such as radio information.
 */
void
ieee802_11_radio_if_print(u_char *arg, const struct pcap_pkthdr *h, const u_char *p)
{
	ieee802_11_radio_print(p, h->len, h->caplen);
   return;
}

/*
 * For DLT_IEEE802_11_RADIO_AVS; like DLT_IEEE802_11, but with an
 * extra header, containing information such as radio information,
 * which we currently ignore.
 */
void
ieee802_11_radio_avs_if_print(u_char *arg, const struct pcap_pkthdr *h, const u_char *p)
{
	ieee802_11_avs_radio_print(p, h->len, h->caplen);
   return;
}
