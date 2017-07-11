
#ifndef __IEEE802_11_H__

u_int
ieee802_11_radio_if_print(const struct pcap_pkthdr *h, const u_char *p);
u_int
ieee802_11_radio_avs_if_print(const struct pcap_pkthdr *h, const u_char *p);
u_int
ieee802_11_if_print(const struct pcap_pkthdr *h, const u_char *p);

#endif
