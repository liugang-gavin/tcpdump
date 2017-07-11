
#ifndef __IEEE802_11_H__

void
ieee802_11_radio_if_print(u_char *arg,
                          const struct pcap_pkthdr *h,
                          const u_char *p);
void
ieee802_11_radio_avs_if_print(u_char *arg,
                              const struct pcap_pkthdr *h,
                              const u_char *p);
void
ieee802_11_if_print(u_char *arg,
                    const struct pcap_pkthdr *h,
                    const u_char *p);

#endif
