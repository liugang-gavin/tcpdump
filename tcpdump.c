#include <pcap.h>  
#include <time.h>  
#include <stdlib.h>  
#include <stdio.h>

#include "ieee80211.h"

int main()  
{  
  char errBuf[PCAP_ERRBUF_SIZE], * devStr;
  pcap_handler callback;
  int  dlt;

  /* get a device */
  devStr = pcap_lookupdev(errBuf);
  //devStr = "wlx488ad239e728";

  if(devStr) {
    printf("success: device: %s\n", devStr);
  } else {
    printf("error: %s\n", errBuf);
    exit(1);
  }
 
  /* open a device, wait until a packet arrives */
  pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);

  if(!device) {  
    printf("error: pcap_open_live(): %s\n", errBuf);
    exit(1);
  }

  dlt = pcap_datalink(device);

  switch (dlt) {
  case DLT_IEEE802_11_RADIO:
    callback = ieee802_11_radio_if_print;
    break;
  case DLT_IEEE802_11_RADIO_AVS:
    callback = ieee802_11_radio_avs_if_print;
    break;
  case DLT_IEEE802_11:
    callback = ieee802_11_if_print;
    break;
  default:
    printf("error: '%s' is not a 80211 interface.\n", devStr);
    goto out;
  }

  printf("%x,\n", dlt);
  /* construct a filter */
  struct bpf_program filter;
  pcap_compile(device, &filter, "ether src 00:08:22:ac:c6:fb", 1, 0);
  pcap_setfilter(device, &filter);

  /* wait loop forever */
  int id = 0;
  pcap_loop(device, -1, callback, (u_char*)&id);

out:
  pcap_close(device);
  return 0;
}
