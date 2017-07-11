#include <pcap.h>  
#include <time.h>  
#include <stdlib.h>  
#include <stdio.h>

#include "ieee80211.h"

void getPacket(u_char * arg,
               const struct pcap_pkthdr * pkthdr,
               const u_char * packet)
{
  int * id = (int *)arg;

//  ieee802_11_if_print(pkthdr, packet);
 
  printf("\n\n");
}
 
int main()  
{  
  char errBuf[PCAP_ERRBUF_SIZE], * devStr;
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

  /* wait a packet to arrive */
/*
  struct pcap_pkthdr packet;
  const u_char * pktStr = pcap_next(device, &packet);

  if(!pktStr) {  
    printf("did not capture a packet!\n");
    exit(1);
  }
 
  printf("Packet length: %d\n", packet.len);
  printf("Number of bytes: %d\n", packet.caplen);
  printf("Recieved time: %s\n", ctime((const time_t *)&packet.ts.tv_sec));
*/
  dlt = pcap_datalink(device);

  printf("%x,\n", dlt);
  /* construct a filter */
  struct bpf_program filter;
  pcap_compile(device, &filter, "ether src 00:08:22:ac:c6:fb", 1, 0);
  pcap_setfilter(device, &filter);

  /* wait loop forever */
  int id = 0;
  pcap_loop(device, -1, getPacket, (u_char*)&id);
  pcap_close(device);
  return 0;
}
