#include <pcap.h>  
#include <time.h>  
#include <stdlib.h>  
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#include "decoder.h"
#include "ieee80211.h"
pcap_t *device;

void* start_capture(void* argv)  
{  
  char errBuf[PCAP_ERRBUF_SIZE], * devStr;
  pcap_handler callback;
  int  dlt;

  /* get a device */
  //devStr = pcap_lookupdev(errBuf);
  devStr = "wlan0";

  if(devStr) {
    printf("success: device: %s\n", devStr);
  } else {
    printf("error: %s\n", errBuf);
    exit(1);
  }
 
  /* open a device, wait until a packet arrives */
  device = pcap_open_live(devStr, 65535, 1, 0, errBuf);

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

  /* wait loop forever */
  pcap_loop(device, -1, callback, NULL);

out:
  pcap_close(device);
  return 0;
}

int decoder_finished(int8_t *passwd, int8_t *bssid, void *arg)
{
	printf("Get SSID: %02x:%02x:%02x:%02x:%02x:%02x.\nPassword:%s\n",
			 bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
			 passwd);
	*(int*)arg = 1;
}


int main(int argc, char **argv)
{   
	pthread_t tid;
	int channel;
	char cmd[128];
	int finished = 0;

	decoder_open(decoder_finished, &finished);
	if (pthread_create(&tid,NULL, start_capture,(void*)NULL)) {
		printf("ERROR: pthread create error.\n");
		goto out;
	}

retry:
	for (channel = 1; channel <= 13; channel ++){
		sprintf(cmd, "iw dev wlan0 set channel %d", channel);
		if (system(cmd)){
			printf("ERROR: set wlan0 to channel %d error.\n", channel);
			goto out;
		}
		usleep(100000);
	}

	if (!finished) {
		printf("WARN: retry\n");
		goto retry;
	}
	
	pcap_breakloop(device);

	pthread_join(tid, NULL);
	decoder_close();
out:
	return 0;
}
