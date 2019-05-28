/*
 * Copyright 2012-2016 Michael Ryan
 *
 * This file is part of Project Ubertooth.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */
#include <ctype.h>
#include <err.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <math.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>

#include "ubertooth.h"
#include "ubertooth_callback.h"
#include "procData.h"
#include "bchEcc.h"
#include "encAlg.h"

#define BLOCK_SIZE 16
#define FREAD_COUNT 4096
#define FILE_MAX 1000

int convert_mac_address(char *s, uint8_t *o) {
	int i;

	// validate length
	if (strlen(s) != 6 * 2 + 5) {
		printf("Error: MAC address is wrong length\n");
		return 0;
	}

	// validate hex chars and : separators
	for (i = 0; i < 6*3; i += 3) {
		if (!isxdigit(s[i]) ||
				!isxdigit(s[i+1])) {
			printf("Error: MAC address contains invalid character(s)\n");
			return 0;
		}
		if (i < 5*3 && s[i+2] != ':') {
			printf("Error: MAC address contains invalid character(s)\n");
			return 0;
		}
	}

	// sanity: checked; convert
	for (i = 0; i < 6; ++i) {
		unsigned byte;
		sscanf(&s[i*3], "%02x",&byte);
		o[i] = byte;
	}

	return 1;
}

//JWHUR get the data from input file
int convert_data(char *filename, uint8_t *o) {
	FILE *input;
	int i, slen = 0, count;

	input = fopen(filename, "r");
	if (input == NULL) {
		printf("open failed\n");
		return 0;
	}

	fseek(input, 0, SEEK_END);
	slen = ftell(input);

	char *buf = malloc(sizeof(char) * slen + 1);
	memset(buf, 0, sizeof(char) * slen + 1);
	fseek(input, 0, SEEK_SET);
	count = fread(buf, slen, 1, input);

	printf("size: %d\n", slen);
	for (i=0; i<slen; i++) {
		o[i] = (uint8_t) buf[i];
	}

	free(buf);
	return slen+1;
}

int syncStart(uint8_t *myMac, int do_adv_index, ubertooth_t *ut, int ubertooth_device, int *time, int8_t *rssi) {
	int status, i, ofsRssi, ofsTime, dataLen;
	u16 channel;

	if (do_adv_index == 37)
		channel = 2402;
	else if (do_adv_index == 38)
		channel = 2426;
	else
		channel = 2480;
	cmd_set_channel(ut->devh, channel);

	printf("********** Start RSSI Sampling **********\n");

	cmd_btle_slave(ut->devh, myMac, UBERTOOTH_BTLE_SYNC, 6);
	struct timespec tspec;
	clock_gettime(CLOCK_MONOTONIC, &tspec);
	uint64_t sync_start = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
	uint64_t start = 0;

	usleep(1000);
	usb_pkt_rx rx;
	ofsRssi = 0;
	ofsTime = 0;
	while(1) {
		int r = cmd_poll(ut->devh, &rx);
		if (r < 0) {
			printf("USB Error\n");
		} else if (r == sizeof(usb_pkt_rx)) {
			fifo_push(ut->fifo, &rx);
			if (start == 0) {
				clock_gettime(CLOCK_MONOTONIC, &tspec);
				start = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
			}
			rssi_sampling(ut, rssi, ofsRssi);
			ofsRssi += 50;
			int time_count = 4;
			while (--time_count) {
				int m = cmd_poll(ut->devh, &rx);
				if (m < 0) {
					printf("USB Error\n");
				}
				if (m == sizeof(usb_time_rx)) {
					fifo_push(ut->fifo, &rx);
					time_sampling(ut, time, ofsTime);
					ofsTime += 16;
				}
			}
			int m = cmd_poll(ut->devh, &rx);
			if (m < 0) {
				printf("USB Error\n");
			} else if (m == sizeof(usb_time_rx)) {
				fifo_push(ut->fifo, &rx);
				time_sampling_last(ut, time, ofsTime);
				ofsTime += 2;
			}
		}
		if (start != 0) {
			clock_gettime(CLOCK_MONOTONIC, &tspec);
			uint64_t now = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
			if (now - start > 5000)
				break;
		}
		usleep(500);
	}
	dataLen = ofsRssi;
	ubertooth_stop(ut);

	usleep(100);

	ut = ubertooth_resume(ut);
	status = ubertooth_connect(ut, ubertooth_device);
	if (status < 0) {
		return 1;
	}

	status = ubertooth_check_api(ut);
	if (status < 0)
		return 1;

	register_cleanup_handler(ut, 1);

	return dataLen;
}

int dataTx(uint8_t *mac_addr, uint8_t *data, int dlen, float txDur, ubertooth_t *ut, int ubertooth_device) {
	int status, i;

	uint8_t *tot_data = (uint8_t*) malloc(sizeof(uint8_t) * (dlen + 6));
	for(i=0; i<6; i++) tot_data[i] = mac_addr[i];
	for(i=0; i<dlen; i++) tot_data[i+6] = data[i];

/*	printf("Tx Mac address: ");
	for(i=0; i<6; i++) printf("%02x ", mac_addr[i]);
	printf("\nBroadcast data: \n");
	for(i=0; i<dlen; i++) printf("%02x ", tot_data[i+6]);
	printf("\ndlen: %d", dlen);
	printf("\n");*/
	cmd_btle_slave(ut->devh, tot_data, UBERTOOTH_BTLE_SLAVE, dlen+6);

	usleep(txDur * 1000000);
	ubertooth_stop(ut);

	usleep(10000);

	ut = ubertooth_resume(ut);
	status = ubertooth_connect(ut, ubertooth_device);
	if (status < 0) {
		printf("Ubertooth_connect error!\n");
		return 1;
	}

	status = ubertooth_check_api(ut);
	if (status < 0) {
		printf("Ubertooth_check_api error!\n");
		return 1;
	}
	register_cleanup_handler(ut, 1); 
	free(tot_data);

	return status;
}

int scanGuest(uint8_t *myMac, uint8_t **guestMac, int maxGuest, float rxDur, ubertooth_t *ut, int ubertooth_device) {

	printf("********** Start Scanning Guest **********\n");
	int status, nGuest = 0, i;

	for(i=0; i<maxGuest; i++) 
		guestMac[i] = (uint8_t *)malloc(sizeof(uint8_t)*6);

	u16 channel = 2402;
	usb_pkt_rx rx;

	cmd_set_jam_mode(ut->devh, JAM_NONE);
	cmd_set_modulation(ut->devh, MOD_BT_LOW_ENERGY);
	cmd_set_channel(ut->devh, channel);
	cmd_btle_sniffing(ut->devh, 2);

	struct timespec tspec;
	uint64_t start = 0, now = 0;
	clock_gettime(CLOCK_MONOTONIC, &tspec);
	start = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
	now = start;
	while(now - start < rxDur*1000) {
		int r = cmd_poll(ut->devh, &rx);
		if (r < 0) {
			printf("USB Error\n");
			break;
		}
		if (r == sizeof(usb_pkt_rx)) {
			fifo_push(ut->fifo, &rx);
			nGuest = find_Guest(ut, myMac, guestMac, nGuest);
			if (nGuest == maxGuest)
				break;
		}
		usleep(500);
		clock_gettime(CLOCK_MONOTONIC, &tspec);
		now = (tspec.tv_sec) * 1000 + (tspec.tv_nsec)/1000000;
	}
	ubertooth_stop(ut);

	usleep(100);
	ut = ubertooth_resume(ut);
	status = ubertooth_connect(ut, ubertooth_device);
	if (status < 0) {
		return status;
	}
	status = ubertooth_check_api(ut);
	if (status < 0)
		return status;
	register_cleanup_handler(ut, 1);

	return nGuest;
}

int listenSync(uint8_t *myMac, int do_adv_index, ubertooth_t *ut, int ubertooth_device, int *time, int8_t *rssi) {

	printf("********** Start Sync Packet Listening **********\n");
	int status, sync = 0, rssiSampling = 0;
	int ofsRssi = 0, ofsTime = 0, dataLen;
	usb_pkt_rx rx;
	u16 channel = 2402;

	status = cmd_set_jam_mode(ut->devh, JAM_NONE);	
	cmd_set_modulation(ut->devh, MOD_BT_LOW_ENERGY);
	if (do_adv_index == 37)
		channel = 2402;
	else if (do_adv_index == 38)
		channel = 2426;
	else
		channel = 2480;
	cmd_set_channel(ut->devh, channel);
	cmd_btle_sniffing(ut->devh, 2);

	struct timespec tspec;
	uint64_t sync_start, start = 0, now = 0;

	clock_gettime(CLOCK_MONOTONIC, &tspec);
	start = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
	now = start;

	while (1) {
		int r = cmd_poll(ut->devh, &rx);
		if (r < 0) {
			printf("USB Error\n");
			break;
		}
		if (r == sizeof(usb_pkt_rx)) {
			fifo_push(ut->fifo, &rx);
			if (!rssiSampling) sync = find_SYNC(ut, myMac);
			if (!rssiSampling) {
				if (sync == 1) {
					clock_gettime(CLOCK_MONOTONIC, &tspec);
					sync_start = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
					start = 0;
					rssiSampling = 1;
					printf("********** Start RSSI Sampling **********\n");
				}
			} else {
				if (start == 0) {
					clock_gettime(CLOCK_MONOTONIC, &tspec);
					start = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
				}
				rssi_sampling(ut, rssi, ofsRssi);
				ofsRssi += 50;
				int time_count = 4;
				while (--time_count) {
					int m = cmd_poll(ut->devh, &rx);
					if (m < 0) {
						printf("USB Error\n");
						break;
					}
					if (m == sizeof(usb_time_rx)) {
						fifo_push(ut->fifo, &rx);
						time_sampling(ut, time, ofsTime);
						ofsTime += 16;
					}
				}
				int m = cmd_poll(ut->devh, &rx);
				if (m < 0) {
					printf("USB Error\n");
					break;
				}
				if (m == sizeof(usb_time_rx)) {
					fifo_push(ut->fifo, &rx);
					time_sampling_last(ut, time, ofsTime);
					ofsTime += 2;
				}
			}
		}
		usleep(500);
		if (start != 0) {	
			clock_gettime(CLOCK_MONOTONIC, &tspec);
			now = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
			if (rssiSampling) {
				if (now - start > 5000) 
					break;
			} else {
				if (now - start > 2000)
					return 0;
			}
		}					
	}

	dataLen = ofsRssi;
	ubertooth_stop(ut);

	usleep(100);
	ut = ubertooth_resume(ut);
	status = ubertooth_connect(ut, ubertooth_device);
	if (status < 0)
		return 1;
	status = ubertooth_check_api(ut);
	if (status < 0)
		return 1;
	register_cleanup_handler(ut, 1);

	return dataLen;
}

int listenPubkey(uint8_t *myMac, int do_adv_index, uint8_t *pubKey, float dur, ubertooth_t *ut, int ubertooth_device) {

	printf("********** Start Public Key Listening **********\n");
	int PAYLOAD_LEN = 11;
	int status, keyRecv = 0, keyLen = 0, numF = 0;
	int *fragRecv, nFrag[1], fNum[1], pLen[1];
	uint8_t targetMac[6] = {0,};
	int i, j, target = 0, same = 0;
	usb_pkt_rx rx;
	uint8_t *frag = (uint8_t *)malloc(sizeof(uint8_t)*PAYLOAD_LEN);
	u16 channel = 2402;

	status = cmd_set_jam_mode(ut->devh, JAM_NONE);	
	cmd_set_modulation(ut->devh, MOD_BT_LOW_ENERGY);
	if (do_adv_index == 37)
		channel = 2402;
	else if (do_adv_index == 38)
		channel = 2426;
	else
		channel = 2480;
	cmd_set_channel(ut->devh, channel);
	cmd_btle_sniffing(ut->devh, 2);

	struct timespec tspec;
	uint64_t start = 0, now = 0;

	clock_gettime(CLOCK_MONOTONIC, &tspec);
	start = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
	now = start;

	while (1) {
		int r = cmd_poll(ut->devh, &rx);
		if (r < 0) {
			printf("USB Error\n");
			break;
		}
		if (r == sizeof(usb_pkt_rx)) {
			fifo_push(ut->fifo, &rx);
			if (!keyRecv) {
				if(!target) {
					target = recv_PUB(ut, target, nFrag, fNum, pLen, targetMac, frag);
					if (target == 1) {
						numF = nFrag[0];
						fragRecv = (int *) malloc(sizeof(int)*numF);
						memset(fragRecv, 0, sizeof(int) * numF);
						for (i=0; i<pLen[0]; i++) {
							pubKey[PAYLOAD_LEN * fNum[0] + i] = frag[i];
						}
						fragRecv[fNum[0]] = pLen[0];
					}
				} else {
					same = recv_PUB(ut, target, nFrag, fNum, pLen, targetMac, frag);
					if (same == 2 && fragRecv[fNum[0]] == 0) {
						fragRecv[fNum[0]] = pLen[0];
						for (i=0; i<pLen[0]; i++) {
							pubKey[PAYLOAD_LEN * fNum[0] + i] = frag[i];
						}
						fragRecv[fNum[0]] = pLen[0];
					}
				}
			}

			if (target) {
				keyLen = 0;
				keyRecv = 1;
				for (i=0; i<numF; i++) {
					if (fragRecv[i] == 0) {
						keyLen = 0;
						keyRecv = 0;
						break;
					}
					keyLen += fragRecv[i];
				}
			}

			if (keyRecv) {
				printf("Public key received\n");
				printf("targetMac: ");
				for (i=0; i<6; i++)
					printf("%02x ", targetMac[i]);
				printf("\n");
				printf("keyLen: %d\n", keyLen);
				break;
			}
		}

		usleep(100);
		if (start != 0) {	
			clock_gettime(CLOCK_MONOTONIC, &tspec);
			now = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
			if (now - start > dur * 1000)
				break;
		}					
	}

	ubertooth_stop(ut);

	usleep(100);
	ut = ubertooth_resume(ut);
	status = ubertooth_connect(ut, ubertooth_device);
	if (status < 0)
		return 1;
	status = ubertooth_check_api(ut);
	if (status < 0)
		return 1;
	register_cleanup_handler(ut, 1);

	for (i=0; i<6; i++)
		myMac[i] = targetMac[i];

	if (target == 1)
		free(fragRecv); 
	free(frag);
	return keyLen;
}

int listenMessage(uint8_t *myMac, uint8_t *guestMac, int do_adv_index, unsigned char *encMessage, int dur, ubertooth_t *ut, int ubertooth_device) {

	printf("********** Start Listening Password **********\n");
	int PAYLOAD_LEN = 11;
	int status, msgRecv = 0, msgLen = 0, numF = 0;
	int *fragRecv, nFrag[1], fNum[1], pLen[1];
	uint8_t targetMac[6] = {0,};
	int i, j, target = 0, same = 0;
	usb_pkt_rx rx;
	uint8_t *frag = (uint8_t *)malloc(sizeof(uint8_t)*PAYLOAD_LEN);
	u16 channel = 2402;

	status = cmd_set_jam_mode(ut->devh, JAM_NONE);	
	cmd_set_modulation(ut->devh, MOD_BT_LOW_ENERGY);
	if (do_adv_index == 37)
		channel = 2402;
	else if (do_adv_index == 38)
		channel = 2426;
	else
		channel = 2480;
	cmd_set_channel(ut->devh, channel);
	cmd_btle_sniffing(ut->devh, 2);

	struct timespec tspec;
	uint64_t start = 0, now = 0;

	clock_gettime(CLOCK_MONOTONIC, &tspec);
	start = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
	now = start;

	while (1) {
		int r = cmd_poll(ut->devh, &rx);
		if (r < 0) {
			printf("USB Error\n");
			break;
		}
		if (r == sizeof(usb_pkt_rx)) {
			fifo_push(ut->fifo, &rx);
			if(!target) {
				target = recv_PWD(ut, target, nFrag, fNum, pLen, guestMac, frag);
				if (target == 1) {
					numF = nFrag[0];
					fragRecv = (int *) malloc(sizeof(int)*numF);
					memset(fragRecv, 0, sizeof(int) * numF);
					for (i=0; i<pLen[0]; i++) 
						encMessage[PAYLOAD_LEN * fNum[0] + i] = frag[i];
					fragRecv[fNum[0]] = pLen[0];
				}
			} else {
				same = recv_PWD(ut, target, nFrag, fNum, pLen, guestMac, frag);
				if (same == 2 && fragRecv[fNum[0]] == 0) {
					for (i=0; i<pLen[0]; i++) 
						encMessage[PAYLOAD_LEN * fNum[0] + i] = frag[i];
					fragRecv[fNum[0]] = pLen[0];
				}
			}

			if (target) {
				msgLen = 0;
				msgRecv = 1;
				for (i=0; i<numF; i++) {
					if (fragRecv[i] == 0) {
						msgLen = 0;
						msgRecv = 0;
						break;
					}
					msgLen += fragRecv[i];
				}
			}

			if (msgRecv) {
				printf("Password received\n");
				break;
			}
		}

		usleep(500);
		if (start != 0) {	
			clock_gettime(CLOCK_MONOTONIC, &tspec);
			now = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
			if (now - start > dur * 1000)
				break;
		}					
	}

	ubertooth_stop(ut);

	usleep(100);
	ut = ubertooth_resume(ut);
	status = ubertooth_connect(ut, ubertooth_device);
	if (status < 0)
		return 1;
	status = ubertooth_check_api(ut);
	if (status < 0)
		return 1;
	register_cleanup_handler(ut, 1);

	for (i=0; i<6; i++)
		myMac[i] = targetMac[i];

	if (target == 1)
		free(fragRecv); 
	free(frag);

	return msgLen;
}

int listenData(uint8_t **guestMac, int nGuest, int *statGuest, int do_adv_index, unsigned char **guestData, float dur, ubertooth_t *ut, int ubertooth_device) {

	printf("********** Start Listening Data**********\n");
	int PAYLOAD_LEN = 11;
	int status;
	int **fragRecv = (int **) malloc(sizeof(int *)*nGuest);
	int numF, nFrag[1], fNum[1], pLen[1], nRecv = 0;
	uint8_t targetMac[6] = {0,};
	int i, j, target = -1;
	usb_pkt_rx rx;
	uint8_t *frag = (uint8_t *)malloc(sizeof(uint8_t)*PAYLOAD_LEN);
	u16 channel = 2402;

	status = cmd_set_jam_mode(ut->devh, JAM_NONE);	
	cmd_set_modulation(ut->devh, MOD_BT_LOW_ENERGY);
	if (do_adv_index == 37)
		channel = 2402;
	else if (do_adv_index == 38)
		channel = 2426;
	else
		channel = 2480;
	cmd_set_channel(ut->devh, channel);
	cmd_btle_sniffing(ut->devh, 2);

	struct timespec tspec;
	uint64_t start = 0, now = 0;

	clock_gettime(CLOCK_MONOTONIC, &tspec);
	start = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
	now = start;

	while (1) {
		int r = cmd_poll(ut->devh, &rx);
		if (r < 0) {
			printf("USB Error\n");
			break;
		}
		if (r == sizeof(usb_pkt_rx)) {
			fifo_push(ut->fifo, &rx);
			target = recv_DATA(ut, target, nFrag, fNum, pLen, guestMac, statGuest, nGuest, frag);
			if (target >= 0) {
				if (statGuest[target] == 0) {
					numF = nFrag[0];
					fragRecv[target] = (int *) malloc(sizeof(int)*numF);
					memset(fragRecv[target], 0, sizeof(int) * numF);
					for (i=0; i<pLen[0]; i++) 
						guestData[target][PAYLOAD_LEN * fNum[0] + i] = (unsigned char)frag[i];
					fragRecv[target][fNum[0]] = pLen[0];
					statGuest[target] = 1;
				}
				else if (statGuest[target] == 1) {
					numF = nFrag[0];
					fragRecv[target][fNum[0]] = pLen[0];
					for (i=0; i<pLen[0]; i++) 
						guestData[target][PAYLOAD_LEN * fNum[0] + i] = frag[i];
				}

				statGuest[target] = 2;
				for (i=0; i< numF; i++) {
					if (fragRecv[target][i] == 0) {
						statGuest[target] = 1;
						break;
					}
				}
			} 
		}

		usleep(500);
		if (start != 0) {	
			clock_gettime(CLOCK_MONOTONIC, &tspec);
			now = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
			if (now - start > dur * 1000)
				break;
		}					
	}

	ubertooth_stop(ut);

	usleep(10000);

	ut = ubertooth_resume(ut);
	status = ubertooth_connect(ut, ubertooth_device);
	if (status < 0)
		return 1;
	status = ubertooth_check_api(ut);
	if (status < 0)
		return 1;
	register_cleanup_handler(ut, 1);

	for(i=0; i<nGuest; i++) {
		if (statGuest[i] == 2)
			nRecv++;
	}

	for(i=0; i<nGuest; i++) {
		if (statGuest[i] > 0)
			free(fragRecv[i]);
	}
	free(fragRecv); 
	free(frag);

	return nRecv;
}

int listenAck(uint8_t *guestMac, int do_adv_index, int rxDur, ubertooth_t *ut, int ubertooth_device) {

	printf("********** Start Listening Ack**********\n");
	int PAYLOAD_LEN = 11;
	int status;
	int i, j, target = 0;
	usb_pkt_rx rx;
	uint8_t *frag = (uint8_t *)malloc(sizeof(uint8_t)*PAYLOAD_LEN);
	u16 channel = 2402;

	status = cmd_set_jam_mode(ut->devh, JAM_NONE);	
	cmd_set_modulation(ut->devh, MOD_BT_LOW_ENERGY);
	if (do_adv_index == 37)
		channel = 2402;
	else if (do_adv_index == 38)
		channel = 2426;
	else
		channel = 2480;
	cmd_set_channel(ut->devh, channel);
	cmd_btle_sniffing(ut->devh, 2);

	struct timespec tspec;
	uint64_t start = 0, now = 0;

	clock_gettime(CLOCK_MONOTONIC, &tspec);
	start = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
	now = start;

	while (now - start < rxDur * 1000) {
		int r = cmd_poll(ut->devh, &rx);
		if (r < 0) {
			printf("USB Error\n");
			break;
		}
		if (r == sizeof(usb_pkt_rx)) {
			fifo_push(ut->fifo, &rx);
			target = recv_ACK(ut, guestMac);
			if (target == 1)
				break;
		}

		usleep(500);

		clock_gettime(CLOCK_MONOTONIC, &tspec);
		now = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
	}

	ubertooth_stop(ut);

	usleep(100);
	ut = ubertooth_resume(ut);
	status = ubertooth_connect(ut, ubertooth_device);
	if (status < 0)
		return 1;
	status = ubertooth_check_api(ut);
	if (status < 0)
		return 1;
	register_cleanup_handler(ut, 1);

	return target;
}

float getMMR(unsigned char *hostBitSeq, unsigned char *guestBitSeq, int seqLen) 
{
	int i, j;
	unsigned char hostBit, guestBit;
	float misMatch = 0;

	for(i=0; i<seqLen-1; i++) {
		for(j=0; j<8; j++) {
			hostBit = (hostBitSeq[i] >> j) & 0x1;
			guestBit = (guestBitSeq[i] >> j) & 0x1;
			if (hostBit == guestBit)
				misMatch += 1;
		}
	}
	for(j=0; j<4; j++) {
		hostBit = (hostBitSeq[seqLen-1] >> j) & 0x1;
		guestBit = (guestBitSeq[seqLen-1] >> j) & 0x1;
		if (hostBit != guestBit)
			misMatch += 1;
	}

	return misMatch/100;
}

static void usage(void)
{
	printf("ubertooth-btle - passive Bluetooth Low Energy monitoring\n");
	printf("Usage:\n");
	printf("\t-h this help\n");
	printf("\n");
	printf("    Major modes:\n");
	printf("\t-f follow connections\n");
	printf("\t-p promiscuous: sniff active connections\n");
	printf("\t-a[address] get/set access address (example: -a8e89bed6)\n");
	printf("\t-s<address> faux slave mode, using MAC addr (example: -s22:44:66:88:aa:cc)\n");
	printf("\t-t<address> set connection following target (example: -t22:44:66:88:aa:cc)\n");
	printf("\n");
	printf("    Interference (use with -f or -p):\n");
	printf("\t-i interfere with one connection and return to idle\n");
	printf("\t-I interfere continuously\n");
	printf("\n");
	printf("    Data source:\n");
	printf("\t-U<0-7> set ubertooth device to use\n");
	printf("\n");
	printf("    Misc:\n");
	printf("\t-r<filename> capture packets to PCAPNG file\n");
	printf("\t-q<filename> capture packets to PCAP file (DLT_BLUETOOTH_LE_LL_WITH_PHDR)\n");
	printf("\t-c<filename> capture packets to PCAP file (DLT_PPI)\n");
	printf("\t-A<index> advertising channel index (default 37)\n");
	printf("\t-v[01] verify CRC mode, get status or enable/disable\n");
	printf("\t-x<n> allow n access address offenses (default 32)\n");
	printf("\t-d set ubertooth advertising data\n");
	printf("\t-o center frequency offset tracking\n");
	printf("\t-R RSSI tracking\n");
	printf("\t-S Rssi sampling synchronization mode\n");
	printf("\t-T BLE scanning duration\n");
	printf("\t-H BLE IoT connection HOST mode\n");
	printf("\t-G BLE IoT connection GUEST mode\n");

	printf("\nIf an input file is not specified, an Ubertooth device is used for live capture.\n");
	printf("In get/set mode no capture occurs.\n");
}

int main(int argc, char *argv[])
{
	//////
	int opt;
	int do_follow, do_promisc, do_cfo, do_rssi;
	int do_get_aa, do_set_aa;
	int do_crc;
	int do_adv_index;
	int do_slave_mode, do_data_mode, do_sync_mode;
	int do_host, do_guest;
	// JWHUR set advertising data
	uint8_t data[FILE_MAX];
	int duration; // ms
	int dlen;
	int do_target;
	enum jam_modes jam_mode = JAM_NONE;
	int ubertooth_device = -1;
	ubertooth_t* ut = (ubertooth_t*)malloc(sizeof(ubertooth_t));
	ut = ubertooth_init();

	btle_options cb_opts = { .allowed_access_address_errors = 32 };

	int r;
	u32 access_address;
	uint8_t mac_address[6] = { 0, };

	do_follow = do_promisc = 0;
	do_cfo = 0;
	do_rssi = 0;
	do_get_aa = do_set_aa = 0;
	do_crc = -1; // 0 and 1 mean set, 2 means get
	do_adv_index = 37;
	do_slave_mode = do_target = do_data_mode = do_sync_mode = 0;
	dlen = 0;
	duration = 20000;

	while ((opt=getopt(argc,argv,"a::r:hfoRpU:v::A:s:d:ST:l:t:x:H:G:c:o:q:jJiI")) != EOF) {
		switch(opt) {
			case 'a':
				if (optarg == NULL) {
					do_get_aa = 1;
				} else {
					do_set_aa = 1;
					sscanf(optarg, "%08x", &access_address);
				}
				break;
			case 'f':
				do_follow = 1;
				break;
			case 'o':
				do_cfo = 1;
				break;
			case 'R':
				do_rssi = 1;
				break;
			case 'p':
				do_promisc = 1;
				break;
			case 'U':
				ubertooth_device = atoi(optarg);
				break;
			case 'r':
				if (!ut->h_pcapng_le) {
					if (lell_pcapng_create_file(optarg, "Ubertooth", &ut->h_pcapng_le)) {
						err(1, "lell_pcapng_create_file: ");
					}
				}
				else {
					printf("Ignoring extra capture file: %s\n", optarg);
				}
				break;
			case 'q':
				if (!ut->h_pcap_le) {
					if (lell_pcap_create_file(optarg, &ut->h_pcap_le)) {
						err(1, "lell_pcap_create_file: ");
					}
				}
				else {
					printf("Ignoring extra capture file: %s\n", optarg);
				}
				break;
			case 'c':
				if (!ut->h_pcap_le) {
					if (lell_pcap_ppi_create_file(optarg, 0, &ut->h_pcap_le)) {
						err(1, "lell_pcap_ppi_create_file: ");
					}
				}
				else {
					printf("Ignoring extra capture file: %s\n", optarg);
				}
				break;
			case 'v':
				if (optarg)
					do_crc = atoi(optarg) ? 1 : 0;
				else
					do_crc = 2; // get
				break;
			case 'A':
				do_adv_index = atoi(optarg);
				if (do_adv_index < 37 || do_adv_index > 39) {
					printf("Error: advertising index must be 37, 38, or 39\n");
					usage();
					return 1;
				}
				break;
			case 's':
				do_slave_mode = 1;
				r = convert_mac_address(optarg, mac_address);
				if (!r) {
					usage();
					return 1;
				}
				break;
				//JWHUR set advertising data
			case 'd':
				dlen = convert_data(optarg, data);
				if (r == 0)
					return;
				do_data_mode = 1;
				break;
				//JWHUR rssi sampling synchronization mode
			case 'S':
				do_sync_mode = 1;
				break;
			case 'T':
				duration = (int) atoi(optarg);
				break;
			case 't':
				do_target = 1;
				r = convert_mac_address(optarg, mac_address);
				if (!r) {
					usage();
					return 1;
				}
				break;
			case 'x':
				cb_opts.allowed_access_address_errors = (unsigned) atoi(optarg);
				if (cb_opts.allowed_access_address_errors > 32) {
					printf("Error: can tolerate 0-32 access address bit errors\n");
					usage();
					return 1;
				}
				break;
				//JWHUR BLE IoT connection
			case 'H':
				do_host = 1;
				r = convert_mac_address(optarg, mac_address);
				if (!r) {
					usage();
					return 1;
				}
				break;
			case 'G':
				do_guest = 1;
				r = convert_mac_address(optarg, mac_address);
				if (!r) {
					usage();
					return 1;
				}
				break;
			case 'i':
			case 'j':
				jam_mode = JAM_ONCE;
				break;
			case 'I':
			case 'J':
				jam_mode = JAM_CONTINUOUS;
				break;
			case 'h':
			default:
				usage();
				return 1;
		}
	}


	r = ubertooth_connect(ut, ubertooth_device);
	if (r < 0) {
		usage();
		return 1;
	}

	r = ubertooth_check_api(ut);
	if (r < 0)
		return 1;

	/* Clean up on exit. */
	register_cleanup_handler(ut, 1);

	if (do_follow && do_promisc) {
		printf("Error: must choose either -f or -p, one or the other pal\n");
		return 1;
	}

	// JWHUR add do_cfo/ do_rssi
	if (do_follow || do_promisc || do_cfo || do_rssi) {
		usb_pkt_rx rx;

		r = cmd_set_jam_mode(ut->devh, jam_mode);
		if (jam_mode != JAM_NONE && r != 0) {
			printf("Jamming not supported\n");
			return 1;
		}
		cmd_set_modulation(ut->devh, MOD_BT_LOW_ENERGY);

		if (do_follow || do_cfo || do_rssi) {
			u16 channel;
			if (do_adv_index == 37)
				channel = 2402;
			else if (do_adv_index == 38)
				channel = 2426;
			else
				channel = 2480;
			cmd_set_channel(ut->devh, channel);
			if (do_follow) cmd_btle_sniffing(ut->devh, 2);
			if (do_cfo) cmd_btle_tracking(ut->devh, 2, 0); // cfo tracking == 0 flag
			if (do_rssi) cmd_btle_tracking(ut->devh, 2, 1); // rssi tracking == 1 flag
		} else {
			cmd_btle_promisc(ut->devh);
		}

		int sync = 0; //JWHUR test for synchronization
		struct timespec tspec;
		uint64_t sync_start, start = 0;

		clock_gettime(CLOCK_MONOTONIC, &tspec);
		start = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;

		while (1) {
			int r = cmd_poll(ut->devh, &rx);
			if (r < 0) {
				printf("USB error\n");
				break;
			}
			if (r == sizeof(usb_pkt_rx)) {
				fifo_push(ut->fifo, &rx);
				if(!do_rssi) sync = cb_btle(ut, &cb_opts);
				if(do_rssi == 0) {
					if (sync == 1) {
						clock_gettime(CLOCK_MONOTONIC, &tspec);
						sync_start = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
						do_rssi = 1;
						start = 0;
					}
				} else {
					if (start == 0) {
						clock_gettime(CLOCK_MONOTONIC, &tspec);
						start = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
					}
					cb_btle_tracking(ut, &cb_opts);
					printf("time measurement : ");
					int time_count = 4;
					while (--time_count) {
						int m = cmd_poll(ut->devh, &rx);
						if (m<0) {
							printf("USB error \n");
							break;
						}
						if (m == sizeof(usb_time_rx)) {
							fifo_push(ut->fifo, &rx);
							cb_btle_time(ut, &cb_opts);
						}
					}
					int m = cmd_poll(ut->devh, &rx);
					if (m<0) {
						printf("USB error \n");
						break;
					}
					if (m == sizeof(usb_time_rx)) {					
						fifo_push(ut->fifo, &rx);
						cb_btle_time_last(ut, &cb_opts);
					}
				}
				if (do_cfo) {
					int m = cmd_poll(ut->devh, &rx);
					if (m < 0) {
						printf("USB error \n");
						break;
					}
					if (m == sizeof(usb_pkt_rx)) {
						fifo_push(ut->fifo, &rx);
						cb_btle_tracking(ut, &cb_opts);
					}
				}
			}
			usleep(500);
			if (start != 0) {
				clock_gettime(CLOCK_MONOTONIC, &tspec);
				uint64_t now = (tspec.tv_sec) * 1000 + (tspec.tv_nsec)/1000000;
				if (do_rssi*(now - start) > 10000 || now - start > duration)
					break;
			}
		}
		ubertooth_stop(ut);
	}

	if (do_get_aa) {
		access_address = cmd_get_access_address(ut->devh);
		printf("Access address: %08x\n", access_address);
		return 0;
	}

	if (do_set_aa) {
		cmd_set_access_address(ut->devh, access_address);
		printf("access address set to: %08x\n", access_address);
	}

	if (do_crc >= 0) {
		int r;
		if (do_crc == 2) {
			r = cmd_get_crc_verify(ut->devh);
		} else {
			cmd_set_crc_verify(ut->devh, do_crc);
			r = do_crc;
		}
		printf("CRC: %sverify\n", r ? "" : "DO NOT ");
	}

	if (do_slave_mode) {
		u16 channel;
		if (do_adv_index == 37)
			channel = 2402;
		else if (do_adv_index == 38)
			channel = 2426;
		else
			channel = 2480;
		cmd_set_channel(ut->devh, channel);

		//JWHUR add advertising data
		uint8_t *tot_data = (uint8_t*) malloc(sizeof(uint8_t) * (dlen + 6));
		int i;
		for(i=0; i<6; i++) tot_data[i] = mac_address[i];
		if (do_data_mode) {
			for(i=6; i< (dlen + 6); i++) tot_data[i] = data[i-6];
			cmd_btle_slave(ut->devh, tot_data, UBERTOOTH_BTLE_SLAVE, dlen+6);
			//			usleep(500000);
			//			ubertooth_stop(ut);
		} else if (do_sync_mode) {	
			printf("\n%02x:%02x:%02x:%02x:%02x:%02x\n", mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5]);
			cmd_btle_slave(ut->devh, mac_address, UBERTOOTH_BTLE_SYNC, 6);
			struct timespec tspec;
			clock_gettime(CLOCK_MONOTONIC, &tspec);
			uint64_t sync_start = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;

			do_rssi = 1;
			uint64_t start = 0;

			usleep(250000);
			usb_pkt_rx rx;
			while (1) {
				int r = cmd_poll(ut->devh, &rx);
				if (r < 0) {
					printf("USB error\n");
					break;
				}
				if (r == sizeof(usb_pkt_rx)) {
					fifo_push(ut->fifo, &rx);
					if(do_rssi) {
						if (start == 0) {
							clock_gettime(CLOCK_MONOTONIC, &tspec);
							start = (tspec.tv_sec) * 1000 + (tspec.tv_nsec)/1000000;
						}
						cb_btle_tracking(ut, &cb_opts);
						printf("time measurement : ");
						int time_count = 4;
						while (--time_count) {
							int m = cmd_poll(ut->devh, &rx);
							if (m<0) {
								printf("USB error \n");
								break;
							}
							if (m == sizeof(usb_time_rx)) {
								fifo_push(ut->fifo, &rx);
								cb_btle_time(ut, &cb_opts);
							}
						}
						int m = cmd_poll(ut->devh, &rx);
						if (m<0) {
							printf("USB error \n");
							break;
						}
						if (m == sizeof(usb_time_rx)) {					
							fifo_push(ut->fifo, &rx);
							cb_btle_time_last(ut, &cb_opts);
						}
					}
				}
				if (do_rssi == 1 && start != 0) {
					clock_gettime(CLOCK_MONOTONIC, &tspec);
					uint64_t now = (tspec.tv_sec) * 1000 + (tspec.tv_nsec)/1000000;
					if (now - start > 10000)
						break;
				}		
				usleep(500);
			}
			ubertooth_stop(ut);

		} else 
			cmd_btle_slave(ut->devh, tot_data, UBERTOOTH_BTLE_SLAVE, dlen+6);
		free(tot_data);
	}

	if (do_target) {
		r = cmd_btle_set_target(ut->devh, mac_address);
		if (r == 0) {
			int i;
			printf("target set to: ");
			for (i = 0; i < 5; ++i)
				printf("%02x:", mac_address[i]);
			printf("%02x\n", mac_address[5]);
		}
	}

	if (do_host) {
		int status, txDur, rxDur, i, j, lenData, maxGuest = 10, nGuest=0;
		int time[50000] = {0, };
		int8_t rssi[50000] = {0, }, hostRssi0[100], hostRssi1[100], hostRssi2[100];
		uint8_t *rssiBitSeq;
		EC_KEY *privKey;
		unsigned char myPubKey[64];
		size_t *secretLen = (size_t *) malloc(sizeof(size_t));

		int nRecv = 0, encLen = 128; // 1024 RSA encryption key
		int minMMRGuest = 0;
		float mmrTemp = 1;
		float *MMR = (float *) malloc(sizeof(float)*maxGuest);
		char authMessage[22] = "You are authenticated!";
		unsigned char myMac[6], encMessage[32] = "";
		uint8_t **guestMac = (uint8_t **) malloc(sizeof(uint8_t *)*maxGuest);
		unsigned char **guestPubKey = (unsigned char **) malloc(sizeof(unsigned char *)*maxGuest);
		unsigned char **guestData = (unsigned char **) malloc(sizeof(unsigned char *)*maxGuest);
		int *statGuest = (int *) malloc(sizeof(int)*maxGuest); // status of received data from the guests, 0: never received, 1: incomplete, 2: complete
		unsigned char **guestBitSeq = (unsigned char **) malloc(sizeof(unsigned char *)*maxGuest);
		unsigned char **sharedSecret = (unsigned char **) malloc(sizeof(unsigned char *)*maxGuest);

		memset(statGuest, -1, sizeof(int)*maxGuest);
		memset(MMR, 1, sizeof(float)*maxGuest);

		struct timespec tspec;
		uint64_t start, now, elapsed;

		clock_gettime(CLOCK_MONOTONIC, &tspec);
		start = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;

		// Get AP information
		for(i=0; i<6; i++)
			myMac[i] = mac_address[i];

		// ECDH private, public key generation
		privKey = createECDH();
		status = getECPubKey(privKey, myPubKey);
/*		for (i=0; i<64; i++)
			printf("%02x ", myPubKey[i]);
		printf("\n"); */

		printf("********** Start Public Key Transmission **********\n");

		status = dataTx(myMac, myPubKey, 64, 1.5, ut, ubertooth_device);

		nGuest = scanGuest(myMac, guestMac, maxGuest, 1.5, ut, ubertooth_device);

		if (nGuest == 0) {
			printf("No guest!\n");
			clock_gettime(CLOCK_MONOTONIC, &tspec);
			now = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
			elapsed = now - start;
			printf("Elapsed time: %ld\n", elapsed);

			return 0;
		}

		printf("nGuest: %d\nguestMac:\n", nGuest);
		for(i=0; i<nGuest; i++) {
			for(j=0; j<6; j++) printf("%02x ", guestMac[i][j]);
			printf("\n");
			guestData[i] = (unsigned char *) malloc(sizeof(unsigned char)*encLen);		//Data buffer for first data
			guestPubKey[i] = (unsigned char *) malloc(sizeof(unsigned char)*64);
			statGuest[i] = 0;	// Status of data buffer
			guestBitSeq[i] = (uint8_t *) malloc(sizeof(uint8_t)*13);
			memset(guestBitSeq[i], 0, sizeof(uint8_t)*13);
			memset(guestPubKey[i], 0, sizeof(unsigned char)*64);
		}

		//status = startAPTx();

		lenData = syncStart(myMac, do_adv_index, ut, ubertooth_device, time, rssi);
//		printf("lenData: %d\n", lenData);
		rssiBitSeq = procData(time, rssi, lenData);

		printf("rssiBitSeq: ");
		for(i=0; i<13; i++)
			printf("%02x ", rssiBitSeq[i]);
		printf("\n");
		for(i=0; i<13; i++)
			printf("%d%d%d%d%d%d%d%d", rssiBitSeq[i] & 0x1, (rssiBitSeq[i] & 0x2) >> 1, (rssiBitSeq[i] & 0x4) >> 2, (rssiBitSeq[i] & 0x8) >>3, (rssiBitSeq[i] & 0x10) >> 4, (rssiBitSeq[i] & 0x20) >> 5, (rssiBitSeq[i] & 0x40) >> 6, (rssiBitSeq[i] & 0x80) >> 7);
		printf("\n");

		nRecv = listenData(guestMac, nGuest, statGuest, do_adv_index, guestPubKey, 3, ut, ubertooth_device);
		if (nRecv == 0) {
			printf("No guest public key received!\n");
			clock_gettime(CLOCK_MONOTONIC, &tspec);
			now = (tspec.tv_sec)*1000 + (tspec.tv_nsec)/1000000;
			elapsed = now - start;
			printf("Elapsed time: %ld\n", elapsed);
			return;
		}
		printf("guest public key nRecv: %d\n", nRecv);
		for(i=0; i<nGuest; i++) {
			if (statGuest[i] == 2) {
				printf("Guest: %d\n");
/*				for(j=0; j<64; j++)
					printf("%02x ", guestPubKey[i][j]);
				printf("\n"); */
				sharedSecret[i] = getSharedSecret(privKey, guestPubKey[i], secretLen);
				printf("Shared Secret: ");
				for(j=0; j<32; j++)
					printf("%02x ", sharedSecret[i][j]);
				printf("\n");
			} else {
				printf("Guest: %d\nNo PeerPubKey received!\n");
			}
		}

		memset(statGuest, 0, sizeof(statGuest));
		nRecv = listenData(guestMac, nGuest, statGuest, do_adv_index, guestData, 3, ut, ubertooth_device);

		printf("guest data nRecv: %d\n", nRecv);
		for(i=0; i<nGuest; i++) {
			if (statGuest[i] == 2) {
				printf("Guest: %d Data received\n");
/*				for(j=0; j<32; j++)
					printf("%02x ", guestData[i][j]);
				printf("\n");*/
				status = aesDecrypt(sharedSecret[i], guestData[i], guestBitSeq[i]);
				printf("guestRssiBitSeq: ");
				for(j=0; j<13; j++)
					printf("%02x ", guestBitSeq[i][j]);
				printf("\n");
				MMR[i] = getMMR(rssiBitSeq, guestBitSeq[i], 13);
				printf("MMR: %.2f\n", MMR[i]);
			} else {
				printf("Guest: %d\nNo guestData received!\n");
			}
		}

		for(i=0; i<nGuest; i++) {
			if (MMR[i] < mmrTemp) {
				minMMRGuest = i;
				mmrTemp = MMR[i];
			}
		}

		if (MMR[minMMRGuest] <= 1) {
			printf("minMMRGuest: %d\n", minMMRGuest);
			status = aesEncrypt(sharedSecret[minMMRGuest], (unsigned char *)authMessage, encMessage);
			status = dataTx(guestMac[minMMRGuest], encMessage, 32, 2, ut, ubertooth_device);
			printf("Secure channel established with device %d!\n", minMMRGuest);
		} else {
			printf("No guest authenticated!\n");
			return 0;
		}

		free(secretLen); free(MMR);
		for (i=0; i<nGuest; i++) {
			free(guestMac[i]);
			free(guestPubKey[i]);
			free(guestData[i]);
			free(sharedSecret[i]);
		}
		free(guestMac); free(guestPubKey);
		free(guestData); free(guestBitSeq);
		free(sharedSecret); free(statGuest);
	}

	if (do_guest) {
		int status, i, lenData, txDur, msgLen, keyLen = 0;
		int time[30000] = {0, };
		int8_t rssi[30000] = {0, };
		uint8_t *rssiBitSeq;
		uint8_t masterMac[6] = {0, }, guestMac[6] = {0, }; // Need Fix

		EC_KEY *privKey;
		unsigned char myPubKey[64], peerPubKey[64], encRssiBitSeq[100], encMessage[32], decMessage[32];
		unsigned char *sharedSecret;
		size_t *secretLen = (size_t *) malloc(sizeof(size_t));

		for(i=0; i<6; i++)
			guestMac[i] = mac_address[i];

		// Protocol 1, listen public key 
		if (status == 1)
			printf("Ubertooth init error!\n");

		// ECDH private, public key generation
		privKey = createECDH();
		status = getECPubKey(privKey, myPubKey);

		keyLen = listenPubkey(masterMac, do_adv_index, peerPubKey, 5, ut, ubertooth_device);

		// Protocol 2, if public key received, advertise myself 
		if (keyLen > 0) {
/*			printf("peerPubKey: ");
			for(i=0; i<64; i++) {
				printf("%02x", peerPubKey[i]);
			}
			printf("\n");*/

			printf("Authenticator MAC address: ");
			for(i=0; i<6; i++)
				printf("%02x ", masterMac[i]);
			printf("\n");

			printf("********** Start Guest Mac Address Advertising **********\n");
			status = dataTx(guestMac, masterMac, 6, 1.5, ut, ubertooth_device);
		} else {
			printf("No public key received!\n");
			return 0;
		}

		// Protocol 3, after advertising, wait for the synchronizaton packet, and moving average filter the samples 
		lenData = listenSync(masterMac, do_adv_index, ut, ubertooth_device, time, rssi);

		if (lenData == 0) {
			printf("No synchronization packet received!\n");
			return 0;
		}

		printf("lenData: %d\n", lenData);
		rssiBitSeq = procData(time, rssi, lenData);

		printf("rssiBitSeq: ");
		for(i=0; i<13; i++)
			printf("%02x ", rssiBitSeq[i]);
		printf("\n");
		for(i=0; i<13; i++)
			printf("%d%d%d%d%d%d%d%d", rssiBitSeq[i] & 0x1, (rssiBitSeq[i] & 0x2) >> 1, (rssiBitSeq[i] & 0x4) >> 2, (rssiBitSeq[i] & 0x8) >>3, (rssiBitSeq[i] & 0x10) >> 4, (rssiBitSeq[i] & 0x20) >> 5, (rssiBitSeq[i] & 0x40) >> 6, (rssiBitSeq[i] & 0x80) >> 7);
		printf("\n");

		status = dataTx(guestMac, myPubKey, 64, 3, ut, ubertooth_device); 
		sharedSecret = getSharedSecret(privKey, peerPubKey, secretLen);

		printf("shared Secret: ");
		for (i=0; i<32; i++)
			printf("%02x ", sharedSecret[i]);
		printf("\n");

		status = aesEncrypt(sharedSecret, rssiBitSeq, encRssiBitSeq);
/*		printf("encRssiBitSeq: ");
		for(i=0; i<32; i++)
			printf("%02x ", encRssiBitSeq[i]);
		printf("\n");*/

		status = dataTx(guestMac, encRssiBitSeq, 32, 3, ut, ubertooth_device);
		msgLen = listenMessage(masterMac, guestMac, do_adv_index, encMessage, 10, ut, ubertooth_device);

		if (msgLen == 32) {
/*			printf("encMessage: ");
			for (i=0; i<msgLen; i++) 
				printf("%02x ", encMessage[i]);
			printf("\n"); */
			status = aesDecrypt(sharedSecret, encMessage, decMessage);
			printf("Decrypted Message: ");

			for (i=0; i<strlen(decMessage); i++) {
				printf("%c", (char)decMessage[i]);
			}
			printf("\n");

			printf("Secure channel established!\n");
		} else {
			printf("Can not establish secure channel!\n");
		}


		free(secretLen);
	}

	if (!(do_follow || do_promisc || do_get_aa || do_set_aa ||
				do_crc >= 0 || do_slave_mode || do_target || do_host || do_guest))
		usage();

	return 0;
}
