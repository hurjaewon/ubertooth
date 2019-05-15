#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdint.h>

#include "procData.h"

#define FLT_MAX 3.402823466e+38F

float kMeans_clustering(int8_t *rssi, int *cls1, int *cls2, int lenData, float *mu) {
	float threshold = 0, cost = 0;
	int i, nCls1 = 0, nCls2 = 0, sumCls1 = 0, sumCls2 = 0;
	threshold = (mu[0] + mu[1]) / 2;

	for(i=0; i<lenData; i++) {
		if (rssi[i] < threshold) {
			cls1[nCls1] = rssi[i];
			sumCls1 += rssi[i];
			cost += abs(rssi[i] - mu[0]);
			nCls1++;
		} else {
			cls2[nCls2] = rssi[i];
			sumCls2 += rssi[i];
			cost += abs(rssi[i] - mu[1]);
			nCls2++;
		}
	}

	if (nCls1 != 0)
		mu[0] = (float) sumCls1/nCls1;
	else
		mu[0] = mu[1] - 1;
	if (nCls2 != 0)
		mu[1] = (float) sumCls2/nCls2;
	else
		mu[1] = mu[0] + 1;

	return cost;
}

float kMeans(int8_t *rssi, int lenData) {
	int i, max_iter = 100, min_iter = 50;
	int *cls1, *cls2;
	float *mu;
	float cost = FLT_MAX, fcost = FLT_MAX, threshold;

	cls1 = malloc(sizeof(int)*lenData);
	cls2 = malloc(sizeof(int)*lenData);
	mu = malloc(sizeof(float)*2);

	//random initialization of mu
	mu[0] = 0;
	for (i=0; i<lenData; i++)
		mu[0] += rssi[i];
	mu[0] /= lenData;
	mu[1] = mu[0] + 1;
	//
	
	for(i=0; i<max_iter; i++) {
		fcost = kMeans_clustering(rssi, cls1, cls2, lenData, mu);
		cost = fcost;
	}
	threshold = (mu[0] + mu[1])/2;

	free(cls1); free(cls2); free(mu);

	if (threshold > -80)
		return threshold;
	else 
		return -80;
}

int maFilter(int *myTime, int8_t *myRssi, int nMySignal, int8_t *rssiMA) {
	// Moving average filtering
	FILE *output;
	int i, j, index;
	float *Samples = malloc(sizeof(float)*500);
	float *nSample = malloc(sizeof(float)*500);
	
	memset(rssiMA, 0, sizeof(int8_t)*500);
	memset(Samples, 0, sizeof(float)*500);
	memset(nSample, 0, sizeof(float)*500);

	// Make a 10 ms  moving averaged samples of 3 seconds, which equals 300 bytes
	for (i=0; i<nMySignal; i++) {
		if (myTime[i] < 5000e4) {
			index = myTime[i] / 10e4;
			Samples[index] += myRssi[i];
			nSample[index]++;
		}
	}

	for (i=0; i<500; i++) {
		if (nSample[i] == 0) {
			j=i-1;
			while (j>=0) {
				if (nSample[j] != 0) {
					rssiMA[i] = Samples[j] / nSample[j];
					break;
				}
				j--;
			}
		} else {
			rssiMA[i] = Samples[i] / nSample[i];
		}
	}

	if (nSample[0] == 0) {
		i = 1;
		while(i<500) {
			if (nSample[i] != 0) {
				rssiMA[0] = rssiMA[i];
				break;
			}
			i++;
		}
	}

	// Save Moving averaged data to rssiMA.dat
/*	output = fopen("rssiMA.dat", "w");
	if (output == NULL)	{
		printf("open failed\n");
		return 0;
	}

	for(i=0; i<1000; i++) {
		fprintf(output, "%d\n", rssiMA[i]);
	}
	fclose(output);	
*/
	free(nSample); free(Samples); 
	return 1;
}

int signalDetect(int *time, int8_t *rssi, int *sTime, int8_t *sRssi, int lenData, float threshold, char *oFile) {
	//Detect the peak of rssi samples
	int i, j = 0;
	int nSignal = 0;
	FILE *output;

	for (i=1; i<lenData; i++) {
		if (rssi[i] >= threshold) {
			sRssi[nSignal] = rssi[i];
			sTime[nSignal] = time[i];
			nSignal++;
		}
	}

	output = fopen(oFile, "w");
	if (output == NULL) {
		printf("open failed\n");
		return 0;
	}
	for(i=0; i<nSignal; i++)
		fprintf(output, "%d %d\n", sTime[i], sRssi[i]);
	fclose(output);

	return nSignal;
}

int mySignalDetect(int *sTime, int8_t *sRssi, int *myTime, int8_t *myRssi, int lenData) {
	int i, j;
	int nMySignal = 0;
	int meanRssi = 0, stdRssi = 0, rDiff;

	for(i=0; i<lenData; i++)
		meanRssi += sRssi[i];
	meanRssi /= lenData;

	for(i=0; i<lenData; i++)
		stdRssi += (sRssi[i] - meanRssi) * (sRssi[i] - meanRssi);
	stdRssi /= lenData;
	stdRssi = sqrt(stdRssi);

	printf("meanRssi: %d, stdRssi: %d\n", meanRssi, stdRssi);

	for(i=0; i<lenData; i++) {
		rDiff = sRssi[i] - meanRssi;
		if (rDiff > -stdRssi && rDiff < stdRssi) {
			myTime[nMySignal] = sTime[i];
			myRssi[nMySignal] = sRssi[i];
			nMySignal++;
		}
	}

	return nMySignal;
}

int makeBarcode(int *eTime, int *eRssi, int nEdge, int *Barcode, char *oFile) {
	FILE *output;
	int i, j;
	int index;

	for (i=0; i<nEdge; i++) {
		if (eTime[i] < 1e6) {
			index = eTime[i]/1e4;
			Barcode[index] = 1;
		}
	}

	output = fopen(oFile, "w");
	if (output == NULL) {
		printf("open failed\n");
		return 0;
	}
	for (i=0; i<127; i++)
		fprintf(output, "%d\n", Barcode[i]);

	return 1;
}

int getData(char *tFile, char*rFile, int *time, int *rssi) {
	FILE *input, *output;
	int i, j, t, lenData = -1;
	int time0 = 0;

	input = fopen(tFile, "r");
	if (input == NULL) {
		printf("open failed\n");
		return 0;
	}

	while(fgetc(input) != EOF) {
		lenData++;
		fscanf(input, "%d", &t);
	}
	fseek(input, 0, SEEK_SET);

	for(i=0; i<lenData; i++) {
		fscanf(input, "%d", &t);
		time[i] = t;
		if (i == 0)
			time0 = time[0];
		time[i] -= time0;
	}

	fclose(input);
	output = fopen(tFile, "w");
	if (output == NULL) {
		printf("open failed\n");
	}

	for(i=0; i<lenData; i++) {
		fprintf(output, "%d\n", time[i]);
	}
	fclose(output);

	input = fopen(rFile, "r");
	if (input == NULL) {
		printf("open failed\n");
	}

	for(i=0; i<lenData; i++) {
		fscanf(input, "%d", &t);
		rssi[i] = t;
	}
	fclose(input);

	return lenData;
}

int8_t *procData(int *rTime, int8_t *rssi, int lenData) {
	int nSignal, nMySignal, nDiff = 0, i;
	float thr;
	srand(time(NULL));

	int temp = rTime[0];
	for(i=0; i<lenData; i++) {
		rTime[i] =rTime[i] - temp;
	}

	thr = kMeans(rssi, lenData);

	int8_t *sRssi = malloc(sizeof(int8_t)*lenData);
	int *sTime = malloc(sizeof(int)*lenData);
	nSignal = signalDetect(rTime, rssi, sTime, sRssi, lenData, -82,"signal.dat");

	int8_t *myRssi = (int8_t *)malloc(sizeof(int8_t)*nSignal);
	int *myTime = (int *)malloc(sizeof(int)*nSignal);
	nMySignal = mySignalDetect(sTime, sRssi, myTime, myRssi, nSignal);
	
	int8_t *rssiMA = malloc(sizeof(int8_t) * 500);
	int status = maFilter(myTime, myRssi, nMySignal, rssiMA);

	free(sRssi); free(sTime);
	free(myRssi); free(myTime);
	return rssiMA;
}

int getAPInfo(char *APMAC, char *APSSID, char *APPWD) {
	char line[10]="";
	char apssid[100] = "", appwd[100] = "", apmac[100] = "";
	int i, len;
	FILE *apSSID = popen("nm-tool | grep '*' > ap; conAP=$(sed -n '2p' < ap); APtemp=$(echo $conAP | awk '{print $1}'); APSSID=${APtemp#'*'}; APSSID=${APSSID%':'}; echo $APSSID; rm ap", "r");
	if(apSSID != NULL) {
		while(fgets(line, sizeof(10), apSSID) != NULL)
			strcat(apssid, line);
	}

	len = strlen(apssid);
	for(i=0; i<len-1; i++)
		APSSID[i] = apssid[i];

	char command[500] = "PWDtemp=$(sudo cat /etc/NetworkManager/system-connections/";
	strcat(command, APSSID);
	strcat(command, " | grep psk=); pwd=${PWDtemp#'psk='}; echo $pwd");
	FILE *apPWD = popen(command, "r");
	if(apPWD != NULL) {
		while(fgets(line, sizeof(10), apPWD) != NULL)
			strcat(appwd, line);
	}

	len = strlen(appwd);
	for(i=0; i<len-1; i++)
		APPWD[i] = appwd[i];

	char command1[500] = "MACtemp=$(sudo cat /etc/NetworkManager/system-connections/";
	strcat(command1, APSSID);
	strcat(command1, " | grep mac-address=); MAC=${MACtemp#'mac-address='}; echo $MAC");
	FILE *apMAC = popen(command1, "r");
	if(apMAC != NULL) {
		while(fgets(line, sizeof(10), apMAC) != NULL)
			strcat(apmac, line);
	}

	len = strlen(apmac);
	for(i=0; i<len-1; i++)
		APMAC[i] = apmac[i];

	pclose(apSSID); pclose(apPWD); pclose(apMAC);
}

int startAPTx() {
	system("nohup ssh mwnl@192.168.1.218 'iperf -c 224.0.0.5 -u -b 1000M -t 10' > foo.out 2> foo.err < /dev/null &");
	system("rm foo.err; rm foo.out");
	return 0;
}
	

int getBCHdata(char *APMAC, uint8_t *data) {
	FILE *dataFile;
	int status, len, i;
	char dd[300] = "", line[10], command[200] = "cat log | grep '", blePrefix[120] = "Data:  ", bleMac[100];
	uint8_t APMAC2Byte[6];

	if(strlen(APMAC) != 6*2+5) {
		printf("Error: MAC address is wrong length\n");
		return 0;
	}

	for (i = 0; i < 6*3; i += 3) {
		if (!isxdigit(APMAC[i]) ||
			!isxdigit(APMAC[i+1])) {
			printf("Error: MAC address contains invalid character(s)\n");
			return 0;
		}
		if (i < 5*3 && APMAC[i+2] != ':') {
			printf("Error: MAC address contains invalid character(s)\n");
			return 0;
		}
	}

	// sanity: checked; convert
	for (i = 0; i < 6; ++i) {
		unsigned byte;
		sscanf(&APMAC[i*3], "%02x",&byte);
		APMAC2Byte[i] = byte;
	}

	sprintf(bleMac, "%02x %02x %02x %02x %02x %02x", APMAC2Byte[5], APMAC2Byte[4], APMAC2Byte[3], APMAC2Byte[2], APMAC2Byte[1], APMAC2Byte[0]);
	printf("bleMac: %s\n", bleMac);

	strcat(blePrefix, bleMac);
	strcat(command, blePrefix);
	strcat(command, "'");
	dataFile = popen(command, "r");
	if(dataFile != NULL) {
		while(fgets(line, sizeof(10), dataFile) != NULL)
			strcat(dd, line);
		printf("%s", dd);
	}
	len = strlen(dd);
	for(i=0; i<len-62; i+=3) {
		unsigned byte;
		sscanf(&dd[62 + i], "%02x", &byte);
		data[i/3] = (uint8_t)byte; 
	}
	return 1;
}

float getCorr(int8_t *rssi0, int8_t *rssi1, int lenData) {
	int i;
	float norm0 = 0, norm1 = 0, corr = 0;
	float avg0 = 0, avg1 = 0;

	for(i=0; i<lenData; i++) {
		avg0 += (float) rssi0[i];
		avg1 += (float) rssi1[i];
	}
	avg0 /= (float)lenData;
	avg1 /= (float)lenData;

	for(i=0; i<lenData; i++) {
		corr += ((float)rssi0[i] - avg0) * ((float)rssi1[i] - avg1);
		norm0 += ((float)rssi0[i] - avg0) * ((float)rssi0[i] - avg0);
		norm1 += ((float)rssi1[i] - avg1) * ((float)rssi1[i] - avg1);
	}
	norm0 = sqrt(norm0);
	norm1 = sqrt(norm1);
	corr /= norm0 * norm1;

	return corr;
}

	

