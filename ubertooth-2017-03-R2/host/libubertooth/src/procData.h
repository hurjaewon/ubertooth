#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

float kMeans_clustering(int8_t *rssi, int *cls1, int *cls2, int lenData, float *mu);
float kMeans(int8_t *rssi, int lenData);
float avg(int8_t *seq, int start, int end);
int max(int a, int b);
int min(int a, int b);
int bitSeqGen(int8_t *rssiMA, uint8_t *rssiBitSeq);
int maFilter(int *myTime, int8_t *myRssi, int nMySignal, int8_t *rssiMA);
int signalDetect(int *time, int8_t *rssi, int *sTime, int8_t *sRssi, int lenData, float threshold, char *oFile);
int mySignalDetect(int *sTime, int8_t *sRssi, int *myTime, int8_t *myRssi, int lenData);
int makeBarcode(int *eTime, int *eRssi, int nEdge, int *Barcode, char *oFile);
int getData(char *tFile, char*rFile, int *time, int *rssi);
int8_t *procData(int *rTime, int8_t *rssi, int lenData);
int getAPInfo(char *APMAC, char *APSSID, char *APPWD);
int startAPTx();
int getBCHdata(char *APMAC, uint8_t *data);
float getCorr(int8_t *rssi0, int8_t *rssi1, int lenData);
