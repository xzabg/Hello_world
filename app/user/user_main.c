/*
 * ESPRSSIF MIT License
 *
 * add a line here for testing
 *
 * Copyright (c) 2015 <ESPRESSIF SYSTEMS (SHANGHAI) PTE LTD>
 *
 * Permission is hereby granted for use on ESPRESSIF SYSTEMS ESP8266 only, in which case,
 * it is free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include "esp_common.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

//#include "lwip/multi-threads/sockets_mt.h"
#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"

#include "pthread.h"
#include "string.h"
#include "uart.h"
#include "gpio.h"
#include "udp.h"
#include "key.h"

//#include "user_config.h"
#include "user_iot_version.h"
#include "user_esp_platform.h"

//#include "espressif/esp8266/ets_sys.h"
//#include "osapi.h"
//#include "mem.h"
//#include "espconn.h"
//#include "espressif/esp8266/gpio_register.h"

#define AP_SSID     "LV_AP"
#define AP_PASSWORD "12345678"

#define DST_AP_SSID     "zhaofengkeji"//"lamost-701"//"@PHICOMM"//"TP-LINK_6D3E"//"USR-WIFI"//
#define DST_AP_PASSWORD "88888888"//"lamostee701"//"wifiwifi"//"12345678"//

#define UDP_STRING		"HF-A11ASSISTHREAD"

#define REMOTE_IP		"101.201.211.87"//"192.168.0.107"//"10.10.100.104"//

#define UDP_LOCAL_PORT  48899
#define SERVER_PORT     8899
#define REMOTE_PORT		8080
#define DATA_LEN        128
#define MAX_CONN		10

#define ORDER_LEN	24
#define ORDER_NUM	30
#define MODE_NUM	20
#define SPI_FLASH_SEC_SIZE  4096
#define SPI_FLASH_START		0x7C

//#define DEBUG

typedef int32 SOCKET;
typedef struct __pthread_t {char __dummy;} *pthread_t;

/* Local functions */
//void scan_done(void *arg, STATUS status);
void TCPClient(void *pvParameters);
void UDPServer(void *pvParameters);
void TCPServer(void *pvParameters);
void UartProcess(void *pvParameters);
void WaitClient(void *pvParameters);
void RecvData(void *pvParameters);
void ProcessData(void *pvParameters);
void Sendorder(void *pvParameters);
void long_press(void);
void short_press(void);
void wifi_handle_event_cb(System_Event_t *evt);

/* Local variable */
//static struct sockaddr_in remote_addr;
//static SOCKET listenfd;
//static SOCKET client_sock = 0;
static SOCKET client_conn[MAX_CONN];
static SOCKET sta_socket;
//static int32 len;
static int client_num=0;
static uint8 ctrlid[9]={0};
//static fd_set fdread;
char test_mode = 2;
uint8 modectl[MODE_NUM];

/******************************************************************************
 * FunctionName : user_rf_cal_sector_set
 * Description  : SDK just reversed 4 sectors, used for rf init data and paramters.
 *                We add this function to force users to set rf cal sector, since
 *                we don't know which sector is free in user's application.
 *                sector map for last several sectors : ABCCC
 *                A : rf cal
 *                B : rf init data
 *                C : sdk parameters
 * Parameters   : none
 * Returns      : rf cal sector
 *******************************************************************************/
uint32 user_rf_cal_sector_set(void) {
	flash_size_map size_map = system_get_flash_size_map();
	uint32 rf_cal_sec = 0;

	switch (size_map) {
	case FLASH_SIZE_4M_MAP_256_256:
		rf_cal_sec = 128 - 5;
		break;

	case FLASH_SIZE_8M_MAP_512_512:
		rf_cal_sec = 256 - 5;
		break;

	case FLASH_SIZE_16M_MAP_512_512:
	case FLASH_SIZE_16M_MAP_1024_1024:
		rf_cal_sec = 512 - 5;
		break;

	case FLASH_SIZE_32M_MAP_512_512:
	case FLASH_SIZE_32M_MAP_1024_1024:
		rf_cal_sec = 1024 - 5;
		break;

	default:
		rf_cal_sec = 0;
		break;
	}

	return rf_cal_sec;
}

/******************************************************************************
 * FunctionName : user_init
 * Description  : entry of user application, init user function here
 * Parameters   : none
 * Returns      : none
 *******************************************************************************/
void user_init(void) {
	uint8 *buff=(uint8*)zalloc(64);
	uint8 len1,len2;

	LOCAL struct keys_param keys;//=(struct keys_param*)zalloc(sizeof(struct keys_param));
	LOCAL struct single_key_param *key;//=(struct single_key_param*)zalloc(sizeof(struct single_key_param));

	key = key_init_single(GPIO_ID_PIN(2), GPIO_PIN_REG_2, FUNC_GPIO2, long_press, short_press);
	keys.single_key = &key;
	keys.key_num=1;
	key_init(&keys);

	uart_init_new();
	// todo: add user��s own code here....
	wifi_set_event_handler_cb(wifi_handle_event_cb);

	GPIO_AS_OUTPUT(GPIO_Pin_4);
	GPIO_OUTPUT(GPIO_Pin_4, 1);		        //outout 1 link turn off

	GPIO_AS_OUTPUT(GPIO_Pin_5);
	GPIO_OUTPUT(GPIO_Pin_5, 0);		        //outout 2 ready turn on
	printf("SDK version:%s\n", "V1.0.5");
	
	//printf("SDK version:%s,%u\n", system_get_sdk_version(),__LINE__ );
    //wifi_set_opmode(STATIONAP_MODE);
    
#if ESP_PLATFORM
    /*Initialization of the peripheral drivers*/
    /*For light demo , it is user_light_init();*/
    /* Also check whether assigned ip addr by the router.If so, connect to ESP-server  */
    //user_esp_platform_init();
    spi_flash_read((SPI_FLASH_START + 2) * SPI_FLASH_SEC_SIZE, (uint32*)buff, 40);
    user_esp_platform_set_token((uint8*)buff);
    //printf("esp_param.tokenrdy:%d",esp_param.tokenrdy);
#endif

	/* Set the device to be STA mode */
			/*wifi_set_opmode(STATION_MODE);
			struct station_config *config = (struct station_config *) zalloc(
					sizeof(struct station_config));
			sprintf(config->ssid, DST_AP_SSID);
			sprintf(config->password, DST_AP_PASSWORD);
			//len1=strcspn(buff+2,",");
			//memcpy(config1->ssid, buff+2,len1);
			//len2=strcspn(buff+len1+3,">");
			//memcpy(config1->password, buff+len1+3, len2);
			wifi_station_set_config(config);
			free(config);
			wifi_station_connect();//*/

	spi_flash_read((SPI_FLASH_START - MODE_NUM - 1) * SPI_FLASH_SEC_SIZE, (uint32*)buff, 64);
	//buff[0]='o';
#ifdef DEBUG
	printf(buff);
#endif

	if(buff[0]=='<'){
		// Set the device to be STA mode
		wifi_set_opmode(STATION_MODE);
		struct station_config *config1 = (struct station_config *) zalloc(
				sizeof(struct station_config));
		//sprintf(config->ssid, DST_AP_SSID);
		//sprintf(config->password, DST_AP_PASSWORD);
		len1=strcspn(buff+2,",");
		memcpy(config1->ssid, buff+2,len1);
		len2=strcspn(buff+len1+3,">");
		memcpy(config1->password, buff+len1+3, len2);
		wifi_station_set_config(config1);
		free(config1);
		wifi_station_connect();
#ifdef DEBUG
		printf("ssid:%s\n",config1->ssid);
		printf("password:%s\n", config1->password);
#endif
	}
	else{
		// Set the device to be AP mode
		 printf("\nAP mode\n");
		 wifi_set_opmode(SOFTAP_MODE);
		 struct softap_config *config2 = (struct softap_config *)zalloc(sizeof(struct softap_config)); // initialization
		 wifi_softap_get_config(config2);           // Get soft-AP config first.
		 sprintf(config2->ssid, AP_SSID);
		 sprintf(config2->password, AP_PASSWORD);
		 config2->authmode = AUTH_WPA_WPA2_PSK;
		 config2->ssid_len = 0;                     // or its actual SSID length
		 config2->max_connection = 4;
		 wifi_softap_set_config(config2);           // Set ESP8266 soft-AP config
		 free(config2);
	}//*/
	free(buff);
	/* Print the message of the station connected to this AP */
	/*struct station_info* station = wifi_softap_get_station_info();
	 while(station){
	 printf("bssid : MACSTR, ip : IPSTR/n",MAC2STR(station->bssid), IP2STR(&station->ip));
	 station = STAILQ_NEXT(station, next);
	 }
	 wifi_softap_free_station_info();//*/ // Free it by calling functions
	/* Scan the AP nearby */
	//wifi_set_opmode(STATIONAP_MODE);
	//wifi_station_scan(NULL,scan_done);
	 //websocket_start(&test_mode);
	 xTaskCreate(UDPServer, "tsk2", 256, NULL, 2, NULL);
	 xTaskCreate(TCPServer, "tsk3", 256, NULL, 2, NULL);
	 xTaskCreate(UartProcess, "tsk4", 512, NULL, 2, NULL);
	 //xTaskCreate(TCPClient, "tsk1", 256, NULL, 2, NULL);
	 //printf("<00000000U0**********FF>");
	 //websocket_start(&test_mode);
}

/*void scan_done(void *arg, STATUS status)
 {
 uint8 ssid[33];
 char temp[128];
 if (status == OK){
 struct bss_info *bss_link = (struct bss_info *)arg;
 while (bss_link != NULL)
 {
 memset(ssid, 0, 33);
 if (strlen(bss_link->ssid) <= 32)
 memcpy(ssid, bss_link->ssid, strlen(bss_link->ssid));
 else
 memcpy(ssid, bss_link->ssid, 32);
 printf("(%d,\"%s\",%d,\""MACSTR"\",%d)\r\n",bss_link->authmode, ssid, bss_link->rssi,MAC2STR(bss_link->bssid),bss_link->channel);
 bss_link = bss_link->next.stqe_next;
 }
 }
 else{
 printf("scan fail !!!\r\n");
 }
 }*/
/* Create a TCP client connected to remote server to send the eletricstate and get order */
void TCPClient(void *pvParameters){
	int ret;
	uint8 recvbytes;
	char *pbuf,*recv_buf,*p;
	struct sockaddr_in remote_ip;
	xTaskHandle ProDataHandle;

	bzero(&remote_ip, sizeof(remote_ip));
	remote_ip.sin_family = AF_INET; /* Internet address family */
	remote_ip.sin_addr.s_addr = inet_addr(REMOTE_IP); /* Any incoming interface */
	remote_ip.sin_len = sizeof(remote_ip);
	remote_ip.sin_port = htons(REMOTE_PORT); /* Remote server port */

	while(1){
		/* Create socket*/
		sta_socket = socket(PF_INET, SOCK_STREAM, 0);
		if(sta_socket == -1){
			close(sta_socket);
			vTaskDelay(1000 / portTICK_RATE_MS);
			continue;
#ifdef DEBUG
			printf("ESP8266 TCP client task > socket error\n");
#endif
		}
#ifdef DEBUG
		printf("ESP8266 TCP client task > socket success!\n");
#endif

		/* Connect to remote server*/
		ret = connect(sta_socket, (struct sockaddr *)(&remote_ip), sizeof(struct sockaddr));
		if(0 != ret){
			close(sta_socket);
			vTaskDelay(1000 / portTICK_RATE_MS);
			continue;
#ifdef DEBUG
			printf("ESP8266 TCP client task > connect fail!\n");
#endif
		}
#ifdef DEBUG
		printf("ESP8266 TCP client task > connect ok!\n");
#endif

		xTaskCreate(ProcessData, "ProcessData", 512, &sta_socket, 2, &ProDataHandle);
	while(1){
		if(!ctrlid[0])
		{
			printf("<00000000U00000000000FF>");
			vTaskDelay(1000 / portTICK_RATE_MS);
			continue;
		}
		/* send get command to remote server */
		pbuf = (char*)zalloc(100);
		//printf("allocate pbuf success\n");
		sprintf(pbuf, "GET /zfzn02/servlet/ElectricOrderServlet?masterCode=%s HTTP/1.1\r\n", ctrlid);
		write(sta_socket, pbuf, strlen(pbuf));
		write(sta_socket, "Connection:keep-alive\r\n", strlen("Connection:keep-alive\r\n"));
		write(sta_socket, "User-Agent:lwip1.3.2\r\n", strlen("User-Agent:lwip1.3.2\r\n"));
		write(sta_socket, "Host:101.201.211.87:8080\r\n", strlen("Host:101.201.211.87:8080\r\n"));
		if(write(sta_socket, "\r\n", 2) < 0){
#ifdef DEBUG
			printf("ESP8266 TCP client task > send fail!\n");
#endif
			close(sta_socket);
//			free(pbuf);
//			vTaskDelay(2000 / portTICK_RATE_MS);
//			vTaskDelete(ProDataHandle);
			free(pbuf);
			break;
		}
		free(pbuf);
		vTaskDelay(2000 / portTICK_RATE_MS);
#ifdef DEBUG
		printf("ESP8266 TCP client task > send success!\n");
#endif

	}//send get order
	}
	vTaskDelete(NULL);
}
/* Process the uart data, send to remote server through TCP client, send to user through TCP server*/
void UartProcess(void *pvParameters) {
	/* send the data to tcp client if the rxbuf is not empty */
	//printf("Welcome to send uart data task!\n");

	//send a order to get mastercode
	printf("<00000000U00000000000FF>");

	uint8 i,orderidx;
	uint8 order[ORDER_NUM][ORDER_LEN],buff[100]={0};
	int32 len;
	SOCKET client_sock;
	while (1) {
		//printf("ready uart data:stringlen=%d\n",stringlen);
		if (stringlen) {
#ifdef DEBUG
			printf("send uart data:stringlen=%d\n",stringlen);
			if(rxbuf != NULL)
				printf(rxbuf);
#endif
			if(rxbuf[0] == '#' && rxbuf[9] == 'U'){
				memcpy(ctrlid, rxbuf+1, 8);
			}
			if(rxbuf[0] == '<' && rxbuf[2] == 'A'){//if the message comes from modectrl do the next procedure
				orderidx = rxbuf[10]-'0';
				if(orderidx >= 0 && orderidx < MODE_NUM){
					xTaskCreate(Sendorder, "Sendorder", 512, &orderidx, 2, NULL);
					//order = (uint8**)zalloc(ORDER_NUM * ORDER_LEN);
					//free(order);
				}
			}
			if(rxbuf[0] == '<' && rxbuf[2] == 'D'){
				spi_flash_read((SPI_FLASH_START - MODE_NUM) * SPI_FLASH_SEC_SIZE, (uint32*)order, ORDER_NUM * ORDER_LEN);
				for(i = 0; order[i][0] == '<' && i < ORDER_NUM; i++)
					if(!memcmp(rxbuf, order[i], 9))
						break;
				if(i < ORDER_NUM){
					orderidx = order[i][13]-'0';
					if(orderidx >= 0 && orderidx < MODE_NUM && order[i][10] == 'H')
						xTaskCreate(Sendorder, "Sendorder", 512, &orderidx, 2, NULL);
				}
			}
			for(i=0; i < client_num; i++){
				client_sock = client_conn[i];
				if (client_sock && (rxbuf != NULL)) {
					//sendto(client_sock, rxbuf, stringlen, 0,(struct sockaddr * )&remote_addr, (socklen_t )len);
					send(client_sock, rxbuf, stringlen, 0);
				}
			}
			if(rxbuf[0] == '<' && sta_socket != -1){
				rxbuf[13] = '\0';//upload 10 bytes info may be not supported,upload 2 bytes anyway
				sprintf(buff,"POST /zfzn02/servlet/ElectricStateServlet?electricState=<%s%s> HTTP/1.1\r\n", ctrlid, rxbuf+1);
				write(sta_socket, buff, strlen(buff));
				//write(sta_socket, "POST /zfzn02/servlet/ElectricStateServlet?electricState=<AA00FF620200E58DZ200> HTTP/1.1\r\n",
					//	strlen("POST /zfzn02/servlet/ElectricStateServlet?electricState=<AA00FF620200E58DZ200> HTTP/1.1\r\n"));
				write(sta_socket, "Connection:keep-alive\r\n", strlen("Connection:keep-alive\r\n"));
				write(sta_socket, "User-Agent:lwip1.3.2\r\n", strlen("User-Agent:lwip1.3.2\r\n"));
				write(sta_socket, "Host:101.201.211.87:8080\r\n", strlen("Host:101.201.211.87:8080\r\n"));
				write(sta_socket, "\r\n", 2);
			}
			//memset(rxbuf, 0, 100);
			memset(rxbuf, 0, 100);
			stringlen = 0;
		}
		vTaskDelay(100 / portTICK_RATE_MS);
	}
	vTaskDelete(NULL);
}
/* Create a UDP server for application to search the ip address and MAC address */
void UDPServer(void *pvParameters) {
	LOCAL uint32 sock_fd;
	struct sockaddr_in server_addr, from;
	struct ip_info info;
	int ret, nNetTimeout;
	char *udp_msg = (char *) zalloc(DATA_LEN);
	uint8 *addr = (uint8 *) zalloc(4);
	uint8 opmode;
	socklen_t fromlen;
#ifdef DEBUG
	printf("Hello, welcome to UDPtask!\r\n");
#endif
	//wifi_station_scan(NULL,scan_done);
	//printf(rxbuf);

	/* create socket */
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(UDP_LOCAL_PORT);
	server_addr.sin_len = sizeof(server_addr);

	do {
		sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (sock_fd == -1) {
#ifdef DEBUG
			printf("ESP8266 UDP task > failed to create socket!\n");
#endif
			vTaskDelay(1000 / portTICK_RATE_MS);
		}
	} while (sock_fd == -1);
#ifdef DEBUG
	printf("ESP8266 UDP task > create socket OK!\n");
#endif

	/* bind socket */
	do {
		ret = bind(sock_fd, (struct sockaddr * )&server_addr,
				sizeof(server_addr));
		if (ret != 0) {
#ifdef DEBUG
			printf("ESP8266 UDP task > captdns_task failed to bind socket\n");
#endif
			vTaskDelay(1000 / portTICK_RATE_MS);
		}
	} while (ret != 0);
#ifdef DEBUG
	printf("ESP8266 UDP task > bind OK!\n");
#endif

	/* receive and send UDP data */
	while (1) {
		memset(udp_msg, 0, DATA_LEN);
		memset(&from, 0, sizeof(from));

		setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (char * )&nNetTimeout,
				sizeof(int));
		fromlen = sizeof(struct sockaddr_in);
		ret = recvfrom(sock_fd, (uint8 * )udp_msg, DATA_LEN, 0,
				(struct sockaddr * )&from, (socklen_t* )&fromlen);
		if (ret > 0) {
#ifdef DEBUG
			printf("ESP8266 UDP task > recv %d Bytes from %s ,Port %d\n", ret, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
#endif
			if (!strcmp(udp_msg, UDP_STRING)) {
				opmode = wifi_get_opmode();
				switch (opmode) {
				case SOFTAP_MODE:
					wifi_get_ip_info(0x01, &info);
					break;
				case STATION_MODE:
					if (wifi_station_get_connect_status() == STATION_GOT_IP)
						wifi_get_ip_info(0x00, &info);
					break;
				case STATIONAP_MODE:
					if (wifi_station_get_connect_status() == STATION_GOT_IP)
						wifi_get_ip_info(0x00, &info);
					else
						wifi_get_ip_info(0x01, &info);
					break;
				}
				if (&info != NULL) {
					addr = (uint8*) &(info.ip.addr);
					memset(udp_msg, 0, DATA_LEN);
					sprintf(udp_msg, "%d.%d.%d.%d,ACCF23635DAC,", addr[0],
							addr[1], addr[2], addr[3]);
#ifdef DEBUG
					printf("got ip addr!\n");
					printf("ip:%s\n",(uint8*)udp_msg);
					printf("stringlen=%d\n",stringlen);
#endif
					sendto(sock_fd, (uint8* )udp_msg, strlen(udp_msg), 0,
							(struct sockaddr * )&from, fromlen);
				}
			}
		}
	}

	if (udp_msg) {
		free(udp_msg);
		udp_msg = NULL;
	}
	close(sock_fd);

	vTaskDelete(NULL);
}
/* Create a TCP server for application to connect for communication */
void TCPServer(void *pvParameters) {
	int32 listenfd;
	int32 ret;
	int32 client_sock;
	struct sockaddr_in server_addr;
	struct sockaddr_in remote_addr;
	int recbytes, stack_counter = 0;

	/* Construct local address structure */
	memset(&server_addr, 0, sizeof(server_addr)); /* Zero out structure */
	server_addr.sin_family = AF_INET; /* Internet address family */
	server_addr.sin_addr.s_addr = INADDR_ANY; /* Any incoming interface */
	server_addr.sin_len = sizeof(server_addr);
	server_addr.sin_port = htons(SERVER_PORT); /* Local port */

	/* Create socket for incoming connections */
	do {
		listenfd = socket(AF_INET, SOCK_STREAM, 0);
		if (listenfd == -1) {
#ifdef DEBUG
			printf("ESP8266 TCP server task > socket error\n");
#endif
			vTaskDelay(1000 / portTICK_RATE_MS);
		}
	} while (listenfd == -1);

#ifdef DEBUG
	printf("ESP8266 TCP server task > create socket: %d\n", listenfd);
#endif
	/* Bind to the local port */
	do {
		ret = bind(listenfd, (struct sockaddr * )&server_addr,
				sizeof(server_addr));
		if (ret != 0) {
#ifdef DEBUG
			printf("ESP8266 TCP server task > bind fail\n");
#endif
			vTaskDelay(1000 / portTICK_RATE_MS);
		}
	} while (ret != 0);
#ifdef DEBUG
	printf("ESP8266 TCP server task > port:%d\n",ntohs(server_addr.sin_port));
#endif

	do {
		/* Listen to the local connection */
		ret = listen(listenfd, MAX_CONN);
		if (ret != 0) {
#ifdef DEBUG
			printf("ESP8266 TCP server task > failed to set listen queue!\n");
#endif
			vTaskDelay(1000 / portTICK_RATE_MS);
		}
	} while (ret != 0);
#ifdef DEBUG
	printf("ESP8266 TCP server task > listen ok:%d\n", listenfd);
#endif

	//pthread_t tpid;
	//FD_ZERO(&fdread);
	//struct listenfd_set *listen = (struct listenfd_set *)zalloc(sizeof(struct listenfd_set));
	//listen->listenfd = listenfd;
	//listen->fdread = &fdread;
	/* Waiting for TCP Client to connect */
	//xTaskCreate(WaitClient, "WaitClient", 256, NULL, 2, NULL);
	int32 len = sizeof(struct sockaddr_in);
	while (1) {
#ifdef DEBUG
		printf("ESP8266 TCP server task > wait client\n");
#endif

		if(client_num < MAX_CONN){
			/*block here waiting remote connect request*/
			if ((client_sock = accept(listenfd, (struct sockaddr * )&remote_addr,(socklen_t * )&len)) < 0) {
#ifdef DEBUG
				printf("ESP8266 TCP server task > accept fail\n");
#endif
				continue;
			}
#ifdef DEBUG
			printf("client num:%d\n",client_num);
			printf("ESP8266 TCP server task > Client from %s %d client_sock %d\n",inet_ntoa(remote_addr.sin_addr), htons(remote_addr.sin_port), client_sock);
#endif
			client_conn[client_num++] = client_sock;
			//FD_SET(client_sock, &fdread);
			xTaskCreate(RecvData, "RecvData", 256, &client_sock, 2, NULL);
		}


		/*char *recv_buf = (char *) zalloc(DATA_LEN);
		while ((recbytes = read(client_sock, recv_buf, DATA_LEN)) > 0) {
			recv_buf[recbytes] = 0;
#ifdef DEBUG
			printf("ESP8266 TCP server task > read data success %d!\nESP8266 TCP server task > ", recbytes);
			//sendto(client_sock, recv_buf, strlen(recv_buf), 0, (struct sockaddr *)&remote_addr, (socklen_t)len);
			send(client_sock,recv_buf,strlen(recv_buf),0);
#endif
			printf(recv_buf);
		}
		free(recv_buf);
		if (recbytes <= 0) {
#ifdef DEBUG
			printf("ESP8266 TCP server task > read data fail!\n");
#endif
			close(client_sock);
		}//*/
	}
	vTaskDelete(NULL);
}
/* Create a task to accept client, but the job finally done in TCPServer task */
void WaitClient(void *pvParameters){
	int ret;
	int32 len = sizeof(struct sockaddr_in);
	SOCKET cliconn,listenfd;
	struct sockaddr_in remote_addr;
#ifdef DEBUG
	printf("waiting for client...\nlistenfd:%d\n", listenfd);
#endif
	while(1){
		/*if((ret = select(0, fdread, NULL, NULL, NULL)) == -1){
			printf("select failed!ret:%d\n", ret);
			continue;
		}*/
		if(client_num < MAX_CONN){
#ifdef DEBUG
			printf("accepting...\n");
#endif
			cliconn = accept(listenfd, (struct sockaddr *)&remote_addr, (socklen_t *)&len );
			if(cliconn < 0){
				printf("accept failed!\n");
			}
			else{
				printf("accept ok!!!cliconn:%d,ip:%s,port:%d\n",cliconn, inet_ntoa(remote_addr.sin_addr),htons(remote_addr.sin_port));
				client_conn[client_num++] = cliconn;
				//printf("client num:%d\n",client_num);
				//FD_SET(cliconn, &fdread);
				xTaskCreate(RecvData, "RecvData", 256, &cliconn, 2, NULL);
			}
		}
		else{
			printf("connection full!\n");
		}
	}
	vTaskDelete(NULL);
}
/* Create a task to process the data of a single client */
void RecvData(void *pvParameters){
#ifdef DEBUG
	printf("reading data...\n");
#endif
	int ret,i,recvbytes;
	uint8 orderidx;
	//uint8 order[ORDER_NUM][ORDER_LEN],buff[ORDER_LEN];
	//fd_set *fdread = (fd_set *)fdread_t;
	SOCKET cliconn = *(SOCKET*)pvParameters;
	while(1){
		/*if((ret = select(0, fdread, NULL, NULL, NULL)) == -1){
			printf("select error!\n");
			continue;
		}*/
#ifdef DEBUG
		if(client_num)
			printf("client num:%d\n", client_num);
#endif
		//for(i=0; i < client_num; i++){
			//cliconn = client_conn[i];
#ifdef DEBUG
			printf("cliconn:%d\n",cliconn);
#endif
			if(cliconn){//FD_ISSET(cliconn, &fdread)
				char *recv_buf = (char *)zalloc(DATA_LEN);
				recvbytes = read(cliconn, recv_buf, DATA_LEN);
				if(recvbytes > 0){
					if(recvbytes > 20 && recv_buf[0]=='<')
					{
						recv_buf[recvbytes] = 0;
						if(recv_buf[1]=='<'){
							spi_flash_erase_sector(SPI_FLASH_START - MODE_NUM - 1);
							spi_flash_write((SPI_FLASH_START - MODE_NUM - 1) * SPI_FLASH_SEC_SIZE, (uint32*)recv_buf, 64);
							printf("set wifi ok!\n");
							system_restart();
						}
						else if(recv_buf[9] == 'T'){
							if(recv_buf[10] == 'H'){
								orderidx = recv_buf[13]-'0';//mode control order index is 13
								if(orderidx >= 0 && orderidx < MODE_NUM && !modectl[orderidx]){
									xTaskCreate(Sendorder, "Sendorder", 512, &orderidx, 2, NULL);
								}
							}
							if(recv_buf[10] == 'G'){//disable mode
								orderidx=recv_buf[13]-'0';
								modectl[orderidx]=1;
							}
							if(recv_buf[10] == 'S'){//enable mode
								orderidx=recv_buf[13]-'0';
								modectl[orderidx]=0;
							}
							if(recv_buf[10] == 'R'){
								orderidx = recv_buf[13]-'0';
								if(orderidx >= 0 && orderidx < MODE_NUM )
									spi_flash_erase_sector(SPI_FLASH_START - orderidx);
							}
						}
						else
							printf(recv_buf);
					}
#ifdef DEBUG
					printf("read %d bytes success:%s\n", recvbytes, recv_buf);
					//send(cliconn, recv_buf, strlen(recv_buf), 0);
#endif
				}
				else if(recvbytes == 0){
					printf("end of file\n");
					for(i=0; i < client_num; i++)
						if(cliconn == client_conn[i])
							break;
					if(i == client_num)
						printf("error:connection not found!\n");
					else if(i < client_num-1)
						for( ; i < client_num; i++)
							client_conn[i] = client_conn[i+1];
					closesocket(cliconn);
					client_num--;
					break;
				}
				else{
					printf("socket disconnected!\n");
					for(i=0; i < client_num; i++)
						if(cliconn == client_conn[i])
							break;
					if(i == client_num)
						printf("error:connection not found!\n");
					else if(i < client_num-1)
						for( ; i < client_num; i++)
							client_conn[i] = client_conn[i+1];
					closesocket(cliconn);
					client_num--;
					break;
				}
				free(recv_buf);
			}
			else{
				printf("connection error!\n");
				closesocket(cliconn);
				client_num--;
				for( ; i < client_num; i++)
					client_conn[i] = client_conn[i+1];
				break;
			}
		//}
	}
	vTaskDelete(NULL);
}
/* Create a task to process the data from remote server */
void ProcessData(void *pvParameters){
#ifdef DEBUG
	printf("processing data...\n");
#endif
	uint8 buff[50];
	int recvbytes;
	uint8 orderidx,i;
	uint8 *recv_buf,*p,order[ORDER_NUM][ORDER_LEN],orderlen;
	uint32 *flash;
	SOCKET cliconn = *(SOCKET*)pvParameters;
	while(1){
		recvbytes = 0;
		recv_buf = (char*)zalloc(320);
		memset(recv_buf, 0, 320);
		if((recvbytes = read(sta_socket, recv_buf, 320)) > 0){
#ifdef DEBUG
			//recv_buf[recvbytes] = 0;
			printf("ESP8266 TCP client task > recv data %d bytes!\nESP8266 TCP client task > %s\n", recvbytes, recv_buf);
#endif
			p = strchr(recv_buf, '{');
			if(p){
				recvbytes = strcspn(p, "}");
//				if(recvbytes < 90){
//					p[recvbytes+1] = 0;
//					printf(p);
//				}
				while(recvbytes > 18){
//					flash = &cliconn;
//					spi_flash_erase_sector(SPI_FLASH_START);
//					spi_flash_write(SPI_FLASH_START * SPI_FLASH_SEC_SIZE, flash, 4);//(uint32*)*order, ORDER_NUM * ORDER_LEN);
//					printf("write order success\n");
					p = strchr(p+1, '<');
					if(p == NULL)
						break;
					orderlen = strcspn(p, ">");
#ifdef DEBUG
							printf("orderlen=%d\n",orderlen);
#endif
					if(p[9] == 'S'){
						orderidx = p[13]-'0';
						if(orderidx >= 0 && orderidx < MODE_NUM){
							//*order = (uint8*)zalloc(ORDER_NUM * ORDER_LEN);
							if(order[0] == NULL)
								printf("invalid pointer order[0]\n");
							spi_flash_read((SPI_FLASH_START - orderidx) * SPI_FLASH_SEC_SIZE, (uint32*)order, ORDER_NUM * ORDER_LEN);
#ifdef DEBUG
							printf("read order ok\n");
#endif

							if(p[10] == 'R'){
								if(p[2] == 'A'){
									memcpy(buff,p,ORDER_LEN);
									printf(buff);
								}
								else{
									for(i = 0; order[i][0] == '<' && i < ORDER_NUM; i++)
										if(!memcmp(p, order[i], 9) && !memcmp(p+11, order[i]+11, 2))
											break;
									if( i == ORDER_NUM-1 )
										order[i][0] = 0xFF;
									else
									{
										for(;(i < ORDER_NUM-1) && (order[i][0] == '<'); i++)
											memcpy(order[i], order[i+1], ORDER_LEN);
									    order[i][0] = 0xFF;
									}
									spi_flash_erase_sector(SPI_FLASH_START - orderidx);
									spi_flash_write((SPI_FLASH_START - orderidx) * SPI_FLASH_SEC_SIZE, (uint32*)*order, ORDER_NUM * ORDER_LEN);
								}
							}
							else{
								if(p[2] == 'A'){
									memcpy(buff,p,ORDER_LEN);
									printf(buff);
								}
								else if(p[2] == 'D'){
									spi_flash_read((SPI_FLASH_START - MODE_NUM) * SPI_FLASH_SEC_SIZE, (uint32*)order, ORDER_NUM * ORDER_LEN);
									for(i = 0; order[i][0] == '<' && i < ORDER_NUM; i++)
										if(!memcmp(p, order[i], 9))
											break;
									if(i < ORDER_NUM){
										p[9] = 'X';
										p[10]= 'H';
										memcpy(order[i], p, ORDER_LEN);
									}
									else
										printf("\r\norder full\r\n");
									spi_flash_erase_sector(SPI_FLASH_START - MODE_NUM);
									spi_flash_write((SPI_FLASH_START - MODE_NUM) * SPI_FLASH_SEC_SIZE, (uint32*)order, ORDER_NUM * ORDER_LEN);
								}
								else{
//									//printf("**********before**********\n");
//									if(order == NULL)
//										printf("invalid pointer order\n");
//									if(order[0] == NULL)
//										printf("invalid pointer order[0]\n");
									for(i = 0; order[i][0] == '<' && i < ORDER_NUM; i++)
										if(!memcmp(p, order[i], 9) && !memcmp(p+11, order[i]+11, 2))
											break;
									//printf("**********after***********\n");
									if(i < ORDER_NUM){
										p[9] = 'X';
										memcpy(order[i], p, ORDER_LEN);
									}
									else
										printf("\r\norder full\r\n");
									spi_flash_erase_sector(SPI_FLASH_START - orderidx);
									spi_flash_write((SPI_FLASH_START - orderidx) * SPI_FLASH_SEC_SIZE, (uint32*)order, ORDER_NUM * ORDER_LEN);
								}
							}
							//free(order);
						}
						recvbytes -= ORDER_LEN;
					}
					else if(p[9] == 'T'){
						if(p[10] == 'H'){
							orderidx = p[13]-'0';
							if(orderidx >= 0 && orderidx < MODE_NUM && !modectl[orderidx]){
								xTaskCreate(Sendorder, "Sendorder", 512, &orderidx, 2, NULL);
								recvbytes -= ORDER_LEN;
							}
						}
						if(p[10] == 'G'){//disable mode
						    if(p[2] == 'D'){
						    	spi_flash_read((SPI_FLASH_START - MODE_NUM) * SPI_FLASH_SEC_SIZE, (uint32*)order, ORDER_NUM * ORDER_LEN);
								for(i = 0; order[i][0] == '<' && i < ORDER_NUM; i++)
									if(!memcmp(p, order[i], 9))
										break;
								if(i < ORDER_NUM){
									p[10]= 'G';
									memcpy(order[i], p, 11);
									spi_flash_erase_sector(SPI_FLASH_START - MODE_NUM);
									spi_flash_write((SPI_FLASH_START - MODE_NUM) * SPI_FLASH_SEC_SIZE, (uint32*)order, ORDER_NUM * ORDER_LEN);
									printf("disable mode ok!\n");
								}
						    }
						    else{
						    	orderidx=p[13]-'0';
								modectl[orderidx]=1;
								recvbytes -= ORDER_LEN;
						    }
						}
						if(p[10] == 'S'){//enable mode
							if(p[2] == 'D'){
								spi_flash_read((SPI_FLASH_START - MODE_NUM) * SPI_FLASH_SEC_SIZE, (uint32*)order, ORDER_NUM * ORDER_LEN);
								for(i = 0; order[i][0] == '<' && i < ORDER_NUM; i++)
									if(!memcmp(p, order[i], 9))
										break;
								if(i < ORDER_NUM){
									p[10]= 'H';
									memcpy(order[i], p, 11);
									spi_flash_erase_sector(SPI_FLASH_START - MODE_NUM);
									spi_flash_write((SPI_FLASH_START - MODE_NUM) * SPI_FLASH_SEC_SIZE, (uint32*)order, ORDER_NUM * ORDER_LEN);
									printf("enable mode ok!\n");
								}
							}
							else{
								orderidx=p[13]-'0';
								modectl[orderidx]=0;
								recvbytes -= ORDER_LEN;
							}
						}
						if(p[10] == 'R'){
							orderidx = p[13]-'0';
							recvbytes -= ORDER_LEN;
							if(orderidx >= 0 && orderidx < MODE_NUM)
								spi_flash_erase_sector(SPI_FLASH_START - orderidx);
						}
					}
					else if(p[9] == 'X'){
						memcpy(buff,p,orderlen+1);
						buff[orderlen+1]=0;
						printf(buff);
						recvbytes -= orderlen;
						vTaskDelay(500 / portTICK_RATE_MS);
					}
				}
			}
			//free(recv_buf);
			//vTaskDelay(5000 / portTICK_RATE_MS);
			//continue;		//get order again
		}
		free(recv_buf);

		if(recvbytes <= 0){
#ifdef DEBUG
			printf("ESP8266 TCP client task > read data fail!\n");
			printf("recvbytes=%d\n",recvbytes);
#endif
			close(sta_socket);
			//printf("sta_socket:%d\n",sta_socket);
			break;
		}
	}
	vTaskDelete(NULL);
}
/* Create a task to send mode order */
void Sendorder(void *pvParameters){
	//printf("welcome to sendorder task\n");
	uint8 orderidx = *(uint8*)pvParameters;
	//int orderidx = *(int*)pvParameters;
	//printf("read flash ok1\n");
	uint8 i,buff[ORDER_LEN];

	//printf("read flash ok2\n");
	uint8 order[ORDER_NUM][ORDER_LEN];
	spi_flash_read((SPI_FLASH_START - orderidx) * SPI_FLASH_SEC_SIZE, (uint32*)order, ORDER_NUM * ORDER_LEN);

	//printf("read flash ok\n");

	while(1){
	for(i = 0; order[i][0] == '<' && i < ORDER_NUM; i++){
		memcpy(buff,order[i],ORDER_LEN);
		printf(buff);
		vTaskDelay(500 / portTICK_RATE_MS);
	}
	break;
	}
	vTaskDelete(NULL);
}
/* wifi event handle function */
void wifi_handle_event_cb(System_Event_t *evt) {
	//printf("event %x\n", evt->event_id);
	switch (evt->event_id) {
	case EVENT_STAMODE_CONNECTED:
#ifdef DEBUG
		printf("connect to ssid %s, channel %d\n",
				evt->event_info.connected.ssid,
				evt->event_info.connected.channel);
#endif
		GPIO_OUTPUT(GPIO_Pin_4, 0);		//outout 0,turn on led
		user_esp_platform_init();
		break;
	case EVENT_STAMODE_DISCONNECTED:
#ifdef DEBUG
		printf("disconnect from ssid %s, reason %d\n",
				evt->event_info.disconnected.ssid,
				evt->event_info.disconnected.reason);
#endif
		GPIO_OUTPUT(GPIO_Pin_4, 1);		//outout 1,turn off led
		break;
	case EVENT_STAMODE_AUTHMODE_CHANGE:
#ifdef DEBUG
		printf("mode: %d -> %d\n", evt->event_info.auth_change.old_mode,
				evt->event_info.auth_change.new_mode);
#endif
		break;
	case EVENT_STAMODE_GOT_IP:
#ifdef DEBUG
		printf("ip:" IPSTR ",mask:" IPSTR ",gw:" IPSTR,
				IP2STR(&evt->event_info.got_ip.ip),
				IP2STR(&evt->event_info.got_ip.mask),
				IP2STR(&evt->event_info.got_ip.gw));
		printf("\n");
#endif
		xTaskCreate(TCPClient, "tsk1", 256, NULL, 2, NULL);
		break;
	case EVENT_SOFTAPMODE_STACONNECTED:
#ifdef DEBUG
		printf("station: " MACSTR "join, AID = %d\n",
				MAC2STR(evt->event_info.sta_connected.mac),
				evt->event_info.sta_connected.aid);
#endif
		break;
	case EVENT_SOFTAPMODE_STADISCONNECTED:
#ifdef DEBUG
		printf("station: " MACSTR "leave, AID = %d\n",
				MAC2STR(evt->event_info.sta_disconnected.mac),
				evt->event_info.sta_disconnected.aid);
#endif
		break;
	default:
		break;
	}
}

void long_press(void){
	printf("long press\n");
	GPIO_OUTPUT(GPIO_Pin_5, 1);
	spi_flash_erase_sector(SPI_FLASH_START - MODE_NUM - 1);
	system_restart();
}
void short_press(void){
	printf("short press\n");
}
