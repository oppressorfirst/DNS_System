#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "DNS.h"

#define LOCAL_PORT 53
#define ROOT_SERVER_PORT 53
#define DNS_HOST			0x01
#define DNS_CNAME			0x05
#define DNS_SOA             0x06
#define DNS_MX              0x0f
#define DNS_PTR             0x0c


int udpSock;
int tcpSock;
struct sockaddr_in local_addr, client_addr;
struct sockaddr_in net_server_addr;
// 接收响应报文长度
uint16_t net_server_response_length;
// 接收响应报文
char net_server_response[1024];
int client_query_len;
char client_query_packet[1024];
char client_wanted_domain[128];
char net_server_return_domain[128];
char *next_server_ip = "127.0.0.1";


void  get_client_wanted_domain();
void parse_server_response();
void receive_net_server();
void  initTcpSock();
void  ask_net_server();
void intToNetworkByteArray(int value, uint8_t* array);
void receive_client();
void initUdpSock();
void sendto_client();


void dns_parse_name(unsigned char* chunk, unsigned char* ptr, char* out, int* len) {
    int flag = 0, n = 0;
    char* string = out + (*len);
    while (1) {
        flag = (int)ptr[0];
        if (flag == 0) break;
        if (is_pointer(flag)) {
            n = (int)ptr[1];
            ptr = chunk + n;
            dns_parse_name(chunk, ptr, out, len);
            break;
        }
        else {
            ptr++;
            memcpy(string, ptr, flag);
            ptr += flag;
            string += flag;
            *len += flag;
            if ((int)ptr[0] != 0) {
                memcpy(string, ".", 1);
                string ++;
                (*len) ++;
            }
        }

    }

}


void intToNetworkByteArray(int value, uint8_t* array) {
    uint16_t networkValue = htons((uint16_t)value);
    array[1] = (networkValue >> 8) & 0xFF;  // 高字节
    array[0] = networkValue & 0xFF;         // 低字节
}

void receive_client(){
        memset(client_query_packet, 0, sizeof(client_query_packet));
        size_t addr_len = sizeof(struct sockaddr_in);
        client_query_len = recvfrom(udpSock, client_query_packet, sizeof(client_query_packet), 0, (struct sockaddr*)&client_addr, (socklen_t *)&addr_len);
        if ( client_query_len < 0) {
            perror("Receive failed");
            exit(1);
        }
        printHex(client_query_packet,client_query_len);
        printf("Received query from client\n\n");

}

void initUdpSock(){
    udpSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSock == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    // 设置本地服务端地址
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(LOCAL_PORT);

    // 绑定套接字到本地服务端地址
    if (bind(udpSock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        perror("Binding failed");
        exit(1);
    }

    printf("Local DNS server started...\n");
}

void get_client_wanted_domain(){
    unsigned char *ptr = client_query_packet;
    memset(client_wanted_domain,0,sizeof (client_wanted_domain));
    ptr += 12;
    int len = 0;
    dns_parse_name( client_query_packet, ptr, client_wanted_domain, &len);
}

void initTcpSock(){
    tcpSock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpSock == -1) {
        perror("Socket creation failed");
        exit(1);
    }
    net_server_addr.sin_family = AF_INET;
    printf("这个是要进行查询的dns服务器%s\n\n",next_server_ip);
    net_server_addr.sin_addr.s_addr = inet_addr(next_server_ip);
    net_server_addr.sin_port = htons(ROOT_SERVER_PORT);

    if (connect(tcpSock, (struct sockaddr*)&net_server_addr, sizeof(net_server_addr)) < 0) {
        perror("Connection to root server failed");
    }
}

void sendto_clent(){        //实现

}

void  ask_net_server(){

    uint8_t askInformationLen[2];
    size_t shot_packet_length = client_query_len + sizeof(askInformationLen);
    char shot_packet[shot_packet_length + 1];
    intToNetworkByteArray(client_query_len, askInformationLen);

    memcpy(shot_packet, askInformationLen, sizeof(askInformationLen));
    memcpy(shot_packet + sizeof(askInformationLen), client_query_packet, client_query_len + 1);

    printHex(shot_packet, client_query_len + 2);
    printf("打印发送的报文\n\n");
    // 发送查询报文
    send(tcpSock, shot_packet, client_query_len + 2, 0);


}
void receive_net_server(){

    net_server_response_length = 0;
    memset(net_server_response, 0, sizeof(net_server_response));

    if (recv(tcpSock, &net_server_response_length, sizeof(net_server_response_length), 0) < 0) {
        perror("Receive length field failed");
        exit(1);
    }
    net_server_response_length = ntohs(net_server_response_length);



    if (recv(tcpSock, net_server_response, net_server_response_length, 0) < 0) {
        perror("Receive failed");
        exit(1);
    }

    printHex(net_server_response, net_server_response_length);
    printf("打印收到dns服务器的报文\n\n");
    close(tcpSock);
}

void parse_server_response(){

    unsigned char *ptr =  net_server_response;
    ptr += 2;
    int flags = ntohs(*(unsigned short int *) ptr);
    int bit = (flags >> 9) % 2;  // 获取指定位置的二进制位（从右往左，最低位为0）
    if (bit == 1) {
        printf("The received message has been truncated!");
        return;
    }
    ptr += 4;
    int answersNum = ntohs(*(unsigned short *) ptr);
    ptr += 2;
    int authoritiesNum = ntohs(*(unsigned short *) ptr);
    ptr += 2;
    int additionsNum = ntohs(*(unsigned short *) ptr);
    int allRRNum = answersNum + authoritiesNum + additionsNum;
    int Num[3] = {answersNum, authoritiesNum, additionsNum};
    ptr += 2;
    //将问题报文中的网址直接跳过，放到后面读取
    while (1) {
        int flag = (int) ptr[0];
        ptr += (flag + 1);
        if (flag == 0) break;
    }
    ptr += 4;

    char cname[128], ip[20], netip[20];
    int len;
    int times = 0;
    struct DNS_RR dnsRr[allRRNum];
    memset(net_server_return_domain, 0, sizeof(net_server_return_domain));

    for (int j = 0; j < 3; j++) {
        //解析汇报区域
        for (int i = 0; i < Num[j]; i++) {

            len = 0;
            if(!times) {
                dns_parse_name(net_server_response, ptr, net_server_return_domain, &len);
                times++;

            }

            ptr += 2;
            dnsRr[i].type = htons(*(unsigned short *) ptr);

            ptr += 4;
            dnsRr[i].ttl = htonl(*(int *) ptr);

            ptr += 4;
            dnsRr[i].data_len = ntohs(*(unsigned short *) ptr);

            ptr += 2;
            if (dnsRr[i].type == DNS_CNAME) {
                bzero(cname, sizeof(cname));
                len = 0;
                dns_parse_name(net_server_response, ptr, cname, &len);
                ptr += dnsRr[i].data_len;
                dnsRr[i].CName = (char *) calloc(strlen(cname) + 1, 1);
                memcpy(dnsRr[i].CName, cname, strlen(cname));
            } else if (dnsRr[i].type == DNS_HOST) {
                bzero(ip, sizeof(ip));
                if (dnsRr[i].data_len == 4) {
                    memcpy(netip, ptr, dnsRr[i].data_len);
                    inet_ntop(AF_INET, netip, ip, sizeof(struct sockaddr));
                    dnsRr[i].ip = (char *) calloc(strlen(ip) + 1, 1);
                    memcpy(dnsRr[i].ip, ip, strlen(ip));
                    next_server_ip= (char *) calloc(strlen(ip) + 1, 1);
                    memcpy(next_server_ip, ip, strlen(ip));
                }
                ptr += dnsRr[i].data_len;
            } else if (dnsRr[i].type == DNS_MX) {
                ptr += 2;
                bzero(cname, sizeof(cname));
                len = 0;
                dns_parse_name(net_server_response, ptr, cname, &len);
                dnsRr[i].MXName = (char *) calloc(strlen(cname) + 1, 1);
                memcpy(dnsRr[i].MXName, cname, strlen(cname));
                ptr += dnsRr[i].data_len - 2;
            }
        }
        for(int i = 0; i < Num[j]; i++){
           printf("type: %d, ",dnsRr[i].type);
            printf("ttl: %d, ", dnsRr[i].ttl);
            printf("%d, ",dnsRr[i].data_len);
            switch (dnsRr[i].type) {
                case DNS_MX:
                    printf("%s, \n", dnsRr[i].MXName);
                    break;
                case DNS_HOST:
                    printf("%s, \n", dnsRr[i].ip);
                    break;
                case DNS_CNAME:
                    printf("%s, \n", dnsRr[i].CName);
                    break;
            }
            printf("00000000000000000000000000\n");
        }
    }

}


int main() {

    initUdpSock();
    while (1) {


        memset(net_server_return_domain, 0 ,sizeof (net_server_return_domain));
        net_server_return_domain[0] = '!';

        receive_client();
        get_client_wanted_domain();
        while(strcmp(net_server_return_domain, client_wanted_domain) != 0){
            initTcpSock();
            ask_net_server();
            receive_net_server();
            parse_server_response();
        }
        //sendto_client();
        memset(net_server_return_domain, 0 ,sizeof (net_server_return_domain));
        net_server_return_domain[0] = '!';
       // forward_dns_query(client_query_len, client_query_packet);

        printf("完成了一次查询\n");
    }



}
