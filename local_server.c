#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
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
char *next_server_ip;
int local_cache_num;
int existCache;
struct DNS_RR dnsCache[100];
struct DNS_Query dnsQuery;
struct DNS_Header dnsHeader;


void  get_client_wanted_domain();
void initSystem();
void appendStructToCSV(const char* filename, struct DNS_RR* dnsRr);
void parse_server_response();
void receive_net_server();
void initTcpSock();
void ask_net_server();
void intToNetworkByteArray(int value, uint8_t* array);
void receive_client();
void initUdpSock();
void dns_parse_query(char* buffer);
void sendto_client(int num, int type);


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
        dns_parse_query(client_query_packet);
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

void dns_create_header(){
    //dnsheader的id在解析中已经记录了。
    dnsHeader.flags = htons(0x8180);
    dnsHeader.questionsNum = htons(1);    //询问报文的问题一般只有一个
    dnsHeader.answerNum = htons(1);
    dnsHeader.authorityNum = htons(0);
    if(dnsQuery.qtype == htons(15)) {
        dnsHeader.additionalNum = htons(1);
    } else{
        dnsHeader.additionalNum = htons(0);
    }
}

void dns_create_question(struct DNS_Query *question, const char *hostname)
{
    if(question == NULL || hostname == NULL) {
        printf("There is some problem in The DNS header struct or The domain you want to search!");
        return ;
    }


    //内存空间长度：hostname长度 + 结尾\0 再多给一个空间
    question->name = malloc(strlen(hostname) + 2);
    if(question->name == NULL)
    {
        printf("内存分配出错了");
        return ;
    }

    question->length =  (int)strlen(hostname) + 2;

    //查询类1表示Internet数据
    question->qclass = htons(1);

    //【重要步骤】
    //名字存储：www.0voice.com -> 3www60voice3com
    const char delim[2] = ".";
    char *qname = question->name; //用于填充内容用的指针

    //strdup先开辟大小与hostname同的内存，然后将hostname的字符拷贝到开辟的内存上
    char *new_hostname = strdup(hostname); //复制字符串，调用malloc
    //将按照delim分割出字符串数组，返回第一个字符串
    char *token = strtok(new_hostname, delim);

    while (token != NULL)
    {

        size_t len = strlen(token);  // 获取当前子字符串的长度
        *qname = len;  // 将长度存储到 qname 所指向的内存位置
        qname++;  // 指针移动到下一个位置

        strncpy(qname, token, len + 1);  // 复制当前子字符串到 qname 所指向的内存位置
        qname += len;  // 指针移动到复制结束的位置

        token = strtok(NULL, delim);  // 获取下一个子字符串
    }

    free(new_hostname);  // 释放通过 strdup 函数分配的内存空间
}


int createResponse(int offset, char *request) {
    memcpy(request, &dnsHeader, sizeof(struct DNS_Header));
    offset = sizeof(struct DNS_Header);

    //Queries部分字段写入到request中，question->length是question->name的长度
    memcpy(request + offset, dnsQuery.name, dnsQuery.length);
    offset += dnsQuery.length;

    memcpy(request + offset, &dnsQuery.qtype, sizeof(dnsQuery.qtype));
    offset += sizeof(dnsQuery.qtype);

    memcpy(request + offset, &dnsQuery.qclass, sizeof(dnsQuery.qclass));
    offset += sizeof(dnsQuery.qclass);
    printHex(request,offset);
    return offset; //返回request数据的实际长度
}

int createRRResponse(int offset, char *request, struct DNS_RR dnsRr){

        memcpy(request + offset, dnsRr.SearchName, dnsRr.SearchNameLen);
        offset += dnsRr.SearchNameLen;

        memcpy(request + offset, &dnsRr.type, sizeof(dnsRr.type));
        offset += sizeof(dnsRr.type);

        memcpy(request + offset, &dnsRr.class, sizeof(dnsRr.class));
        offset += sizeof(dnsRr.class);

        memcpy(request + offset, &dnsRr.ttl, sizeof(dnsRr.ttl));
        offset += sizeof(dnsRr.ttl);

       unsigned short len = htons((int)dnsRr.data_len);
       printf("dnsRr.data_len    %d\n",dnsRr.data_len);
        memcpy(request + offset, &len, sizeof(dnsRr.data_len));
        offset += sizeof(dnsRr.data_len);

   //    memcpy(request + offset, dnsRr.ip, 4);
    //   offset += 4;



    if (dnsRr.type  == htons(1)){
        //A
        memcpy(request + offset, dnsRr.ip, 4);
        offset += 4;
    }else if(dnsRr.type  == htons(5)){
        //CNAME
        memcpy(request + offset, dnsRr.CName, dnsRr.data_len);
        offset += dnsRr.data_len;
    } else if(dnsRr.type  == htons(15)){
        //MX
        memcpy(request + offset, &dnsRr.preference, 2);
        offset += 2;
        memcpy(request + offset, dnsRr.MXName, dnsRr.data_len);
        offset += dnsRr.data_len-2;
    } else if(dnsRr.type  == htons(12)){
        //PTR
        printHex(dnsRr.PTRName,dnsRr.data_len);
        memcpy(request + offset, dnsRr.PTRName, dnsRr.data_len);
        offset += dnsRr.data_len;
    } else{
        printf("error\n\n");
    }



    printHex(request,offset);
    return offset; //返回request数据的实际长度

}
void buildRR(struct DNS_RR *dnsRr, int num, char* response,int responseLen){

    printf("builedRR     %s\n",dnsCache[num].SearchName);
    dnsRr->SearchName = malloc(dnsCache[num].SearchNameLen + 2);
    dnsRr->SearchNameLen = strlen(dnsCache[num].SearchName) + 2;
    const char delim[2] = ".";
    char *qname =dnsRr->SearchName; //用于填充内容用的指针

    //strdup先开辟大小与hostname同的内存，然后将hostname的字符拷贝到开辟的内存上
    char *new_hostname = strdup(dnsCache[num].SearchName); //复制字符串，调用malloc
    //将按照delim分割出字符串数组，返回第一个字符串
    char *token = strtok(new_hostname, delim);

    while (token != NULL)
    {

        size_t len = strlen(token);  // 获取当前子字符串的长度
        *qname = len;  // 将长度存储到 qname 所指向的内存位置
        qname++;  // 指针移动到下一个位置

        strncpy(qname, token, len + 1);  // 复制当前子字符串到 qname 所指向的内存位置
        qname += len;  // 指针移动到复制结束的位置

        token = strtok(NULL, delim);  // 获取下一个子字符串
    }

    free(new_hostname);  // 释放通过 strdup 函数分配的内存空间


    printHex(dnsRr->SearchName,dnsRr->SearchNameLen);
    int position=0;
    for (int i = 0; i < responseLen; ++i) {
        if(response[i]==dnsRr->SearchName[0]){
            int temp = 1;
            for (int j = 0; j < dnsRr->SearchNameLen; ++j) {
                if(response[i+j]!=dnsRr->SearchName[j]) {
                    temp = 0;

                }

            }
            if(temp == 1){
                position = i;
                break;
            }
        }
    }
    printf("%d\n", position);
    if (position != 0) {
        dnsRr->SearchNameLen = 2;
        dnsRr->SearchName = malloc( 2);
        dnsRr->SearchName[0]= 0xc0;
        dnsRr->SearchName[1]= position;
    }

    dnsRr->class = htons(1);
    dnsRr->type = htons(dnsCache[num].type);
    dnsRr->ttl = htonl(dnsCache[num].ttl);



    if (dnsCache[num].type  == 1){
        dnsRr->data_len= 4;
        unsigned char ip_parts[4];
        uint32_t dns_address = 0;
        printf("%s\n",dnsCache[num].ip);
        sscanf(dnsCache[num].ip, "%hhu.%hhu.%hhu.%hhu", &ip_parts[0], &ip_parts[1], &ip_parts[2], &ip_parts[3]);
        dns_address = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3];
        dnsRr->ip = malloc(sizeof (unsigned char *)&dns_address);
        uint32_t network_order = htonl(dns_address);
        memcpy(dnsRr->ip, &network_order, sizeof(network_order));
        printHex(dnsRr->ip,4);

    }else if(dnsCache[num].type  == 5){
        //CNAME
        printf("CNMAE   %s\n",dnsCache[num].CName);

        dnsRr->data_len = strlen (dnsCache[num].CName)+2;
        const char delim[2] = ".";
        dnsRr->CName = malloc(sizeof (dnsRr->data_len));
        char *qname = dnsRr->CName; //用于填充内容用的指针

        //strdup先开辟大小与hostname同的内存，然后将hostname的字符拷贝到开辟的内存上
        char *new_hostname = strdup(dnsCache[num].CName); //复制字符串，调用malloc
        //将按照delim分割出字符串数组，返回第一个字符串
        char *token = strtok(new_hostname, delim);


        while (token != NULL)
        {
            size_t len = strlen(token);  // 获取当前子字符串的长度
            *qname = len;  // 将长度存储到 qname 所指向的内存位置
            qname++;  // 指针移动到下一个位置

            strncpy(qname, token, len + 1);  // 复制当前子字符串到 qname 所指向的内存位置
            qname += len;  // 指针移动到复制结束的位置

            token = strtok(NULL, delim);  // 获取下一个子字符串
        }

        free(new_hostname);  // 释放通过 strdup 函数分配的内存空间


        printf("000000000000000000000000\n");
    } else if(dnsCache[num].type  == 15){
        //MX
        dnsRr->preference = htons(dnsCache[num].preference);
        dnsRr->data_len = strlen (dnsCache[num].MXName)+4;
        dnsRr->MXName = malloc(sizeof (dnsRr->data_len));
        const char delim[2] = ".";
        char *qname = dnsRr->MXName; //用于填充内容用的指针

        //strdup先开辟大小与hostname同的内存，然后将hostname的字符拷贝到开辟的内存上
        char *new_hostname = strdup(dnsCache[num].MXName); //复制字符串，调用malloc
        //将按照delim分割出字符串数组，返回第一个字符串
        char *token = strtok(new_hostname, delim);

        while (token != NULL)
        {

            size_t len = strlen(token);  // 获取当前子字符串的长度
            *qname = len;  // 将长度存储到 qname 所指向的内存位置
            qname++;  // 指针移动到下一个位置

            strncpy(qname, token, len + 1);  // 复制当前子字符串到 qname 所指向的内存位置
            qname += len;  // 指针移动到复制结束的位置

            token = strtok(NULL, delim);  // 获取下一个子字符串
        }

        free(new_hostname);  // 释放通过 strdup 函数分配的内存空间
    } else if(dnsCache[num].type  == 12){
        //PTR
        printf("%s\n",dnsCache[num].PTRName);
        dnsRr->data_len = strlen (dnsCache[num].PTRName) + 2;
        dnsRr->PTRName = malloc(sizeof (dnsRr->data_len));
        memset(dnsRr->PTRName,0,sizeof (dnsRr->PTRName));
        const char delim[2] = ".";
        char *qname = dnsRr->PTRName; //用于填充内容用的指针
        printf("9999999999999999\n");
        //strdup先开辟大小与hostname同的内存，然后将hostname的字符拷贝到开辟的内存上
        char *new_hostname = strdup(dnsCache[num].PTRName); //复制字符串，调用malloc
        //将按照delim分割出字符串数组，返回第一个字符串
        char *token = strtok(new_hostname, delim);

        while (token != NULL)
        {

            size_t len = strlen(token);  // 获取当前子字符串的长度
            *qname = len;  // 将长度存储到 qname 所指向的内存位置
            qname++;  // 指针移动到下一个位置

            strncpy(qname, token, len + 1);  // 复制当前子字符串到 qname 所指向的内存位置
            qname += len;  // 指针移动到复制结束的位置

            token = strtok(NULL, delim);  // 获取下一个子字符串
        }
        printHex(dnsRr->PTRName, dnsRr->data_len);
        //free(new_hostname);  // 释放通过 strdup 函数分配的内存空间
        //dnsRr->PTRName[dnsRr->data_len-1] = 0;
    } else{
        printf("error\n\n");
    }



}

void sendto_client(int num, int type){        //实现
    type = ntohs(type);
    dns_create_header();
    int offset = 0;
    char response[513] = {0};
    offset = createResponse(offset, response);
    printf(")))))))))))))))))))))))\n");
    struct DNS_RR temp, MX_NAME;
    int MXpos = -1;
    memset(&temp, 0, sizeof(struct DNS_RR));
    memset(&MX_NAME, 0, sizeof(struct DNS_RR));
    buildRR(&temp, num, response, offset);
    printf("chulaile\n");

    if (temp.type == htons(12))
        printHex(temp.PTRName,temp.data_len);

    offset = createRRResponse(offset,response,temp);
    if(dnsCache[num].type == 15) {
        for (int i = 0; i < local_cache_num; ++i) {
            if (strcmp(dnsCache[num].MXName, dnsCache[i].SearchName) == 0 && dnsCache[i].type==1) {
                MXpos = i;
                break;
            }
        }
        printf("%d\n",MXpos);
        if (MXpos != -1) {
            buildRR(&MX_NAME, MXpos, response, offset);
            offset = createRRResponse(offset, response, MX_NAME);
        }
    }


    sendto(udpSock,response,offset,0,(struct sockaddr *)&client_addr, sizeof(struct sockaddr));

}

void dns_parse_query(char* buffer){
    unsigned char *ptr = buffer;
    dnsHeader.id = (*(unsigned short int *) ptr);
    ptr += 2;
    int flags = *(unsigned short int *) ptr;
    //dnsHeader.flags = flags;
    int bit = (flags >> 9) % 2;  // 获取指定位置的二进制位（从右往左，最低位为0）
    if (bit == 1) {
        printf("The received message has been truncated!");
        return;
    }

    char qname[128];
    bzero(qname, sizeof(qname));

    int len = 0;
    ptr += 10;
    dns_parse_QueryName(buffer, ptr,qname,&len);

    dnsQuery.name = (char *) calloc(strlen(qname) + 1, 1);
    memcpy(dnsQuery.name, qname, strlen(qname));

    ptr += (len+2);
    dnsQuery.qtype = *(unsigned short *) ptr;
    printf("%s   %d   %u\n",dnsQuery.name, len, dnsQuery.qtype);
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

        for (int i = 0; i < allRRNum; i++) {

            len = 0;
            if(!times) {
                dns_parse_name(net_server_response, ptr, net_server_return_domain, &len);
                times++;
            }
            dnsRr[i].SearchName = (char *) calloc(strlen(net_server_return_domain) + 1, 1);
            memcpy(dnsRr[i].SearchName, net_server_return_domain, strlen(net_server_return_domain));


            ptr += 2;
            dnsRr[i].type = htons(*(unsigned short *) ptr);

            ptr += 4;
            dnsRr[i].ttl = htonl(*(int *) ptr);

            ptr += 4;
            dnsRr[i].data_len = ntohs(*(unsigned short *) ptr);

            if (dnsRr[i].type == DNS_MX) {
                dnsRr[i].preference = ntohs(*(unsigned short *) ptr);
                ptr+=2;
            }
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
                bzero(cname, sizeof(cname));
                len = 0;
                dns_parse_name(net_server_response, ptr, cname, &len);
                dnsRr[i].MXName = (char *) calloc(strlen(cname) + 1, 1);
                memcpy(dnsRr[i].MXName, cname, strlen(cname));
                ptr += dnsRr[i].data_len;
            }   else if (dnsRr[i].type == DNS_PTR) {
                bzero(cname, sizeof(cname));
                len = 0;
                dns_parse_name(net_server_response, ptr, cname, &len);
                dnsRr[i].PTRName = (char *) calloc(strlen(cname) + 1, 1);
                memcpy(dnsRr[i].PTRName, cname, strlen(cname));
                ptr += dnsRr[i].data_len;
            }
        }
        for(int i = 0; i < allRRNum; i++){
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

        for (int i = 0; i < allRRNum; ++i) {
            if (strcmp(client_wanted_domain, dnsRr[i].SearchName) == 0 ) {
                dnsCache[local_cache_num].SearchName = dnsRr[i].SearchName;
                dnsCache[local_cache_num].ttl = dnsRr[i].ttl;
                time(&dnsCache[local_cache_num].updateTime);
                //printf("Current timestamp: %ld\n", dnsCache[local_cache_num].updateTime);
                dnsCache[local_cache_num].updateTime += dnsCache[local_cache_num].ttl;
                //printf("added timestamp: %ld\n", dnsCache[local_cache_num].updateTime);
                dnsCache[local_cache_num].data_len = dnsRr[i].data_len;
                dnsCache[local_cache_num].class = 1;
                dnsCache[local_cache_num].type = dnsRr[i].type;
                switch (dnsRr[i].type) {
                    case DNS_MX:
                        dnsCache[local_cache_num].preference = dnsRr[i].preference;
                        dnsCache[local_cache_num].MXName = dnsRr[i].MXName;
                        break;
                    case DNS_HOST:
                        dnsCache[local_cache_num].ip = dnsRr[i].ip;
                        break;
                    case DNS_CNAME:
                        dnsCache[local_cache_num].CName = dnsRr[i].CName;
                        break;
                    case DNS_PTR:
                        dnsCache[local_cache_num].PTRName = dnsRr[i].PTRName;
                        break;
                }
                appendStructToCSV("cache.csv", (struct DNS_RR *) &dnsCache[local_cache_num]);
                local_cache_num++;
            }
        }
        printf("\n\n%d\nMMMMMMMMMMMMMMMMMMMMMMMMMMM\n",local_cache_num);


    }


void appendStructToCSV(const char* filename, struct DNS_RR* dnsRr) {
    FILE* file = fopen(filename, "a");
    if (file == NULL) {
        printf("无法打开文件\n");
        return;
    }
    fprintf(file, "%s,%d,IN,", dnsRr->SearchName, dnsRr->ttl);

    if (dnsRr->type == 5) {
        fprintf(file, "CNAME,");
        fprintf(file, "%s\n", dnsRr->CName);
    } else if (dnsRr->type == 1) {
        fprintf(file, "A,");
        fprintf(file, "%s\n", dnsRr->ip);
    } else if (dnsRr->type == 15) {
        fprintf(file, "MX,");
        fprintf(file, "%d,", dnsRr->preference);
        fprintf(file, "%s\n", dnsRr->MXName);
    } else if(dnsRr->type == 12){
        fprintf(file, "PTR,");
        fprintf(file, "%s\n", dnsRr->PTRName);
    } else{
        printf("error\n\n");
    }




    fclose(file);
}

void initSystem(){
    local_cache_num = 0;
    next_server_ip = "114.114.114.114";
    memset(net_server_return_domain, 0 ,sizeof (net_server_return_domain));
    net_server_return_domain[0] = '!';

    FILE *fp = fopen("cache.csv", "r");
    if (fp == NULL) {
        fprintf(stderr, "fopen() failed.\n");
        exit(EXIT_FAILURE);
    }

    char row[80];
    char *token;

    while (fgets(row, 80, fp) != NULL) {
        row[strcspn(row, "\n")] = '\0'; // 去除行末的换行符

        token = strtok(row, ",");
        dnsCache[local_cache_num].SearchName = (char *) calloc(strlen(token) + 1, 1);
        memcpy(dnsCache[local_cache_num].SearchName, token, strlen(token));
       //printf("SearchName: %s\n", dnsCache[local_cache_num].SearchName);


        token = strtok(NULL, ",");
        dnsCache[local_cache_num].ttl = atoi(token);
        //printf("ttl: %d\n", dnsCache[local_cache_num].ttl);
        time(&dnsCache[local_cache_num].updateTime);
        //printf("Current timestamp: %ld\n", dnsCache[local_cache_num].updateTime);
        dnsCache[local_cache_num].updateTime += dnsCache[local_cache_num].ttl;
        //printf("added timestamp: %ld\n", dnsCache[local_cache_num].updateTime);

        token = strtok(NULL, ",");
        if (!strcmp(token, "IN")){
            dnsCache[local_cache_num].class = 1;
        }
        //printf("class: %d\n", dnsCache[local_cache_num].class);


        token = strtok(NULL, ",");
        //printf("%s\n", token);
        if (strcmp(token, "CNAME") == 0) {
            dnsCache[local_cache_num].type = 5;

            token = strtok(NULL, ",");

            dnsCache[local_cache_num].CName = (char *) calloc(strlen(token) + 1, 1);
            memcpy(dnsCache[local_cache_num].CName, token, strlen(token));


            //printf("CNAME: %s\n\n", dnsCache[local_cache_num].CName);
            // 在此处添加处理 CNAME 类型的代码
        } else if (strcmp(token, "A") == 0) {
            dnsCache[local_cache_num].type = 1;

            token = strtok(NULL, ",");

            dnsCache[local_cache_num].ip = (char *) calloc(strlen(token) + 1, 1);
            memcpy(dnsCache[local_cache_num].ip, token, strlen(token));
            // 在此处添加处理 A 类型的代码
            //printf("IP: %s\n\n", dnsCache[local_cache_num].ip);
        } else if (strcmp(token, "MX") == 0) {
            dnsCache[local_cache_num].type = 15;

            token = strtok(NULL, ",");
            dnsCache[local_cache_num].preference = atoi(token);
            token = strtok(NULL, ",");
            dnsCache[local_cache_num].MXName = (char *) calloc(strlen(token) + 1, 1);
            memcpy(dnsCache[local_cache_num].MXName, token, strlen(token));
            // 在此处添加处理 MX 类型的代码
           // printf("MXName: %s\n\n", dnsCache[local_cache_num].MXName);
        } else if(strcmp(token, "PTR") == 0){
            dnsCache[local_cache_num].type = 12;

            token = strtok(NULL, ",");

            dnsCache[local_cache_num].PTRName = (char *) calloc(strlen(token)+1 , 1);
            memcpy(dnsCache[local_cache_num].PTRName, token, strlen(token));
            //printf("PTRName: %s\n\n", dnsCache[local_cache_num].PTRName);
        } else{
            printf("error\n\n");
        }
        local_cache_num++;
    }
    existCache = local_cache_num;
    fclose(fp);
}

void sendto_AuthToClient(){
    sendto(udpSock, net_server_response, net_server_response_length, 0, (struct sockaddr *)&client_addr, sizeof(struct sockaddr));
}

int main() {

    clock_t start_time = clock();
    clock_t process_time;
    clock_t end_time;
    initUdpSock();
    while (1) {

        initSystem();
        receive_client();
        get_client_wanted_domain();
        dns_create_question(&dnsQuery, client_wanted_domain);
        int isCached = 0;
        for (int i = 0; i < local_cache_num; ++i) {
            if (strcmp(dnsCache[i].SearchName, client_wanted_domain) == 0 && dnsCache[i].type == ntohs(dnsQuery.qtype)) {
                isCached = i;
            }
        }
        int times = 0;
        if (isCached == 0) {
            while (strcmp(net_server_return_domain, client_wanted_domain) != 0) {
                process_time = clock();
                initTcpSock();
                ask_net_server();
                receive_net_server();
                end_time = clock();
                double execution_time = (double)(end_time - process_time) / CLOCKS_PER_SEC;
                printf("查询到第%d台服务器了，它的ip是%s，响应时间是：%f秒\n",times+1,next_server_ip, execution_time);
                parse_server_response();
                times++;
            }
            sendto_AuthToClient();
            double execution_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
            printf("总响应时间是：%f秒\n",execution_time);
            memset(net_server_return_domain, 0, sizeof(net_server_return_domain));
            net_server_return_domain[0] = '!';
            // forward_dns_query(client_query_len, client_query_packet);
        } else{
            printf("本地有缓存\n");
            end_time = clock();
            sendto_client(isCached, dnsQuery.qtype);
            double execution_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
            printf("总响应时间是：%f秒\n", execution_time);

        }
        printf("完成了一次查询\n");
    }

}
