//
// Created by 杨锐智 on 2023/5/31.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "DNS.h"

#define ROOT_SERVER_PORT 53


struct DNS_Query dnsQuery;

struct DNS_Header dnsHeader;

char* searchName;

struct DNS_RR dnsRr;

int createResponse(int offset, char *request);

void intToNetworkByteArray(int value, uint8_t* array) {
    uint16_t networkValue = htons((uint16_t)value);
    array[1] = (networkValue >> 8) & 0xFF;  // 高字节
    array[0] = networkValue & 0xFF;         // 低字节
}

void dns_create_header(){
    //dnsheader的id在解析中已经记录了。
    dnsHeader.flags = htons(0x8180);
    dnsHeader.questionsNum = htons(1);    //询问报文的问题一般只有一个
    dnsHeader.answerNum = htons(0);
    dnsHeader.authorityNum = htons(1);
    dnsHeader.additionalNum = htons(0);
}

void dns_create_reply(char* subName,char* response,int responseLen){
    struct DNS_RR *reply = &dnsRr;
    printf("%s",subName);

    memset(reply, 0, sizeof(struct DNS_RR));
    int subNameLen = strlen(subName);
    int position=0;
    for (int i = 0; i < responseLen; ++i) {
        if(response[i]==subName[0]){
            int temp = 1;
            for (int j = 0; j < subNameLen; ++j) {
                if(response[i+j]!=subName[j]) {
                    temp = 0;
                }
            }
            if(temp == 1){
                position = i;
                position--;
                break;
            }
        }
    }
    //printf("%d",position);
    if (position != 0) {
        dnsRr.SearchName = malloc( 3);
        dnsRr.SearchNameLen = 2;
        dnsRr.SearchName[0]= 0xc0;
        dnsRr.SearchName[1]= position;
    }
    else
    {
        dnsRr.SearchName = malloc(subNameLen + 2);
        dnsRr.SearchNameLen = subNameLen + 2;
        const char delim[2] = ".";
        char *qname =dnsRr.SearchName; //用于填充内容用的指针

        //strdup先开辟大小与hostname同的内存，然后将hostname的字符拷贝到开辟的内存上
        char *new_hostname = strdup(subName); //复制字符串，调用malloc
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
    //printHex(dnsRr.SearchName,dnsRr.SearchNameLen);
    dnsRr.type= htons(1);
    dnsRr.class = htons(1);
    dnsRr.ttl = htonl(172800);
    dnsRr.data_len = htons(4);
    uint32_t dns_address = 0;

    if(!strcmp(subName,"yrz")){
        char ip[] = "114.114.114.114";
        unsigned char ip_parts[4];
        sscanf(ip, "%hhu.%hhu.%hhu.%hhu", &ip_parts[0], &ip_parts[1], &ip_parts[2], &ip_parts[3]);
        dns_address = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3];

    }
    dnsRr.ip = (unsigned char *)&dns_address;
    uint32_t network_order = htonl(dns_address);

// 将network_order的字节表示复制到ip指针
    memcpy(dnsRr.ip, &network_order, sizeof(network_order));
    //snprintf(dnsRr.ip, sizeof(dnsRr.ip), "%08X", dns_address);
    //printHex(dnsRr.ip,4);

}

int createResponse(int offset, char *request){
    if(offset == 0) {
        memcpy(request, &dnsHeader, sizeof(struct DNS_Header));
        offset = sizeof(struct DNS_Header);

        //Queries部分字段写入到request中，question->length是question->name的长度
        memcpy(request + offset, dnsQuery.name, dnsQuery.length);
        offset += dnsQuery.length;

        memcpy(request + offset, &dnsQuery.qtype, sizeof(dnsQuery.qtype));
        offset += sizeof(dnsQuery.qtype);

        memcpy(request + offset, &dnsQuery.qclass, sizeof(dnsQuery.qclass));
        offset += sizeof(dnsQuery.qclass);
    } else{
        memcpy(request + offset, dnsRr.SearchName, dnsRr.SearchNameLen);
        offset += dnsRr.SearchNameLen;

        memcpy(request + offset, &dnsRr.type, sizeof(dnsRr.type));
        offset += sizeof(dnsRr.type);

        memcpy(request + offset, &dnsRr.class, sizeof(dnsRr.class));
        offset += sizeof(dnsRr.class);

        memcpy(request + offset, &dnsRr.ttl, sizeof(dnsRr.ttl));
        offset += sizeof(dnsRr.ttl);

        memcpy(request + offset, &dnsRr.data_len, sizeof(dnsRr.data_len));
        offset += sizeof(dnsRr.data_len);

        memcpy(request + offset, dnsRr.ip, 4);
        offset += 4;
    }
    printHex(request,offset);
    return offset; //返回request数据的实际长度

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

    searchName = (char *) calloc(strlen(qname) + 1, 1);
    memcpy(searchName, qname, strlen(qname));

    ptr += (len+2);
    dnsQuery.qtype = *(unsigned short *) ptr;
    printf("nbnbnbnbnbnbnbnb\n");
    printf("%s   %d    %u\n",qname, len, dnsQuery.qtype);
}

// 处理 DNS 查询报文并返回响应报文
void handle_dns_query(int client_sock) {
    // 接收查询报文长度字段
    uint16_t query_length;
    if (recv(client_sock, &query_length, sizeof(query_length), 0) < 0) {
        perror("Receive query length field failed");
        exit(1);
    }
    query_length = ntohs(query_length);

    // 接收查询报文
    char query_packet[1024];
    memset(query_packet, 0, sizeof(query_packet));
    if (recv(client_sock, query_packet, query_length, 0) < 0) {
        perror("Receive query packet failed");
        exit(1);
    }

    printHex(query_packet,query_length);

    dns_parse_query(query_packet);
    dns_create_header();
    dns_create_question(&dnsQuery,searchName);
    char response[513] = {0};
    int  responseLen = 0;
    responseLen = createResponse(responseLen,response);
    printf("888888999999%s\n",searchName);

    char copyName[100];
    strcpy(copyName, searchName); // Create a copy of searchName

    char *ltdName = strrchr(copyName, '.');

    printf("000000%s",ltdName);

    if (ltdName != NULL) {
        *ltdName = '\0'; // 用0符号替换"."
        char *subName = strrchr(copyName, '.'); // Find the last dot before the domain name
        if (subName != NULL) {
            printf("倒数第二个顶级域名是：%s\n", subName + 1);
            dns_create_reply(subName+1,response,responseLen);
        }
    }else {
        printf("无效的域名\n");
    }


   responseLen = createResponse(responseLen,response);
    printf("%d",responseLen);


    uint8_t temp[2];

    // 添加长度字段
    intToNetworkByteArray(responseLen,temp);
    size_t new_packet_length = responseLen + sizeof(temp);
    char new_packet[new_packet_length + 1];

    memcpy(new_packet, temp, sizeof(temp));
    memcpy(new_packet + sizeof(temp), response, responseLen + 1);

    printHex(new_packet,responseLen+2);


    // 发送响应报文
    if (send(client_sock, new_packet, responseLen+2, 0) < 0) {
        perror("Send response packet failed");
        exit(1);
    }
}

int main() {
    int sock;
    struct sockaddr_in server_addr, client_addr;

    // 创建 TCP 套接字
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    // 设置根服务器地址
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(ROOT_SERVER_PORT);



    // 设置 SO_REUSEADDR 套接字选项
    //int optval = 1;
    //if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
    //    perror("Setting socket option failed");
    //    exit(1);
    //}

    // 绑定套接字到根服务器地址
    if (bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Binding failed");
        exit(1);
    }

    // 监听连接请求
    if (listen(sock, 10) < 0) {
        perror("Listen failed");
        exit(1);
    }

    printf("com DNS server started...\n");

    while (1) {
        int client_len = sizeof(client_addr);
        int client_sock = accept(sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("Accept connection failed");
            exit(1);
        }

        printf("Accepted connection from client\n");

        // 处理 DNS 查询报文并返回响应报文
        handle_dns_query(client_sock);

        // 关闭客户端连接
        close(client_sock);
    }

    // 关闭套接字
    close(sock);

    return 0;
}
