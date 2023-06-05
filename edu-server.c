//
// Created by 杨锐智 on 2023/6/2.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "DNS.h"

#define YRZ_SERVER_PORT 53


struct DNS_Query dnsQuery;

struct DNS_Header dnsHeader;

char* searchName;

int yrz_cache_num;

struct DNS_RR dnsRr;
struct DNS_RR yrzDnsCache[100];

void initCsv() {
    yrz_cache_num = 0;
    FILE *fp = fopen("edu.csv", "r");
    if (fp == NULL) {
        fprintf(stderr, "fopen() failed.\n");
        exit(EXIT_FAILURE);
    }

    char row[80];//最多每行读 80 个字符
    char *token;


    while (fgets(row,80,fp) !=NULL) {
        //www.yrz.com
        row[strcspn(row, "\n")] = '\0'; // 去除行末的换行符
        token = strtok(row, ","); //分解读进来的row，","为分隔符
        yrzDnsCache[yrz_cache_num].SearchName = (char *) calloc(strlen(token)+1,1);
        memcpy(yrzDnsCache[yrz_cache_num].SearchName,token, strlen(token));

        //3042（ttl）
        token = strtok(NULL,",");
        yrzDnsCache[yrz_cache_num].ttl = atoi(token);

        time(&yrzDnsCache[yrz_cache_num].updateTime);
        yrzDnsCache[yrz_cache_num].updateTime += yrzDnsCache[yrz_cache_num].ttl;


        //IN
        token = strtok(NULL, ",");
        if (!strcmp(token, "IN")){
            yrzDnsCache[yrz_cache_num].class = 1;
        }


        //四种类型
        token = strtok(NULL, ",");
        if(strcmp(token,"CNAME") == 0){
            yrzDnsCache[yrz_cache_num].type = 5;

            token = strtok(NULL, ",");

            //yrz.com(CNAME)
            yrzDnsCache[yrz_cache_num].CName = (char *) calloc(strlen(token) + 1, 1);
            memcpy(yrzDnsCache[yrz_cache_num].CName,token, strlen(token));

        } else if (strcmp(token, "A") == 0){
            yrzDnsCache[yrz_cache_num].type = 1;

            token = strtok(NULL, ",");

            //1.1.1.1(A)
            yrzDnsCache[yrz_cache_num].ip = (char *) calloc(strlen(token) + 1, 1);
            memcpy(yrzDnsCache[yrz_cache_num].ip,token, strlen(token));

        } else if (strcmp(token, "MX") == 0) {
            yrzDnsCache[yrz_cache_num].type = 15;

            //10,preference优先级
            token = strtok(NULL, ",");
            yrzDnsCache[yrz_cache_num].preference = atoi(token);

            //MX邮件服务器域名
            token = strtok(NULL, ",");
            yrzDnsCache[yrz_cache_num].MXName = (char *) calloc(strlen(token) + 1, 1);
            memcpy(yrzDnsCache[yrz_cache_num].MXName,token, strlen(token));

        } else if(strcmp(token, "PTR") == 0){
            yrzDnsCache[yrz_cache_num].type = 12;

            //one.one.one.one
            token = strtok(NULL, ",");

            yrzDnsCache[yrz_cache_num].PTRName = (char *) calloc(strlen(token) + 1, 1);
            memcpy(yrzDnsCache[yrz_cache_num].PTRName, token, strlen(token));

        }else{
            printf("error\n\n");
        }

        yrz_cache_num++;

    }
    fclose(fp);
    printf("文件已全部读入\n");
}



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
    if(dnsQuery.qtype == htons(15)) {//邮件判断
        dnsHeader.additionalNum = htons(1);
    } else{
        dnsHeader.additionalNum = htons(0);
    }
}
void buildRR(struct DNS_RR *dnsRr, int num, char* response,int responseLen){

    printf("builedRR     %s\n",yrzDnsCache[num].SearchName);
    dnsRr->SearchName = malloc(yrzDnsCache[num].SearchNameLen + 2 +100);
    dnsRr->SearchNameLen = strlen(yrzDnsCache[num].SearchName) + 2;
    const char delim[2] = ".";
    char *qname =dnsRr->SearchName; //用于填充内容用的指针

    //strdup先开辟大小与hostname同的内存，然后将hostname的字符拷贝到开辟的内存上
    char *new_hostname = strdup(yrzDnsCache[num].SearchName); //复制字符串，调用malloc
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
        free(dnsRr->SearchName);
        dnsRr->SearchName = malloc( 3 +100);
        dnsRr->SearchName[0]= 0xc0;
        dnsRr->SearchName[1]= position;
        dnsRr->SearchName[2] = '\0';
    }

    dnsRr->class = htons(1);
    dnsRr->type = htons(yrzDnsCache[num].type);
    dnsRr->ttl = htonl(yrzDnsCache[num].ttl);



    if (yrzDnsCache[num].type  == 1){
        dnsRr->data_len= 4;
        unsigned char ip_parts[4];
        uint32_t dns_address = 0;
        printf("%s\n",yrzDnsCache[num].ip);
        sscanf(yrzDnsCache[num].ip, "%hhu.%hhu.%hhu.%hhu", &ip_parts[0], &ip_parts[1], &ip_parts[2], &ip_parts[3]);
        dns_address = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3];
        dnsRr->ip = malloc(sizeof (unsigned char *)&dns_address +100);
        uint32_t network_order = htonl(dns_address);
        memcpy(dnsRr->ip, &network_order, sizeof(network_order));
        printHex(dnsRr->ip,4);

    }else if(yrzDnsCache[num].type  == 5){
        //CNAME
        printf("CNAME   %s\n",yrzDnsCache[num].CName);

        dnsRr->data_len = strlen (yrzDnsCache[num].CName)+2;
        const char delim[2] = ".";
        dnsRr->CName = malloc(sizeof (dnsRr->data_len) +100);
        char *qname = dnsRr->CName; //用于填充内容用的指针

        //strdup先开辟大小与hostname同的内存，然后将hostname的字符拷贝到开辟的内存上
        char *new_hostname = strdup(yrzDnsCache[num].CName); //复制字符串，调用malloc
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
    } else if(yrzDnsCache[num].type  == 15){
        //MX
        dnsRr->preference = htons(yrzDnsCache[num].preference);
        dnsRr->data_len = strlen (yrzDnsCache[num].MXName)+4;
        dnsRr->MXName = malloc(sizeof (dnsRr->data_len) +100);
        const char delim[2] = ".";
        char *qname = dnsRr->MXName; //用于填充内容用的指针

        //strdup先开辟大小与hostname同的内存，然后将hostname的字符拷贝到开辟的内存上
        char *new_hostname = strdup(yrzDnsCache[num].MXName); //复制字符串，调用malloc
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
    } else if(yrzDnsCache[num].type  == 12){
        //PTR
        printf("%s\n",yrzDnsCache[num].PTRName);
        dnsRr->data_len = strlen (yrzDnsCache[num].PTRName) + 2;
        dnsRr->PTRName = malloc(sizeof (dnsRr->data_len) +100);
        memset(dnsRr->PTRName,0,sizeof (dnsRr->PTRName));
        const char delim[2] = ".";
        char *qname = dnsRr->PTRName; //用于填充内容用的指针
        printf("9999999999999999\n");
        //strdup先开辟大小与hostname同的内存，然后将hostname的字符拷贝到开辟的内存上
        char *new_hostname = strdup(yrzDnsCache[num].PTRName); //复制字符串，调用malloc
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
    }
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
    dns_create_header();//头部直接抄就行
    dns_create_question(&dnsQuery,searchName);//构建query部分
    printf("域名可以出来啦：%s\n",searchName);

    char response[513] = {0};
    int  responseLen = 0;
    responseLen = createResponse(responseLen,response);//这一步相当于把之前的header和 query合体

    //遍历一遍从文件读进来的结构体yrzDnsCache，然后找到与searchName匹配的那个序号
    int isCached = -1;
    for (int i = 0; i < yrz_cache_num; ++i) {
        if (strcmp(yrzDnsCache[i].SearchName, searchName) == 0 && yrzDnsCache[i].type == ntohs(dnsQuery.qtype)) {
            isCached = i;
        }
    }
    printf("需要匹配的序号：%d\n",isCached);
//
//    char copyName[100] = ".";
//    char copyName1[100];
//    strcpy(copyName1, searchName); // Create a copy of searchName
//    strcat(copyName, copyName1);
//
//    char *ltdName = strrchr(copyName, '.');



//    if (ltdName != NULL){
//        *ltdName = '\0'; // 把最后一个"."置 0
//        char *subName = strrchr(copyName,'.');
//        if (subName != NULL){
//            *subName = '\0';
//            char *thirdLTD = strrchr(copyName,'.');
//            printf("thirdLTD 指针的值：%s\n", thirdLTD);
//            if (thirdLTD != NULL) {
//                printf("倒数第三个顶级域名是：%s\n", thirdLTD + 1);
//                dns_create_reply(thirdLTD+1,response,responseLen);
//            }
//        }
//    }else {
//        printf("无效的域名\n");
//    }

    //临时的temp和MX_NAME 分别用于MX和非MX
    struct DNS_RR temp1, MX_NAME;
    int MXpos = -1;
    memset(&temp1, 0, sizeof(struct DNS_RR));
    memset(&MX_NAME, 0, sizeof(struct DNS_RR));
    buildRR(&temp1, isCached, response, responseLen);
    responseLen = createRRResponse(responseLen,response,temp1);
    //printf("%d",responseLen);


    //上面只有返回MX 邮件服务器的域名，接下来的操作是判断 MX 邮件的 A 记录
    if(yrzDnsCache[isCached].type == 15) {
        for (int i = 0; i < yrz_cache_num; ++i) {
            if (strcmp(yrzDnsCache[isCached].MXName, yrzDnsCache[i].SearchName) == 0 && yrzDnsCache[i].type==1) {
                MXpos = i;
                break;
            }
        }
        printf("%d\n",MXpos);
        if (MXpos != -1) {
            buildRR(&MX_NAME, MXpos, response, responseLen);
            responseLen = createRRResponse(responseLen, response, MX_NAME);
        }
    }

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
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.8");
    server_addr.sin_port = htons(YRZ_SERVER_PORT);

    
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

    printf("yrz DNS server started...\n");

    initCsv();//将文件读入

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
