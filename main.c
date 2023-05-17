//
// Created by jialun zhang on 17/5/2023.
//
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <time.h>

#define DNS_SERVER_PORT     53
#define DNS_SERVER_IP       "114.114.114.114"
#define DNS_HOST			0x01
#define DNS_CNAME			0x05

struct DNS_Header{
    unsigned short id; //2字节（16位）
    unsigned short flags;

    unsigned short questionsNum; //问题数
    unsigned short answerNum; //回答数
    unsigned short authorityNum;
    unsigned short additionalNum;
};

struct DNS_Query{
    unsigned char *name;        //要查询的主机名（长度不确定）
    unsigned short qtype;
    unsigned short qclass;
    int length;     //主机名的长度
};

struct DNS_RR{
    unsigned char *name;
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
    unsigned char *ip;
};




int dns_create_header(struct DNS_Header *header)
{
    if(header == NULL){
        printf("There is some problem in The DNS header struct!");
        return -1;
    }

    memset(header, 0, sizeof(struct DNS_Header));

    //id用随机数,种子用time(NULL),表明生成随机数的范围
    srandom(time(NULL)); // 线程不安全
    header->id = random()& 0xFFFF;

    //网络字节序（大端）地址低位存数据高位
    //主机(host)字节序转网络(net)字节序
    header->flags = htons(0x100);   //一般询问报文的flags是0x100
    header->questionsNum = htons(1);    //询问报文的问题一般只有一个
    return 0;
}

void dns_create_question(struct DNS_Query *question, const char *hostname, int type)
{
    if(question == NULL || hostname == NULL) {
        printf("There is some problem in The DNS header struct or The domain you want to search!");
        return ;
    }

    memset(question, 0, sizeof(struct DNS_Query));

    //内存空间长度：hostname长度 + 结尾\0 再多给一个空间
    question->name = malloc(strlen(hostname) + 2);
    if(question->name == NULL)
    {
        printf("内存分配出错了");
        return ;
    }

    question->length =  (int)strlen(hostname) + 2;

    //查询类型1表示获得IPv4地址
    question->qtype = htons(type);
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
int dns_build_request(struct DNS_Header *header, struct DNS_Query *question, char *request, int initLen){
    if (header == NULL || question == NULL || request == NULL)
    {
        printf("dns报文没有构建成功");
        return -1;
    }

    memset(request, 0, initLen);

    //header -> request
    memcpy(request, header, sizeof(struct DNS_Header));
    int offset = sizeof(struct DNS_Header);

    //Queries部分字段写入到request中，question->length是question->name的长度
    memcpy(request + offset, question->name, question->length);
    offset += question->length;

    memcpy(request + offset, &question->qtype, sizeof(question->qtype));
    offset += sizeof(question->qtype);

    memcpy(request + offset, &question->qclass, sizeof(question->qclass));
    offset += sizeof(question->qclass);



    return offset; //返回request数据的实际长度
}

int is_pointer(int in) {
    return ((in & 0xC0) == 0xC0);
}

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


int dns_parse_response(char* buffer) {

    unsigned char *ptr = buffer;

    ptr += 2;
    int flags = ntohs(*(unsigned short int *) ptr);
    int bit = (flags >> 9) % 2;  // 获取指定位置的二进制位（从右往左，最低位为0）
    if (bit == 1) {
        printf("The received message has been truncated!");
        return -1;
    }

    struct DNS_Query dnsQuery;
    ptr += 4;
    int answersNum = ntohs(*(unsigned short *) ptr);
    ptr += 2;
    int authoritiesNum = ntohs(*(unsigned short *) ptr);
    ptr += 2;
    int additionsNum = ntohs(*(unsigned short *) ptr);
    int allRRNum = answersNum + authoritiesNum + additionsNum;

    ptr += 2;

    //将问题报文中的网址直接跳过，放到后面读取
    while (1) {
        int flag = (int)ptr[0];
        ptr += (flag + 1);
        if (flag == 0) break;
    }
    ptr += 4;



    //到了回答区域
    char cname[128], aname[128], ip[20], netip[4];
    int len, type, ttl, datalen;

    int cnt = 0;

    struct DNS_RR dnsRr[allRRNum];
    memset(dnsRr, 0, allRRNum * sizeof(struct DNS_RR));
    for (int i = 0; i < answersNum; i++) {

        bzero(aname, sizeof(aname));
        len = 0;

        dns_parse_name(buffer, ptr, aname, &len);
        ptr += 2;

        type = htons(*(unsigned short*)ptr);
        ptr += 4;

        ttl = htons(*(unsigned short*)ptr);
        ptr += 4;

        datalen = ntohs(*(unsigned short*)ptr);
        ptr += 2;

        if (type == DNS_CNAME) {

            bzero(cname, sizeof(cname));
            len = 0;
            dns_parse_name(buffer, ptr, cname, &len);
            ptr += datalen;

        }
        else if (type == DNS_HOST) {

            bzero(ip, sizeof(ip));

            if (datalen == 4) {
                memcpy(netip, ptr, datalen);
                inet_ntop(AF_INET, netip, ip, sizeof(struct sockaddr));

                printf("%s has address %s\n", aname, ip);
                printf("\tTime to live: %d minutes , %d seconds\n", ttl / 60, ttl % 60);

                dnsRr[cnt].name = (char*)calloc(strlen(aname) + 1, 1);
                memcpy(dnsRr[cnt].name, aname, strlen(aname));

                dnsRr[cnt].ip = (char*)calloc(strlen(ip) + 1, 1);
                memcpy(dnsRr[cnt].ip, ip, strlen(ip));

                cnt++;
            }

            ptr += datalen;
        }
    }
}

int main(){

    printf("please input the domain you want to search:\n");
    char domain[512];
    scanf("%s",domain);

    char temp[10];
    // 获取用户输入的类型
    printf("请输入记录类型（CNAME、A、MX）：");
    scanf("%s", temp);
    int type;
    // 根据类型输出相应的值
    if (strcmp(temp, "CNAME") == 0) {
        type = 5;
        printf("CNAME\n");
        // 在此处添加处理 CNAME 类型的代码
    } else if (strcmp(temp, "A") == 0) {
        type = 1;
        printf("A\n");
        // 在此处添加处理 A 类型的代码
    } else if (strcmp(temp, "MX") == 0) {
        type = 15;
        printf("MX\n");
        // 在此处添加处理 MX 类型的代码
    } else {
        printf("无效的类型\n");
    }

    //1.创建UDP socket
    //网络层ipv4, 传输层用udp
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
    {
        return -1;
    }

    //2.socket结构体填充数据
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr)); //将结构体数组清空
    servaddr.sin_family = AF_INET;  //选择ipv4通信
    servaddr.sin_port = htons(DNS_SERVER_PORT);  //选择服务器的53端口
    inet_pton(AF_INET, DNS_SERVER_IP, &servaddr.sin_addr.s_addr);//将目标地址的ip转化成网络字节序的二进制形式

    struct DNS_Header header = {0}; //清零dns头部
    dns_create_header(&header); //具体构建过程

    struct DNS_Query question = {0}; //清零dns问题部分
    dns_create_question(&question, domain, type);

    char request[1024] = {0};
    int len = dns_build_request(&header, &question, request, 1024);

    //4.通过sockfd发送DNS请求报文
    sendto(sockfd, request, len, 0, (struct sockaddr *)&servaddr, sizeof(struct sockaddr));
    //5.接受DNS服务器的响应报文
    //addr和addr_len是输出参数
    char response[1024] = {0};
    struct sockaddr_in addr;
    size_t addr_len = sizeof(struct sockaddr_in);
    //5.接受DNS服务器的响应报文
    //addr和addr_len是输出参数

    int n = recvfrom(sockfd, response, sizeof(response), 0, (struct sockaddr *)&addr, (socklen_t *)&addr_len);
    dns_parse_response(response);
}