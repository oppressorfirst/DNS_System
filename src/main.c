#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "DNS.h"

#define DNS_SERVER_PORT     53
#define DNS_SERVER_IP       "127.0.0.2"
#define DNS_HOST			0x01
#define DNS_CNAME			0x05
#define DNS_MX              0x0f
#define DNS_PTR             0x0c

int noSuchName;


int dns_create_header(struct DNS_Header *header)
{
    if(header == NULL){
        printf("There is some problem in The DNS header struct!");
        return -1;
    }

    memset(header, 0, sizeof(struct DNS_Header));

    
    srandom(time(NULL)); 
    header->id = random()& 0xFFFF;

    
    
    header->flags = htons(0x100);   
    header->questionsNum = htons(1);    
    return 0;
}

void dns_create_question(struct DNS_Query *question, const char *hostname, int type)
{
    if(question == NULL || hostname == NULL) {
        printf("There is some problem in The DNS header struct or The domain you want to search!");
        return ;
    }

    memset(question, 0, sizeof(struct DNS_Query));

    
    question->name = malloc(strlen(hostname) + 2);
    if(question->name == NULL)
    {
        printf("内存分配出错了");
        return ;
    }

    question->length =  (int)strlen(hostname) + 2;

    
    question->qtype = htons(type);
    
    question->qclass = htons(1);

    
    
    const char delim[2] = ".";
    char *qname = question->name; 

    
    char *new_hostname = strdup(hostname); 
    
    char *token = strtok(new_hostname, delim);

    while (token != NULL)
    {

        size_t len = strlen(token);  
        *qname = len;  
        qname++;  

        strncpy(qname, token, len + 1);  
        qname += len;  

        token = strtok(NULL, delim);  
    }

    free(new_hostname);  
}

int dns_build_request(struct DNS_Header *header, struct DNS_Query *question, char *request, int initLen){
    if (header == NULL || question == NULL || request == NULL)
    {
        printf("dns报文没有构建成功");
        return -1;
    }

    memset(request, 0, initLen);

    
    memcpy(request, header, sizeof(struct DNS_Header));
    int offset = sizeof(struct DNS_Header);

    
    memcpy(request + offset, question->name, question->length);
    offset += question->length;

    memcpy(request + offset, &question->qtype, sizeof(question->qtype));
    offset += sizeof(question->qtype);

    memcpy(request + offset, &question->qclass, sizeof(question->qclass));
    offset += sizeof(question->qclass);



    return offset; 
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

void dns_parse_response(char* buffer) {

    unsigned char *ptr = buffer;

    ptr += 2;
    int flags = ntohs(*(unsigned short int *) ptr);
    noSuchName = flags;
    if (noSuchName == 0x8183) {
        printf("你想查的域名我们没得！\n");
        return;
    }
    int bit = (flags >> 9) % 2;  
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

    
    while (1) {
        int flag = (int) ptr[0];
        ptr += (flag + 1);
        if (flag == 0) break;
    }
    ptr += 4;



    
    char cname[128], aname[128], ip[20], netip[20];
    int len;


    struct DNS_RR dnsRr[allRRNum];
    memset(dnsRr, 0, allRRNum * sizeof(struct DNS_RR));

    for (int i = 0; i < allRRNum; i++) {

        bzero(aname, sizeof(aname));
        len = 0;

        dns_parse_name(buffer, ptr, aname, &len);


        ptr += 2;
        dnsRr[i].SearchName = (char *) calloc(strlen(aname) + 1, 1);
        memcpy(dnsRr[i].SearchName, aname, strlen(aname));


        dnsRr[i].type = htons(*(unsigned short *) ptr);


        ptr += 4;
        dnsRr[i].ttl = htonl(*(int *) ptr);

        ptr += 4;
        dnsRr[i].data_len = ntohs(*(unsigned short *) ptr);

        ptr += 2;
        if (dnsRr[i].type == DNS_MX) {
            dnsRr[i].preference = ntohs(*(unsigned short *) ptr);
            ptr+=2;
        }

         if (dnsRr[i].type == DNS_CNAME) {
            bzero(cname, sizeof(cname));
            len = 0;
            dns_parse_name(buffer, ptr, cname, &len);
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
            }
            ptr += dnsRr[i].data_len;
        } else if (dnsRr[i].type == DNS_MX) {
            bzero(cname, sizeof(cname));
            len = 0;
            dns_parse_name(buffer, ptr, cname, &len);
            dnsRr[i].MXName = (char *) calloc(strlen(cname) + 1, 1);
            memcpy(dnsRr[i].MXName, cname, strlen(cname));
            ptr += dnsRr[i].data_len - 2;
        } else if (dnsRr[i].type == DNS_PTR) {
            bzero(cname, sizeof(cname));
            len = 0;
            dns_parse_name(buffer, ptr, cname, &len);
            dnsRr[i].PTRName = (char *) calloc(strlen(cname) + 1, 1);
            memcpy(dnsRr[i].PTRName, cname, strlen(cname));
            ptr += dnsRr[i].data_len;
        }
    }
    if (answersNum!=0) {
        printf("Answer:\n");
        for (int i = 0; i < answersNum; i++) {
            printf("%s, ", dnsRr[i].SearchName);
            printf("type: %d, ", dnsRr[i].type);
            printf("ttl: %d, ", dnsRr[i].ttl);
            if (dnsRr[i].CName != NULL)
                printf("CNAME: %s, ", dnsRr[i].CName);
            if (dnsRr[i].ip != NULL)
                printf("ip: %s, ", dnsRr[i].ip);
            if (dnsRr[i].MXName != NULL){
                printf("MX: %s, ", dnsRr[i].MXName);
            printf("MX preference: %d", dnsRr[i].preference);
        }
            if (dnsRr[i].PTRName != NULL)
                printf("PTR: %s, ", dnsRr[i].PTRName);
            printf("\n");
        }
        printf("\n");
    }
    if (authoritiesNum!=0) {
    printf("Authority Answer:\n");
    for(int i = answersNum; i < answersNum+authoritiesNum; i++){
        printf("%s, ",dnsRr[i].SearchName);
        printf("type: %d, ",dnsRr[i].type);
        printf("ttl: %d, ", dnsRr[i].ttl);
        if(dnsRr[i].CName != NULL)
            printf("CNAME: %s, ",dnsRr[i].CName);
        if(dnsRr[i].ip != NULL)
            printf("ip: %s, ", dnsRr[i].ip);
        if(dnsRr[i].MXName != NULL) {
            printf("MX: %s, ", dnsRr[i].MXName);
            printf("MX preference: %d", dnsRr[i].preference);
        }
        if(dnsRr[i].PTRName != NULL)
            printf("PTR: %s, ",dnsRr[i].PTRName);
        printf("\n");
    }
        printf("\n");
    }
    if (additionsNum!=0) {
    printf("Additional Answer:\n");
    for(int i = answersNum+authoritiesNum; i < allRRNum; i++){
        printf("%s, ",dnsRr[i].SearchName);
        printf("type: %d, ",dnsRr[i].type);
        printf("ttl: %d, ", dnsRr[i].ttl);
        if(dnsRr[i].CName != NULL)
            printf("CNAME: %s, ",dnsRr[i].CName);
        if(dnsRr[i].ip != NULL)
            printf("ip: %s, ", dnsRr[i].ip);
        if(dnsRr[i].MXName != NULL){
            printf("MX: %s, ",dnsRr[i].MXName);
        printf("MX preference: %d", dnsRr[i].preference);
    }
        if(dnsRr[i].PTRName != NULL)
            printf("PTR: %s, ",dnsRr[i].PTRName);
        printf("\n");
    }
        printf("\n");
    }

}

char* reverseString(char* ip) {
    char* token;
    char* stack[4];
    int top = -1;
    char* newIp = (char*) malloc(sizeof(char) * (16));  

    
    token = strtok(ip, ".");
    while(token != NULL) {
        stack[++top] = token;
        token = strtok(NULL, ".");
    }

    
    newIp[0] = '\0';

    
    while(top >= 0) {
        strcat(newIp, stack[top--]);
        if(top >= 0) {
            strcat(newIp, ".");
        }
    }

    return newIp;
}

int main(int agrs,char *argv[]){

    printf("please input the domain you want to search:\n");
    char domain[512];
    scanf("%s",domain);
    char temp[10];
    printf("请输入记录类型（CNAME、A、MX、PTR）：");
    scanf("%s", temp);
    int type;
    
    if (strcasecmp(temp, "CNAME") == 0) {
        type = 5;
        printf("CNAME\n");
        
    } else if (strcasecmp(temp, "A") == 0) {
        type = 1;
        printf("A\n");
        
    } else if (strcasecmp(temp, "MX") == 0) {
        type = 15;
        printf("MX\n");
        
    } else if(strcasecmp(temp, "PTR") == 0)
    {
        type = 12;
        printf("PTR\n");
        char* reserveDomain = reverseString(domain);
        memset(domain,0,sizeof(domain));
        for (int i = 0; i < strlen(reserveDomain); ++i) {
            domain[i] = reserveDomain[i];
        }
        strcat(domain, ".in-addr.arpa");
    }
    else {
        printf("无效的类型\n");
        return  -2;
    }
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
    {
        return -1;
    }

    
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr)); 
    servaddr.sin_family = AF_INET;  
    servaddr.sin_port = htons(DNS_SERVER_PORT);  
    inet_pton(AF_INET, DNS_SERVER_IP, &servaddr.sin_addr.s_addr);

    struct DNS_Header header = {0}; 
    dns_create_header(&header); 

    struct DNS_Query question = {0}; 
    dns_create_question(&question, domain, type);

    char request[1024] = {0};
    int len = dns_build_request(&header, &question, request, 1024);

    
    sendto(sockfd, request, len, 0, (struct sockaddr *)&servaddr, sizeof(struct sockaddr));
    
    
    char response[1024] = {0};
    struct sockaddr_in addr;
    size_t addr_len = sizeof(struct sockaddr_in);
    int n = recvfrom(sockfd, response, sizeof(response), 0, (struct sockaddr *)&addr, (socklen_t *)&addr_len);
    dns_parse_response(response);
}
