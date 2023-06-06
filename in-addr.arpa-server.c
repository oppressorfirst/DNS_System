


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "DNS.h"

#define COM_SERVER_PORT 53


struct DNS_Query dnsQuery;

struct DNS_Header dnsHeader;

char* searchName;

int com_cache_num;

struct DNS_RR dnsRr;
struct DNS_RR comDnsCache[100];

void reverse_and_append(char* domain, char* result) {
    char* parts[30];
    int count = 0;
    char* token;

    
    token = strtok(domain, ".");
    while(token != NULL) {
        parts[count++] = token;
        token = strtok(NULL, ".");
    }

    
    for(int i = count - 1; i >= 0; --i) {
        strcat(result, parts[i]);
        if(i != 0) {
            strcat(result, ".");
        }
    }

    
    strcat(result, ".in-addr.arpa");
}

void initCsv() {
    com_cache_num = 0;
    FILE *fp = fopen("in-addr.arpa.csv", "r");
    if (fp == NULL) {
        fprintf(stderr, "fopen() failed.\n");
        exit(EXIT_FAILURE);
    }

    char row[80];
    char *token;


    while (fgets(row,80,fp) !=NULL) {
        
        row[strcspn(row, "\n")] = '\0'; 
        token = strtok(row, ","); 

        
        char ip[17] = {0};
        memcpy(ip,token, strlen(token));




        

        
        token = strtok(NULL,",");
        printf("%s\n",token);

        comDnsCache[com_cache_num].ttl = atoi(token);
        time(&comDnsCache[com_cache_num].updateTime);
        comDnsCache[com_cache_num].updateTime += comDnsCache[com_cache_num].ttl;


        
        token = strtok(NULL, ",");
        if (!strcmp(token, "IN")){
            comDnsCache[com_cache_num].class = 1;
        }


        
        token = strtok(NULL, ",");
        if(strcmp(token, "PTR") == 0){
            comDnsCache[com_cache_num].type = 12;

            
            token = strtok(NULL, ",");

            comDnsCache[com_cache_num].PTRName = (char *) calloc(strlen(token) + 1, 1);
            memcpy(comDnsCache[com_cache_num].PTRName, token, strlen(token));

        }else{
            printf("不是PTR类型！error！！\n\n");
        }

        char ipReverse[30]="";
        reverse_and_append(ip, ipReverse);
        printf("wenjian:%s\n",ipReverse);
        comDnsCache[com_cache_num].SearchName = (char *) calloc(strlen(ipReverse)+5,1);
        memcpy(comDnsCache[com_cache_num].SearchName,ipReverse, strlen(ipReverse));
        com_cache_num++;

    }
    fclose(fp);
    printf("文件已全部读入\n");
}

int createResponse(int offset, char *request);

void intToNetworkByteArray(int value, uint8_t* array) {
    uint16_t networkValue = htons((uint16_t)value);
    array[1] = (networkValue >> 8) & 0xFF;  
    array[0] = networkValue & 0xFF;         
}

void dns_create_header(){
    
    dnsHeader.flags = htons(0x8180);
    dnsHeader.questionsNum = htons(1);    
    dnsHeader.answerNum = htons(0);
    dnsHeader.authorityNum = htons(1);
    if(dnsQuery.qtype == htons(15)) {
        dnsHeader.additionalNum = htons(1);
    } else{
        dnsHeader.additionalNum = htons(0);
    }
}


void buildRR(struct DNS_RR *dnsRr, int num, char* response,int responseLen){

    printf("builedRR     %s\n",comDnsCache[num].SearchName);
    dnsRr->SearchName = malloc(comDnsCache[num].SearchNameLen + 2 +100);
    dnsRr->SearchNameLen = strlen(comDnsCache[num].SearchName) + 2;
    const char delim[2] = ".";
    char *qname =dnsRr->SearchName; 

    
    char *new_hostname = strdup(comDnsCache[num].SearchName); 
    
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
    dnsRr->type = htons(comDnsCache[num].type);
    dnsRr->ttl = htonl(comDnsCache[num].ttl);


    if(comDnsCache[num].type  == 12){
        
        printf("%s\n",comDnsCache[num].PTRName);
        dnsRr->data_len = strlen (comDnsCache[num].PTRName) + 2;
        dnsRr->PTRName = malloc(sizeof (dnsRr->data_len) +100);
        memset(dnsRr->PTRName,0,sizeof (dnsRr->PTRName));
        const char delim[2] = ".";
        char *qname = dnsRr->PTRName; 
        printf("9999999999999999\n");
        
        char *new_hostname = strdup(comDnsCache[num].PTRName); 
        
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
        printHex(dnsRr->PTRName, dnsRr->data_len);
        
        
    } else{
        printf("不是 PTR！！！！error！！！\n\n");
    }




}

int createResponse(int offset, char *request){
    if(offset == 0) {
        memcpy(request, &dnsHeader, sizeof(struct DNS_Header));
        offset = sizeof(struct DNS_Header);

        
        memcpy(request + offset, dnsQuery.name, dnsQuery.length);
        offset += dnsQuery.length;

        memcpy(request + offset, &dnsQuery.qtype, sizeof(dnsQuery.qtype));
        offset += sizeof(dnsQuery.qtype);

        memcpy(request + offset, &dnsQuery.qclass, sizeof(dnsQuery.qclass));
        offset += sizeof(dnsQuery.qclass);
    }
    printHex(request,offset);
    return offset; 

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

    
    


    
    if(dnsRr.type  == htons(12)){
        
        printHex(dnsRr.PTRName,dnsRr.data_len);
        memcpy(request + offset, dnsRr.PTRName, dnsRr.data_len);
        offset += dnsRr.data_len;
    } else{
        printf("不是PTR!回答部分构建错误！！！error！！！\n\n");
    }



    printHex(request,offset);
    return offset; 

}

void dns_create_question(struct DNS_Query *question, const char *hostname)
{
    if(question == NULL || hostname == NULL) {
        printf("There is some problem in The DNS header struct or The domain you want to search!");
        return ;
    }


    
    question->name = malloc(strlen(hostname) + 2);
    if(question->name == NULL)
    {
        printf("内存分配出错了");
        return ;
    }

    question->length =  (int)strlen(hostname) + 2;

    
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

void dns_parse_query(char* buffer){
    unsigned char *ptr = buffer;
    dnsHeader.id = (*(unsigned short int *) ptr);
    ptr += 2;
    int flags = *(unsigned short int *) ptr;
    
    int bit = (flags >> 9) % 2;  
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


void handle_dns_query(int client_sock) {
    
    uint16_t query_length;
    if (recv(client_sock, &query_length, sizeof(query_length), 0) < 0) {
        perror("Receive query length field failed");
        exit(1);
    }
    query_length = ntohs(query_length);

    
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
    


    int isCached = -1;
    
    for (int i = 0; i < com_cache_num; ++i) {
        if (strcmp(comDnsCache[i].SearchName, searchName) == 0) {
            isCached = i;
        }
    }

    printf("需要匹配的序号：%d\n",isCached);





















    
    struct DNS_RR temp1;
    memset(&temp1, 0, sizeof(struct DNS_RR));
    buildRR(&temp1, isCached, response, responseLen);
    responseLen = createRRResponse(responseLen,response,temp1);
    

    responseLen = createResponse(responseLen,response);
    printf("%d",responseLen);


    uint8_t temp[2];

    
    intToNetworkByteArray(responseLen,temp);
    size_t new_packet_length = responseLen + sizeof(temp);
    char new_packet[new_packet_length + 1];

    memcpy(new_packet, temp, sizeof(temp));
    memcpy(new_packet + sizeof(temp), response, responseLen + 1);

    printHex(new_packet,responseLen+2);


    
    if (send(client_sock, new_packet, responseLen+2, 0) < 0) {
        perror("Send response packet failed");
        exit(1);
    }
}

int main() {
    int sock;
    struct sockaddr_in server_addr, client_addr;

    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.6");
    server_addr.sin_port = htons(COM_SERVER_PORT);



    
    
    
    
    
    

    
    if (bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Binding failed");
        exit(1);
    }

    
    if (listen(sock, 10) < 0) {
        perror("Listen failed");
        exit(1);
    }

    printf("This is in-addr.arpa server...\n");

    initCsv();

    while (1) {
        int client_len = sizeof(client_addr);
        int client_sock = accept(sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("Accept connection failed");
            exit(1);
        }

        printf("Accepted connection from client\n");

        
        handle_dns_query(client_sock);

        
        close(client_sock);
    }

    
    close(sock);

    return 0;
}
