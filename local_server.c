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
#define DNS_MX              0x0f
#define DNS_PTR             0x0c


int udpSock;
int tcpSock;
struct sockaddr_in local_addr, client_addr;
struct sockaddr_in net_server_addr;
uint16_t net_server_response_length;
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
void receive_net_server();
void initSystem();
void appendStructToCSV(const char* filename, struct DNS_RR* dnsRr);
void parse_server_response();
void receive_net_server();
void initTcpSock();
void reverseIP(char* domain, char* result);
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
    array[1] = (networkValue >> 8) & 0xFF;
    array[0] = networkValue & 0xFF;
}

void receive_client(){
        memset(client_query_packet, 0, sizeof(client_query_packet));
        size_t addr_len = sizeof(struct sockaddr_in);
        client_query_len = recvfrom(udpSock, client_query_packet, sizeof(client_query_packet), 0, (struct sockaddr*)&client_addr, (socklen_t *)&addr_len);
        if ( client_query_len < 0) {
            perror("Receive failed");
            exit(1);
        }
        printf("Received query from client\n\n");
        dns_parse_query(client_query_packet);
}

void initUdpSock(){
    udpSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSock == -1) {
        perror("Socket creation failed");
        exit(1);
    }



    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = inet_addr("127.0.0.2");
    local_addr.sin_port = htons(LOCAL_PORT);

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

    struct sockaddr_in tcp_local_addr;
    tcp_local_addr.sin_family = AF_INET;
    tcp_local_addr.sin_addr.s_addr = inet_addr("127.0.0.2");  
    tcp_local_addr.sin_port = htons(0);

    if (bind(tcpSock, (struct sockaddr*)&tcp_local_addr, sizeof(tcp_local_addr)) < 0) {
        perror("Binding failed");
        exit(1);
    }

    net_server_addr.sin_family = AF_INET;
    net_server_addr.sin_addr.s_addr = inet_addr(next_server_ip);
    net_server_addr.sin_port = htons(ROOT_SERVER_PORT);

    if (connect(tcpSock, (struct sockaddr*)&net_server_addr, sizeof(net_server_addr)) < 0) {
        perror("Connection to root server failed");
    }
}

void dns_create_header(){
    
    dnsHeader.flags = htons(0x8180);
    dnsHeader.questionsNum = htons(1);    
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


        question->name = malloc(strlen(hostname) + 2 );
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


int createResponse(int offset, char *request) {
    memcpy(request, &dnsHeader, sizeof(struct DNS_Header));
    offset = sizeof(struct DNS_Header);

    
    memcpy(request + offset, dnsQuery.name, dnsQuery.length);
    offset += dnsQuery.length;

    memcpy(request + offset, &dnsQuery.qtype, sizeof(dnsQuery.qtype));
    offset += sizeof(dnsQuery.qtype);

    memcpy(request + offset, &dnsQuery.qclass, sizeof(dnsQuery.qclass));
    offset += sizeof(dnsQuery.qclass);
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
        memcpy(request + offset, &len, sizeof(dnsRr.data_len));
        offset += sizeof(dnsRr.data_len);

   
    



    if (dnsRr.type  == htons(1)){
        
        memcpy(request + offset, dnsRr.ip, 4);
        offset += 4;
    }else if(dnsRr.type  == htons(5)){
        
        memcpy(request + offset, dnsRr.CName, dnsRr.data_len);
        offset += dnsRr.data_len;
    } else if(dnsRr.type  == htons(15)){
        
        memcpy(request + offset, &dnsRr.preference, 2);
        offset += 2;
        memcpy(request + offset, dnsRr.MXName, dnsRr.data_len);
        offset += dnsRr.data_len-2;
    } else if(dnsRr.type  == htons(12)){
        memcpy(request + offset, dnsRr.PTRName, dnsRr.data_len);
        offset += dnsRr.data_len;
    } else{
        printf("error\n\n");
    }

    return offset; 

}
void buildRR(struct DNS_RR *dnsRr, int num, char* response,int responseLen){

    dnsRr->SearchName = malloc(dnsCache[num].SearchNameLen + 2 );
    dnsRr->SearchNameLen = strlen(dnsCache[num].SearchName) + 2;
    const char delim[2] = ".";
    char *qname =dnsRr->SearchName; 

    
    char *new_hostname = strdup(dnsCache[num].SearchName); 
    
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
    if (position != 0) {
        dnsRr->SearchNameLen = 2;
        free(dnsRr->SearchName);
        dnsRr->SearchName = malloc( 3 );
        dnsRr->SearchName[0]= 0xc0;
        dnsRr->SearchName[1]= position;
        dnsRr->SearchName[2] = '\0';
    }

    dnsRr->class = htons(1);
    dnsRr->type = htons(dnsCache[num].type);
    dnsRr->ttl = htonl(dnsCache[num].ttl);



    if (dnsCache[num].type  == 1){
        dnsRr->data_len= 4;
        unsigned char ip_parts[4];
        uint32_t dns_address = 0;
        sscanf(dnsCache[num].ip, "%hhu.%hhu.%hhu.%hhu", &ip_parts[0], &ip_parts[1], &ip_parts[2], &ip_parts[3]);
        dns_address = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3];
        dnsRr->ip = malloc(sizeof (unsigned char *)&dns_address );
        uint32_t network_order = htonl(dns_address);
        memcpy(dnsRr->ip, &network_order, sizeof(network_order));

    }else if(dnsCache[num].type  == 5){
        

        dnsRr->data_len = strlen (dnsCache[num].CName)+2;
        const char delim[2] = ".";
        dnsRr->CName = malloc(sizeof (dnsRr->data_len) );
        char *qname = dnsRr->CName; 

        
        char *new_hostname = strdup(dnsCache[num].CName); 
        
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
    } else if(dnsCache[num].type  == 15){
        
        dnsRr->preference = htons(dnsCache[num].preference);
        dnsRr->data_len = strlen (dnsCache[num].MXName)+4;
        dnsRr->MXName = malloc(sizeof (dnsRr->data_len) );
        const char delim[2] = ".";
        char *qname = dnsRr->MXName; 

        
        char *new_hostname = strdup(dnsCache[num].MXName); 
        
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
    } else if(dnsCache[num].type  == 12){
        
        dnsRr->data_len = strlen (dnsCache[num].PTRName) + 2;
        dnsRr->PTRName = malloc(sizeof (dnsRr->data_len) );
        memset(dnsRr->PTRName,0,sizeof (dnsRr->PTRName));
        const char delim[2] = ".";
        char *qname = dnsRr->PTRName; 
        
        char *new_hostname = strdup(dnsCache[num].PTRName); 
        
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
        
        
    } else{
        printf("error\n\n");
    }



}

void sendto_client(int num, int type){        
    type = ntohs(type);
    dns_create_header();
    int offset = 0;
    char response[513] = {0};
    offset = createResponse(offset, response);
    struct DNS_RR temp, MX_NAME;
    int MXpos = -1;
    memset(&temp, 0, sizeof(struct DNS_RR));
    memset(&MX_NAME, 0, sizeof(struct DNS_RR));
    buildRR(&temp, num, response, offset);


    offset = createRRResponse(offset,response,temp);



    if(dnsCache[num].type == 15) {
        for (int i = 0; i < local_cache_num; ++i) {
            if (strcmp(dnsCache[num].MXName, dnsCache[i].SearchName) == 0 && dnsCache[i].type==1) {
                MXpos = i;
                break;
            }
        }
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

    dnsQuery.name = (char *) calloc(strlen(qname) + 1, 1);
    memcpy(dnsQuery.name, qname, strlen(qname));

    ptr += (len+2);
    dnsQuery.qtype = *(unsigned short *) ptr;
}

void  ask_net_server(){

    uint8_t askInformationLen[2];
    size_t shot_packet_length = client_query_len + sizeof(askInformationLen);
    char shot_packet[shot_packet_length + 1];
    intToNetworkByteArray(client_query_len, askInformationLen);

    memcpy(shot_packet, askInformationLen, sizeof(askInformationLen));
    memcpy(shot_packet + sizeof(askInformationLen), client_query_packet, client_query_len + 1);

    
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

    close(tcpSock);
}

void parse_server_response(){

    unsigned char *ptr =  net_server_response;
    ptr += 2;
    int flags = ntohs(*(unsigned short int *) ptr);
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

    char cname[128], ip[20], netip[20];
    int len;
    int times = 0;
    struct DNS_RR dnsRr[allRRNum];
    memset(dnsRr,0,sizeof(dnsRr));
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
                ptr += dnsRr[i].data_len - 2;
            }   else if (dnsRr[i].type == DNS_PTR) {
                bzero(cname, sizeof(cname));
                len = 0;
                dns_parse_name(net_server_response, ptr, cname, &len);
                dnsRr[i].PTRName = (char *) calloc(strlen(cname) + 1, 1);
                memcpy(dnsRr[i].PTRName, cname, strlen(cname));
                ptr += dnsRr[i].data_len;
            }
        }

        for (int i = 0; i < allRRNum; ++i) {
            if (strcmp(client_wanted_domain, dnsRr[i].SearchName) == 0 ) {
                dnsCache[local_cache_num].SearchName = malloc(strlen(dnsRr[i].SearchName));
                memcpy( dnsCache[local_cache_num].SearchName, dnsRr[i].SearchName, strlen(dnsRr[i].SearchName));



                dnsCache[local_cache_num].ttl = dnsRr[i].ttl;
                time(&dnsCache[local_cache_num].updateTime);
                
                dnsCache[local_cache_num].updateTime += dnsCache[local_cache_num].ttl;
                
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
    }


void appendStructToCSV(const char* filename, struct DNS_RR* dnsRr) {
    FILE* file = fopen(filename, "a");
    if (file == NULL) {
        printf("无法打开文件\n");
        return;
    }

    if (dnsRr->type == 12)
    {
        char ipPart[20] = {0};

        
        char* inPosition = strstr(dnsRr->SearchName, ".in-addr.arpa");

        
        size_t length = inPosition - (char *)dnsRr->SearchName;

        
        for (int j = 0; j < length; ++j) {
            ipPart[j] = dnsCache[local_cache_num].SearchName[j];
        }
        ipPart[length] = '\0';
        char trueIP[20];

        reverseIP(ipPart,trueIP);


        fprintf(file, "%s,%d,IN,", trueIP, dnsRr->ttl);
    }else{
        fprintf(file, "%s,%d,IN,", dnsRr->SearchName, dnsRr->ttl);
    }


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
        printf("写文件出错error\n\n");
    }




    fclose(file);
}


void reverseIP(char* domain, char* result) {
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

}


void initSystem(){
    local_cache_num = 0;
    next_server_ip = "127.0.0.3";
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
        row[strcspn(row, "\n")] = '\0'; 

        token = strtok(row, ",");
        dnsCache[local_cache_num].SearchName = (char *) calloc(strlen(token) + 1, 1);
        memcpy(dnsCache[local_cache_num].SearchName, token, strlen(token));


        token = strtok(NULL, ",");
        dnsCache[local_cache_num].ttl = atoi(token);
        time(&dnsCache[local_cache_num].updateTime);
        dnsCache[local_cache_num].updateTime += dnsCache[local_cache_num].ttl;

        token = strtok(NULL, ",");
        if (!strcmp(token, "IN")){
            dnsCache[local_cache_num].class = 1;
        }


        token = strtok(NULL, ",");
        if (strcmp(token, "CNAME") == 0) {
            dnsCache[local_cache_num].type = 5;

            token = strtok(NULL, ",");

            dnsCache[local_cache_num].CName = (char *) calloc(strlen(token) + 1, 1);
            memcpy(dnsCache[local_cache_num].CName, token, strlen(token));


            
            
        } else if (strcmp(token, "A") == 0) {
            dnsCache[local_cache_num].type = 1;

            token = strtok(NULL, ",");

            dnsCache[local_cache_num].ip = (char *) calloc(strlen(token) + 1, 1);
            memcpy(dnsCache[local_cache_num].ip, token, strlen(token));
            
            
        } else if (strcmp(token, "MX") == 0) {
            dnsCache[local_cache_num].type = 15;

            token = strtok(NULL, ",");
            dnsCache[local_cache_num].preference = atoi(token);
            token = strtok(NULL, ",");
            dnsCache[local_cache_num].MXName = (char *) calloc(strlen(token) + 1, 1);
            memcpy(dnsCache[local_cache_num].MXName, token, strlen(token));
            
           
        } else if(strcmp(token, "PTR") == 0){
            dnsCache[local_cache_num].type = 12;

            token = strtok(NULL, ",");

            char writeDomain[50] = "";

            reverseIP(dnsCache[local_cache_num].SearchName, writeDomain);

            


            free(dnsCache[local_cache_num].SearchName);
            dnsCache[local_cache_num].SearchName = malloc(strlen(writeDomain));
            memcpy(dnsCache[local_cache_num].SearchName, writeDomain, strlen(writeDomain));
            strcat(dnsCache[local_cache_num].SearchName, ".in-addr.arpa");


            dnsCache[local_cache_num].PTRName = (char *) calloc(strlen(token)+1 , 1);
            memcpy(dnsCache[local_cache_num].PTRName, token, strlen(token));

        } else{
            printf("读文件出错error\n\n");
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
        int isCached = -1;

        for (int i = 0; i < local_cache_num; ++i) {
            if (strcmp(dnsCache[i].SearchName, client_wanted_domain) == 0 && dnsCache[i].type == ntohs(dnsQuery.qtype)) {
                isCached = i;
            }
        }
        int times = 0;
        int pointNum = 0;
        if (isCached == -1) {
            while (strcmp(net_server_return_domain, client_wanted_domain) != 0) {
                process_time = clock();
                initTcpSock();
                ask_net_server();
                receive_net_server();
                end_time = clock();
                double execution_time = (double)(end_time - process_time) / CLOCKS_PER_SEC;
                parse_server_response();
                pointNum = 0;
                for (int i = 0; i < strlen(net_server_return_domain); ++i) {
                    if(net_server_return_domain[i] == '.')
                        pointNum++;

                }
                printf("查询到第%d台服务器了，它的ip是%s，它是%d级服务器（0-根服务器；1-顶级DNS服务器；2-二级DNS服务器），响应时间是：%f秒\n",times+1,next_server_ip, pointNum,execution_time);
                times++;
            }
            sendto_AuthToClient();
            double execution_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
            printf("总响应时间是：%f秒\n",execution_time);
            memset(net_server_return_domain, 0, sizeof(net_server_return_domain));
            net_server_return_domain[0] = '!';
        } else{
            printf("本地有缓存\n");
            end_time = clock();
            sendto_client(isCached, dnsQuery.qtype);
            double execution_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
            printf("总响应时间是：%f秒\n", execution_time);

        }
        printf("完成了一次查询\n\n");
    }

}
