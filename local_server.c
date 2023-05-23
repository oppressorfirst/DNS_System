#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "DNS.h"

#define LOCAL_PORT 53
#define ROOT_SERVER_IP "127.0.0.1"
#define ROOT_SERVER_PORT 53

void printHex(const char* string, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02X ", (unsigned char)string[i]);
    }
    printf("\n");
}

void intToNetworkByteArray(int value, uint8_t* array) {
    uint16_t networkValue = htons((uint16_t)value);
    array[1] = (networkValue >> 8) & 0xFF;  // 高字节
    array[0] = networkValue & 0xFF;         // 低字节
}

// 转发 DNS 查询报文给 Root 服务器
void forward_dns_query(int query_length, char* query_packet) {
    struct sockaddr_in root_server_addr;

    // 创建 TCP 套接字
    int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    // 设置 Root 服务器地址
    root_server_addr.sin_family = AF_INET;
    root_server_addr.sin_addr.s_addr = inet_addr(ROOT_SERVER_IP);
    root_server_addr.sin_port = htons(ROOT_SERVER_PORT);

    // 建立 TCP 连接
    if (connect(tcp_sock, (struct sockaddr*)&root_server_addr, sizeof(root_server_addr)) < 0) {
        perror("Connection to root server failed");
        //exit(1);
    }

    uint8_t temp[2];

    // 添加长度字段
    intToNetworkByteArray(query_length,temp);
    size_t new_packet_length = query_length + sizeof(temp);
    char new_packet[new_packet_length + 1];

    memcpy(new_packet, temp, sizeof(temp));
    memcpy(new_packet + sizeof(temp), query_packet, query_length + 1);

    printHex(new_packet,query_length+2);

    // 发送查询报文
    if (send(tcp_sock, new_packet, query_length+2, 0)) {
        perror("Send failed");
        //exit(1);
    }





//    // 接收响应报文长度
//    uint16_t response_length;
//    if (recv(tcp_sock, &response_length, sizeof(response_length), 0) < 0) {
//        perror("Receive length field failed");
//        exit(1);
//    }
//    response_length = ntohs(response_length);
//
//    // 接收响应报文
//    char response[1024];
//    memset(response, 0, sizeof(response));
//    if (recv(tcp_sock, response, response_length, 0) < 0) {
//        perror("Receive failed");
//        exit(1);
//    }

    // 处理响应报文
    // ...

    // 关闭连接
    //close(tcp_sock);
}




int main() {
    int sock;
    struct sockaddr_in local_addr, client_addr;
    char query_packet[1024];

    // 创建 UDP 套接字
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    // 设置本地服务端地址
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(LOCAL_PORT);

    // 绑定套接字到本地服务端地址
    if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        perror("Binding failed");
        exit(1);
    }

    printf("Local DNS server started...\n");

    while (1) {
        // 接收来自客户端的查询报文
        int client_len = sizeof(client_addr);
        memset(query_packet, 0, sizeof(query_packet));
        int query_len = recvfrom(sock, query_packet, sizeof(query_packet), 0, (struct sockaddr*)&client_addr, &client_len);
        if ( query_len < 0) {
            perror("Receive failed");
            exit(1);
        }

        printf("Received query from client\n");

        //printBinary(query_packet,query_len);

        // 转发查询报文给 Root 服务器
        forward_dns_query(query_len, query_packet);

        // 将响应报文返回给客户端
        // ...
    }
}
