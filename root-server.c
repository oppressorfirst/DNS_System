#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define ROOT_SERVER_PORT 53


void printHex(const char* string, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02X ", (unsigned char)string[i]);
    }
    printf("\n");
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


    // 处理查询报文，构造响应报文

    char response_packet[200] = {0};
    // ...

    // 发送响应报文长度字段
//    uint16_t response_length = strlen(response_packet);
//    response_length = htons(response_length);
//    if (send(client_sock, &response_length, sizeof(response_length), 0) < 0) {
//        perror("Send response length field failed");
//        exit(1);
//    }
//
//    // 发送响应报文
//    if (send(client_sock, response_packet, strlen(response_packet), 0) < 0) {
//        perror("Send response packet failed");
//        exit(1);
//    }
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

    printf("Root DNS server started...\n");

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
