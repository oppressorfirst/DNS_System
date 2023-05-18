//
// Created by jialun zhang on 18/5/2023.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>


#define DNS_SERVER "8.8.8.8"
#define DNS_PORT 53
#define BUFFER_SIZE 1024

void handle_dns_query(int server_socket, struct sockaddr_in client_addr, char* buffer, int query_length) {
    int dns_socket;
    struct sockaddr_in dns_server_addr;

    // 创建 UDP socket
    dns_socket = socket(AF_INET, SOCK_DGRAM, 0);

    // 设置 DNS 服务器地址和端口
    dns_server_addr.sin_family = AF_INET;
    dns_server_addr.sin_port = htons(DNS_PORT);
    if (inet_pton(AF_INET, DNS_SERVER, &(dns_server_addr.sin_addr)) <= 0) {
        perror("Failed to set DNS server address");
        close(dns_socket);
        return;
    }

    // 向公共 DNS 服务器发送 DNS 查询请求
    sendto(dns_socket, buffer, query_length, 0, (struct sockaddr*)&dns_server_addr, sizeof(dns_server_addr));

    // 接收 DNS 响应数据
    socklen_t dns_server_addr_len = sizeof(dns_server_addr);
    int response_length = recvfrom(dns_socket, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&dns_server_addr, &dns_server_addr_len);

    // 发送 DNS 响应数据给客户端
    sendto(server_socket, buffer, response_length, 0, (struct sockaddr*)&client_addr, sizeof(client_addr));

    // 关闭 socket 连接
    close(dns_socket);
}

int main() {
    int server_socket;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE];

    // 创建 UDP socket
    server_socket = socket(AF_INET, SOCK_DGRAM, 0);

    // 设置本地地址和端口
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(53);

    // 绑定到本地地址和端口
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to bind");
        return 1;
    }

    printf("DNS server is runnssssssssssing...\n");
    while (1) {
        socklen_t client_addr_len = sizeof(client_addr);

        // 接收来自客户端的 DNS 查询请求
        int query_length = recvfrom(server_socket, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr, &client_addr_len);

        // 处理 DNS 查询请求
        handle_dns_query(server_socket, client_addr, buffer, query_length);

    }

    // 关闭 socket 连接
    close(server_socket);

    return 0;
}
