cmake_minimum_required(VERSION 3.25)
project(DNS_System C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(DNS_System
        DNS.h
        local_server.c
        main.c
        root-server.c)
