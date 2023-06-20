cmake_minimum_required(VERSION 3.24)
project(2columnS C)

set(CMAKE_C_STANDARD 11)

add_executable(2columnS
        comm_test/netlink_kernel.c
        comm_test/netlink_user.c
        kernel/firewall.c)
