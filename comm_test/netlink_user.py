import os
import socket
import struct


# sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_USERSOCK)

sock.bind((0,0))
sock.setsockopt(270, 1, 31)

sock.send("Hello py".encode())

#
#sock2 = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
#sock2.bind((os.getpid(),0))
#data = sock2.recv(65535)
#
#msg_len, msg_type, flags, seq, pid = struct.unpack("=LHHLL", data[:16])
#
#print(msg_len)
#print(msg_type)
#print(flags)
#print(pid)
#
###