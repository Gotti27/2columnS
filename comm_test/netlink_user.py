import socket
import struct

NETLINK_MYGROUP = 2

sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_USERSOCK)

sock.bind((0, NETLINK_MYGROUP))

print("Sending msg")

msg_data = b"Netlink connection established\x00"
msg_len = 16 + len(msg_data)


msg = msg_len.to_bytes(4, 'little') + b"\x03\x00" + b"\x00"*2 + b"\x00"*4 + b"\xb3\x15\x00\x00" + b"Netlink connection established\x00"

sock.send(msg)


print("Starting reciving.....")
while True:
    data = sock.recvmsg(1024)[0]
    msg_hdr = data[:16]

    msg_len, msg_type, flags, seq, pid = struct.unpack("=LHHLL", msg_hdr)
    msg_data = data[16:msg_len]
    print(f"msg_len: {msg_len}")
    print(f"msg_type: {msg_type}")
    print(f"flags: {flags}")
    print(f"seq: {seq}")
    print(f"pid: {pid}")
    print(f"msg_data: {msg_data}")
    print()
