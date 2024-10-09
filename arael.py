#!/usr/bin/python3
from argparse import ArgumentParser
from random import randint
import struct
import array

""" Todo:
    - construct pseudo header
    - finish checksum
    - construct packet
    - randomize src port
    - build flood loop
"""

#Generate a randomized IP to sent the SYN packets from

def rand_ip():
    ip = [randint(0,255) for _ in range(4)]
    rand_ip = ".".join(map(str, ip))
    return(rand_ip)

class TCPPacket:
    def __intit__(self,
                  src_host:     str,
                  src_port:     int,
                  dst_host:     str,
                  dst_port:     int,
                  flags:        int=0):
        self.src_host = src_host
        self.src_port = src_port
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.flags = flags

    def build(self) -> bytes:
        #Create binary representation of TCP Header
        packet = struct.pack(
            #!:Data should be packed in big-endian
            #H: unsigned short(2 Bytes each)
            #I: unsigned int(4 Bytes each)
            #B: unsigned char(1 Byte each)
            '!HHIIBBHHH',
            self.src_port,  # Source Port
            self.dst_port,  # Destination Port
            0,              # Seq Number
            0,              # Ack Number
            5 << 4,         # Offset
            self.flags,     # TCP Flags
            8192,           # Sliding Window Value
            0,              # Checksum (init, will be calculated later)
            0               # Urgent pointer
        )

def args():
    #Define command-line args
    parser = ArgumentParser()
    parser.add_argument('-t', '--target', action='store', help='Specify the target IP address')
    parser.add_argument('-p','--port', action='store', help='Specify the target port')
    parser.add_argument('-c', '--count', action='store', help='Specify the amount of packets sent')
    
    errors = []
    #Process given args
    args = parser.parse_args()

    if args.target and args.port and args.count: 
        print("Arguments parsed")

    #Raise error if args are missing
    else:
        if args.target is None:
            errors.append("Error: --t or --target is required.")
        if args.port is None:
            errors.append("Error: --p or --port is required.")
        if args.count is None:
            errors.append("Error: --c or --count is required.")
    if errors:
        raise ValueError("\n".join(errors))



#Calculate Checksum for TCP Packet

def checksum(packet: bytes) ->int:
    if len(packet) % 2 != 0:
        packet += b'\0'
    #Convert Byte packet into aray of unsigned 16-bit ints and sum the values 
    res = sum(array.array("H", packet))
    #Extract the upper carry and lower 16 bit 
    res = (res >> 16) + (res & 0xffff)
    #Final Carry Fold if the sum still exceeds 16 bit
    res += res >> 16
    #Flip bits of the sum and mask the lower 16 to produce the checksum
    return(~res) & 0xffff


if __name__ == "__main__":
    args()
    print(rand_ip())



