#!/usr/bin/python3
from argparse import ArgumentParser
from random import randint
import struct
import array
import socket

#-------------------To-do---------------------#

#- build flood loop
# - build function to send packets via sockets

#---------------------------------------------# 

#Calculate Checksum for TCP Packet

def cal_checksum(packet: bytes) ->int:
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

#Generate a randomized IP to sent the SYN packets from

def rand_ip():
    ip = [randint(0,255) for _ in range(4)]
    rand_ip = ".".join(map(str, ip))
     
    return(rand_ip)

#Generate random port if

def rand_port():
    port = randint(1000,9000)
    return port

class TCPPacket:
    def __init__(self,
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
        #Construct pseudo header for TCP -> Size 12 Bytes
        """
            Composition of pseudo header:
        _________________________________
                | Src IP |
        _________________________________
                | Dst IP |
        _________________________________
        | Reserved | Protocol | TCP len |
        
        """
        pseudohdr = struct.pack(
            #Formatting to tell struct how to pack
            #4s: 4 Byte string
            #H: 16 Bit unsigned int
            '!4s4sHH',
            #Pack IP Adresses into 32 Bit representation
            socket.inet_aton(self.src_host),#Src address
            socket.inet_aton(self.dst_host),#Dst address
            socket.IPPROTO_TCP,
            len(packet)
        )
        #Construct checksum
        checksum = cal_checksum(pseudohdr + packet)
        
        #testsum = checksum.to_bytes(2,'big')
        #print(f"Checksum in hex:{testsum}")

        packet = packet[:16] + struct.pack('H', checksum) + packet[18:]
        #print(f"Packet: {packet}")
        
        return packet


def args():
    #Define command-line args
    parser = ArgumentParser()
    parser.add_argument('-t', '--target', action='store', help='Specify the target IP address')
    parser.add_argument('-p','--port', action='store',type=int, help='Specify the target port')
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
    
    return args 

def display_interface(src_ip, src_p, trg_ip, trg_p):
    # Hardcoded ASCII art interface
    interface = f"""
    +----------------------------+
                Arael
    +----------------------------+
    | Src IP:   = {src_ip} 
    | Src Port: = {src_p}  
    +----------------------------+
    | Src IP:   = {trg_ip} 
    | Trg Port: = {trg_p}  
    +----------------------------+
    """
    print(interface)





if __name__ == "__main__":
    try:
        parsed_args = args()
        ip = rand_ip()
        port = rand_port()
        #print(f"Source IP: {ip}, Port: {port}")
        #print(f"Target IP: {parsed_args.target}, Port: {parsed_args.port}, Count: {parsed_args.count}")
        display_interface(ip,port,parsed_args.target, parsed_args.port)
        pak = TCPPacket(
            ip,
            port,
            parsed_args.target,
            parsed_args.port,
            0b000000010  
        )

        raw_pack = pak.build()
        #Print Packet for debugging
        #print(f"Built raw packet: {raw_pack}")
        
    except ValueError as e:   
        print(e)        



