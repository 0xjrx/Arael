#!/usr/bin/python3
from argparse import ArgumentParser

from random import randint


def rand_ip():
    ip = [randint(0,255) for _ in range(4)]
    rand_ip = ".".join(map(str, ip))
    return(rand_ip)



def main():
    parser = ArgumentParser()
    parser.add_argument('-t', '--target', action='store', help='Specify the target IP address')
    parser.add_argument('-p','--port', action='store', help='Specify the target port')
    parser.add_argument('-c', '--count', action='store', help='Specify the amount of packets sent')
    
    errors = []

    args = parser.parse_args()

    if args.target and args.port and args.count: 
        print("Arguments parsed")
    else:
        if args.target is None:
            errors.append("Error: --t or --target is required.")
        if args.port is None:
            errors.append("Error: --p or --port is required.")
        if args.count is None:
            errors.append("Error: --c or --count is required.")
    if errors:
        raise ValueError("\n".join(errors))

if __name__ == "__main__":
    main()
    print(rand_ip())




