#!/usr/bin/python3

from random import randint


def rand_ip():
    ip = [randint(0,255) for _ in range(4)]
    rand_ip = ".".join(map(str, ip))
    return(rand_ip)

if __name__=="__main__":
    print(rand_ip())

