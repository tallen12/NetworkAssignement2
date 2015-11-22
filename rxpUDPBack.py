from socket import *
nextEvenPortUDP=8000
SockOddUDP={}
def getUDPOddSock(port):
    if port not SockOddUDP:
        s = socket(AF_INET, SOCK_DGRAM)
        portUDP=nextEvenPortUDP+1
        s.bind(('',portUDP))
        SockOddUDP[port]=s
        s = socket(AF_INET, SOCK_DGRAM)
        portUDP=nextEvenPortUDP
        s.bind(('',portUDP))
        SockEvenPortUDP[port]=s
        nextEvenPortUDP=nextEvenPortUDP+2
    return SockOddUDP[port]
SockEvenUDP={}
def getUDPEvenSock(port):
    if port not SockEvenUDP:
        s = socket(AF_INET, SOCK_DGRAM)
        portUDP=nextEvenPortUDP+1
        s.bind(('',portUDP))
        SockOddUDP[port]=s
        s = socket(AF_INET, SOCK_DGRAM)
        portUDP=nextEvenPortUDP
        s.bind(('',portUDP))
        SockEvenUDP[port]=s
        nextEvenPortUDP=nextEvenPortUDP+2
    return SockEvenUDP[port]
