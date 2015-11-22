#rxcp
from socket import *
from struct import *
import random
import time
from hashlib import md5
server4WayState={
"Listen": lambda x: x.AuthServerListen(),
"Established":lambda x: x.AuthServEstablished()
}
client4WayState={
"Auth": lambda x: x.AuthClient1(),
"Auth2": lambda x:x.AuthClient2(),
"Established": lambda x: x.AuthClientEstablished(),
}


class RxPSocket:
    def setNetEMU(self,port):
        self.netEMU=port
    def __init__(self,udpPort=8000,rxpPort=9000,recvBufferSize=0,sendBufferSize=0):
        self.udpPort=udpPort
        self.port=rxpPort
        self.socket=socket(AF_INET, SOCK_DGRAM)
        self.netEMU=5000
        self.sendBuffer=bytearray(sendBufferSize)
        self.recvBuffer=bytearray(recvBufferSize)
    def  bind(self,port,address=''):
        self.host=address
        self.port=port
        self.socket.bind(('',self.udpPort))
        self.secretKey=random.randint(0,100000)
    def listen(self):
        self.listen=True
    def accept(self):
        state="Listen"
        while self.listen:
            #Put the connection state machine
            state,address=server4WayState[state](self)
            if state=="Established":
                nsock=RxPSocket(recvBufferSize=1000000,sendBufferSize=1000000)
                host2,port2=address
                nsock.host=self.host
                nsock.port=self.port
                nsock.otherHost=host2
                nsock.otherPort=port2
                nsock.socket=self.socket
                return nsock,address
        if not self.listen:
            print "This socket is not listening, can't accept connections"
        return None
    def connect(self,host,port,sendBufferSize=1000000,recvBufferSize=1000000000):
        accepted=False
        self.otherPort=port
        self.otherHost=host
        self.socket.bind(('',self.udpPort))
        #Generate the buffers to send and recieve
        self.sendBuffer=bytearray(sendBufferSize)
        self.recvBuffer=bytearray(recvBufferSize)
        self.windowStart=0
        state="Auth"
        while not accepted:
            #do the connect state machine
            state=client4WayState[state](self)
            if state=="Established":
                accepted=True
        return accepted
    def AuthClient1(self):
        header,message=self.buildHeader("HELLO",0,0,"1000000",0)
        self.socket.sendto(message,(self.otherHost,int(self.netEMU)))
        self.socket.settimeout(10)
        try:
            data,adress=self.socket.recvfrom(1500)
            if not data==None:
                host,port=adress
                print "AUTH 1"
                print data
                if self.checkForCorruption(data):
                    dest,source,seqnum,acknum,length,flag,cs,rw=self.unpackHeader(data)
                    if((flag^int('1100000',2))==0):
                        self.seqNumber=random.randint(0,10000)
                        header,message=self.buildHeader(data[28:],self.seqNumber,acknum,,"0010000",1000000)
                        self.socket.sendto(message,(host,int(self.netEMU)))
                    if((flag^int('0110000',2))==0):
                        self.socket.settimeout(None)
                        #Send Auth
                        return "Established"
                return "Auth"
        except timeout:
            print "Timeout"
        return "Auth"
    def AuthServerListen(self):
        data,adress=self.socket.recvfrom(1500)
        host,port=adress
        if self.checkForCorruption(data):
            dest,source,seqnum,acknum,length,flag,cs,rw=self.unpackHeader(data)
            if((flag^int('1000000',2))==0):
                #Send Auth
                timer=time.clock()
                authMsg=pack("hdl",source,timer,self.secretKey)
                authMsg=authMsg+host
                hashed=md5(authMsg).hexdigest()
                authMsg=pack("hd",source,timer)
                authMsg=authMsg+host+hashed
                self.otherPort=port
                self.otherHost=host
                header,message=self.buildHeader(authMsg,0,0,"1100000",len(self.recvBuffer))
                self.socket.sendto(message,(host,int(self.netEMU)))
                print "START"
            elif((flag^int('0010000',2))==0):
                #Recieve Echo
                s2,t2=unpack("hd",data[28:40])
                h2=data[40:40+len(host)]
                checkMsg=pack("hdl",s2,t2,self.secretKey)
                checkMs=checkMsg+h2
                if md5(checkMs).hexdigest()==data[40+len(host):] and s2==source and h2==host:
                    self.seqNumber=random.randint(0,10000)
                    header,message=self.buildHeader("GOOD",self.seqNumber,acknum,"0110000",len(self.recvBuffer))
                    self.socket.sendto(message,(host,int(self.netEMU)))
                    return "Established", (host,source)
        return "Listen",None
    def send(self,message):

        self.socket.sendto(message,(self.otherHost,int(self.netEMU)))
    def recv(self,amount):
        pass
    def close(self):
        pass
    def buildHeader(self,message,seqnum,acknum,flags,rw):
        dest=self.otherPort
        source=self.port
        header=pack('hhqqbbhl', int(dest), int(source), seqnum,acknum,0,int(flags,2),0,rw)
        length=len(header)
        header=pack('hhqqbbhl', int(dest), int(source), seqnum,acknum,length,int(flags,2),0,rw)
        packet=header+message
        cs=checksum(packet)
        header=pack('hhqqbbHl', int(dest), int(source), seqnum,acknum,length,int(flags,2),cs,rw)
        return header,header+message
    def unpackHeader(self,message):
        return unpack('hhqqbbHl',message[0:28])
    def checkForCorruption(self,message):
        try:
            dest, source, seqnum,acknum,length,flags,cs,rw=self.unpackHeader(message)
            rhead=pack('hhqqbbhl', dest, source, seqnum,acknum,length,flags,0,rw)
            rcs=checksum(rhead+message[28:])
            return cs==rcs
        except error:
            return False
    def AuthServEstablished(self):
        pass
    def AuthClientEstablished(self):
        pass
def checksum(packet):
    b=bytearray(packet)
    s=0
    for a,c in zip(b[0::2],b[1::2]):
        d=a+c<<8
        d=d+s
        d=(d&0xFFFF)+(d>>16)
    return ~s&0xFFFF
