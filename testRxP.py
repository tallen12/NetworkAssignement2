from rxcpBase import *
rxp=RxPSocket(8001)
rxp.bind(12000)
rxp.listen()
while True:
    sock,addr=rxp.accept()
