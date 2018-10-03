#!/usr/bin/python

import socket, pickle, sys

class STPHeader:
    def __init__(self):
        self.srcPort = None
        self.destPort = None
        self.seqNum = None
        self.ackNum = None
        self.headerLength = None
        self.checksum = None
        self.SYN = False
        self.ACK = False
        self.FIN = False
    
    def copy(self, header):
        self.srcPort = header.srcPort
        self.destPort = header.destPort
        self.seqNum = header.seqNum
        self.ackNum = header.ackNum
        self.headerLength = header.headerLength
        self.checksum = header.checksum
        self.SYN = header.SYN
        self.ACK = header.ACK
        self.FIN = header.FIN

    def getHeaderLength(self):
        data = pickle.dumps(self)
        self.headerLength = len(data)
        print self.headerLength
        data = pickle.dumps(self)
        self.headerLength = len(data)
        print self.headerLength

LOCALHOST = "127.0.0.1"
RECEIVER_PORT = None
STORED_FILE = None

try:
    RECEIVER_PORT = int(sys.argv[1])
    STORED_FILE = sys.argv[2]
except:
    print "Usage:\tpython receiver.py <receiver_port> <file_r.pdf>"
    sys.exit(1)

address = (LOCALHOST, RECEIVER_PORT)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(address)

while True:
    data, addr = s.recvfrom(1024)
    header = STPHeader()
    tmpHeader = pickle.loads(data)
    header.copy(tmpHeader)
    payload = data[header.headerLength:]
    print payload
