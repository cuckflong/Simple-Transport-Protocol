#!/usr/bin/python

import socket, pickle, sys

RECEIVER_IP = None
RECEIVER_PORT = None
FILE = None
MWS = None
MSS = None
GAMMA = None
PDROP = None
PDUPLICATE = None
PCORRUPT = None
PORDER = None
MAXORDER = None
PDELAY = None
MAXDELAP = None
SEED = None

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

if len(sys.argv) == 4:
    try:
        RECEIVER_IP = sys.argv[1]
        RECEIVER_PORT = int(sys.argv[2])
        FILE = sys.argv[3]

    except:
        print "Arguments not correct"
        sys.exit(1)
else:
    try:
        RECEIVER_IP = sys.argv[1]
        RECEIVER_PORT = int(sys.argv[2])
        FILE = sys.argv[3]
        MWS = int(sys.argv[4])
        MSS = int(sys.argv[5])
        GAMMA = int(sys.argv[6])
        PDROP = float(sys.argv[7])
        PDUPLICATE = float(sys.argv[8])
        PCORRUPT = float(sys.argv[9])
        PORDER = float(sys.argv[10])
        MAXORDER = int(sys.argv[11])
        PDELAY = float(sys.argv[12])
        MAXDELAP = float(sys.argv[13])
        SEED = float(sys.argv[14])

    except:
        print """Usage:\tpython sender.py <receiver_host_ip> <receiver_port> 
        \t<file.pdf> <MWS> <MSS> <gamma> <pDrop> <pDuplicate> <pCorrupt> <pOrder> 
        \t<maxOrder> <pDelay> <maxDelay> <seed>"""
        sys.exit(1)

address = (RECEIVER_IP, RECEIVER_PORT)

header = STPHeader()
header.getHeaderLength()
data = pickle.dumps(header)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(address)

s.send(data+"abcd")
s.close()

print "Data sent"
