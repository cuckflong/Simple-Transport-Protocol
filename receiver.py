#!/usr/bin/python

import socket, pickle, sys, md5

# Header structure and some useful functions
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
    
    # Copy from another header structure
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

    # Calculate the header's length
    def getHeaderLength(self):
        data = pickle.dumps(self)
        self.headerLength = len(data)
        data = pickle.dumps(self)
        self.headerLength = len(data)

    # Generate the md5 checksum for the provided data
    def generateChecksum(self, data):
        m = md5.new()
        m.update(data)
        self.checksum = m.digest()

    # Verify the md5 checksum with the provided data
    def verifyChecksum(self, data):
        m = md5.new()
        m.update(data)
        if m.digest() == self.checksum:
            return True
        return False

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
    if header.verifyChecksum(payload):
        print payload
    else:
        print "checksum failed"
