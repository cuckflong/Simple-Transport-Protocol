#!/usr/bin/python

import socket, pickle, sys, md5, random

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
    
    # Clear the header
    def clear(self):
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

def sendPacket(header, data):
    header.generateChecksum(data)
    header.getHeaderLength()
    packet = pickle.dumps(header)
    if data != None:
        packet += data
    s.send(packet)
    print "[+] Packet sent with length %d" % len(data)

# Read data from the provided file
def getDataFromFile():
    f = open(FILE, "r")
    return f.read()

# Randomly generate the initial sequence number
def initialSeqNum():
    return random.randint(0, 1000000)

def EstablishConnection():
    header = STPHeader()
    header.SYN = True
    header.seqNum = initialSeqNum()

# A simple mode with just IP, port and file
if len(sys.argv) == 4:
    try:
        RECEIVER_IP = sys.argv[1]
        RECEIVER_PORT = int(sys.argv[2])
        FILE = sys.argv[3]

    except:
        print "Arguments not correct"
        sys.exit(1)
# Proper mode with all 14 arguments
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

# Address from the give IP and Port
ADDRESS = (RECEIVER_IP, RECEIVER_PORT)

# Create a global socket and connect to it
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(ADDRESS)

def main():
    header = STPHeader()
    sendPacket(header, getDataFromFile())

if __name__ == "__main__":
    main()