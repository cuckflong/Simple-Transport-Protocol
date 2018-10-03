#!/usr/bin/python

import socket, pickle, sys, md5, random, time

LOCALHOST = "127.0.0.1"
RECEIVER_PORT = None
STORED_FILE = None

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

# Randomly generate the initial sequence number
def initialSeqNum():
    return random.randint(0, 1000000)

def sendPacket(header, addr):
    s.connect(addr)
    packet = pickle.dumps(header)
    s.send(packet)

# Wait for a connection to be established
def EstablishConnection():
    headerRecv = STPHeader()
    header = STPHeader()
    lastSeqNum = initialSeqNum()
    lastAckNum = None
    seqNumRecv = None
    ackNumRecv = None
    while True:
        packet, addr = s.recvfrom(1024)
        headerRecv.copy(pickle.loads(packet))
        if headerRecv.SYN == True:
            seqNumRecv = headerRecv.seqNum
            ackNumRecv = headerRecv.ackNum
            header.SYN = True
            header.seqNum = lastSeqNum
            header.ackNum = seqNumRecv + 1
            lastAckNum = seqNumRecv + 1
            sendPacket(header, addr)
            print "[+] Connection Established"
            return (lastSeqNum, lastAckNum)
        else:
            print "[!] Connection Establishing: False Packet received"
            continue

try:
    RECEIVER_PORT = int(sys.argv[1])
    STORED_FILE = sys.argv[2]
except:
    print "Usage:\tpython receiver.py <receiver_port> <file_r.pdf>"
    sys.exit(1)

ADDRESS = (LOCALHOST, RECEIVER_PORT)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(ADDRESS)

def main():
    # Wait for a connection to be established
    lastSeqAck = EstablishConnection()
    print "lol"

if __name__ == "__main__":
    main()