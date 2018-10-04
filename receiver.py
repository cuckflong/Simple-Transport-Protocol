#!/usr/bin/python

import socket, pickle, sys, md5, random, time

LOCALHOST = "127.0.0.1"
RECEIVER_PORT = None
STORED_FILE = None

# Header structure and some useful functions
class STPHeader:
    def __init__(self):
        self.seqNum = None
        self.ackNum = None
        self.headerLength = None
        self.checksum = None
        self.SYN = False
        self.ACK = False
        self.FIN = False
    
    # Clear the header
    def clear(self):
        self.seqNum = None
        self.ackNum = None
        self.headerLength = None
        self.checksum = None
        self.SYN = False
        self.ACK = False
        self.FIN = False

    # Copy from another header structure
    def copy(self, header):
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

    # Print the details of the header
    def info(self):
        print "################################################"
        print "* [?] Header Details:                          *"
        print "* [?]\tSequence Number: %-22s*" % self.seqNum
        print "* [?]\tAcknoledgement Number: %-16s*" % self.ackNum
        print "* [?]\tSYN: %-34s*" % self.SYN
        print "* [?]\tACK: %-34s*" % self.ACK
        print "* [?]\tFIN: %-34s*" % self.FIN
        print "################################################"

# Randomly generate the initial sequence number
def initialSeqNum():
    return random.randint(0, 1000000)

def sendPacket(header, addr):
    s.connect(addr)
    packet = pickle.dumps(header)
    #header.info()
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
            header.ACK = True
            header.seqNum = lastSeqNum
            header.ackNum = seqNumRecv + 1
            lastAckNum = seqNumRecv + 1
            print "[+] Connection Establishing: Sending SYN/ACK Packet"
            sendPacket(header, addr)
            break
        else:
            print "[!] Connection Establishing: False Packet received"
            continue
    while True:
        packet, addr = s.recvfrom(1024)
        headerRecv.copy(pickle.loads(packet))
        if headerRecv.ACK == True:
            seqNumRecv = headerRecv.seqNum
            ackNumRecv = headerRecv.ackNum
            print "[+] Connection Established"
            return (lastSeqNum, lastAckNum, seqNumRecv, ackNumRecv)

def HandlePacket(tmpHeader, data, SentRecv, addr):
    lastSeqNum = SentRecv[0]
    lastAckNum = SentRecv[1]
    seqNumRecv = SentRecv[2]
    ackNumRecv = SentRecv[3]
    header = STPHeader()
    headerRecv = STPHeader()
    headerRecv.copy(tmpHeader)
    print "Data Received: %s" % data
    print "Verification: %s" % headerRecv.verifyChecksum(data)
    header.ACK = True
    header.ackNum = headerRecv.seqNum + len(data)
    header.seqNum = headerRecv.ackNum
    sendPacket(header, addr)

def CloseConnection(addr):
    headerRecv = STPHeader()
    header = STPHeader()
    header.ACK = True
    print "[+] Closing Connection: Sending ACK Packet"
    sendPacket(header, addr)
    # Enter CLOSE_WAIT state
    header.clear()
    header.FIN = True
    print "[+] Closing Connection: Sending FIN Packet"
    sendPacket(header, addr)
    # Enter LAST_ACK state
    while True:
        packet, addr = s.recvfrom(1024)
        headerRecv.copy(pickle.loads(packet))
        if headerRecv.ACK == True:
            s.close()
            print "[+] Connection Closed"
            return
        else:
            print "[!] LAST_ACK: Wrong Packet Received"

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
    headerRecv = STPHeader()
    # Wait for a connection to be established
    SentRecv = EstablishConnection()
    while True:
        packet, addr = s.recvfrom(1024)
        headerRecv.copy(pickle.loads(packet))
        # Check if the client want to close the connection
        if headerRecv.FIN == True:
            CloseConnection(addr)
            print "[+] Exiting Program..."
            sys.exit(0)
        else:
            data = packet[headerRecv.headerLength:]
            HandlePacket(headerRecv, data, SentRecv, addr)
        
if __name__ == "__main__":
    main()