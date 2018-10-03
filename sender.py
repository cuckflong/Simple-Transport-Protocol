#!/usr/bin/python

import socket, pickle, sys, md5, random, time, binascii

RECEIVER_IP = None
RECEIVER_PORT = None
FILE = None
MWS = None
MSS = None
GAMMA = None
PDROP = 0
PDUPLICATE = 0
PCORRUPT = 0
PORDER = 0
MAXORDER = None
PDELAY = 0
MAXDELAY = None
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

class PacketLossDelay:
    def __init__(self):
        self.heldPacket = None
        self.waited = 0
    
    def flip(self, probability):
        p = random.uniform(0, 1)
        if p < probability:
            return True
        else:
            return False
    def sendCorruptPacket(self, header, data):
        if data == None:
            sendPacket(header, data)
            return
        # Calculate the checksum before corrupting the data
        header.generateChecksum(data)
        # Reverse one bit of the data
        print "[+] PLD: Original Data: %s" % (data)
        binData = bin(int(binascii.hexlify(data), 16))
        randomOffset = random.randint(2, len(binData)-1)
        binDataList = list(binData)
        if binDataList[randomOffset] == "1":
            binDataList[randomOffset] = "0"
        else: 
            binDataList[randomOffset] = "1"
        binData = "".join(binDataList)
        data = binascii.unhexlify('%x' % int(binData, 2))
        print "[+] PLD: Corrupted Data: %s" % (data)
        header.getHeaderLength()
        packet = pickle.dumps(header)
        packet += data
        s.send(packet)

    def checkHeldPacket(self):
        if self.heldPacket != None:
            self.waited += 1
            if self.waited == MAXORDER:
                print "[+] PLD: Re-Order Wait Finished, Sending Held Back Packet"
                sendPacket(self.heldPacket[0], self.heldPacket[1])
                self.heldPacket = None
                self.waited = 0
            else:
                print "[+] PLD: Already Held Back For %d Packet" % (self.waited)
        else:
            print "[+] PLD: No Held Back Packet"

    def sendPLDPacket(self, header, data):
        if self.flip(PDROP):
            print "[+] PLD: Packet Dropped"
            self.checkHeldPacket()
            return
        if self.flip(PDUPLICATE):
            print "[+] PLD: Sending Duplicate Packets"
            sendPacket(header, data)
            sendPacket(header, data)
            self.checkHeldPacket()
            return
        if self.flip(PCORRUPT):
            print "[+] PLD: Sending Corrupted Packet"
            self.sendCorruptPacket(header, data)
            self.checkHeldPacket()
            return
        if self.flip(PORDER):
            print "[+] PLD: Reordering Packets"
            if self.heldPacket != None:
                print "[+] PLD: A Packet Already On Hold, Sending Current Packet"
                sendPacket(header, data)
                return
            print "[+] PLD: Holding Back For %d Packets" % (MAXORDER)
            self.heldPacket = (header, data)
            self.waited = 0
            return
        if self.flip(PDELAY):
            print "[+] PLD: Delaying Packets"
            delay = random.uniform(0, MAXDELAY)
            time.sleep(delay)
            sendPacket(header, data)
            self.checkHeldPacket()
            return
        print "[+] PLD: Sending Normal Packet"
        sendPacket(header, data)
        self.checkHeldPacket()


def sendPacket(header, data):
    if data != None:
        header.generateChecksum(data)
    header.getHeaderLength()
    packet = pickle.dumps(header)
    if data != None:
        packet += data
    s.send(packet)

# Read data from the provided file
def getDataFromFile():
    f = open(FILE, "r")
    return f.read()

# Randomly generate the initial sequence number
def initialSeqNum():
    return random.randint(0, 1000000)

# Establish the connection with a three-way handshake
def EstablishConnection():
    headerRecv = STPHeader()
    header = STPHeader()
    header.SYN = True
    lastSeqNum = initialSeqNum()
    lastAckNum = None
    seqNumRecv = None
    ackNumRecv = None
    header.seqNum = lastSeqNum
    sendPacket(header, None)
    print "[+] Connection Establishing: 1st Handshake"
    # Set a timeout value for receiving the 2nd handshake
    timeout = time.time() + 2
    while True:
        if time.time() > timeout:
            print "[!] Connection Establishment Failed: Timeout"
            return None
        packet, addr = s.recvfrom(1024)
        headerRecv.copy(pickle.loads(packet))
        if (headerRecv.SYN == True and headerRecv.ACK == True and headerRecv.ackNum == lastSeqNum+1):
            seqNumRecv = headerRecv.seqNum
            ackNumRecv = headerRecv.ackNum
            print "[+] Connection Establishing: 2nd Handshake"
            break
        else:
            print "[!] Connection Establishing: Wrong Packet Received"
            continue
    header.clear()
    header.ACK = True
    header.seqNum = lastSeqNum + 1
    header.ackNum = seqNumRecv + 1
    lastSeqNum += 1
    lastAckNum = seqNumRecv + 1
    sendPacket(header, None)
    print "[+] Connection Established: 3rd Handshake"
    return (lastSeqNum, lastAckNum, seqNumRecv, ackNumRecv)

# Closing the connection
def CloseConnection():
    headerRecv = STPHeader()
    header = STPHeader()
    header.FIN = True
    sendPacket(header, None)
    # Enter FIN_WAIT_1 state
    while True:
        packet, addr = s.recvfrom(1024)
        headerRecv.copy(pickle.loads(packet))
        if headerRecv.ACK == True:
            print "[+] FIN_WAIT_1: Done"
            break
        else:
            print "[!] FIN_WAIT_1: Wrong Packet Received"
            continue
    # Enter FIN_WAIT_2 state
    while True:
        packet, addr = s.recvfrom(1024)
        headerRecv.copy(pickle.loads(packet))
        if headerRecv.FIN == True:
            header.clear()
            header.ACK = True
            sendPacket(header, None)
            print "[+] FIN_WAIT_2: Done"
            break
        else:
            print "[!] FIN_WAIT_2: Wrong Packet Received"
            continue
    # Enter TIME_WAIT state
    s.close()
    print "[+] Connection Closed"

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
        MAXDELAY = float(sys.argv[13])
        SEED = float(sys.argv[14])

    except:
        print """Usage:\tpython sender.py <receiver_host_ip> <receiver_port> 
        \t<file.pdf> <MWS> <MSS> <gamma> <pDrop> <pDuplicate> <pCorrupt> <pOrder> 
        \t<maxOrder> <pDelay> <maxDelay> <seed>"""
        sys.exit(1)

# Seed for randomisation
if SEED != None:
    random.seed(SEED)

# Address from the give IP and Port
ADDRESS = (RECEIVER_IP, RECEIVER_PORT)

# Create a global socket and connect to it
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(ADDRESS)

# Module for Packet Loss and Delay
pld = PacketLossDelay()

def main():
    # A loop to ensure the connection is established
    while True:
        LastRecv = EstablishConnection()
        if LastRecv != None:
            break
    header = STPHeader()
    data = "12345678910abcdefghij"
    pld.sendPLDPacket(header, data)
    CloseConnection()

if __name__ == "__main__":
    main()