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
    
    def pack(self):
        pack = []
        pack.append(self.seqNum)
        pack.append(self.ackNum)
        pack.append(self.headerLength)
        pack.append(self.checksum)
        pack.append(self.SYN)
        pack.append(self.ACK)
        pack.append(self.FIN)
        return pack

    def unpack(self, pack):
        self.seqNum = pack[0]
        self.ackNum = pack[1]
        self.headerLength = pack[2]
        self.checksum = pack[3]
        self.SYN = pack[4]
        self.ACK = pack[5]
        self.FIN = pack[6]

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
        data = pickle.dumps(self.pack())
        self.headerLength = len(data)
        data = pickle.dumps(self.pack())
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

def clearFile():
    f = open(STORED_FILE, "w")
    f.close()

def appendDataToFile(data):
    f = open(STORED_FILE, "a")
    f.write(data)
    f.close()

def sendPacket(header, addr):
    s.connect(addr)
    packet = pickle.dumps(header.pack())
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
        headerRecv.unpack(pickle.loads(packet))
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
        headerRecv.unpack(pickle.loads(packet))
        if headerRecv.ACK == True:
            seqNumRecv = headerRecv.seqNum
            ackNumRecv = headerRecv.ackNum
            print "[+] Connection Established"
            return (lastSeqNum, lastAckNum, seqNumRecv, ackNumRecv)

def HandlePackets(SentRecv):
    header = STPHeader()
    headerRecv = STPHeader()
    lastSeqNum = SentRecv[0]
    lastAckNum = SentRecv[1]
    seqNumRecv = SentRecv[2]
    ackNumRecv = SentRecv[3]
    bufferInfo = []
    while True:
        # print len(bufferInfo)
        packet, addr = s.recvfrom(1024)
        headerRecv.unpack(pickle.loads(packet))
        if headerRecv.FIN == True:
            CloseConnection(addr)
            return
        data = packet[headerRecv.headerLength:]
        header.clear()
        if not headerRecv.verifyChecksum(data) or headerRecv.seqNum < lastAckNum:
            print "[!] Corrupted Data Received"
            header.ACK = True
            header.ackNum = lastAckNum
            header.seqNum = lastSeqNum
        elif headerRecv.seqNum == lastAckNum:
            print "[+] Correct Data Received"
            #print "[+] Data: %s" % data
            appendDataToFile(data)
            if bufferInfo:
                nextSeq = headerRecv.seqNum
                nextLen = len(data)
                for i in range(len(bufferInfo)):
                    info = bufferInfo[i]
                    if nextSeq + nextLen == info[0]:
                        appendDataToFile(info[3])
                        nextSeq = info[0]
                        nextLen = info[2]
                        header.ACK = True
                        header.ackNum = nextSeq + nextLen
                        header.seqNum = info[1]
                    else:
                        bufferInfo = bufferInfo[i:]
                        break
            else:
                header.ACK = True
                header.ackNum = headerRecv.seqNum + len(data)
                header.seqNum = headerRecv.ackNum
        elif headerRecv.seqNum > lastAckNum:
            # Sequence Number, Acknoledgement Number, Length Of Data, Data 
            dataInfo = (int(headerRecv.seqNum), int(headerRecv.ackNum), len(data), data)
            if not bufferInfo:
                bufferInfo.append(dataInfo)
                continue
            else:
                inserted = False
                for i in range(len(bufferInfo)):
                    info = bufferInfo[i]
                    if dataInfo[0] + dataInfo[2] <= info[0]:
                        inserted = True
                        bufferInfo.insert(i, dataInfo)
                        break
                    else:
                        continue
                if not inserted:
                    bufferInfo.append(dataInfo)
            header.ACK = True
            header.ackNum = lastAckNum
            header.seqNum = lastSeqNum
        seqNumRecv = headerRecv.seqNum
        ackNumRecv = headerRecv.ackNum
        lastSeqNum = header.seqNum
        lastAckNum = header.ackNum   
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
        headerRecv.unpack(pickle.loads(packet))
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

# Create a global socket and bind to it
ADDRESS = (LOCALHOST, RECEIVER_PORT)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(ADDRESS)

def main():
    # Wait for a connection to be established
    SentRecv = EstablishConnection()
    # Clear the data in file
    clearFile()
    # Handle Remaining Packets
    HandlePackets(SentRecv)
    print "[+] Exiting Program"
    sys.exit(0)

if __name__ == "__main__":
    main()