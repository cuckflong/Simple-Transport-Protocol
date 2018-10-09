#!/usr/bin/python

import argparse, socket, pickle, sys, md5, random, time

# Localhost
LOCALHOST = "127.0.0.1"

# Log File
LOGFILE = "Receiver_log.txt"

# Statistics
DATARECEIVED = 0
SEGMENTS = 0
DATASEGMENTS = 0
ERRORSEGMENTS = 0
DUPSEGMENTS = 0
DUPACK = 0

# Timer
TIMER = 0

# Header structure and some useful functions
class STPHeader:
    def __init__(self):
        self.seqNum = 0
        self.ackNum = 0
        self.headerLength = 0
        self.checksum = ""
        self.SYN = False
        self.ACK = False
        self.FIN = False
    
    # Clear the header
    def clear(self):
        self.seqNum = 0
        self.ackNum = 0
        self.headerLength = 0
        self.checksum = ""
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
        self.checksum += "a"*32
        data = pickle.dumps(self.pack())
        self.headerLength = len(data)
        data = pickle.dumps(self.pack())
        self.headerLength = len(data)

    # Generate the md5 checksum for the provided data
    def generateChecksum(self, data):
        m = md5.new()
        checksumString = str(self.seqNum) + str(self.ackNum) + str(self.headerLength)
        if data != None:
            checksumString += data
        m.update(checksumString)
        self.checksum = m.hexdigest()

    # Verify the md5 checksum with the provided data
    def verifyChecksum(self, data):
        m = md5.new()
        checksumString = str(self.seqNum) + str(self.ackNum) + str(self.headerLength)
        if data != "":
            checksumString += data
        m.update(checksumString)
        if m.hexdigest() == self.checksum:
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
    f = open(args.STORED_FILE, "w")
    f.close()

def appendDataToFile(data):
    global DATARECEIVED
    DATARECEIVED += len(data)
    f = open(args.STORED_FILE, "a")
    f.write(data)
    f.close()

def sendPacket(header, addr):
    s.connect(addr)
    packet = pickle.dumps(header.pack())
    # header.info()
    s.send(packet)

def verbosePrint(type, message):
    if not args.verbose:
        return
    if type == "error":
        print "[!] %s" % message
    elif type == "normal":
        print "[+] %s" % message
    elif type == "info":
        print message

# Write information to log file
def writeLog(event, header, dataLen):
    current = round(time.time() - TIMER, 3)
    if header == None:
        line = "%-20s%-20.2f Corrupted Header" % (event, current)
        return
    if dataLen > 0:
        packetType = "D"
    elif header.SYN and header.ACK:
        packetType = "SA"
    elif header.SYN:
        packetType = "S"
    elif header.ACK:
        packetType = "A"
    elif header.FIN:
        packetType = "F"
    else:
        packetType = "Unknown"
    line = "%-20s%-20.2f%-20s%-20d%-20d%-20d" % (event, current, packetType, header.seqNum, dataLen, header.ackNum)
    log.write(line + "\n")

# Write statistic to log file
def writeStatistic():
    log.write("\n")
    log.write("="*72 + "\n")
    log.write("%-60s%10d\n" % ("Amount Of Data Received (bytes)", DATARECEIVED))
    log.write("%-60s%10d\n" % ("Total Segments Received", SEGMENTS))
    log.write("%-60s%10d\n" % ("Data Segments Received", DATASEGMENTS))
    log.write("%-60s%10d\n" % ("Data Segments With Bit Errors", ERRORSEGMENTS))
    log.write("%-60s%10d\n" % ("Duplicate Data Segments Received", DUPSEGMENTS))
    log.write("%-60s%10d\n" % ("Duplicate ACKs Sent", DUPACK))
    log.write("="*72)

# Wait for a connection to be established
def EstablishConnection():
    global SEGMENTS
    global TIMER
    headerRecv = STPHeader()
    header = STPHeader()
    lastSeqNum = initialSeqNum()
    lastAckNum = 0
    seqNumRecv = 0
    ackNumRecv = 0
    while True:
        packet, addr = s.recvfrom(1024)
        try:
            headerRecv.unpack(pickle.loads(packet))
            TIMER = time.time()
            writeLog("rcv", headerRecv, 0)
            SEGMENTS += 1
        except:
            verbosePrint("error", "Corrupted Header Received")
            continue
        if headerRecv.SYN == True:
            seqNumRecv = headerRecv.seqNum
            ackNumRecv = headerRecv.ackNum
            header.SYN = True
            header.ACK = True
            header.seqNum = lastSeqNum
            header.ackNum = seqNumRecv + 1
            lastAckNum = seqNumRecv + 1
            verbosePrint("normal", "Connection Establishing: Sending SYN/ACK Packet")
            sendPacket(header, addr)
            writeLog("snd", header, 0)
            break
        else:
            verbosePrint("error", "Connection Establishing: False Packet received")
            continue
    while True:
        packet, addr = s.recvfrom(1024)
        try:
            headerRecv.unpack(pickle.loads(packet))
            writeLog("rcv", headerRecv, 0)
            SEGMENTS += 1
        except:
            verbosePrint("error", "Corrupted Header Received")
            continue
        if headerRecv.ACK == True:
            seqNumRecv = headerRecv.seqNum
            ackNumRecv = headerRecv.ackNum
            verbosePrint("normal", "Connection Established")
            return (lastSeqNum, lastAckNum, seqNumRecv, ackNumRecv)

def HandlePackets(SentRecv):
    global SEGMENTS
    global DATASEGMENTS
    global ERRORSEGMENTS
    global DUPSEGMENTS
    global DUPACK
    header = STPHeader()
    headerRecv = STPHeader()
    lastSeqNum = SentRecv[0]
    lastAckNum = SentRecv[1]
    bufferInfo = []
    while True:
        packet, addr = s.recvfrom(1024)
        try:
            headerRecv.unpack(pickle.loads(packet))
        except:
            SEGMENTS += 1
            ERRORSEGMENTS += 1
            writeLog("rcv/corr", None, 0)
            verbosePrint("error", "Corrupted Header Received")
            header.ACK = True
            header.ackNum = lastAckNum
            header.seqNum = lastSeqNum
            sendPacket(header, addr)
            writeLog("snd/DA", header, 0)
            continue
        if headerRecv.FIN == True and headerRecv.seqNum == lastAckNum:
            SEGMENTS += 1
            writeLog("rcv", headerRecv, 0)
            CloseConnection(addr, headerRecv)
            return
        elif headerRecv.SYN != True:
            continue
        data = packet[headerRecv.headerLength:]
        header.clear()
        SEGMENTS += 1
        DATASEGMENTS += 1
        if not headerRecv.verifyChecksum(data):
            ERRORSEGMENTS += 1
            writeLog("rcv/corr", headerRecv, len(data))
            verbosePrint("error", "Corrupted Data Received")
            header.ACK = True
            header.ackNum = lastAckNum
            header.seqNum = lastSeqNum
            writeLog("snd/DA", header, 0)
        elif headerRecv.seqNum == lastAckNum:
            verbosePrint("normal", "Correct Data Received")
            writeLog("rcv", headerRecv, len(data))
            appendDataToFile(data)
            # If Segment Connects With The Buffer, Send The Latest ACK
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
                        if i == len(bufferInfo)-1:
                            bufferInfo = []
                            break
                    else:
                        header.ACK = True
                        header.ackNum = nextSeq + nextLen
                        header.seqNum = info[1]
                        bufferInfo = bufferInfo[i:]
                        break
            else:
                header.ACK = True
                header.ackNum = headerRecv.seqNum + len(data)
                header.seqNum = headerRecv.ackNum
            writeLog("snd", header, 0)
        # Buffer For Out-Of-Order Segments
        elif headerRecv.seqNum > lastAckNum:
            DUPACK += 1
            writeLog("rcv", headerRecv, len(data))
            # Sequence Number, Acknoledgement Number, Length Of Data, Data 
            dataInfo = (int(headerRecv.seqNum), int(headerRecv.ackNum), len(data), data)
            if not bufferInfo:
                bufferInfo.append(dataInfo)
                continue
            else:
                inserted = False
                for i in range(len(bufferInfo)):
                    info = bufferInfo[i]
                    if dataInfo[0] == info[0]:
                        inserted = True
                        break
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
            writeLog("snd/DA", header, 0)
        else:
            writeLog("rcv", headerRecv, len(data))
            DUPSEGMENTS += 1
            DUPACK += 1
            header.ACK = True
            header.seqNum = lastSeqNum
            header.ackNum = lastAckNum
            writeLog("snd/DA", header, 0)
        lastSeqNum = header.seqNum
        lastAckNum = header.ackNum  
        sendPacket(header, addr)             

def CloseConnection(addr, lastPacket):
    global SEGMENTS
    headerRecv = STPHeader()
    header = STPHeader()
    header.ACK = True
    header.ackNum = lastPacket.seqNum + 1
    header.seqNum = lastPacket.ackNum
    verbosePrint("normal", "Closing Connection: Sending ACK Packet")
    sendPacket(header, addr)
    writeLog("snd", header, 0)
    # Enter CLOSE_WAIT state
    header.ACK = False
    header.FIN = True
    verbosePrint("normal", "Closing Connection: Sending FIN Packet")
    sendPacket(header, addr)
    writeLog("snd", header, 0)
    # Enter LAST_ACK state
    while True:
        packet, addr = s.recvfrom(1024)
        try:
            headerRecv.unpack(pickle.loads(packet))
            writeLog("rcv", headerRecv, 0)
            SEGMENTS += 1
        except:
            verbosePrint("error", "Corrupted Header Received")
            continue
        if headerRecv.ACK == True:
            s.close()
            verbosePrint("normal", "Connection Closed")
            return
        else:
            verbosePrint("error", "LAST_ACK: Wrong Packet Received")

# Parse the arguments
parser = argparse.ArgumentParser()
parser.add_argument("RECEIVER_PORT", type=int, help="The port number on which the Receiver will open a UDP socket for receiving datagrams from the Sender")
parser.add_argument("STORED_FILE", type=str, help="The name of the pdf file into which the data sent by the sender should be stored")
parser.add_argument("-v", "--verbose", help="Print Sender's actions", action="store_true")
args = parser.parse_args()

# Create a global socket and bind to it
ADDRESS = (LOCALHOST, args.RECEIVER_PORT)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(ADDRESS)

# Open log file for writing
log = open(LOGFILE, "w")
log.write("%-20s%-20s%-20s%-20s%-20s%-20s\n\n" % ("Event", "Time", "Type Of Packet", "Sequence Number", "Data Bytes", "Acknowledge Number"))

def main():
    # Wait for a connection to be established
    SentRecv = EstablishConnection()

    # Clear the data in file
    clearFile()
    
    # Handle Remaining Packets
    HandlePackets(SentRecv)

    # Write Statistics
    writeStatistic()
    log.close()

    # Finish
    verbosePrint("normal", "Exiting Program")
    sys.exit(0)

if __name__ == "__main__":
    main()