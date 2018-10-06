#!/usr/bin/python

import socket, pickle, sys, md5, random, time, binascii, threading

# Arguments
RECEIVER_IP = None
RECEIVER_PORT = None
FILE = None
MWS = None
MSS = 4
GAMMA = None
PDROP = 0
PDUPLICATE = 0
PCORRUPT = 0
PORDER = 0
MAXORDER = 0
PDELAY = 0
MAXDELAY = 0
SEED = None

# Timeout Interval
TIMEOUT = 0

# Initial value for EstimatedRTT and DevRTT
ESTRTT = 0.5    # 500 millisecond
DEVRTT = 0.25   # 250 millisecond

# Timer
TIMER = 0
TIMERLIST = []

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
        # print "[+] PLD: Original Data: %s" % (data)
        binData = bin(int(binascii.hexlify(data), 16))
        randomOffset = random.randint(2, len(binData)-1)
        binDataList = list(binData)
        if binDataList[randomOffset] == "1":
            binDataList[randomOffset] = "0"
        else: 
            binDataList[randomOffset] = "1"
        binData = "".join(binDataList)
        try:
            data = binascii.unhexlify('%x' % int(binData, 2))
        except:
            data = binascii.unhexlify('0%x' % int(binData, 2))
        #print "[+] PLD: Corrupted Data: %s" % (data)
        header.getHeaderLength()
        packet = pickle.dumps(header.pack())
        packet += data
        print "[+] PLD CORRUPT: Sending Corrupted Packet"
        # header.info()
        s.send(packet)

    def checkHeldPacket(self):
        if self.heldPacket != None:
            self.waited += 1
            if self.waited >= MAXORDER:
                print "[+] PLD REORDER: Re-Order Wait Finished, Sending Held Back Packet"
                sendPacket(self.heldPacket[0], self.heldPacket[1])
                self.heldPacket = None
                self.waited = 0
            else:
                print "[+] PLD REORDER: Already Held Back For %d Packet" % (self.waited)
        else:
            print "[+] PLD REORDER: No Held Back Packet"

    def sendDelayPacket(self, header, data):
        delay = random.uniform(0, MAXDELAY)
        print "[+] PLD DELAY: Delaying For %s Seconds" % delay
        time.sleep(delay)
        try:         
            sendPacket(header, data)
            print "[+] PLD DELAY: Sending Delayed Packet With %s Seconds Delay" % delay
        except:
            sys.exit(1)

    def sendPLDPacket(self, header, data):
        if self.flip(PDROP):
            print "[+] PLD DROP: Packet Dropped"
            self.checkHeldPacket()
            return
        if self.flip(PDUPLICATE):
            print "[+] PLD DUPLICATE: Duplicating Packet"
            sendPacket(header, data)
            sendPacket(header, data)
            self.checkHeldPacket()
            return
        if self.flip(PCORRUPT):
            print "[+] PLD CORRUPT: Corrupting Packet"
            self.sendCorruptPacket(header, data)
            self.checkHeldPacket()
            return
        if self.flip(PORDER):
            print "[+] PLD REORDER: Reordering Packets"
            if self.heldPacket != None:
                print "[+] PLD REORDER: A Packet Already On Hold, Sending Current Packet"
                sendPacket(header, data)
                self.checkHeldPacket()
                return
            if MAXORDER == 0:
                print "[+] PLD REORDER: MAXORDER=0, No Need To Hold Packet, Sending Current Packet"
                sendPacket(header, data)
                return
            print "[+] PLD REORDER: Holding Back For %d Packets" % (MAXORDER)
            # print data
            newHeader = STPHeader()
            newHeader.copy(header)
            self.heldPacket = (newHeader, data)
            self.waited = 0
            return
        if self.flip(PDELAY):
            tmpHeader = STPHeader()
            print "[+] PLD DELAY: Delaying Packet"
            tmpHeader.copy(header)
            # Start a new thread to simulate the delay packet
            try:
                t = threading.Thread(target=self.sendDelayPacket, args=(tmpHeader, data))
                t.start()
            except:
                print "Threading Exception"
                sys.exit(1)
            self.checkHeldPacket()
            return

        print "[+] PLD NORMAL: Sending Normal Packet"
        sendPacket(header, data)
        self.checkHeldPacket()


def sendPacket(header, data):
    if data != None:   
        header.generateChecksum(data)
    header.getHeaderLength()
    packet = pickle.dumps(header.pack())
    if data != None:
        packet += data
    # header.info()
    # print "[+] Sending Packet With Data: %s" % data
    s.send(packet)

# Read data from the provided file
def getDataFromFile():
    f = open(FILE, "r")
    data = f.read()
    f.close()
    return data

# Randomly generate the initial sequence number
def initialSeqNum():
    return random.randint(0, 1000000)

# Establish the connection with a three-way handshake
def EstablishConnection():
    headerRecv = STPHeader()
    header = STPHeader()
    header.SYN = True
    sentSeqNum = initialSeqNum()
    sentAckNum = None
    seqNumRecv = None
    ackNumRecv = None
    header.seqNum = sentSeqNum
    print "[+] Connection Establishing: 1st Handshake"
    sendPacket(header, None)
    while True:
        try:
            packet, addr = s.recvfrom(1024+MSS)
        except socket.timeout:
            print "[!] Connection Establishment Failed: Timeout"
            return None
        headerRecv.unpack(pickle.loads(packet))
        if (headerRecv.SYN == True and headerRecv.ACK == True and headerRecv.ackNum == sentSeqNum+1):
            seqNumRecv = headerRecv.seqNum
            ackNumRecv = headerRecv.ackNum
            print "[+] Connection Establishing: 2nd Handshake"
            break
        else:
            print "[!] Connection Establishing: Wrong Packet Received"
            continue
    header.clear()
    header.ACK = True
    header.seqNum = sentSeqNum + 1
    header.ackNum = seqNumRecv + 1
    sentSeqNum += 1
    sentAckNum = seqNumRecv + 1
    print "[+] Connection Established: 3rd Handshake"
    sendPacket(header, None)
    return (sentSeqNum, sentAckNum, seqNumRecv, ackNumRecv)

# Transfer the file to server without pipelining
def SendFile(SentRecv):
    global ESTRTT
    global DEVRTT
    global TIMEOUT
    global TIMER
    sentSeqNum = SentRecv[0]
    sentAckNum = SentRecv[1]
    seqNumRecv = SentRecv[2]
    ackNumRecv = SentRecv[3]
    header = STPHeader()
    headerRecv = STPHeader()
    data = getDataFromFile()
    segmentData = None
    offset = 0
    sentDataLen = 0
    header.SYN = True
    while len(data[offset:]) > 0:
        header.seqNum = sentSeqNum
        header.ackNum = sentAckNum
        if len(data[offset:]) > MSS:
            segmentData = data[offset:offset+MSS]
        else:
            segmentData = data[offset:]
        sentDataLen = len(segmentData)
        #print "[+] Sending Data: %s" % segmentData
        pld.sendPLDPacket(header, segmentData)
        TIMER = time.time()
        while True:
            try:
                packet, addr = s.recvfrom(1024+MSS)
                sampleRTT = time.time()-TIMER
                ESTRTT = 0.875*ESTRTT + 0.125*(sampleRTT)
                DEVRTT = 0.75*DEVRTT + 0.25*abs(sampleRTT-ESTRTT)
                TIMEOUT = ESTRTT + GAMMA*DEVRTT
                print "TIMEOUT INTERVAL: %s" % TIMEOUT
                s.settimeout(TIMEOUT)
            except socket.timeout:
                print "[!] Receiving ACK Timeout, Sending Packet Again"
                break
            headerRecv.unpack(pickle.loads(packet))
            #headerRecv.info()
            #print "[+] Packet Received"
            if headerRecv.ACK == True and headerRecv.ackNum == sentSeqNum+sentDataLen:
                print "[+] ACK Received"
                seqNumRecv = headerRecv.seqNum
                ackNumRecv = headerRecv.ackNum
                offset += sentDataLen
                sentSeqNum = ackNumRecv
                sentAckNum = seqNumRecv + 1
                break

def PipelineSendFile(SentRecv):
    global ESTRTT
    global DEVRTT
    global TIMEOUT
    global TIMER
    global TIMERLIST
    sentSeqNum = SentRecv[0]
    sentAckNum = SentRecv[1]
    header = STPHeader()
    headerRecv = STPHeader()
    data = getDataFromFile()
    segmentData = None
    offset = 0
    sentDataLen = 0
    sendBase = sentSeqNum
    baseAck = sentAckNum
    # sentList = []
    baseOffset = sendBase
    lastToAck = sentSeqNum
    timeoutInterval = 0
    duplicateList = []
    dupExist = False
    header.SYN = True
    while len(data[sendBase-baseOffset:]) > 0:
        while lastToAck - sendBase <= MWS:
            if lastToAck - baseOffset >= len(data):
                break
            header.seqNum = sentSeqNum
            header.ackNum = sentAckNum
            offset = sentSeqNum - baseOffset
            if len(data[offset:]) > MSS:
                segmentData = data[offset:offset+MSS]
            else:
                segmentData = data[offset:]
            sentDataLen = len(segmentData)
            lastToAck = sentSeqNum + sentDataLen
            for timer in TIMERLIST:
                if timer[0] == lastToAck:
                    TIMERLIST.remove(timer)
                    break
            TIMERLIST.append((lastToAck, time.time()))
            pld.sendPLDPacket(header, segmentData)
            # sentList.append((sentSeqNum, sentAckNum, lastToAck))
            sentSeqNum += sentDataLen
            sentAckNum += 1

        timeoutInterval = time.time() + TIMEOUT
        duplicateList = []
        while True:
            if sendBase - baseOffset >= len(data):
                break
            if time.time() > timeoutInterval:
                break
            try:
                packet, addr = s.recvfrom(1024+MSS)
            except socket.timeout:
                print "[!] Receiving ACK Timeout, Sending Packets Again"
                if sendBase - baseOffset >= len(data):
                    break
                header.seqNum = sendBase
                header.ackNum = baseAck
                offset = sendBase - baseOffset
                if len(data[offset:]) > MSS:
                    segmentData = data[offset:offset+MSS]
                else:
                    segmentData = data[offset:]
                lastToAck = sendBase + sentDataLen
                for timer in TIMERLIST:
                    if timer[0] == lastToAck:
                        TIMERLIST.remove(timer)
                        break
                TIMERLIST.append((lastToAck, time.time()))
                pld.sendPLDPacket(header, segmentData)
                break
            try:
                headerRecv.unpack(pickle.loads(packet))
            except:
                print "[!] Corrupted Header"
                continue
            for timer in TIMERLIST:
                if timer[0] == headerRecv.ackNum:
                    sampleRTT = time.time() - timer[1]
                    ESTRTT = 0.875*ESTRTT + 0.125*(sampleRTT)
                    DEVRTT = 0.75*DEVRTT + 0.25*abs(sampleRTT-ESTRTT)
                    TIMEOUT = ESTRTT + GAMMA*DEVRTT
                    print "TIMEOUT INTERVAL: %s" % TIMEOUT
                    s.settimeout(TIMEOUT)
                    TIMERLIST.remove(timer)
                    break
            if headerRecv.ACK == True and headerRecv.ackNum > sendBase:
                sendBase = headerRecv.ackNum
                baseAck = headerRecv.seqNum + 1
                sentSeqNum = sendBase
                sentAckNum = baseAck
                # for i in range(len(sentList)):
                #     sent = sentList[i]
                #     if sent[2] == headerRecv.ackNum:
                #         sentList = sentList[i+1:]
                #         break
            elif headerRecv.ACK == True and headerRecv.ackNum <= sendBase:
                dupExist = False
                for dup in duplicateList:
                    if dup[0] == headerRecv.ackNum:
                        dupExist = True
                        if dup[1] == 3:
                            sentSeqNum = headerRecv.ackNum
                            sentAckNum = headerRecv.seqNum + 1
                            header.seqNum = sentSeqNum
                            header.ackNum = sentAckNum
                            offset = sentSeqNum - baseOffset
                            if len(data[offset:]) > MSS:
                                segmentData = data[offset:offset+MSS]
                            else:
                                segmentData = data[offset:]
                            lastToAck = sentSeqNum + sentDataLen
                            for timer in TIMERLIST:
                                if timer[0] == lastToAck:
                                    TIMERLIST.remove(timer)
                                    break
                            TIMERLIST.append((lastToAck, time.time()))
                            print "!!!!!!!!!!! Triple ACK !!!!!!!!!!"
                            duplicateList.remove(dup)
                            pld.sendPLDPacket(header, segmentData)
                        else:
                            dup[1] += 1
                if not dupExist:
                    duplicateList.append([headerRecv.ackNum, 1])
                    

# Closing the connection
def CloseConnection():
    #s.settimeout(1)
    headerRecv = STPHeader()
    header = STPHeader()
    header.FIN = True
    print "[+] Closing Connection: Sending FIN Packet"
    sendPacket(header, None)
    # Enter FIN_WAIT_1 state
    while True:
        try:
            packet, addr = s.recvfrom(1024+MSS)
        except socket.timeout:
             continue
        headerRecv.unpack(pickle.loads(packet))
        if headerRecv.ACK == True:
            print "[+] FIN_WAIT_1: Done"
            break
        else:
            print "[!] FIN_WAIT_1: Wrong Packet Received"
            continue
    # Enter FIN_WAIT_2 state
    while True:
        try:
            packet, addr = s.recvfrom(1024+MSS)
        except socket.timeout:
             continue
        headerRecv.unpack(pickle.loads(packet))
        if headerRecv.FIN == True:
            header.clear()
            header.ACK = True
            print "Closing Connection: Sending ACK Packet"
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
        MAXDELAY = float(sys.argv[13])/1000
        SEED = float(sys.argv[14])

    except:
        print """Usage:\tpython sender.py <receiver_host_ip> <receiver_port> 
        \t<file.pdf> <MWS> <MSS> <gamma> <pDrop> <pDuplicate> <pCorrupt> <pOrder> 
        \t<maxOrder> <pDelay> <maxDelay> <seed>"""
        sys.exit(1)

# Seed for randomisation
if SEED != None:
    random.seed(SEED)

# Set initial timeout interval
if GAMMA != None:
    TIMEOUT = ESTRTT + GAMMA*DEVRTT

# Address from the give IP and Port
ADDRESS = (RECEIVER_IP, RECEIVER_PORT)

# Create a global socket and connect to it
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(ADDRESS)
s.settimeout(TIMEOUT)

# Module for Packet Loss and Delay
pld = PacketLossDelay()

def main():
    # A loop to ensure the connection is established
    while True:
        SentRecv = EstablishConnection()
        if SentRecv != None:
            break

    # File Transfer State
    PipelineSendFile(SentRecv)

    # Closing Connection
    CloseConnection()

if __name__ == "__main__":
    main()