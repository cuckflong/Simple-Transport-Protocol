#!/usr/bin/python

import argparse, socket, pickle, sys, md5, random, time, binascii, threading

# Log File
LOGFILE = "Sender_log.txt"

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
        self.checksum = "a"*32
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
        header.getHeaderLength()
        header.generateChecksum(data)
        # Reverse one bit of the data
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
        packet = pickle.dumps(header.pack())
        packet += data
        verbosePrint("normal", "PLD CORRUPT: Sending Corrupted Packet")
        s.send(packet)

    def checkHeldPacket(self):
        if self.heldPacket != None:
            self.waited += 1
            if self.waited >= args.MAXORDER:
                verbosePrint("normal", "PLD REORDER: Re-Order Wait Finished, Sending Held Back Packet")
                sendPacket(self.heldPacket[0], self.heldPacket[1])
                writeLog("snd/rord", self.heldPacket[0], len(self.heldPacket[1]))
                self.heldPacket = None
                self.waited = 0
            else:
                verbosePrint("normal", "PLD REORDER: Already Held Back For %d Packet" % (self.waited))

    def sendDelayPacket(self, header, data):
        delay = random.uniform(0, args.MAXDELAY)
        verbosePrint("normal", "PLD DELAY: Delaying For %s Seconds" % delay)
        time.sleep(delay)
        try:         
            sendPacket(header, data)
            verbosePrint("normal", "PLD DELAY: Sending Delayed Packet With %s Seconds Delay" % delay)
        except:
            sys.exit(1)

    def sendPLDPacket(self, header, data):
        if self.flip(args.PDROP):
            verbosePrint("normal", "PLD DROP: Packet Dropped")
            writeLog("drop", header, len(data))
            self.checkHeldPacket()
            return
        if self.flip(args.PDUPLICATE):
            verbosePrint("normal", "PLD DUPLICATE: Duplicating Packet")
            sendPacket(header, data)
            writeLog("snd", header, len(data))
            sendPacket(header, data)
            writeLog("snd/dup", header, len(data))
            self.checkHeldPacket()
            return
        if self.flip(args.PCORRUPT):
            verbosePrint("normal", "PLD CORRUPT: Corrupting Packet")
            self.sendCorruptPacket(header, data)
            writeLog("snd/corr", header, len(data))
            self.checkHeldPacket()
            return
        if self.flip(args.PORDER):
            verbosePrint("normal", "PLD REORDER: Reordering Packets")
            if self.heldPacket != None:
                verbosePrint("normal", "PLD REORDER: A Packet Already On Hold, Sending Current Packet")
                sendPacket(header, data)
                writeLog("snd", header, len(data))
                self.checkHeldPacket()
                return
            if args.MAXORDER == 0:
                verbosePrint("normal", "PLD REORDER: args.MAXORDER=0, No Need To Hold Packet, Sending Current Packet")
                sendPacket(header, data)
                writeLog("snd", header, len(data))
                return
            verbosePrint("normal", "PLD REORDER: Holding Back For %d Packets" % (args.MAXORDER))
            newHeader = STPHeader()
            newHeader.copy(header)
            self.heldPacket = (newHeader, data)
            self.waited = 0
            return
        if self.flip(args.PDELAY):
            verbosePrint("normal", "PLD DELAY: Delaying Packet")
            tmpHeader = STPHeader()
            tmpHeader.copy(header)
            # Start a new thread to simulate the delay packet
            try:
                t = threading.Thread(target=self.sendDelayPacket, args=(tmpHeader, data))
                writeLog("snd/dely", tmpHeader, len(data))
                t.start()
            except:
                print "Threading Exception"
                sys.exit(1)
            self.checkHeldPacket()
            return

        verbosePrint("normal", "PLD NORMAL: Sending Normal Packet")
        sendPacket(header, data)
        writeLog("snd", header, len(data))
        self.checkHeldPacket()

def verbosePrint(type, message):
    if not args.verbose:
        return
    if type == "error":
        print "[!] %s" % message
    elif type == "normal":
        print "[+] %s" % message
    elif type == "info":
        print message

def sendPacket(header, data):
    header.getHeaderLength()
    header.generateChecksum(data)
    packet = pickle.dumps(header.pack())
    if data != None:
        packet += data
    s.send(packet)

# Read data from the provided file
def getDataFromFile():
    f = open(args.FILE, "r")
    data = f.read()
    f.close()
    return data

# Write information to log file
def writeLog(event, header, dataLen):
    current = round(time.time() - TIMER, 3)
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
    line = "%20s%20f%20s%20d%20d%20d" % (event, current, packetType, header.seqNum, dataLen, header.ackNum)
    log.write(line + "\n")
    pass

# Randomly generate the initial sequence number
def initialSeqNum():
    return random.randint(0, 1000000)

# Establish the connection with a three-way handshake
def EstablishConnection():
    headerRecv = STPHeader()
    header = STPHeader()
    header.SYN = True
    sentSeqNum = initialSeqNum()
    sentAckNum = 0
    seqNumRecv = 0
    ackNumRecv = 0
    header.seqNum = sentSeqNum
    verbosePrint("normal", "Connection Establishing: 1st Handshake")
    sendPacket(header, None)
    writeLog("snd", header, 0)
    while True:
        try:
            packet, addr = s.recvfrom(1024+args.MSS)
        except socket.timeout:
            verbosePrint("error", "Connection Establishment Failed: Timeout")
            return None
        try:
            headerRecv.unpack(pickle.loads(packet))
            writeLog("rcv", headerRecv, 0)
        except:
            verbosePrint("error", "Corrupt Header Received")
            continue
        if (headerRecv.SYN == True and headerRecv.ACK == True and headerRecv.ackNum == sentSeqNum+1):
            seqNumRecv = headerRecv.seqNum
            ackNumRecv = headerRecv.ackNum
            verbosePrint("normal", "Connection Establishing: 2nd Handshake")
            break
        else:
            verbosePrint("error", "Connection Establishing: Wrong Packet Received")
            continue
    header.clear()
    header.ACK = True
    header.seqNum = sentSeqNum + 1
    header.ackNum = seqNumRecv + 1
    sentSeqNum += 1
    sentAckNum = seqNumRecv + 1
    verbosePrint("normal", "Connection Established: 3rd Handshake")
    sendPacket(header, None)
    writeLog("snd", header, 0)
    return (sentSeqNum, sentAckNum, seqNumRecv, ackNumRecv)

# Transfer args.FILE With Maximum Window Size
def PipelineSendFile(SentRecv):
    global ESTRTT
    global DEVRTT
    global TIMEOUT
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
    baseOffset = sendBase
    lastToAck = sentSeqNum
    timeoutInterval = 0
    duplicateList = []
    dupExist = False
    header.SYN = True
    while len(data[sendBase-baseOffset:]) > 0:
        # Send Segments Until The Window Is Full
        while lastToAck - sendBase <= args.MWS:
            if lastToAck - baseOffset >= len(data):
                break
            header.seqNum = sentSeqNum
            header.ackNum = sentAckNum
            offset = sentSeqNum - baseOffset
            if len(data[offset:]) > args.MSS:
                segmentData = data[offset:offset+args.MSS]
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
            sentSeqNum += sentDataLen
            sentAckNum += 1

        timeoutInterval = time.time() + TIMEOUT
        duplicateList = []
        # Wait For Reply With A Timeout Interval
        while True:
            if sendBase - baseOffset >= len(data):
                break
            # Timeout Interval Before Sending Again From Sendbase
            if time.time() > timeoutInterval:
                break
            try:
                packet, addr = s.recvfrom(1024+args.MSS)
            except socket.timeout:
                verbosePrint("error", "Receiving ACK Timeout, Sending Packets Again")
                if sendBase - baseOffset >= len(data):
                    break
                # Timeout, Send Segments From The Sendbase again
                header.seqNum = sendBase
                header.ackNum = baseAck
                offset = sendBase - baseOffset
                if len(data[offset:]) > args.MSS:
                    segmentData = data[offset:offset+args.MSS]
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
                verbosePrint("error", "Corrupted Header")
                continue
            # Update The Timeout Interval
            for timer in TIMERLIST:
                if timer[0] == headerRecv.ackNum:
                    sampleRTT = time.time() - timer[1]
                    ESTRTT = 0.875*ESTRTT + 0.125*(sampleRTT)
                    DEVRTT = 0.75*DEVRTT + 0.25*abs(sampleRTT-ESTRTT)
                    TIMEOUT = ESTRTT + args.GAMMA*DEVRTT
                    verbosePrint("info", "TIMEOUT INTERVAL: %s" % TIMEOUT)
                    s.settimeout(TIMEOUT)
                    TIMERLIST.remove(timer)
                    break
            # Update Sendbase If Received ACK
            if headerRecv.ACK == True and headerRecv.ackNum > sendBase:
                writeLog("rcv", headerRecv, 0)
                sendBase = headerRecv.ackNum
                baseAck = headerRecv.seqNum + 1
                sentSeqNum = sendBase
                sentAckNum = baseAck
            # Check For Fast Retransmission
            elif headerRecv.ACK == True and headerRecv.ackNum <= sendBase:
                dupExist = False
                for dup in duplicateList:
                    if dup[0] == headerRecv.ackNum:
                        dupExist = True
                        if dup[1] == 3:
                            verbosePrint("info", "!!!!!!!!!!!!! Triple ACK !!!!!!!!!!!!!")
                            sentSeqNum = headerRecv.ackNum
                            sentAckNum = headerRecv.seqNum + 1
                            header.seqNum = sentSeqNum
                            header.ackNum = sentAckNum
                            offset = sentSeqNum - baseOffset
                            if len(data[offset:]) > args.MSS:
                                segmentData = data[offset:offset+args.MSS]
                            else:
                                segmentData = data[offset:]
                            lastToAck = sentSeqNum + sentDataLen
                            for timer in TIMERLIST:
                                if timer[0] == lastToAck:
                                    TIMERLIST.remove(timer)
                                    break
                            TIMERLIST.append((lastToAck, time.time()))
                            duplicateList.remove(dup)
                            sendPacket(header, segmentData)
                            writeLog("snd/RXT", header, len(segmentData))
                        else:
                            writeLog("rcv/DA", headerRecv, 0)
                            dup[1] += 1
                if not dupExist:
                    writeLog("rcv/DA", headerRecv, 0)
                    duplicateList.append([headerRecv.ackNum, 1])
    lastPacket = STPHeader()
    lastPacket.copy(headerRecv)
    return lastPacket

# Closing the connection
def CloseConnection(lastPacket):
    headerRecv = STPHeader()
    header = STPHeader()
    header.FIN = True
    header.seqNum = lastPacket.ackNum
    header.ackNum = lastPacket.seqNum
    verbosePrint("normal", "Closing Connection: Sending FIN Packet")
    sendPacket(header, None)
    writeLog("snd", header, 0)
    # Enter FIN_WAIT_1 state
    while True:
        try:
            packet, addr = s.recvfrom(1024+args.MSS)
        except socket.timeout:
             continue
        try:
            headerRecv.unpack(pickle.loads(packet))
            writeLog("rcv", headerRecv, 0)
        except:
            verbosePrint("error", "Corrupted Header Received")
            continue
        if headerRecv.ACK == True and headerRecv.ackNum == header.seqNum+1:
            verbosePrint("normal", "FIN_WAIT_1: Done")
            break
        else:
            verbosePrint("error", "FIN_WAIT_1: Wrong Packet Received")
            continue
    # Enter FIN_WAIT_2 state
    while True:
        try:
            packet, addr = s.recvfrom(1024+args.MSS)
        except socket.timeout:
             continue
        try:
            headerRecv.unpack(pickle.loads(packet))
            writeLog("rcv", headerRecv, 0)
        except:
            verbosePrint("error", "Corrupted Header Received")
            continue
        if headerRecv.FIN == True and headerRecv.ackNum == header.seqNum+1:
            header.clear()
            header.ACK = True
            header.seqNum = headerRecv.ackNum
            header.ackNum = headerRecv.seqNum + 1
            verbosePrint("normal", "Closing Connection: Sending ACK Packet")
            sendPacket(header, None)
            writeLog("snd", header, 0)
            verbosePrint("normal", "FIN_WAIT_2: Done")
            break
        else:
            header.info()
            headerRecv.info()
            verbosePrint("error", "FIN_WAIT_2: Wrong Packet Received")
            continue
    # Enter TIME_WAIT state
    s.close()
    verbosePrint("normal", "Connection Closed")

# Parse the arguments
parser = argparse.ArgumentParser()
parser.add_argument("RECEIVER_IP", type=str, help="The IP address of the host machine on which the Receiver is running")
parser.add_argument("RECEIVER_PORT", type=int, help="The  port  number  on  which  Receiver  is  expecting  to  receive  packets  from  the sender")
parser.add_argument("FILE", type=str, help="The name of the pdf file that has to be transferred from sender to receiver using your STP")
parser.add_argument("MWS", type=int, help="The maximum window size used by your STP protocol in bytes")
parser.add_argument("MSS", type=int, help="Maximum Segment Size which is the maximum amount of data (in bytes) carried in each STP segment")
parser.add_argument("GAMMA", type=int, help="This  value  is  used  for  calculation  of  timeout  value")
parser.add_argument("PDROP", type=float, help="The probability that a STP data segment which is ready to be transmitted will be dropped. This value must be between 0 and 1")
parser.add_argument("PDUPLICATE", type=float, help="The probability that a data segment which is not dropped will be duplicate. This value must also be between 0 and 1")
parser.add_argument("PCORRUPT", type=float, help="The probability that a data segment which is not dropped/duplicated will be corrupted. This value must also be between 0 and 1")
parser.add_argument("PORDER", type=float, help="The probability that a data segment which is not dropped, duplicatedand corrupted will be re-ordered. This value must also be between 0 and 1")
parser.add_argument("MAXORDER", type=int, help="The maximum number of packets a particular packet is held back for re-ordering purpose. This value must be between 1 and 6")
parser.add_argument("PDELAY", type=float, help="The probability that a data segment which is not dropped, duplicated, corrupted or re-ordered will be delayed. This value must also be between 0 and 1")
parser.add_argument("MAXDELAY", type=float, help="The maximum delay (in milliseconds) experienced by those data segments that are delayed")
parser.add_argument("SEED", type=float, help="The seed for your random number generator")
parser.add_argument("-v", "--verbose", help="Print Sender's actions", action="store_true")
args = parser.parse_args()

# Convert from millisecond to second
args.MAXDELAY /= 1000

# Seed for randomisation
random.seed(args.SEED)

# Set initial timeout interval
TIMEOUT = ESTRTT + args.GAMMA*DEVRTT

# Address from the give IP and Port
ADDRESS = (args.RECEIVER_IP, args.RECEIVER_PORT)

# Create a global socket and connect to it
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(ADDRESS)
s.settimeout(TIMEOUT)

# Module for Packet Loss and Delay
pld = PacketLossDelay()

# Open log file for writing
log = open(LOGFILE, "w")

def main():
    # A global timer for log file
    global TIMER
    TIMER = time.time()
    # A loop to ensure the connection is established
    while True:
        SentRecv = EstablishConnection()
        if SentRecv != None:
            break

    # File Transfer State
    lastPacket = PipelineSendFile(SentRecv)

    # Closing Connection
    CloseConnection(lastPacket)

if __name__ == "__main__":
    main()