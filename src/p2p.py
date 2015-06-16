# Client program
import sys
import socket
import base64
import time
from cipher import *
import threading
import netifaces
import base64
import netaddr
network = netifaces.interfaces()
ip = []
mode = 0        #UI mode: 0, debugmode: 1
for i in network:
    try:
    	addrs = netifaces.ifaddresses(i)
    	ipinfo = addrs[socket.AF_INET][0]
    	address = ipinfo['addr']
    	netmask = ipinfo['netmask']
    	cidr = netaddr.IPNetwork('%s/%s' % (address, netmask))
    	network = cidr.network
        """
    	print 'Network info for %s:' % i
    	print '--'
    	print 'address:', address
    	print 'netmask:', netmask
    	print '   cidr:', cidr
    	print 'network:', network"""
        if str(address) != "127.0.0.1":
            ips = netaddr.IPNetwork(str(cidr))
            ip.append((str(address), str(ips.broadcast)))
    except BaseException:
        pass
print "Here's the net you attached to:"
print ip

c = Cipher('mykey.pem', gen_key=True)
publickey = base64.b64encode(c.get_publickey())
fingerprint = c.get_fingerprint()
print "Your own Fingerprint: %s" %fingerprint.encode("hex")[0:10]
fing_table = {}
exit_flag = None

class broadcast_thread (threading.Thread):
    def __init__(self, threadID, name):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
    def run(self):
        print "Starting " + self.name
        broadcast(self.name)
        print "Exiting " + self.name
class receiver_thread (threading.Thread):
    def __init__(self, threadID, name):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
    def run(self):
        print "Starting " + self.name
        receiver(self.name)
        print "Exiting " + self.name
class Tcp_receiver (threading.Thread):
    def __init__(self, threadID, name, threadnum):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.threadnum = threadnum
    def run(self):
        print "Starting " + self.name
        tcp_receiver(self.name, self.threadnum)
        print "Exiting " + self.name

def broadcast(threadName):
    global exit_flag
    global fing_table
    global ip
    global mode
    exit_flag = 0
    addr = []
#    print ip
    for i in ip:
        addr.append((i[1], 33333))
#    print addr
#    addr = ('255.255.255.255', 33333)
    UDPSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Create socket
    UDPSock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    hopnum = 0
    while True:
        packet = ""
        tmp = str(socket.gethostbyname(socket.gethostname()))   #add address
        for i in range(0, 15-len(tmp)):
            tmp = "0"+tmp
        packet += tmp
        tmp = str(len(publickey))
        for i in range(0, 4-len(tmp)):
            tmp = "0"+tmp
        packet += tmp                                           #public key len
        packet += publickey                                     #public key
        packet += fingerprint                                   #fingerprint
        tmp = str(hopnum)                                       #hop number
        for i in range(0, 4-len(tmp)):                          
            tmp = "0"+tmp
        packet += tmp
#        print packet
        n = 0
        for i in addr:
            rpacket = packet+str(33333+n)
            n += 1
            if UDPSock.sendto(rpacket, i):
                if mode == 1:
                    print "%s: Sending message to %s..." %(threadName, i)
        time.sleep(10)
        while exit_flag == 1:
            sleep(1)
        exit_flag = 1
        del_list = []
        for i in fing_table:
            fing_table[i][3] += 5
            if fing_table[i][3] > 30:
                del_list.append(i)
                if mode == 0:
                    print "%s: A node leaved the net: Fingerprint = %s" %(threadName, i.encode("hex")[0:10])
                if mode == 1:
                    print "%s: deleted a node, fingerprint = %s" %(threadName, i.encode("hex")[0:10])
        for i in del_list:
            del fing_table[i]
        exit_flag = 0
    UDPSock.close()             # Close socket
def receiver(threadName):
    global exit_flag
    global fing_table
    global ip
    global mode
    addr = ('', 33333)
    UDPSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    UDPSock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    UDPSock.bind(addr)
    
    addrb = []
    for i in ip:
        addrb.append((i[1], 33333))

    # Receive messages
    while True:
        data, addr = UDPSock.recvfrom(1024)
        i = 0
        broadaddr = addr[0]
        broadplen = int(data[15:19])
        broadpublic = data[19:(19+broadplen)]
        broadfinger = data[(19+broadplen):(51+broadplen)]
        broadhop = int(data[(51+broadplen):(55+broadplen)])
        broadport = int(data[(55+broadplen):(60+broadplen)])
        itself = 1
        for i in range(0, len(fingerprint)):
            if fingerprint[i] != broadfinger[i]:
                itself = 0
        if itself == 1:
            continue

        while exit_flag == 1:
            sleep(1)
        exit_flag = 1
        exists = 0
        if broadfinger not in fing_table:
            print "%s: Find new node on the Net!!\n                 From addr: %s\tFingerprint: %s" %(threadName, broadaddr, broadfinger.encode("hex")[0:10])
            fing_table[broadfinger] = [broadaddr, broadhop, broadpublic, 0, broadport]
        else:
            if mode == 1:
                print "%s: Refresh an old node from addr %s" %(threadName, broadaddr)
            exists = 1
            if fing_table[broadfinger][1] >= broadhop:
                exists = 0
                fing_table[broadfinger] = [broadaddr, broadhop, broadpublic, 0, broadport]
            fing_table[broadfinger][3] = 0
        exit_flag = 0

        if len(ip) >= 2 and exists == 0:
            packet = ""
            tmp = ""   #add address
            for i in range(0, 15):
                tmp += "0"
            packet += tmp
            packet += data[15:19]                                     #public key len
            packet += broadpublic                                   #public key 
            packet += broadfinger                                   #hop number
            broadhop += 1
            tmp = str(broadhop)
            for i in range(0, 4-len(tmp)):                          
                tmp = "0"+tmp
            packet += tmp
            n = 0
            for i in addrb:
                rpacket = packet + str(33333+n)
                n += 1
                UDPSock.sendto(rpacket, i)
                if mode == 1:
                    print "%s: Transfer message to %s... %s" %(threadName, i, broadhop)
    UDPSock.close()
def tcp_receiver(threadName, threadnum):
    global fing_table
    global exit_flag
    global c
    global fingerprint
    global ip
    global mode
    TCP_IP = ip[threadnum][0]
    TCP_PORT = 33333+threadnum
    BUFFER_SIZE = 1024
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((TCP_IP, TCP_PORT))
    s.listen(1)
    while 1:
        conn, addr = s.accept()
        data = conn.recv(BUFFER_SIZE)
        desfinger = data[0:32]
        if desfinger == fingerprint:
            cip = [data[32:len(data)]]
            if mode == 1:
                print "%s: datalen = %s" %(threadName, len(data))
            plain = c.decrypt(cip)
            if mode == 1:
                print "%s: received data: %s" %(threadName, plain)
            else:
                print "%s: %s said to you: %s" %(threadName, desfinger.encode("hex")[0:10], plain)
        else:
            if mode == 1:
                print "%s: Not being destination, transfer..." %(threadName)
            if desfinger not in fing_table:
                if mode == 1:
                    print "%s: Such node doesn't exist." %threadName
                continue
            tmp = fing_table[desfinger]
            TCP_IP = tmp[0]
            TCP_PORT = tmp[4]
            BUFFER_SIZE = 1024
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.connect((TCP_IP, TCP_PORT))
            s2.send(data)
            s2.close()
            if mode == 1:
                print "%s: Transfer finished." %threadName

        conn.close()

thread1 = broadcast_thread(1, "Broadcast_thread")
thread1.daemon = True
thread1.start()
thread2 = receiver_thread(2, "Receiver_thread")
thread2.daemon = True
thread2.start()
for i in range(0, len(ip)):
    thread3 = Tcp_receiver(3, "TCP_receiver", i)
    thread3.daemon = True
    thread3.start()

#main part:
# function: list IP, send to a IP, received from a IP
print "Entering 'list' to show how many nodes on this network."
print "Entering 'send' to check which node to send."
print "Enterinf 'chmod' to change mod."
while 1:
    cmd = sys.stdin.readline().split('\n')[0]
    if cmd != 'list' and cmd != 'send' and cmd != 'chmod':
        print "Entering 'list' to show how many nodes on this network."
        print "Entering 'send' to check which node to send."
        print "Enterinf 'chmod' to change mod."
    if cmd == 'list':
        tmp = []
        for ips in fing_table:
            tmp.append(ips)
        for i in range(0, len(tmp)):
            print "No: %s\tAddr: %s\tHop: %s\tFingerprint: %s" %(i+1, fing_table[tmp[i]][0], fing_table[tmp[i]][1], ips.encode("hex")[0:10])
        if tmp == []:
            print "No available node on this net"
    if cmd == 'send':
        print "Input the number you want to send:"
        try:
            transfer = int(sys.stdin.readline().split('\n')[0])-1
        except BaseException:
            print "please enter the node nubmer in the 'list'"
            continue
        if len(fing_table) == 0:
            print "No node on the net yet"
            continue
        i = 0
        for ips in fing_table:
            if i == transfer:
                tmp = fing_table[ips]
                break
            i += 1
        print "Enter what you want to send:"
        f = open("other_key.pem", "w")
        f.write("-----BEGIN RSA PRIVATE KEY-----\n")
        f.write("%s\n" %tmp[2])
        f.write("-----END RSA PRIVATE KEY-----")
        f.close()
        otherskey = Cipher('other_key.pem', gen_key=False)
        data = sys.stdin.readline().split('\n')[0]
        cip = otherskey.encrypt(data)[0]
        TCP_IP = tmp[0]
        print len(ips)
        data = ips+cip
        TCP_PORT = tmp[4]
        BUFFER_SIZE = 1024

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TCP_IP, TCP_PORT))
        s.send(data)
        s.close()
        print "send finished."
    if cmd == 'chmod':
        print "Input the mode you want to change(0: UI mode, 1: debug mode):"
        try:
            i = int(sys.stdin.readline().split('\n')[0])-1
        except BaseException:
            print "please enter 0/1."
            continue
        if i != 0 and i != 1:
            print "please enter 0/1."
        mode = i

print "Existing Main thread"
