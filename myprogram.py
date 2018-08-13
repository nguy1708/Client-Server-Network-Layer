import sys,os,random,hashlib,threading as t
from socket import *
from select import *
from argparse import ArgumentParser


TIMEOUT = 10
MAXSIZE = 512
SYN = '\x16\x00'
ACK = '\x06\x00'
SYNACK = '\x16\x06'
RESET = '\x18\x00'
FIN = '\x19\x00'
CLOSE = '\x06\x19'

def main():
    dependents = [str(x) for x in input("Please enter your host, port, and file in that order with one space between each: ").split()]
    if (dependents[0] == ''):
        dependents[0] = 'localhost'
    if (dependents[1] == ''):
        dependents[1] == '5001'
    while (dependents[2] == ''):
        print("Error, please specify a file. Try inputing all 3 arguments again.\n\n")
        dependents = [str(x) for x in input("Please enter your host, port, and file in that order with one space between each: ").split()]
    TCPServer(dependents[0], int(dependents[1]))
    return TCPClient(dependents[0], int(dependents[1]), dependents[2])

def TCPClient(host, port, fd):
    connected = False                           #Variables to determine connection to host
    initial = True
    sequence = 0
    try:                                        #Essentially this will try to open the designated file
        file = open(fd, 'r')
        infoStream = file.read()
        infoStreamLength = len(infoStream)
        file.close()
        i = 0
    except error as m:
        print(m)
        exit()
    if ('/' in fd):                             #This function will just focus on everything after the \
        seperatedFD = fd.split('/')
        fd = seperatedFD[-1]
    print("Client attempting to connected to server...")
    try:                                        #Attempt to establish connection
        clientSock = socket(AF_INET, SOCK_STREAM)
        clientSock.connect((host,port))
    except error as m:
        print(m)
        exit()
    dataOut = create_packet(sequence, SYN, 0)
    print("Sending: Sending SYN packet #" + str(sequence) + "...")
    clientSock.send(dataOut.encode())
    while True:
        status = select([clientSock],[],[],TIMEOUT)
        if (status[0]):
            print("SUCCESS, packet " + str(sequence) + " recieved...")
            data = clientSock.recv(MAXSIZE).decode()
        else:
            if(initial):
                print("Client has timedout, resending packet: #" + str(sequence))
            clientSock.send(dataOut.encode())
            continue
        initial = False
        if (len(data) < MAXSIZE):
            print("Connection has been terminated by server...")
            break
        if not validation(data):
            print("Packet did not pass validation check...\nResending packet: #" + str(sequence))
            clientSock.send(dataOut.encode())
            continue
        content = data[45:]
        packetSize = int(data[41:44])
        checkSeq = int(data[40])
        lastValue = int(data[44])

        if(content[:2] == RESET):
            print("Connection was reset by the server...")
            break
        if (sequence != checkSeq) and (lastValue == 0):
            print("The sequence number of this packet is invalid...\nResending packet " + str(sequence))
            clientSock.send(dataOut.encode())
            continue
        if not connected:
            if (content[:2] == SYNACK):
                connected = True
                print("Handshaking ...")
                sequence = (sequence + 1) % 10
                dataOut = create_packet(sequence, ACK+fd,0)
                print("Confirming transmission of " +str(fd) + " in packet " + str(sequence))
                clientSock.send(dataOut.encode())
                continue
            else:
                print("Confirmation of the packet was not complete...\nResending packet " + str(sequence))
                clientSock.send(dataOut.encode())
                continue
        if (content[:2] == CLOSE):
            print("Recieved a request to close...")
            sequence = (sequence + 1) % 10
            dataOut = create_packet(sequence, ACK, 1)
            print("Confirming disconnect to server...")
            clientSock.send(dataOut.encode())
            break
        if content[:2] == ACK:
            print("Acknowledgement from server received...")
            sequence = (sequence + 1) % 10
            timer = min(i + 467, infoStreamLength)
            contentOut = infoStream[i:timer]
            i = timer
            if (len(contentOut) == 0):
                content_sending = FIN
            dataOut = create_packet(sequence, contentOut, 0)
            if (contentOut == FIN):
                print("Packet " + str(sequence) + " is end of file...")
            clientSock.send(dataOut.encode())
        else:
            print("Awknowledgement is invalid...\nClient has timedout, resending packet: #" + str(sequence))
            clientSock.send(dataOut.encode())
    print("Connection has been closed.")
    clientSock.close()
            
def TCPServer(host, port):
    print("Server initiated......")                 #This is the initial server, once handshaking is complete, it will pass to GBN protocol
    try:
        serverSock = socket(AF_INET, SOCK_STREAM)
        serverSock.bind((host,port))
        serverSock.listen(10)
    except error as m:
        print(m)
        exit()
    while True:
        print("Server awaiting requests...")
        connectionSock, addr = serverSock.accept()
        serverProtocol = t.Thread(target = GBNProtocol, args = [connectionSock, addr[0]])
        serverProtocol.start()


def GBNProtocol(serverSock, addr):                              #This takes over once handshaking passes
    sequence = 0
    dataOut = ''
    exp_seq = 0
    fd = ''
    connected = False
    awknowledged = False
    end = False
    while True:
        status = select([serverSock],[],[],TIMEOUT)
        if (status[0]):
            data = serverSock.recv(MAXSIZE).decode()
        else:
            if (len(dataOut) != 0):
                print("Timed out....resending packet " + str(sequence).encode())
                serverSock.send(dataOut.encode())
                continue
            else:
                print("Serever did not receive a packet...")
                continue
        if (len(data) < MAXSIZE):
            print("Client has closed its connection to the server...")
            break
        if not validation(data):
            print("The sequence number of this packet is invalid...\nResending packet " + str(sequence))
            serverSock.send(dataOut.encode())
            continue
        content = data[45:]
        packetSize = int(data[41:44])
        sequence = int(data[40])
        lastValue = int(data[44])
        if (exp_seq != sequence) and (lastValue == 0):
            print("The sequence number of this packet is invalid...\nResending packet " + str(sequence))
            serverSock.send(dataOut.encode())
            continue
        if not connected:
            if (content[:2] == SYN):
                connected = True
                dataOut = create_packet(sequence, SYNACK, 0)
                exp_seq = (sequence+1) % 10
                print("Sending packet to client...packet #" + str(sequence))
                serverSock.send(dataOut.encode())
                continue
            else:
                dataOut = create_packet(0, RESET, 1)
                print("Server ran into error, reseting...")
                serverSock.send(dataOut.encode())
                break
        if not awknowledged:
            if (content[:2] == ACK):
                awknowledged = True
                fd = content[2:packetSize]
                print("Received, collecting packets for " + str(fd))
                openfd = open(fd,'w')
                dataOut = create_packet(sequence,ACK,0)
                print("Sending packet " + str(sequence) + " to client...")
                serverSock.send(dataOut.encode())
                exp_seq = (sequence+1)%10
                continue
            else:
                dataOut = create_packet(0, RESET, 1)
                print("Server ran into error, reseting...")
                serverSock.send(dataOut.encode())
                break           
        if (content[:2] == FIN):
            end = True
            openfd.close()
            print("Recieved a request to close...")
            dataOut = create_packet(sequence, CLOSE, 0)
            serverSock.send(dataOut.encode())
            exp_seq = (sequence + 1) % 10
            continue
        if (lastValue == 1):
            break
        openfd.write(content[:packetSize])
        dataOut = create_packet(sequence, ACK, 0)
        print("Sending packet " + str(sequence) + " to the client...")
        serverSock.send(dataOut.encode())
        exp_seq = (sequence + 1) % 10
    serverSock.close()

def create_packet(sequence, data, lastValue):
    initPacket = str(sequence) + '%03d'%(len(data))+str(lastValue)+data
    fullPacket = initPacket + '\x00'*(467-len(data))
    hashed = hashlib.sha1(fullPacket.encode()).hexdigest()
    hashed = (40-len(hashed))*''+hashed
    return (hashed+fullPacket)

def validation(data):
    packetValue = data[40:]
    packetKey = data[:40]
    hashed = hashlib.sha1(packetValue.encode()).hexdigest()
    hashed = (40-len(hashed)) * ""+hashed
    return (packetKey == hashed)

def parse_args():
    parser = ArgumentParser()
    parser.add_argument('-n', '--host', type = str, default = 'localhost',
                        help = "specify a host to send and listen (default: localhost)")
    parser.add_argument('-p', '--port', type = int, default = -1,
                        help = "specify a port to send and listen (default: 5001 for server, 5002 for client)")
    parser.add_argument('-f', '--filename', type = str, default = '',
                        help = "specify a file which will be transferred to the server. Leaving this arg empty means this program will be a server")
    args = parser.parse_args()
    return (args.host, args.port, args.filename)

def main2():
    (host, port, filename) = parse_args()
    if filename == '':
        if port < 0:
            port = 5001
        return TCPServer(host, port)
    else:
        if port < 0:
            port = 5002
        return TCPClient(host, port, filename)

main2()
