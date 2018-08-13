#!/usr/bin/env python

import os, sys, time, socket, threading, random #, hashlib

PORT,MAXBLOCKS,DELAY = int(sys.argv[1]),int(sys.argv[2]),float(sys.argv[3])
PROB_DEL,PROB_MANGLING = int(sys.argv[4]),int(sys.argv[5])

blocks,lock = {}, threading.Lock()

def main():
    global blocks, lock
    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssock.bind( ('', PORT) )
    ssock.listen(20)
    print("Hello..")
    n = 0
    while 1:
        try:
            cx, addr = ssock.accept()
            n += 1
            print(time.asctime()+" --- New connection ("+str(n)+") from "+addr[0])
            server = threading.Thread(target=networkLayer, name='%s'%(str(n)+str(addr)), args=[cx, addr, n])
            server.start()
        except Exception as e: 
            print("Exceptions when starting new threads. e = "+str(e)+' Skipped')
            continue

def networkLayer(cx1, addr, n):
    global blocks, lock
    cx2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        print("Trying to connect back to %s:5001"%addr[0])
        cx2.connect((addr[0], 5001))
        print("Successful Connected.")
    except:
        print("Connection from %s failed. Port 5001 did not accept."%addr[0])
        return

    print('Block lock acquiring in networkLayer()')
    lock.acquire()
    blocks[cx1], blocks[cx2] = [],[]
    lock.release()
    print('Block lock released in networkLayer()')
    
    r2 = threading.Thread(target=networkLayerReader, name='reader CX2 %s'%(str(n)+str(addr)), args=[cx2, cx1])
    r1 = threading.Thread(target=networkLayerReader, name='reader CX1 %s'%(str(n)+str(addr)), args=[cx1, cx2])
    w1 = threading.Thread(target=networkLayerWriter, name='writer CX1 %s'%(str(n)+str(addr)), args=[cx2, cx1])
    w2 = threading.Thread(target=networkLayerWriter, name='writer CX2 %s'%(str(n)+str(addr)), args=[cx1, cx2])
    r2.start()
    r1.start()
    w1.start()
    w2.start()
        

def networkLayerReader(reader, cxOther):
    global blocks, lock
    try:
        while True:
            b = grabBlock(reader)
            printStatus(b)

            print('blocks lock acquiring in networkLayerReader()')
            lock.acquire()
            blocks[cxOther].append(b)
            lock.release()
            print('blocks lock released in networkLayerReader()')
            
            if len(blocks[cxOther]) > MAXBLOCKS:
                #raise Exception, "len(blocks[cxOther])>MAXBLOCKS) occured from "+str(cxOther)
                print('len(blocks[cxOther]>MAXBLOCKS) occured from '+str(cxOther))
                cxOther.close()
                reader.close()
                return
    except Exception as e:
        print('Exceptions occur in networkLayerReader(). Deleting blocks & Closing Connection. ' + str(e))
        #closeConnections(reader,cxOther)
        if reader in blocks:
            reader.close()
            lock.acquire()
            del blocks[reader]
            lock.release() 
        return

def printStatus(b):
    print("------------PACKET---------------")
    #h = hashlib.sha1(b[20:]).digest()
    #if h == b[0:20]: print "Hash good"
    #else: print "Hash bad"
    #print "Payload = "+str(b[26:])


def networkLayerWriter(writer, cxOther):
    global blocks, lock, DELAY, PROB_MANGLING, PROB_DEL
    try:
        while True:
            time.sleep(DELAY)
            
            l = len(blocks[writer])
            if l > 0:
                r = random.randint(0, l-1)
                print("\nNumber of blocks that are supposed to send to the writer socket = "+str(l))
                print("Randomly pick the %dth one to send"%r)
                b = blocks[writer][r]

                print('Blocks lock acquiring in networkLayerWriter')
                lock.acquire()
                del blocks[writer][r]
                lock.release()
                print('Blocks lock released in networkLayerWriter')
                
                print("Found block b[%d]."%r)
                print("len(blocks[writer]) will be "+str(len(blocks[writer]))+", after picking off this block.")
                
                pd = random.randint(1,100)
                if pd<=PROB_DEL:
                    print("Deleting block b[%d]."%r)
                    del b
                    print("Deleted successfully. Nothing will be sent.")
                else:
                    pm = random.randint(1,100)
                    if pm<=PROB_MANGLING:
                        print("Mangling block b[%d]."%r)
                        for i in range(1,random.randint(1,len(b))): # grab a random number of bytes
                            b = replaceChar(b, i*random.randint(1,1024) % len(b))
                    print("Writing block b[%d], of size len(b) =%d"%(r,len(b)))
                    # Please uncomment the next line if you are using this program with your Java Program.
                    # b = b + "\n"
                    writer.send(b.encode())
                    del b
                    print("Sent b[%d] successfully"%r)
    except Exception as e:
        print("Writing block failed. Closing Connection. (networkLayerWriter) e = "+str(e))
        #closeConnections(writer,cxOther)
        if writer in blocks:
            writer.close()

            lock.acquire()
            del blocks[writer]
            lock.release()
        return


def closeConnections(cx1,cx2):
    global blocks, lock
    try:
        print('Block lock acquiring in closeConnection()')
        lock.acquire()
        del blocks[cx1]
        del blocks[cx2]
    except:
        print('Exception when deleting blocks[cx1] and blocks[cx2]')
    finally:
        lock.release()
        print('Block lock released in closeConnections()')

    try:
        print('Closing socket cx1 and cx2')
        cx1.close()
        cx2.close()
        print("Connection closed successfully.")
    except Exception as e:
        print("Exception when closing connections. e = "+str(e))


def grabBlock(cx):
    bsize = 512
    block = ""
    while len(block)<bsize:
        r = cx.recv(bsize-len(block)).decode()
        if len(r) > 0:
            block = block + r
        else:
            print("Socket appears to be closed.")
            raise Exception("Reading block failed.")
    return block


def replaceChar(s, i):
    count = 0
    r = ""
    for c in s:
        if count == i:
            r = r + str(chr(random.randint(32,126)))
        else: r = r + str(c)
        count = count + 1
    return r

main()
