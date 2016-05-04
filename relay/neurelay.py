
#code snippets adapted from http://voorloopnul.com/blog/a-python-proxy-in-less-than-100-lines-of-code/

from Crypto.PublicKey import RSA
from Crypto import Random
import sys
import socket 
import time
import select 

buffer_size = 4096 
delay = 0.0001
deacons = {}
relay_to = ('server.nullmuse.net', 7600)
f = open('pkey.pem','r')
key = RSA.importKey(f.read())
f.close() 
class Relay:
    def __init__(self):
        self.relay = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def init(self, deacon):
        try:
            self.relay.connect((deacon[0], deacon[1]))
            return self.relay
        except Exception as e:
            print e
            return False

class Server:
   inputs = []
   schan = {}
   
   def __init__(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(200)

   def main_(self,key):
        self.inputs.append(self.server)
        while 1:
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.inputs, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept()
                    break
                try:
                   self.data = self.s.recv(buffer_size)
                except:
                   pass
                if len(self.data) == 0:
                    self.on_close()
                    break
                else:
                    self.on_recv(key)

   def on_accept(self):
        rel = Relay().init(relay_to)
        clientsock, clientaddr = self.server.accept()
        if rel:
            print clientaddr, "has connected"
            self.inputs.append(clientsock)
            self.inputs.append(rel)
            self.schan[clientsock] = rel
            self.schan[rel] = clientsock
        else:
            print "Can't establish connection with remote server.",
            print "Closing connection with client side", clientaddr
            clientsock.close()

   def on_close(self):
        print self.s.getpeername(), "has disconnected"
        #remove objects from input_list
        self.inputs.remove(self.s)
        self.inputs.remove(self.schan[self.s])
        out = self.schan[self.s]
        # close the connection with client
        self.schan[out].close()  # equivalent to do self.s.close()
        # close the connection with remote server
        self.schan[self.s].close()
        # delete both objects from channel dict
        del self.schan[out]
        del self.schan[self.s]

   def on_recv(self,key):
        data = key.decrypt(self.data)
        #print data
        if 'HI!' in data[:3]:
        # here we can parse and/or modify the data before send forward
           self.s.send('GT\r\n')
           for item in self.schan.iterkeys():
           #self.schan[self.s].send(data)
              print self.s, item
              if self.schan[item] is not self.s:
                 self.schan[item].send(data[3:]) 
        else:
           print 'incorrect magic'
           pass
           
if __name__ == '__main__':
        f = open('pkey.pem','r')
        key = RSA.importKey(f.read())
        f.close()

        server = Server('', 4443)
        try:
            server.main_(key)
        except KeyboardInterrupt:
            print "Ctrl C - Stopping server"
            sys.exit(1)
