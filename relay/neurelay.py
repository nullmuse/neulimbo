from Crypto.PublicKey import RSA
from Crypto import Random
import sys
import socket
import time
import select
import Queue 

buffer_size = 4096
delay = 0.0001
class Server:
   inputs = [] 
   outputs = [] 
   message_queues = {} 
   
   def __init__(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(200)
        
   def main_(self,key):
      self.inputs.append(self.server)
      while self.inputs:
         time.sleep(delay) 
         readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs)
         for self.s in readable:
            if self.s is self.server:
               self.on_accept() 
               break
            else:
               self.on_recv(key)
         for self.s in writable:
            try:
               next_msg = self.message_queues[self.s].get_nowait() 
            except Exception:
               pass 
            else:
               self.s.send(next_msg) 
        





   def on_accept(self):
      connection, client_addr = self.s.accept() 
      print 'new connection from', client_addr
      connection.setblocking(0) 
      self.inputs.append(connection)
      self.message_queues[connection] = Queue.Queue() 
      
   def on_recv(self, key):
      data = self.s.recv(1024) 
      if data:
         if self.s not in self.outputs:
               self.outputs.append(self.s)
         data = data[3:]
         data = key.decrypt(data)
         print data 
         if 'HI!' in data[:3]:
            self.message_queues[self.s].put('GT')
            for item in self.outputs:
               if item is not self.s:
                  self.message_queues[item].put(data[3:])  
         else:
            print 'bad magic'
            self.message_queues[self.s].put('BT')
     
      else:
         if self.s in self.outputs:
            self.outputs.remove(self.s)
         self.inputs.remove(self.s)
         self.s.close()
         del self.message_queues[self.s]

 



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


