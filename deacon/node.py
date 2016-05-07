from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
import sys
import socket
import time
import threading 
import struct
import Queue
import os 
import getpass


def pass_validate(passw):
   password = getpass.getpass('Enter a strong passphrase for your private key: ')
   password2 = getpass.getpass('Enter it again. Make sure you remember your password! ') 
   if password != password2:
      print 'Passwords do not match' 
      return 1 
   else:
      passw.append(password) 
      return 0


def genkeys():
   passw = list()
   res = raw_input('I could not find your private key. Would you like to generate a new one? ')
   if 'y' not in res.lower():
         print 'Please restart with your private key in the same directory as me.'
         sys.exit()
   else:
         print "Generating new private key...."
         rgen = Random.new().read
         pkey = RSA.generate(2048, rgen)
         while pass_validate(passw) == 1: 
            pass 
         try:
            print 'exporting your private key to private.pem'
            f = open('private.pem','wb') 
            f.write(pkey.exportKey('PEM',passw[0])) 
            f.flush() 
            print 'key exported' 
            f.close() 
            return pkey 
         except Exception as e:
            print '{0}: error exporting your private key!!!!'.format(e)  
            sys.exit()



def encrypt_document(key, document):
   this = open(document,'rb').read()
   public_key = key.publickey()
   this = public_key.encrypt(this, 32) 
   doc = open(document,'wb')
   doc.write(this[0])
   

def decrypt_document(key, document):
   this = open(document,'rb').read() 
   this = key.decrypt(this)
   doc = open(document,'wb')
   doc.write(this)





class Command(object):
   CONNECT, SEND, RECEIVE, CLOSE = range(4)
   
   def __init__(self, type, data=None):
      self.type = type
      self.data = data 


class Reply(object):
   ERROR, SUCCESS = range(2) 

   def __init__(self, type, data=None):
      self.type = type
      self.data = data


class SocketClientThread(threading.Thread): 
   def __init__(self, cmd_q=None, reply_q=None):
      super(SocketClientThread, self).__init__()
      self.cmd_q = cmd_q or Queue.Queue() 
      self.reply_q = reply_q or Queue.Queue()
      self.alive = threading.Event() 
      self.alive.set() 
      self.socket = None 
      self.handlers = { 
         Command.CONNECT: self._handle_CONNECT,
         Command.CLOSE: self._handle_CLOSE, 
         Command.SEND: self._handle_SEND, 
         Command.RECEIVE: self._handle_RECEIVE,
      } 

   def run(self):
      while self.alive.isSet():
         try:
            cmd = self.cmd_q.get(True, 0.1)
            self.handlers[cmd.type](cmd) 
         except Queue.Empty as e:
            pass

   def join(self, timeout=None):
      self.alive.clear() 
      threading.Thread.join(self, timeout) 
      
   def _handle_CONNECT(self, cmd):
      try:
         self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
         self.socket.connect((cmd.data[0], cmd.data[1]))
         self.reply_q.put(self._success_reply())
      except Exception as e:
         self.reply_q.put(self._error_reply(str(e)))
   
   def _handle_CLOSE(self, cmd):
      self.socket.close() 
      reply = Reply(Reply.SUCCESS)
      self.reply_q.put(reply)
 
   def _handle_SEND(self, cmd):
      header = struct.pack('<L', len(cmd.data)) 
      try:
         self.socket.sendall(header + cmd.data)
         self.reply_q.put(self._success_reply()) 
      except Exception as e:
         self.reply_q.put(self._error_reply(str(e)))

   def _handle_RECEIVE(self, cmd): 
      try:
         header_data = self._recv_n_bytes(4)
         if len(header_data) == 4:
            msg_len = struct.unpack('<L', header_data)[0]
            data = self._recv_n_bytes(msg_len)
         if len(data) == msg_len:
            self.reply_q.put(self._success_reply(data)) 
            return 
         self.reply_q.put(self._error_reply('Socket closed prematurely')) 
      except IOError as e:
         self.reply_q.put(self._error_reply(str(e))) 
     
   def _recv_n_bytes(self, n): 
      data = '' 
      while len(data) < n:
         chunk = self.socket.recv(n - len(data))
         if chunk == '':
            break 
         data += chunk 
      return data 

   def _error_reply(self, errstr):
      return Reply(Reply.ERROR, errstr)

   def _success_reply(self, data=None):
      return Reply(Reply.SUCCESS, data)



def dsign(key, item):
   hash = SHA256.new(item).digest()
   signature = key.sign(hash, '')
   return signature 


def verify(pubkey, signature, item)
   hash = SHA256.new(item).digest()
   return pubkey.verify(hash, signature)



class neuPacket(object):
   TREQ, PUSH   = range(3)
   magic = "NLMB"
   def __init__(self, id, data=None, dirid,  sig):
      super(neuPacket, self).__init__()
      self.id = id
      self.data = data
      self.dirid = dirid
      self.sig = sig


def send_packet(npack, key, network):
   packet = npack.magic + str(npack.id) + npack.data + npack.magic + npack.dirid + npack.magic +  npack.sig
   message = key.encrypt(packet, 32)
   startup = Command(Command.SEND, message[0])
   network.cmd_q.put(startup)


   

def req_tree(key, relaykey, network):
   pubkey = key.publickey()
   sig = dsign(key,pubkey)
   treepacket = neuPacket(neuPacket.TREQ,key.publickey(),sig) 
   send_packet(treepacket, relaykey, network) 


def push_item(key, pubkey, relaykey, network, doc):
      sig = dsign(key,doc)
      doc = encrypt_document(pubkey, doc) 
      packet = neuPacket(neuPacket.PUSH, doc, sig)
      send_packet(packet, relaykey, network) 




   


   
















if __name__ == '__main__':
   try:
      f = open('private.pem')
      passwd = getpass.getpass('Enter your private key password: ')
      key = RSA.importKey(f.read(),passwd) 
      print 'Your private key has been successfully located.'
      f.close()  
   except Exception as e:
      print e
      key = genkeys()
   
   try: 
      f = open('relay_key.pem') 
      relay_key = RSA.importKey(f.read()) 
   except Exception as e:
      print e
      print 'no relay key found. exiting' 
      sys.exit() 


   network = SocketClientThread()
   startup = Command(Command.CONNECT,('localhost',4443))
   print startup.type
   print startup.data
   network.cmd_q.put(startup)  
   message = 'HI!fuuuck'
   network.start()  
   rep = network.reply_q.get() 
   print rep.data
   message = relay_key.encrypt(message, 32)
   startup = Command(Command.SEND, message[0]) 
   network.cmd_q.put(startup) 
   print rep.data
   encrypt_document(key,"text")    
   decrypt_document(key,"text")
   
             
     
