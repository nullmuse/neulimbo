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
import glob

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


def load_document(key, document):
   this = open(document,'rb').read()
   this = key.decrypt(this)
   return this



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
         data = ''
         msg_len = 0
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


def verify(pubkey, signature, item):
   hash = SHA256.new(item).digest()
   return pubkey.verify(hash, signature)



class neuPacket(object):
   TREQ, KPUSH, PUSH   = range(3)
   magic = "NLMB"
   def __init__(self, id, data=' ', dirid=' ',  sig=' '):
      super(neuPacket, self).__init__()
      self.id = id
      self.data = data or ' '
      self.dirid = dirid or ' '
      self.sig = sig or ' '


def send_packet(npack, key, network):
   packet = npack.magic + str(npack.id) + npack.data + npack.magic + npack.dirid + npack.magic +  npack.sig
   message = key.encrypt(packet, 32)
   startup = Command(Command.SEND, message[0])
   network.cmd_q.put(startup)


   

def req_tree(key, relaykey, network):
   pubkey = key.publickey()
   sig = dsign(key,pubkey)
   treepacket = neuPacket(neuPacket.TREQ,pubkey,sig) 
   send_packet(treepacket, relaykey, network) 



def push_item(key, pubkey, relaykey, network, doc):
      sig = dsign(key,doc)
      pkey = RSA.importKey(pubkey)
      doc = pkey.encrypt(doc, 32)
      packet = neuPacket(neuPacket.PUSH, doc, sig)
      send_packet(packet, relaykey, network) 


def mass_push(key, k_register, relaykey, network, doc):
     sig = dsign(key,doc)
     for item in k_register:
         pkey = RSA.importKey(item)
         doc = pkey.encrypt(doc, 32)
         packet = neuPacket(neuPacket.PUSH, doc, sig)
         send_packet(packet, relaykey, network)

def push_key(key, relaykey, network):
   pubkey = key.publickey().exportKey('PEM')
   sig = dsign(key,pubkey)
   kpacket = neuPacket(neuPacket.KPUSH,pubkey, '', sig)
   send_packet(kpacket, relaykey, network)



def handle_packet(key, relaykey, network, k_register):
   try:
      rec_command = Command(Command.RECEIVE)
      network.cmd_q.put(rec_command)
      packet = network.reply_q.get()
      if packet:
         print packet.data
         dpacket = key.decrypt(packet.data)
         if dpacket[:3] is not 'NLMB':
            return 1
         if dpacket[0] == neuPacket.TREQ:
            tree_friend(dpacket, key, relaykey, network, k_register)
         elif dpacket[0] == neuPacket.KPUSH:
            add_key(dpacket, k_register) 
         elif dpacket[0] == neuPacket.PUSH:
            dpacket  = dpacket[3:]
            pt1 = dpacket.index('NLMB')
            pt = dpacket[(pt1 + 4):].index('NLMB')
            signature = dpacket[(pt + 4):]
            data = dpacket[1:pt1]
            pt = 0
            for item in k_register:
               if verify(item, signature, data) == True:
                  break
               pt +=1
            if pt == len(k_register):
               return 1
            add_doc(dpacket, key) 
   except:
      pass         


     
def add_key(packet, k_register):
    pt1 = packet.index('NLMB')
    key = packet[0:pt1]
    if key not in k_register: 
       k_register.append(key)
       os.system('echo {0}>keys'.format(key))
   

def tree_friend(packet, key, relaykey, network, k_register):
   add_key(packet, k_register) 
   push_key(key, relaykey, network)
   for filename in glob.glob('neudocs/*'):
      filed = load_document(key,filename)
      push_item(key, k_register[-1], relaykey, network, filed) 

def compare_hash(data,filename):
   if SHA256.new(data).digest() == SHA256.new(filename).digest():   
      return True
   return False 

def add_doc(packet, key):
   pt1 = packet.index('NLMB')
   data = packet[0:pt1]
   pt = packet[pt1:].index('NLMB')
   dirid = packet[pt1:pt] 
   os.chdir('neudocs')
   dirlist = dirid.split('/')
   filename = dirlist[-1]
   dirlist = dirlist[:-1]
   retlist = []
   for item in dirlist:
      retlist.append('../')
      try:
         os.chdir(item)
      except:
         os.system('mkdir {0}'.format(item))
         os.chdir(item)
   if os.system('dir {0}'.format(filename)) == 0:
      f1 = load_file(key, filename)
      if compare_hash(data,f1) == True:
         return 1
   file1 = open(filename,'w')
   data = key.encrypt(data, 32)
   file1.write(data)
   file1.flush()
   file.close() 
   for item in retlist:
      os.chdir(item)

 
              
     
def handle_changes(key, relaykey, network, k_register, checklist):
   newlist = glob.glob('neudocs/*')
   for filename in newlist:
      if filename not in checkist:
         try:
            doc = load_file(key,filename)
            mass_push(key, k_register, relaykey, network, doc)
            checklist.append(filename) 
         except:
            continue 
   
   return newlist

   
















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
   
   try:
      os.chdir('neudocs')
      os.chdir('../')
   except:
      os.system('mkdir neudocs')
   checklist = glob.glob('neudocs/*') 
   k_register = [] 
   network = SocketClientThread()
   startup = Command(Command.CONNECT,('localhost',4443))
   print startup.type
   print startup.data
   network.start()
   network.cmd_q.put(startup)
   res = network.reply_q.get()
   print res.data
   while True:
      handle_packet(key, relay_key, network, k_register)             
      checklist =  handle_changes(key, relay_key, network, k_register, checklist)
      time.sleep(1) 
