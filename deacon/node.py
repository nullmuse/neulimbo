from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
import binascii
import sys
import socket
import time
import threading 
import struct
import Queue
import os 
import getpass
import glob
import re
def pass_validate(passw):
   password = getpass.getpass('Enter a strong passphrase for your private key: ')
   password2 = getpass.getpass('Enter it again. Make sure you remember your password! ') 
   if password != password2:
      print 'Passwords do not match' 
      return 1 
   else:
      passw.append(password) 
      return 0


def pack(fmt, *args):
    (byte_order, fmt, data) = (fmt[0], fmt[1:], '') if fmt and fmt[0] in ('@', '=', '<', '>', '!') else ('@', fmt, '')
    fmt = filter(None, re.sub("p", "\tp\t",  fmt).split('\t'))
    for sub_fmt in fmt:
        if sub_fmt == 'p':
            (sub_args, args) = ((args[0],), args[1:]) if len(args) > 1 else ((args[0],), [])
            sub_fmt = str(len(sub_args[0]) + 1) + 'p'
        else:
            (sub_args, args) = (args[:len(sub_fmt)], args[len(sub_fmt):])
            sub_fmt = byte_order + sub_fmt
        data += struct.pack(sub_fmt, *sub_args)
    return data




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
   this = cryptslice(this, key)
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
         #self.socket.sendall(header + cmd.data)
         self.socket.send(cmd.data)
         self.reply_q.put(self._success_reply()) 
      except Exception as e:
         self.reply_q.put(self._error_reply(str(e)))

   def _handle_RECEIVE(self, cmd): 
      try:
         msg_len = 0
         data = ''
         #header_data = self._recv_n_bytes(4)
         #if len(header_data) == 4:
         #   msg_len = struct.unpack('<L', header_data)[0]
         #data = self._recv_n_bytes(msg_len)
         data = self.socket.recv(4096)
         print data
         if len(data) == len(data):
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
   print 'verifying'
   hash = SHA256.new(item).digest()
   return pubkey.verify(hash, signature)



class neuPacket(object):
   TREQ, KPUSH, PUSH   = range(3)
   magic = "NLMB"
   def __init__(self, id, data=' ', dirid=' ',  sig=' '):
      super(neuPacket, self).__init__()
      self.id = id
      self.data = data or ' '
      self.dirid = dirid or '0'
      self.sig = sig or ' '


def cryptpack(data, key):
   it = 256
   bound = 0
   cryptdata = ''
   slice = ''
   zone = 'ZON'
   while (len(data) - bound) >= 256:
         slice = data[bound:it]
         slice = key.encrypt(slice, 32)
         cryptdata += slice[0]
         cryptdata += zone
         bound = it
         it += 256
   if (len(data) - bound) > 0:
      print len(data) - bound
      slice = data[bound:] 
      slice = key.encrypt(slice, 32)
      cryptdata += slice[0]
      cryptdata += zone
   print 
   return cryptdata

def cryptslice(data, key):
   bound = 0
   cryptdata = ''
   slice = ''
   zone = "ZON"
   it = data.count(zone)
   print it 
   while it > 0:
      try:
         point = data.index(zone)
         slice = data[:point]
         data = data[(point + 3):]
         cryptdata += key.decrypt(slice)
         it -= 1
      except Exception as e:
         return e
   return cryptdata



def send_packet(npack, key, network):
   packet = npack.magic + str(npack.id) + npack.data + npack.magic + npack.dirid + npack.magic +  npack.sig
   ndata = binascii.hexlify(npack.data)
   print binascii.hexlify(SHA256.new(packet).digest())
   file = RSA.importKey(open('pkey.pem').read())
   #message = key.encrypt(teststr, 32) 
   message = cryptpack(packet, key)
   retstr = cryptslice(message,file)
   print(len(retstr))
   print binascii.hexlify(SHA256.new(retstr).digest())
   startup = Command(Command.SEND, message)
   network.cmd_q.put(startup)
   return network.reply_q.get()

   

def req_tree(key, relaykey, network):
   pubkey = key.publickey().exportKey('PEM')
   sig = dsign(key,pubkey)
   treepacket = neuPacket(neuPacket.TREQ,pubkey,'',str(sig[0])) 
   send_packet(treepacket, relaykey, network) 



def push_item(key, pubkey, relaykey, network, doc, dirid):
      doc = "NLMB" + doc
      sig = dsign(key,doc)
      pkey = RSA.importKey(pubkey) 
      doc = cryptpack(doc, pkey)
      packet = neuPacket(neuPacket.PUSH, doc, dirid, str(sig[0]))
      send_packet(packet, relaykey, network) 


def mass_push(key, k_register, relaykey, network, doc):
     doc = "NLMB" + doc
     sig = dsign(key,doc)
     for item in k_register:
         pkey = RSA.importKey(item)
         doc = cryptpack(doc, pkey)
         packet = neuPacket(neuPacket.PUSH, doc, dirid, str(sig[0]))
         send_packet(packet, relaykey, network)

def push_key(key, relaykey, network):
   pubkey = key.publickey().exportKey('PEM')
   sig = dsign(key,pubkey)
   kpacket = neuPacket(neuPacket.KPUSH,pubkey, '', str(sig[0]))
   send_packet(kpacket, relaykey, network)



def handle_packet(key, relaykey, network, k_register):
   try:
      rec_command = Command(Command.RECEIVE)
      network.cmd_q.put(rec_command)
      packet = network.reply_q.get()
      if packet:
         print 'got a fucking packet'
         packet = packet.data
         print packet[4]
         if 'NLMB' not in packet:
            print 'fucked'
            return 1
         if int(packet[4]) == neuPacket.TREQ:
            tree_friend(packet[5:], key, relaykey, network, k_register)
         elif int(packet[4]) == neuPacket.KPUSH:
            print 'add_key tripped'
            add_key(packet[5:], k_register) 
         elif int(packet[4]) == neuPacket.PUSH:
            print 'push tripped'
            packet  = packet[4:]
            pt1 = packet.index('NLMB')
            pt = packet[(pt1 + 4):].index('NLMB')
            print packet
            signature = packet[(pt + 4):]
            data = packet[1:pt1]
            pt = 0
            print signature
            print 'we are here'
            print len(data)
            for item in k_register:
               if verify(RSA.importKey(item), signature, long(float(data))) == True:
                  print 'digital signature verified'
                  break
               pt +=1
            if pt == len(k_register):
               print 'digital signature failed'
               return 1
            add_doc(packet[5:], key) 
   except Exception as e:
      print e


     
def add_key(packet, k_register):
    print 'in add_key'
    pt1 = packet.index('NLMB')
    key = packet[0:pt1]
    if key not in k_register: 
       k_register.append(key)
       os.system('echo \"{0}\" >keys'.format(key))
   

def tree_friend(packet, key, relaykey, network, k_register):
   print 'in tree_friend'
   add_key(packet, k_register) 
   push_key(key, relaykey, network)
   for filename in glob.glob('neudocs/*'):
      filed = load_document(key,filename)
      push_item(key, k_register[-1], relaykey, network, filed, filename) 

def compare_hash(data,filename):
   if SHA256.new(data).digest() == SHA256.new(filename).digest():   
      return True
   return False 

def add_doc(packet, key):
   print 'in add_doc'
   pt1 = packet.index('NLMB')
   data = cryptslice(packet[0:pt1],key)
   test = data[:4]
   if test is not 'NLMB':
      return 1
   data = data[4:]
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
   data = cryptpack(data, key)
   file1.write(data)
   file1.flush()
   file.close() 
   for item in retlist:
      os.chdir(item)

 
              
     
def handle_changes(key, relaykey, network, k_register, checklist):
   newlist = glob.glob('neudocs/*')
   for filename in newlist:
      if filename not in checklist:
         try:
            doc = load_file(key,filename)
            mass_push(key, k_register, relaykey, network, doc, filename)
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
   res = req_tree(key, relay_key, network)
   while True:
      handle_packet(key, relay_key, network, k_register)             
      checklist =  handle_changes(key, relay_key, network, k_register, checklist)
      time.sleep(1) 
