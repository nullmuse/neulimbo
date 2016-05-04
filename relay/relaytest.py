from Crypto.PublicKey import RSA
from Crypto import Random
import sys
import socket


f = open("pubkey.pem")
key = RSA.importKey(f.read())
f.close() 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

data = raw_input('give me some input: ')
magic = "HI!" 

s.connect(('localhost',4443)) 
#data = key.encrypt(data)
magic += data 
data = key.encrypt(magic, 32) 
s.send(data[0])
this = s.recv(1024) 
print this 
s.close()




