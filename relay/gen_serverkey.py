from Crypto.PublicKey import RSA
from Crypto import Random
import sys

print 'generating relay server keys....'

rgen = Random.new().read
pkey = RSA.generate(2048, rgen) 

if pkey:
   print 'private key generated, storing at pkey.pem' 
   try:
      this = open('pkey.pem','wb')
      this.write(pkey.exportKey('PEM'))
      this.flush()
      print 'key written.' 
   except:
      print 'error writing private key!!!!'
      sys.exit() 
else:
   print 'error generating private key!!!!'
   sys.exit() 

print 'generating public key. neulimbo hosts will need this to work with the relay'
public_key = pkey.publickey() 

try:
   print 'public relay key generated. putting it as pubkey.pem'
   this = open('pubkey.pem','wb')
   this.write(public_key.exportKey('PEM'))
   this.flush()
   print 'public key created' 
except:
   print 'error writting public key!!!!' 
   sys.exit() 



