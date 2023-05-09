import socket, threading
import os, sys
import hmac
import hashlib
from Crypto.Cipher import AES
from time import sleep

#We use MAC then Encrypt

ENCKEY_LENGTH = 16 #AES-128
MAC_LENGTH = 32 #HMAC-SHA256
BLOCK_LENGTH = 16 #AES block size

def decrypt():
  pass

def verify():
  pass

def ae_decrypt():
  pass

def handler():
  pass

def run(ae, enckey, mackey, iv, addr = "localhost", port = "22"):
  bob = socket.socket.AF_INET, socket.SOCK_STREAM)
  bob.bind((addt, port))
  
  bob.listen(2)
  logging.info("[*] Server is Listening on {}:{}".format(addr, port))
  
  while True:
    alice, info = bob.accept()
    
    logging.info("[*] Server accept the connection from {}:{}".format(info[0], info[1]))
    handle = threading.Thread(target = handler, args = (alice, enckey, mackey, iv))
