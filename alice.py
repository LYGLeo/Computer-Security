import socket
import os, sys
import hmac
import hashlib
from Crypto.Cipher import AES
from time import sleep

#We use MAC then Encrypt

ENCKEY_LENGTH = 16 #AES-128
MAC_LENGTH = 32 #HMAC-SHA256
BLOCK_LENGTH = 16 #AES block size

pid = "000"
lat = "000.0000000"
lon = "00.0000000"

pids = [pid for _ in range(24)]
lats = [lat for _ in range(24)]
lons = [lon for _ in range(24)]

label_pid = ["pid" for _ in range(24)]
label_lat = ["latitude" for _ in range(24)]
label_lon = ["longitude" for _ in range(24)]

def encrypt():
  pass

def calc_mac():
  pass

def ae_encrypt:
  pass

def run(ae, enckey, mackey, iv, addr = "localhost", port = "22"):
  alice = socket.socket.AF_INET, socket.SOCK_STREAM)
  alice.connect((addt, port))
  logging.info("[*] Client is connected to {}:{}".format(addr, port))
  
  for i in range(24):
    msg = "{}: {}{}: {}{}: {}".format(label_pid[i], pids[i], label_lat[i], lats[i], label_lon[i], lons[i])
    alice.send(msg)
    sleep(2)
    
