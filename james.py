#!/bin/python3
import socket, argparse, logging
import os, sys
import hmac, hashlib
from Crypto.Cipher import AES
from time import sleep
import json

# initiate: python3 alice.py --addr 127.0.0.1  --port 6000 --enckey AAAAAAAAAAAAAAAA --mackey BBBBBBBBBBBBBBBB --iv CCCCCCCCCCCCCCCC
#We use MAC then Encrypt

ENCKEY_LENGTH = 16 #AES-128
MAC_LENGTH = 32 #HMAC-SHA256
BLOCK_LENGTH = 16 #AES block size

# Data Generation
pid = "000"
lat = "000.0000000"
lon = "00.0000000"

pids = [pid for _ in range(24)]
hours = [i for i in range(24)]
lats = [lat for _ in range(24)]
lons = [lon for _ in range(24)]

for i in range(24):
  if hours[i] < 10:
    hours[i] = "0" + str(hours[i])
  else:
    hours[i] = str(hours[i])
    
label_pid = ["pid" for _ in range(24)]
label_hour = ["hour" for _ in range(24)]
label_lat = ["latitude" for _ in range(24)]
label_lon = ["longitude" for _ in range(24)]

pre = [{} for i in range(24)]
for i in range(24):
    pre[i][label_pid[i]] = pids[i]
    pre[i][label_hour[i]] = hours[i]
    pre[i][label_lat[i]] = lats[i]
    pre[i][label_lon[i]] = lons[i]

data = {"data": 
        pre
        }
jdata = json.dumps(data)
encoded = jdata.encode()

#Encryption
def encrypt(key, iv, msg):
    pad = (BLOCK_LENGTH - len(msg)) % BLOCK_LENGTH # must be positive integer
    msg = msg + pad * chr(pad).encode()
    aes = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    encrypted = aes.encrypt(msg)
    #raise NotImplementedError("You need to implement the encrypt() function that performs AES-128 encryption")
    return encrypted

#Generate MAC key
# string * bytes -> bytes
def calc_mac(key, msg):
    h = hmac.new(key.encode(), msg, hashlib.sha256) # input type of byte
    return h.digest()

#MAC then encrypt
# int * string * string * string * string -> bytes
def ae_encrypt(enckey, mackey, iv, msg):
    encrypted = None
#    msg = msg.encode()
    mac = calc_mac(mackey, msg)
    msg += mac 
    encrypted = encrypt(enckey, iv, msg)
    return encrypted

#Send
def run(addr, port, enckey, mackey, iv):
    alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice.connect((addr, port))
    logging.info("[*] Client is connected to {}:{}".format(addr, port))
    logging.info("[*] send GPS information")

    msg = encoded
    logging.info("[*] Sending Data: {}".format(msg))

    st = time()
    cpu_st = process_time()

    encrypted = ae_encrypt(enckey, mackey, iv, msg)
    
    ed = time()
    cpu_ed = process_time()

    print("\ntotal elapsed time:", ed-st)
    print("total cpu_time:", cpu_ed-cpu_st)
    
    alice.send(encrypted)
    received = alice.recv(7)
    logging.info("[*] Received: {}".format(received))
    # sleep(2)

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    #parser.add_argument("-w", "--ae", metavar="<authenticated encryption (0: mac-then-encrypt / 1: encrypt-then-mac)>", help="Authenticated encryption (0: mac-then-encrypt / 1: encrypt-then-mac)", type=int, choices=[0, 1], required=True)
    parser.add_argument("-x", "--enckey", metavar="<encryption key (AES-128)>", help="Encryption key (AES-128)", type=str, required=True)
    parser.add_argument("-y", "--mackey", metavar="<mac key (HMAC-SHA256)>", help="MAC key (HMAC-SHA256)", type=str, required=True)
    parser.add_argument("-z", "--iv", metavar="<initialization vector (16 byte)>", help="Initialization vector (16 byte)", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    if len(args.enckey) != ENCKEY_LENGTH:
        logging.error("Encryption key length error (hint: AES-128): {} bytes".format(len(args.enckey)))
        sys.exit(1)

    if len(args.iv) != BLOCK_LENGTH:
        logging.error("IV length error (hint: AES)")
        sys.exit(1)

    run(args.addr, args.port, args.enckey, args.mackey, args.iv)

if __name__ == "__main__":
    main()
