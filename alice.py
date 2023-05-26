#!/bin/python3
import socket, argparse, logging
import os, sys
import hmac, hashlib
from Crypto.Cipher import AES
from time import sleep, time, process_time
from memory_profiler import memory_usage

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
ats = [126.9503846, 126.9503871, 126.9503877, 126.9503875, 126.9503823, 126.9503838, 126.9503858, 126.9503804, 126.9503850, 126.9503834, 126.9503888, 126.9503843, 126.9503890, 126.9503892, 126.9503800, 126.9503880, 126.9503800, 126.9503887, 126.9503810, 126.9503878, 126.9503858, 126.9503842, 126.9503867, 126.9502446]
lons = [37.5450378, 37.5450382, 37.5450376, 37.5450381, 37.5450390, 37.5450364, 37.5450379, 37.5450544, 37.5450389, 37.5450392, 37.5450404, 37.5450397, 37.5450394, 37.5450400, 37.5450545, 37.5450382, 37.5450545, 37.5450389, 37.5450427, 37.5450386, 37.5450383, 37.5450391, 37.5450383, 37.5446519]

for i in range(24):
  if hours[i] < 10:
    hours[i] = "0" + str(hours[i])
  else:
    hours[i] = str(hours[i])
    
label_pid = ["pid" for _ in range(24)]
label_hour = ["hour" for _ in range(24)]
label_lat = ["latitude" for _ in range(24)]
label_lon = ["longitude" for _ in range(24)]

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
    msg = msg.encode()
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

    st = time()
    cpu_st = process_time()
    
    sum_time = 0
    sum_time_cpu = 0
    for i in range(24):
        #msg = "{}: {}, {}: {}, {}: {}, {}: {}".format(label_pid[i], pids[i], label_hour[i], hours[i], label_lat[i], lats[i], label_lon[i], lons[i])
#        msg = "{}: {},{}: {},{}: {},{}: {}".format(label_pid[i], pids[i], label_hour[i], hours[i], label_lat[i], lats[i], label_lon[i], lons[i])
        msg = "{}: {}{}: {}{}: {}{}: {}".format(label_pid[i], pids[i], label_hour[i], hours[i], label_lat[i], lats[i], label_lon[i], lons[i])
        logging.info("[*] Sending Data: {}".format(msg))

        st_for = time()
        cpu_st_for = process_time()
        
        encrypted = ae_encrypt(enckey, mackey, iv, msg)

        ed_for = time()
        cpu_ed_for = process_time()

        alice.send(encrypted)
        received = alice.recv(7)
        logging.info("[*] Received: {}".format(received))

        sum_time += (ed_for - st_for)
        sum_time_cpu += (cpu_ed_for - cpu_st_for)
    
#        sleep(2)

    ed = time()
    cpu_ed = process_time()

    print("\ntotal encryption time:", sum_time)
    print("total encryption cpu time:", sum_time_cpu)

    print("\ntotal elapsed time:", ed-st)
    print("total cpu_time:", cpu_ed-cpu_st)

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
