import socket, threading, argparse, logging, random, queue
import os, sys
import hmac, hashlib
from Crypto.Cipher import AES
from time import sleep

# initiate: python3 bob.py --port 6000 --enckey AAAAAAAAAAAAAAAA --mackey BBBBBBBBBBBBBBBB --iv CCCCCCCCCCCCCCCC
#We use MAC then Encrypt
ENCKEY_LENGTH = 16 #AES-128
MAC_LENGTH = 32 #HMAC-SHA256
BLOCK_LENGTH = 16 #AES block size

def decrypt(key, iv, encrypted):
    aes = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    decrypted = aes.decrypt(encrypted)
    decrypted = decrypted[0:-decrypted[-1]] # last value is the length of padding (int)
    #raise NotImplementedError("You need to implement the decrypt() function that performs AES-128 decryption")
    return decrypted

# string * bytes * bytes -> bool
def verify(key, msg, answer):
    h = hmac.new(key.encode(), msg, hashlib.sha256) 
    mac = h.digest()
    ret = False
    #raise NotImplementedError("You need to implement the verify() funtion that verifies the MAC code")
    if mac == answer:
        return True
    else:
        return ret
    
# int * string * string * string -> string * bool
def ae_decrypt(enckey, mackey, iv, received):
    decrypted = None
    verified = False
    decrypted = decrypt(enckey, iv, received)
    verified = verify(mackey, decrypted[:-MAC_LENGTH], decrypted[-MAC_LENGTH:]) # cutting to distinguih the message and mac
    decrypted = decrypted[:-MAC_LENGTH] # message without mac
    decrypted = decrypted.decode()
    return decrypted, verified

def handler(alice, enckey, mackey, iv):
    received = alice.recv(1082)
    logging.info("[*] Received: {}".format(received))
    decrypted, verified = ae_decrypt(enckey, mackey, iv, received)
    if verified:
        logging.info("[*] MAC verified")
        logging.info("[*] Plaintext: {}".format(decrypted))
        logging.info("[*] Success!")
        result = "success"
    else:
        logging.error("[*] Invalid MAC")
        result = "failure"

    alice.send(result.encode())
    #alice.close()

    '''
    pid = decrypted[:8]
    hour = decrypted[8:16]
    lat = decrypted[16:37]
    lon = decrypted[37:58]
    MAC = decrypted[58:]
    
    alice.send(result.encode())
    '''    

def run(addr, port, enckey, mackey, iv):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))
    bob.listen(2)
    logging.info("[*] Server is Listening on {}:{}".format(addr, port))

    alice, info = bob.accept()
    logging.info("[*] Server accept the connection from {}:{}".format(info[0], info[1]))    
    #handle = threading.Thread(target = handler, args = (alice, enckey, mackey, iv))
    #handle.start()
    
    for i in range(24):
        handle = threading.Thread(target = handler, args = (alice, enckey, mackey, iv))
        handle.start()
    

    bob.close()        



def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    #parser.add_argument("-w", "--ae", metavar="<authenticated encryption (0: mac-then-encrypt / 1: encrypt-then-mac)>", help="Authenticated encryption (0: mac-then-encrypt / 1: encrypt-then-mac)", type=int, choices=[0, 1], required=True)
    parser.add_argument("-x", "--enckey", metavar="<encryption key (AES-128)>", help="encryption key (AES-128)", type=str, required=True)
    parser.add_argument("-y", "--mackey", metavar="<MAC key (HMAC-SHA256)>", help="MAC key (HMAC-SHA256)", type=str, required=True)
    parser.add_argument("-z", "--iv", metavar="<initialization vector (16 byte)>", help="Initialization vector (16 byte)", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    if len(args.enckey) != ENCKEY_LENGTH:
        logging.error("Encryption key length error (hint: AES-128)")
        sys.exit(1)

    if len(args.iv) != BLOCK_LENGTH:
        logging.error("IV length error (hint: AES)")
        sys.exit(1)

    run(args.addr, args.port, args.enckey, args.mackey, args.iv)

if __name__ == "__main__":
    main()