import os
import string
from tkinter.filedialog import askopenfilename
import socket
import base64
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto import Random

HEADERSIZE = 10
TIMEOUT = 60

def buffered_send(msg):
    return f'{len(msg):<{HEADERSIZE}}' + msg

def buffered_recv(s):
    # Buffered receive for variable content length
    print("[~] Buffered receiver started.")
    buffer = ''
    default_block_size = 1024
    try: length = int(s.recv(HEADERSIZE))
    except:
        print("[!] Error! Header Invalid! Are you sure we should be buffering? Will attempt to continue...")
        length = 0
    while True:
        print(f"[~] Data length: {length}")
        x = length - len(buffer)
        if x < default_block_size:
            data = s.recv(x)
        else : data = s.recv(default_block_size)
        if data == b'':
            raise socket.error(f"Buffered receive didn't work right... Buffer reached {len(buffer)}\n{buffer}")
        buffer += data.decode("utf-8")
        print(f"[~] {round((len(buffer)/length)*100)}%", end="\r")
        if len(buffer) == length:
            print(f"[~] 100% Full message received.")
            break
    return buffer

def randomString(stringLength=8):
    letters = string.ascii_lowercase
    letters += string.ascii_uppercase
    letters += string.digits
    return ''.join(Random.random.choice(letters) for i in range(stringLength))

def start():
    HOST = input("Enter host address: ")
    if HOST == "":
        print("[!] Host cannot be empty, exiting...")
        exit()
    PORT = input("Enter port [42069]: ")
    if PORT == "":
        PORT = 42069

    # AES Password is generated at runtime.
    AES_PASSWORD = randomString(16)
    print(f"[+] Generated random AES password: {AES_PASSWORD}")

    print(f"[~] Awaiting connection...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)

    try:
        s.connect((HOST, PORT))
        print(f"[+] Connection to {HOST} has been established!")
    except Exception as e:
        print(f"[!] Error: {e}")
        input("Please press any key to exit...")
        exit()

    try:
        greeting = s.recv(25).decode("utf-8")
        print("[~] %s" % greeting)
        if greeting == "220 MOSHI MOSHI LILY DESU":
            print("[+] Banner OK, Sending HELO and ready to receive public key..")
            s.send(bytes("HELO","utf-8"))
            public_key = buffered_recv(s)
            print("[+] Received public key, making cipher.")
            public_key = RSA.importKey(public_key)
            rsa_cipher = PKCS1_OAEP.new(public_key)
            while True:    
                print("[+] Opening file dialogue...")    
                FILEPATH = askopenfilename(initialdir = ".", title = "Select a file.")
                # Quick check for a Bad Path
                try:
                    infile = open(FILEPATH, 'rb')
                    infile.read()
                    infile.close()
                    if os.name == 'posix': FILENAME = FILEPATH.split("\\").pop()
                    elif os.name == 'nt': FILENAME = FILEPATH.split("/").pop()
                    else:
                        print("[!] Error: Unrecognized os.name\n[!] Exiting...")
                        exit()
                except Exception as e:
                    print("[!] Error:", e)
                    print("[!] Exiting...")
                    exit()
                # Start with encrypting the file.
                with open(FILEPATH, 'rb') as infile:
                    plaintext = infile.read()
                # Make Key, Prepare plaintext, Make cipher, and encrypt
                aes_key = hashlib.sha256(AES_PASSWORD.encode()).digest()
                plaintext = plaintext + b"\0" * (AES.block_size - len(plaintext) % AES.block_size)
                iv = Random.new().read(AES.block_size)
                aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                ciphertext = iv + aes_cipher.encrypt(plaintext) 
                while (True):
                    print(f"[+] Sending NAME, {FILENAME}.")
                    s.send(bytes("NAME","utf-8"))
                    enc_filename = rsa_cipher.encrypt(bytes(FILENAME,"utf-8"))
                    encrypted64 = base64.b64encode(enc_filename).decode()
                    s.send(bytes(buffered_send(encrypted64),"utf-8"))
                    break
                    """
                    POSSIBLE WAY TO MITIGATE DUPE FILENAMES
                    data = s.recv(2).decode("utf-8")
                    if data == "NO": FILENAME = input("Server says name is in use, enter a different one: ")
                    elif data == "OK": break
                    """
                print("[+] Sending DATA...")
                s.send(bytes("DATA","utf-8"))
                print("[+] Encrypting the AES Password and Sending...") 
                enc_password = rsa_cipher.encrypt(bytes(AES_PASSWORD,"utf-8"))
                encrypted64 = base64.b64encode(enc_password).decode()
                s.send(bytes(buffered_send(encrypted64),"utf-8"))
                print("[+] Sending Cipher Text...") 
                encrypted64 = base64.b64encode(ciphertext).decode()
                s.send(bytes(buffered_send(encrypted64),"utf-8"))
                print("[~] Please wait warmly...") 
                s.settimeout(None)
                data = s.recv(2).decode("utf-8")
                if data == "OK":
                    print("[+] Server OK.") 
                replay=input("[?] Send something else? (y/N): ").lower()
                if replay != 'y':
                    break
                else: print("\n")
                s.settimeout(TIMEOUT)
            print("[+] Sending EXIT, and exiting...")
            s.send(bytes("EXIT","utf-8"))
            print("[+] Exited.")
        else: 
            print("[!] This isn't Lily, exting...")
            s.close()
            input("Please press any key to exit...")
            exit()
    except Exception as e:
        print(f"[!] Error: {e}")
        input("Please press any key to exit...")
        exit()

start()