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
HOST = "192.168.1.12"
PORT = 42069

def buffered_send(msg):
    return f'{len(msg):<{HEADERSIZE}}' + msg

def buffered_recv(s):
    # Buffered recieve for variable content length
    print("[~] Buffered reciever started.")
    buffer = ''
    length = 0
    beginning = True
    default_block_size = 64
    while True:
        if beginning:
            data = s.recv(default_block_size)
            if len(buffer) > HEADERSIZE:
                try:
                    length = int(buffer[:HEADERSIZE])
                    print(f"[~] Data length: {length}")
                except:
                    print("[!] Error! Header Invalid! Are you sure we should be buffering?")
                beginning = False
        else:
            x = length + HEADERSIZE - len(buffer)
            if x < default_block_size:
                data = s.recv(x)
            else : data = s.recv(default_block_size)
            if data == b'':
                raise socket.error(f"Buffered Recieve didn't work right... Buffer reached {len(buffer)}\n{buffer}")
            #print(f"[~] {round(((len(buffer)-HEADERSIZE)/length)*100)}%", end="\r")
        buffer += data.decode("utf-8")
        if len(buffer)-HEADERSIZE == length:
            print(f"[~] 100% Full message recieved.")
            buffer = buffer[HEADERSIZE:]
            break
    return buffer

def randomString(stringLength=8):
    letters = string.ascii_lowercase
    letters += string.ascii_uppercase
    letters += string.digits
    return ''.join(Random.random.choice(letters) for i in range(stringLength))

def start():
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

    # AES Password is generated at runtime.
    password = randomString(16)
    print(f"[+] Generated random AES password: {password}")

    # Make Key, Prepare plaintext, Make cipher, and encrypt
    aes_key = hashlib.sha256(password.encode()).digest()
    plaintext = plaintext + b"\0" * (AES.block_size - len(plaintext) % AES.block_size)
    iv = Random.new().read(AES.block_size)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = iv + aes_cipher.encrypt(plaintext) 

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, PORT))
        print(f"[+] Connection to {HOST} has been established!")
    except:
        print("[!] Error: Could Not Connect")

    print("[+] Sending HELO, and ready to receive public key.")
    s.send(bytes("HELO","utf-8"))
    public_key = buffered_recv(s)
    print("[+] Received public key, making cipher.")
    public_key = RSA.importKey(public_key)
    rsa_cipher = PKCS1_OAEP.new(public_key)

    print(f"[+] Sending NAME, {FILENAME}.")
    s.send(bytes("NAME","utf-8"))
    enc_filename = rsa_cipher.encrypt(bytes(FILENAME,"utf-8"))
    encrypted64 = base64.b64encode(enc_filename).decode()
    s.send(bytes(buffered_send(encrypted64),"utf-8"))

    print("[+] Sending DATA...")
    s.send(bytes("DATA","utf-8"))
    print("[+] Encrypting the AES Password and Sending...") 
    enc_password = rsa_cipher.encrypt(bytes(password,"utf-8"))
    encrypted64 = base64.b64encode(enc_password).decode()
    s.send(bytes(buffered_send(encrypted64),"utf-8"))
    print("[+] Sending Cipher Text...") 
    encrypted64 = base64.b64encode(ciphertext).decode()
    s.send(bytes(buffered_send(encrypted64),"utf-8"))
    print("[~] Please wait warmly...") 
    data = s.recv(2)
    data = data.decode("utf-8")
    if data == "OK":
        print("[+] Server OK.") 
    print("[+] Sending EXIT, and exiting...")
    s.send(bytes("EXIT","utf-8"))
    print("[+] Exited.")

while True:
    start()
    replay=input("\n\tSend something else? (y/N): ").lower()
    if replay != 'y':
        break
    else: print("\n")