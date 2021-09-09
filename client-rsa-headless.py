import os, string, sys, socket, base64, hashlib, gzip
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto import Random

# Run with commandline arguments HOST, PORT, and FILEPATHS
# client-rsa-headless.py 192.168.1.2 42069 test.txt test2.txt etc

HEADERSIZE = 10
TIMEOUT = 60
DEFAULT_BLOCK_SIZE = 8192

def buffered_send(msg):
    return f'{len(msg):<{HEADERSIZE}}' + msg

def buffered_recv(s):
    # Buffered receive for variable content length
    print("[~] Buffered receiver started.")
    buffer = ''
    
    try: length = int(s.recv(HEADERSIZE))
    except:
        raise socket.error("[!] Error on buffered_recv! Header Invalid!")
    while True:
        print(f"[~] Data length: {length}")
        x = length - len(buffer)
        if x < DEFAULT_BLOCK_SIZE:
            data = s.recv(x)
        else : data = s.recv(DEFAULT_BLOCK_SIZE)
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

def start(HOST, PORT, FILEPATHS):

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
            print("[+] Banned OK, Sending HELO and ready to receive public key.")
            s.send(bytes("HELO","utf-8"))
            public_key = buffered_recv(s)
            print("[+] Received public key, making cipher.")
            public_key = RSA.importKey(public_key)
            rsa_cipher = PKCS1_OAEP.new(public_key)
            for FILEPATH in FILEPATHS:
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
                # Start with reading the file in and compressing
                print(f"[+] Compressing {FILENAME}...")
                with open(FILEPATH, 'rb') as infile:
                    plaintext = gzip.compress(infile.read())
                # Make Key, Prepare plaintext, Make cipher, and encrypt
                aes_key = hashlib.sha256(AES_PASSWORD.encode()).digest()
                plaintext = plaintext + b"\0" * (AES.block_size - len(plaintext) % AES.block_size)
                iv = Random.new().read(AES.block_size)
                aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                ciphertext = iv + aes_cipher.encrypt(plaintext) 
                print(f"[+] Sending NAME, {FILENAME}.")
                s.send(bytes("NAME","utf-8"))
                enc_filename = rsa_cipher.encrypt(bytes(FILENAME,"utf-8"))
                encrypted64 = base64.b64encode(enc_filename).decode()
                s.send(bytes(buffered_send(encrypted64),"utf-8"))
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
                data = s.recv(2).decode("utf-8")
                if data == "OK":
                    print("[+] Server OK.") 
            print("[+] Sending EXIT, and exiting...")
            s.send(bytes("EXIT","utf-8"))
            print("[+] Exited.")
        else:
            print("[!] Unexpected response, this might not be Lily. Exiting...")
    except Exception as e:
        print(f"[!] Error: {e}")

FILES = sys.argv[3:]
start(sys.argv[1], int(sys.argv[2]), FILES)
