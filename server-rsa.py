from datetime import datetime
import socket
import base64
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto import Random

HEADERSIZE = 10
HOST = socket.gethostbyname(socket.getfqdn())
PORT = 42069
TIMEOUT = 60

# This returns msg with the HEADER
# The header is a HEADERSIZE'd string that is then filled with a number, which is interpreted by the client as the length of our message.
# This number can only have HEADERSIZE digits. This is predefined on both ends so this information is not interpreted as part of the message. 
# The header can be made longer to accommadate more identifying pieces of information. 
# This helps facilitate buffered content sending for vastly variable sizes
def buffered_send(temp: str):
    return f'{len(temp):<{HEADERSIZE}}' + temp

def buffered_recv(s):
    # Buffered receive for variable content length
    print("[~] Buffered receiver started.")
    buffer = ''
    length = 0
    beginning = True
    default_block_size = 64
    while True:
        if beginning:
            data = s.recv(default_block_size)
            if len(buffer) >= HEADERSIZE:
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
                raise socket.error(f"Buffered Receive didn't work right... Buffer reached {len(buffer)}\n{buffer}")
            print(f"[~] {round(((len(buffer)-HEADERSIZE)/length)*100)}%", end="\r")
        buffer += data.decode("utf-8")
        if len(buffer)-HEADERSIZE == length:
            print(f"[~] 100% Full message received.")
            buffer = buffer[HEADERSIZE:]
            break
    return buffer

def now():
    return datetime.now().strftime("%b %d %Y, %I:%M %p")

def start():
    # Generate Key Pair
    random_generator = Random.new().read
    private_key = RSA.generate(2048, random_generator)
    public_key = private_key.publickey()
    cipher = PKCS1_OAEP.new(private_key)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)

    while True:
        print(f"[+] Awaiting connection...")
        client, address = s.accept()
        client.settimeout(TIMEOUT)
        print(f"[+] Connection to {address} has been established!")
        name = "received_file.txt"
        verified = False
        try:
            while True:
                data = client.recv(4)
                data = data.decode("utf-8")
                if data == "HELO":
                    # HELO to verify connection, and send our public key.
                    print("[+] HELO recieved, sending public key.")
                    client.send(bytes(buffered_send(public_key.exportKey().decode("utf-8")),"utf-8"))
                    verified = True
                elif data == "NAME" and verified:
                    # NAME to set the name of the file
                    buffer = buffered_recv(client)
                    encrypted = base64.b64decode(buffer.encode())
                    decrypted = cipher.decrypt(encrypted)
                    name = decrypted.decode("utf-8")
                    print(f"[+] NAME recieved, setting new file name to {name}.")
                elif data == "DATA" and verified:
                    # DATA, accept RSA encrypted AES password, Decrypt the file, and then write. 
                    print("[+] DATA recieved...")
                    print("[~] Accepting AES key...")
                    buffer = buffered_recv(client)
                    encrypted = base64.b64decode(buffer.encode())
                    decrypted = cipher.decrypt(encrypted)
                    password = decrypted.decode("utf-8")
                    aes_key = hashlib.sha256(password.encode()).digest()
                    print("[~] Recieving file...")
                    buffer = buffered_recv(client)
                    ciphertext = base64.b64decode(buffer.encode())
                    print("[~] Decrypting file...")
                    iv = ciphertext[:AES.block_size]
                    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                    plaintext = aes_cipher.decrypt(ciphertext[AES.block_size:])
                    decrypted = plaintext.rstrip(b"\0")
                    print(f"[~] Writing to ./received/{name}...")
                    with open(f'./received/{name}', 'wb') as fileout:
                        fileout.write(decrypted)
                        fileout.close()
                    print("[~] Complete! Sending OK.")
                    client.send(bytes("OK","utf-8"))    
                elif data == "TIME":
                    # TIME simply returns the current time
                    print(f"[+] TIME recieved, ding dong! The time is {now()}!")
                    client.send(bytes(buffered_send(f"The time is {now()}!"),"utf-8")) 
                elif data == "EXIT":
                    # EXIT to cleanly close a connection
                    print("[+] EXIT recieved, closing connection.")
                    client.close()
                    break
                else:
                    # If an unverified connection tries to use certain commands or we dont recognize what theyre saying, close connection.
                    print("[!] Error, closing connection.")
                    client.close()
                    break
        except socket.timeout as e:
            print("[!] Client timed out, returning to idle...")
        except socket.error as e:
            print(f"[!] Error: {e}\n[!] Client disconnected, returning to idle...")
        except Exception as e:
            print(f"[!] Fatal Error: {e}\n[!] Something catastrophic happened, exiting...")
            exit()

start()
