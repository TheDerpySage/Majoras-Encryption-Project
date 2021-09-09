MAJORA'S ENCRYPTION PROJECT
===========================
A secure file transfer program using pycryptodome implementations of RSA and AES.
This is the result of a week of reading and attempting to make my own scripts that I can use in other projects.

DEPENDENCIES
============
Python 3

pip install pycryptodome

HOW TO PLAY
===========

server-rsa.py
-------------
The server runs by default on port 42069. Server will listen for incoming connections and then wait for commands.

HELO to verify connection, and send our public key.

NAME to set the name of the file. (Requires HELO)

DATA, accept RSA encrypted AES password, the file, decrypts the file, and then writes. When complete, it will send OK. (Requires HELO)

TIME simply returns the current time.

EXIT to cleanly close a connection.

Server script will attempt to return to idle on basic socket errors.

client-rsa.py
-------------
A cross platform client that will open a file dialogue and allow you to open any file for sending. AES password will be generated at runtime for you to see, but when it is sent it will be encrypted via the servers public key. When sending DATA, after sending the AES encrypted file, the script waits for the OK from the server indicating that it's recieved it all. There is purposely no timeout on this so that the client doesnt disconnect before everything is sent to accomadate larger files. When complete, script loops if you'd like to send something else.

I also had an automated script for a pure cli implementation at an earlier point in development, but it needs to be updated.

Reasonable restrictions apply (hasn't be tested for over 1GB).

PROOF OF CONCEPT
================
(note: as of the latest commit, the POC is outdated)
Inside the folder PoC was a packet capture I ran on a file transfer. Included is the file.txt, the packet capture file, and a readme.txt with some of the key packets. The only thing sent in the clear is the Server's public key, after that commands are sent in the clear but the data after those commands are RSA encrypted, and the file itself is AES encrypted.

NOTES
=====
I do not gaurentee the security of this application. Please avoid using this in such a way where security may be your highest priority.

TO-DO
=====
Improve buffered_recv, it's a bit slow right now...