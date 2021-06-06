from hashlib import new
import socket
import diffie
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import cryptography.hazmat.backends

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:

        print('Connected by', addr)
        
        p = int.from_bytes(conn.recv(1024),"big")
        g = int.from_bytes(conn.recv(1024),"big")


        conn.send(bytes("ACK",'utf-8'))

        a_param = int.from_bytes(conn.recv(1024),"big")

        key_exchange = diffie.DH(p,g)
        b = key_exchange.get_param()

        key = key_exchange.generate_secret(a_param)

        conn.send(b.to_bytes(1024,"big"))


        c = conn.recv(1024)
        IV = conn.recv(1024)

        cipher = Cipher(algorithms.AES(key),modes.CBC(IV),cryptography.hazmat.backends.default_backend())
        dec = cipher.decryptor()

        m = dec.update(c) + dec.finalize()

        
        new_IV = os.urandom(16)

        cipher_2 = Cipher(algorithms.AES(key), modes.CBC(new_IV),cryptography.hazmat.backends.default_backend())
        enc = cipher_2.encryptor()

        c2 = enc.update(m) + enc.finalize()

        new_message = c2 + new_IV

        conn.send(new_message)
        