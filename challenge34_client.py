import socket
import diffie
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 64321        # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    key_exchange = diffie.DH()

    param = key_exchange.get_param()

    s.send((key_exchange.p).to_bytes(1024,"big"))
    s.send((key_exchange.g).to_bytes(1024,"big"))
    s.send(param.to_bytes(1024,"big"))

    b_param = int.from_bytes(s.recv(1024),"big")

    key = key_exchange.generate_secret(b_param)


    IV = os.urandom(16)

    cipher = Cipher(algorithms.AES(key),modes.CBC(IV))
    enc = cipher.encryptor()

    m = bytearray(input("What is your message?\n"),'utf=8')

    padder = padding.PKCS7(128).padder()
    padded_m = padder.update(m) + padder.finalize()

    cipher_text = enc.update(padded_m) + enc.finalize()

    s.send(cipher_text)
    s.send(IV)


    verify = s.recv(1024)
    verify_iv = s.recv(1024)

    cipher_2 = Cipher(algorithms.AES(key), modes.CBC(verify_iv))

    dec = cipher_2.decryptor()

    verify_m = dec.update(verify) + dec.finalize()

    if padded_m != verify_m:
        print(verify_m)
        print(m)
    else:
        print("Yep!")



    
