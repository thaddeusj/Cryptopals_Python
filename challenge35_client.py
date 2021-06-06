import socket

from cryptography.hazmat.backends import default_backend
import diffie
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import cryptography.hazmat.backends

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 64321        # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = int.from_bytes(os.urandom(1024),"big") % p

    key_exchange = diffie.DH(p,g)

    param = key_exchange.get_param()

    s.send((key_exchange.p).to_bytes(1024,"big"))
    s.send((key_exchange.g).to_bytes(1024,"big"))

    ACK = s.recv(3).decode('utf-8')

    if ACK != "ACK": raise Exception("Server did not acknowledge.")


    s.send(param.to_bytes(1024,"big"))

    b_param = int.from_bytes(s.recv(1024),"big")

    key = key_exchange.generate_secret(b_param)

    IV = os.urandom(16)

    cipher = Cipher(algorithms.AES(key),modes.CBC(IV),default_backend())
    enc = cipher.encryptor()

    m = bytes(input("What is your message?\n"),'utf-8')

    padder = padding.PKCS7(128).padder()
    padded_m = padder.update(m) + padder.finalize()

    cipher_text = enc.update(padded_m) + enc.finalize()

    s.send(cipher_text)
    s.send(IV)


    verify_total = s.recv(1024)

    verify = verify_total[0:len(verify_total)-16]
    verify_iv = verify_total[len(verify_total)-16:len(verify_total)]

    cipher_2 = Cipher(algorithms.AES(key), modes.CBC(verify_iv),default_backend())

    dec = cipher_2.decryptor()

    verify_m = dec.update(verify) + dec.finalize()

    if padded_m != verify_m:
        print(verify_m)
        print(m)
    else:
        print("Yep!")



    
