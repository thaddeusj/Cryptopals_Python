import socket
import diffie
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 64321

forward_HOST = "127.0.0.1"
forward_PORT = 65432


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()

    with conn:
        p = int.from_bytes(conn.recv(1024),"big")
        g = int.from_bytes(conn.recv(1024),"big")
        a_param = int.from_bytes(conn.recv(1024),"big")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward_s:
            forward_s.connect((forward_HOST,forward_PORT))

            forward_s.send((p).to_bytes(1024,"big"))
            forward_s.send((g).to_bytes(1024,"big"))
            forward_s.send((p).to_bytes(1024,"big"))

            b_param = int.from_bytes(forward_s.recv(1024),"big")


            key_exchange = diffie.DH()

            key = key_exchange.generate_secret(p)



            conn.send((p).to_bytes(1024,"big"))


            a_c = conn.recv(1024)
            a_IV = conn.recv(1024)

            cipher = Cipher(algorithms.AES(key),modes.CBC(a_IV))
            dec = cipher.decryptor()

            a_m = dec.update(a_c) + dec.finalize()

            print("A's message is:")
            print(a_m)


            forward_s.send(a_c)
            forward_s.send(a_IV)

            b_c = forward_s.recv(1024)
            b_iv = forward_s.recv(1024)

            cipher_2 = Cipher(algorithms.AES(key), modes.CBC(b_iv))
            dec_2 = cipher_2.decryptor()

            b_m = dec_2.update(b_c) + dec_2.finalize()

            print("B replied with:")
            print(b_m)

            conn.send(b_c)
            conn.send(b_iv)
            

