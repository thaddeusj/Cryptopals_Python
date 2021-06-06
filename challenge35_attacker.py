import socket
import diffie
import os
from cryptography.hazmat.primitives.ciphers import AEADCipherContext, Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import cryptography.hazmat.backends


# Choosing g value:
#   - if we choose g = 1 to forward to B, then the shared secret will just be 1
#   - if we choose g = p, the secret will be 0
#   - if we choosse g = p-1, the secret will be 1 or -1

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

        conn.send(bytes("ACK",'utf-8'))

        a_param = int.from_bytes(conn.recv(1024),"big")

        forward_p = p
        forward_g = 1

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward_s:
            forward_s.connect((forward_HOST,forward_PORT))

            forward_s.send((p).to_bytes(1024,"big"))
            forward_s.send((1).to_bytes(1024,"big"))

            ack_ignore = forward_s.recv(1024)

            forward_s.send((1).to_bytes(1024,"big"))

            ignored_param = int.from_bytes(forward_s.recv(1024),"big")

            b_param = 1



            key_exchange = diffie.DH(p,g)
            key = key_exchange.generate_secret(0)

            b_key_exchange = diffie.DH(p,1)
            b_key = b_key_exchange.generate_secret(1)

            conn.send((0).to_bytes(1024,"big"))


            a_c = conn.recv(1024)
            a_IV = conn.recv(1024)

            cipher = Cipher(algorithms.AES(key),modes.CBC(a_IV),cryptography.hazmat.backends.default_backend())
            dec = cipher.decryptor()

            a_m = dec.update(a_c) + dec.finalize()

            print("A's message is:")
            print(a_m)

            cipher_forward = Cipher(algorithms.AES(b_key),modes.CBC(a_IV),cryptography.hazmat.backends.default_backend())
            enc_2 = cipher_forward.encryptor()
            forward_a_c = enc_2.update(a_m) + enc_2.finalize()

            forward_s.send(forward_a_c)
            forward_s.send(a_IV)

            b = forward_s.recv(1024)

            b_c = b[0:len(b)-16]
            b_iv = b[len(b)-16:len(b)]

            print("B key is:")
            print(b_key)
            print("B IV is:")
            print(b_iv)
            print("B ciphertext is:")
            print(b_c)

            cipher_2 = Cipher(algorithms.AES(b_key), modes.CBC(b_iv),cryptography.hazmat.backends.default_backend())
            dec_2 = cipher_2.decryptor()

            b_m = dec_2.update(b_c) + dec_2.finalize()

            print("B replied with:")
            print(b_m)

            cipher_passback = Cipher(algorithms.AES(key),modes.CBC(b_iv),cryptography.hazmat.backends.default_backend())
            enc_passback = cipher_passback.encryptor()

            passback_c = enc_passback.update(b_m) + enc_passback.finalize()


            conn.send(passback_c+b_iv)
            
            

