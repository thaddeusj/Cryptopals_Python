import ECB
import padding

class CBC:
    def __init__(self, iv, key):
        self.iv = iv
        self.key = key

    
    def encrypt(self, plaintext):
        padded_plaintext = padding.pkcd7_padding(plaintext,len(self.key))

        blocks = [padded_plaintext[i:i+len(self.key)] for i in range(0,len(padded_plaintext),len(self.key))]

        cipher_text = []

        cipher_text.append(ECB.AES_ECB_encrypt(blocks[0]^self.iv,self.key))

        for x in range(len(self.key), len(padded_plaintext), len(self.key)):
            cipher_text.append(ECB.AES_ECB_encrypt(blocks[int(x/len(self.key))]^cipher_text[int(x/len(self.key))-1],self.key))

        return cipher_text