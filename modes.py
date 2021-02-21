import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

import XOR_tools
import padding


class ECB_CBC_oracle:   #For later
    @staticmethod
    def detect(cipher_text,key_length):         #This is a probabilistic test for telling ECB from CBC
                                                #The idea is that for long cipher texts encrypted in ECB, you should have a large number of collisions.
                                                #This is not true for CBC.

        sensitivity = 0.001                     #This will be the threshold for choosing ECB vs CBC

        blocks = [cipher_text[x:x+key_length] for x in range(0,len(cipher_text),key_length)]

        collisions = 0

        blocks_seen_so_far = []

        for block in blocks:
            if block in blocks_seen_so_far:
                collisions += 1
            else:
                blocks_seen_so_far.append(block)

        guess = 0

        if (collisions > sensitivity*len(blocks)):
            guess = 1

        #print("The number of collisions was: " + str(collisions))
        #print("There are " + str(len(blocks)) + " blocks.")

        return guess

class ECB_to_attack:                        #I'm going to blackbox the encryption and padding here.
                                            #So the attack just needs to hook into this class.
    def __init__(self,offset,key,text):
        self.text = text
        self.offset = offset
        self.key = key

        self.cipher = Cipher(algorithms.AES(key),modes.ECB())

    def pad(self,text):
        return padding.pkcs7_padding(text,len(self.key))

    def encrypt(self,injection):
        offset_text = bytearray(os.urandom(self.offset))
        offset_text.extend(injection)
        offset_text.extend(self.text)
        padded_text = self.pad(offset_text)

        encryptor = self.cipher.encryptor()


        cipher_text = encryptor.update(padded_text) + encryptor.finalize()

        return cipher_text



class ECB_injection_attack:
    def __init__(self,ECB_hook):
        self.ECB_hook = ECB_hook

    def find_block_length(self):

        cipher_without_padding = self.ECB_hook.encrypt(bytearray(0))

        current_length = len(cipher_without_padding)

        first_increase = 0
        second_increase = 0

        for x in range(1,100):

            if second_increase > 0:
                break

            cipher_with_padding = self.ECB_hook.encrypt(bytearray(x))

            length = len(cipher_with_padding)

            if length > current_length:
                current_length = length
                
                if first_increase == 0:
                    first_increase = x
                elif second_increase == 0:
                    second_increase = x
            
            

        self.block_length = second_increase - first_increase

    def find_offset(self):

        #We're going to prepend two blocks of A onto the cipher text, and then start pushing it forward until blocks 2 and 3 match.
        #Repeat that with Bs, to avoid situations where the cipher text starts with a bunch of 0s.
        #On of the two will work, since the plaintext can't start with both A and B.
        #Take the higher of the two if they don't agree, since if one is lower then the first few terms of the text are that char.

        #I am assuming the offset is at most one block.

        A_total = 0
        B_total = 0


        #A-Test

        match = False
        trial_num = 0

        while(not match):

            attack_text = bytearray(0)

            if(trial_num > 0):
                attack_text.extend(bytearray([1 for x in range(0,trial_num)]))
            
            attack_text.extend(bytearray([0 for x in range(0,2*self.block_length)]))

            cipher = self.ECB_hook.encrypt(attack_text)

            if cipher[self.block_length:2*self.block_length] == cipher[2*self.block_length:3*self.block_length]:
                match = True
                A_total = trial_num

            trial_num +=1

        #B-Test

        match = False
        trial_num = 0

        while(not match):

            attack_text = bytearray(0)

            if(trial_num > 0):
                attack_text.extend(bytearray([2 for x in range(0,trial_num)]))
            
            attack_text.extend(bytearray([1 for x in range(0,2*self.block_length)]))


            cipher = self.ECB_hook.encrypt(attack_text)

            if cipher[self.block_length:2*self.block_length] == cipher[2*self.block_length:3*self.block_length]:
                match = True
                B_total = trial_num

            trial_num +=1


        self.offset = self.block_length - max(A_total,B_total)


    def break_ECB(self):
        #First, we'll check if it is ECB encrypted or not. (It is, but we should check.)

        self.find_block_length()

        ECB_check_text = bytearray(10*self.block_length)

        if ECB_CBC_oracle.detect(self.ECB_hook.encrypt(ECB_check_text),self.block_length) != 1:
            raise Exception("This is not ECB encrypted or you do not have the right block length.")
        
        #Now that we know it's in ECB, we need to identify the offset length.

        self.find_offset()

        #Now we can mount the attack.

        #We're going to prepend block_length - offset + block_length - 1 characters (I'll be using 0) to the data to capture the first byte of the secret.
        #Then we'll start computing the encryption with the second block being all versions of 000...00X.
        #Once we hit the correct encryption for the second block, we've found our secret. Move over one byte.

        #The tricky part will come when we've found the first byte.

        #In this, we aren't appending any garbage to the end, so it'll end when we've finished capturing the padding.
        #I'm not sure how you'd handle if each encryption had different garbage at the end. I guess you'd need to do some sort of offset calculation at the end, similar to the initial offset calculation.

        print("The cipher text has " + str(len(self.ECB_hook.encrypt(bytearray(0)))) + " bytes.")
        print("There are " + str(self.offset) + " bytes of offset.")

        total_bytes_in_plaintext = len(self.ECB_hook.encrypt(bytearray(0))) - self.offset  #This includes padding.

        known_bytes = bytearray(0)

        plaintext = bytearray(0)

        print(total_bytes_in_plaintext)

        into_padding = False

        while(not into_padding):

            attack_text = bytearray(self.block_length - self.offset + self.block_length - 1 - (len(known_bytes)%self.block_length))

            current_block = int(len(known_bytes)/self.block_length) + 1

            target = self.ECB_hook.encrypt(attack_text)[current_block*self.block_length:(current_block +1)*self.block_length]

            attack_text.extend(known_bytes)

            for x in range(0,256):

                attack_text.append(x)

                block_with_x = self.ECB_hook.encrypt(attack_text)[current_block*self.block_length:(current_block +1)*self.block_length]

                # if x == 0 and len(known_bytes) == 139:
                #     print("The target block is: " + str(target))

                # if len(known_bytes) == 139:
                #     print("The block with x is: " + str(block_with_x))

                if block_with_x == target:
                    known_bytes.append(x)
                    break

                attack_text.pop()

                if x == 255:                    #If it goes through the loop without matching, that's because the cipher text immediately after the known block depends on length.
                                                #I.e., we've run into padding. This will happily gobble up the first padding byte.
                                                #Actually, since we're looking at the modified text, this should be gobbling up the only padding byte.
                                                #We're setting up target so that the last 7 bytes of plaintext are in a block, which then get padded.
                                                #So we'll capture that single padding block.
                                                #This also explains why we can't push into the next block: we're creating a new padding block at that point and I have no control over that block.
                    into_padding = True
        
        known_bytes.pop()                       #Because we've grabbed one byte of padding, we need to pop it off first before sending the plaintext on.

        self.plaintext = known_bytes








class my_CBC:   #For now, we're tying this explicitly to AES. Later on, if necessary, I'll refactor to allow for different encryption primitives.
    def __init__(self, iv, key):
        self.iv = iv
        self.key = key

    
    def encrypt(self, plaintext):
        padded_plaintext = padding.pkcs7_padding(plaintext,len(self.key))

        blocks = [padded_plaintext[i:i+len(self.key)] for i in range(0,len(padded_plaintext),len(self.key))]

        cipher_text = bytearray(0)

        cipher_text.extend(my_ECB.AES_ECB_encrypt(XOR_tools.bytearray_XOR(blocks[0],self.iv),self.key))

        for x in range(0, len(blocks)):
            cipher_text.extend(my_ECB.AES_ECB_encrypt(XOR_tools.bytearray_XOR(blocks[x],cipher_text[(x-1)*len(self.key):x*len(self.key)]),self.key))

        return cipher_text

    def decrypt(self, cipher_text):

        plaintext = bytearray(0)

        if(len(cipher_text)> 0):
            plaintext.extend(XOR_tools.bytearray_XOR(self.iv,my_ECB.AES_ECB_decrypt(cipher_text[0:len(self.key)],self.key)))

        for x in range(len(self.key), len(cipher_text), len(self.key)):
            plaintext.extend(XOR_tools.bytearray_XOR(cipher_text[x-len(self.key):x],my_ECB.AES_ECB_decrypt(cipher_text[x:x+len(self.key)],self.key)))

        return plaintext



class my_ECB:  #For now, we're tying this explicitly to AES. Later on, if necessary, I'll refactor to allow for different encryption primitives.

    @staticmethod
    def AES_ECB_encrypt(plaintext,key): #We're going to assume that the plaintext has already been padded.
        cipher_text=[]

        cipher = Cipher(algorithms.AES(key),modes.ECB())

        encryptor = cipher.encryptor()

        for x in range(0,int(len(plaintext)/len(key))):
            cipher_text.extend(encryptor.update(plaintext[x*len(key):(x+1)*len(key)]))

        return cipher_text


    @staticmethod
    def AES_ECB_decrypt(cipher_text,key):   # The python crypto packages require an encryption mode to be specified. So, we're going to specify ECB and then use it block by block.
                                            # Not ideal, but it has the same effect as if I had just the AES primitive. AES in ECB mode on one block is just the AES primitive really.

        cipher = Cipher(algorithms.AES(key),modes.ECB())

        decryptor = cipher.decryptor()

        plaintext = bytearray(0)

        for x in range(0,int(len(cipher_text)/len(key))):
            plaintext.extend(decryptor.update(bytearray(cipher_text[x*len(key):(x+1)*len(key)])))

        return plaintext


    @staticmethod
    def detect_ECB_mode(cipher_texts, key_len):  #Idea: break cipher texts into blocks, check for collisions.
                                                #Highest incidence number will be the ECB encoded text.

                                                #Assumptions: that the plaintext contains repeated fragments of text.


        line_num = 0
        max_coincidences = 0

        for line in range(0,len(cipher_texts)):
            line_blocks = block_decompse(cipher_texts[line], key_len)

            temp_coincidences = 0

            for block1 in range(0,len(line_blocks)):
                for block2 in range(block1,len(line_blocks)):
                    if (line_blocks[block1] == line_blocks[block2]):
                        temp_coincidences +=1

            if (temp_coincidences > max_coincidences):
                max_coincidences = temp_coincidences
                line_num = line

        return [line_num,cipher_texts[line_num]]







def block_decompse(iarray, block_len):
    blocks = []

    for x in range(0, int(len(iarray)/block_len)):
        blocks.append(iarray[x*block_len:(x+1)*block_len])

    return blocks

