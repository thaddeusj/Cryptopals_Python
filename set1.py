import text_conversion
import encrypt_XOR
import break_XOR
import cryptography
import ECB

def challenge1():
    print(text_conversion.intarray_to_base64string(text_conversion.hexstring_to_intarray("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")))

def challenge4():
    break_XOR.detect_single_XOR("4.txt")

def challenge5(key,text):
    key_bytes = text_conversion.string_to_intarray(key)
    text_bytes = text_conversion.string_to_intarray(text)

    cipher_text = encrypt_XOR.repeating_XOR(key_bytes,text_bytes)

    return (text_conversion.intarray_to_hexstring(cipher_text))


def challenge6(file_string):

    b64string = ""

    with open(file_string) as file:
        lines = file.read().splitlines()

        for x in range(0,len(lines)):
            b64string += lines[x]

    cipher_text = text_conversion.base64string_to_intarray(b64string)

    #print(text_conversion.intarray_to_hexstring(cipher_text))

    #print(cipher_text)

    break_XOR.break_repeating_key_XOR(cipher_text)

def challenge7(file_string):

    b64string = ""

    with open(file_string) as file:
        lines = file.read().splitlines()

        for x in range(0,len(lines)):
            b64string += lines[x]

    cipher_text = text_conversion.base64string_to_intarray(b64string)

    return ECB.AES_ECB_decrypt(cipher_text,b"YELLOW SUBMARINE")

def challenge8(file_string):

    cipher_texts = []

    with open(file_string) as file:
        lines = file.read().splitlines()

        for line in lines:
            cipher_texts.append(text_conversion.hexstring_to_intarray(line))
    
    detected_line = ECB.detect_ECB_mode(cipher_texts,16)

    print("The ECB encoded string is string " + str(detected_line[0]) + " out of " + str(len(lines)) + ".")
    print("The detected line was " + str(text_conversion.intarray_to_hexstring(detected_line[1])) + ".")
    


