import vigenere
import XOR_tools
import text_conversion
import set1

def hamming_test(str1,str2):
    return vigenere.hamming_distance(text_conversion.string_to_intarray(str1),text_conversion.string_to_intarray(str2))

def vigenere_test(key,plaintext):

    cipher_text = XOR_tools.repeating_XOR(text_conversion.string_to_intarray(key),text_conversion.string_to_intarray(plaintext))

    vigenere.break_repeating_key_XOR(cipher_text)