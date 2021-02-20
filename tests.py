import break_XOR
import encrypt_XOR
import text_conversion
import set1

def hamming_test(str1,str2):
    return break_XOR.hamming_distance(text_conversion.string_to_intarray(str1),text_conversion.string_to_intarray(str2))

def vigenere_test(key,plaintext):

    cipher_text = encrypt_XOR.repeating_XOR(text_conversion.string_to_intarray(key),text_conversion.string_to_intarray(plaintext))

    break_XOR.break_repeating_key_XOR(cipher_text)