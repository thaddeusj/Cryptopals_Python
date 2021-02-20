import padding
import modes

def challenge9(text,block_size): #Text here is a string

    text_bytes = bytearray(text, 'utf-8')

    padded_text_bytes = padding.pkcd7_padding(text_bytes,block_size)

    print(str(padded_text_bytes))