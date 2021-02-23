def pkcs7_padding(text,block_size):  #Takes a bytearray to pad.

    padded_text = text

    if (len(text)% block_size == 0):
        padded_text.extend([block_size for x in range(0,block_size)])
    else:
        missing_bytes = block_size - len(text)% block_size
        padded_text.extend([missing_bytes for x in range(0,missing_bytes)])

    return padded_text

def pkcs7_unpad(text):
    pad_length = text[len(text)-1]

    pkcs7_validate(text)

    return text[0:len(text)-pad_length]

def pkcs7_validate(text):
    pad_length = text[len(text) - 1]

    pad = text[-int(pad_length):]

    for x in range(0, len(pad) - 1):
        if pad[x] != pad_length:
            raise Exception("Invalid padding!")

    return 1

    
