def pkcd7_padding(text,block_size):  #Takes a bytearray to pad.

    padded_text = text

    if (len(text)% block_size == 0):
        padded_text.extend([block_size for x in range(0,block_size)])
    else:
        missing_bytes = block_size - len(text)% block_size
        padded_text.extend([missing_bytes for x in range(0,missing_bytes)])

    return padded_text
    
