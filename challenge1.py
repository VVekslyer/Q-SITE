import numpy as np
import base64

Alice_bases = "+XX+++++++++X+++X+XX++X+++++++XXX++++X+XXX+++X+XXXX+X++X++XXXX++++++X+X+++X+XX++X++++XX+++X+XXXX++XXX+XX+XX++XXX++XXX+X+X+XX+++X+++++++XXX++XXXX+XXXXXXXXX+X+X+X++X+X+++XX+X+XXXX++XX+XXXX++X++XXX+XXXXXX+++++XXX+XX++X+++++X+++XXX+XXX++++XXXXX++X+++XX++++XXX+++X+XX+XXX+X+XXX++XXX++XX++++XXX+X++XX+++XXXX+X+X++++XXX+XXXXX+XXX+X+XXX+XXXX+X+++XXX+X+++++++XX+X++++X++XXXX+++"

Bob_bases = "XX++++++XXXX+XX+XX+X++X++++++X+X++XX+++X+XX++++XXX+X++XXX+++XXX+++X+++XX+XXX+XX+++XX++++XXX++X+X+X++X++X+XX+++++XX+XXXX++XXXX+X+++X+XX+++X++XX+X+X+X++XX+++XXX+X+++++X++++X+XX+X+X+++XXXX++++XXX+XX+X+XXX+XXXXXXX+++XXXX+XX+X++XX+XXXX+X+XXXXX+X+XXX++X+X+++++XXXX++XXX+X+X+XX++X+X+XX++++XXXXXXX++XXXXX+XX+X++X+X++++X+XXX+X+XX+XXXXXXX+X++X++X+X+X+X++++X+X+++X++X+++++X+X++XX"

alice_bits = [1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0 , 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0]

encrypted_flag = base64.b64decode("UA/JtI3+ZGIHejABkuiel2757g==")

"""
Helper Functions!
"""

def stringify(arr):
    s = ""
    for x in arr:
        s += str(x)
    return s

def bit_array_to_bytes(bits):
    return bytearray([int("".join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8)])

def bytes_to_bit_array(bytes):
    return [int(bit) for bit in ''.join(format(byte, '08b') for byte in bytes)]

def pretty(x):
    #return base64.b64encode(bit_array_to_bytes(stringify(x)))
    return base64.b64encode(bit_array_to_bytes(x))

# xor_crypt -> takes in a key and a text, returns the xor of the two
# key and text must be the same length
# returns a list of the xor of the two
def xor_crypt(key, text):
    # Repeat the key if it's shorter than the text
    if len(text) > len(key):
        key = (key * (len(text) // len(key) + 1))[:len(text)]
    return [a^b for a,b in zip(key,text)]


# Convert bases and bits to arrays
Alice_bases = list(Alice_bases)
Bob_bases = list(Bob_bases)

# Find where Alice and Bob used the same basis
same_bases = [i for i in range(len(Alice_bases)) if Alice_bases[i] == Bob_bases[i]]

# Use these positions to create the key
key = [alice_bits[i] for i in same_bases]

# Decrypt the flag using the extended key
decrypted_flag = xor_crypt(key, bytes_to_bit_array(encrypted_flag))

# Convert decrypted flag from bits to bytes and then to string
decrypted_flag = bit_array_to_bytes(decrypted_flag).decode()

# Decrypted flag: flag{Q-Site Rul3z!}
print("Decrypted flag:", decrypted_flag)



