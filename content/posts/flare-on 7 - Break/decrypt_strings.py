from malduck import unhex, aes
from idaapi import *

def decrypt_odd(s):
    dec = []
    for i in range(0, len(s)-1, 2):
        dec.append(((0x10 * (s[i] - 1)) | (s[i+1]- 1) & 0xf) & 0xff)
    return ''.join([chr(c) for c in dec])

def decrypt_even(b):
    key = b[:16]
    size = int.from_bytes(b[16:20], 'little')
    data = b[20:]
    return aes.ecb.decrypt(key, data[:size])

array_ptr = get_name_ea(0, "string_array") # 0x081A5140
string_ptr = ida_bytes.get_32bit(array_ptr)
even = True

while string_ptr:
    try:
        enc = ida_bytes.get_bytes(string_ptr, ida_bytes.get_32bit(array_ptr + 4) - string_ptr)
        if even:
            dec = decrypt_even(enc)
            even = False
        else:
            dec = decrypt_odd(enc[:-1])
            even = True

        print(f"0x{string_ptr:x}: {dec}")
    except:
        pass
    array_ptr += 4
    string_ptr = ida_bytes.get_32bit(array_ptr)