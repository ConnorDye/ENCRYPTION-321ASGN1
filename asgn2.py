# 1.) Read file in
# 2.) Preserve the header of the file
# 3.) Pad the file
# 4.) Encrypt the file 
 


from ast import Constant
from lib2to3.pgen2.token import NEWLINE
from unittest import result
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto import Random
import os
import urllib
import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
import codecs

HEADER_SIZE = 54

def ECB():
    with open("mustang.bmp", "rb") as image:
        fileheader = image.read(54)
        filedata = image.read()
        # b = bytearray(f)
        
    #STEP 1.) AFTER PRESERVING HEADER, PAD THE FILE DATA   
    padded_file = pad(filedata)

    #STEP 2.) ENCRYPT filedata
    # encrypted_output = cipher.encrypt(padded_file)
    encrypted_output =  encrypt_EBC(padded_file)
    

    #STEP 3.) FIRST WRITE THE HEADER TO THE NEW FILE
    with open("encrypted_ECB.bmp","wb") as encrypted_file:
        encrypted_file.write(fileheader)
        encrypted_file.write(encrypted_output)
        
def encrypt_EBC(padded_file):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    index1 = 0
    index2 = 16
    counter = len(padded_file) / 16
    output = bytes()
    while(counter >= 0):
        block = padded_file[index1:index2]
        # print(block)
        index1 = index1 + 16
        index2 = index2 + 16
        counter = counter - 1
        # output = cipher.encrypt(output) + block CBC + WE NEED IV
        output = output + cipher.encrypt(block)
    # output = cipher.encrypt(padded_file)
    # print(output)
    return output


def CBC():
    with open("mustang.bmp", "rb") as image:
        fileheader = image.read(54)
        filedata = image.read()
        # b = bytearray(f)
        
    #STEP 1.) AFTER PRESERVING HEADER, PAD THE FILE DATA   
    padded_file = pad(filedata)

    #STEP 2.) ENCRYPT filedata

    encrypted_output =  encrypt_CBC(padded_file)

    #STEP 3.) FIRST WRITE THE HEADER TO THE NEW FILE
    with open("encrypted_CBC.bmp","wb") as encrypted_file:
        encrypted_file.write(fileheader)
        encrypted_file.write(encrypted_output)

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

# def xor_blocks(ciphertext, plaintext):
#     xor_block = bytes()
#     counter = len(ciphertext)
#     while (counter > 0):
#         # print(type(ciphertext))
#         # print(type(plaintext))
#         xor_block = xor_block + byte_xor(ciphertext, plaintext)
#         counter = counter - 1


#     return xor_block
    

def encrypt_CBC(padded_file):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)
    index1 = 0
    index2 = 16
    counter = len(padded_file) / 16
    output = bytes()

    # ENCRYPT THE FIRST BLOCK WITH IV
    block = padded_file[index1:index2]
    first_block = cipher.encrypt(block)
    output = output + first_block
    index1 = index1 + 16
    index2 = index2 + 16
    counter = counter - 1

    # ENCRYPT REMAINING BLOCKS WITHOUT IV
    # we encrypt a block and XOR it with our plaintext
    # encrypted_cipher = bytes()
    while(counter > 0):
        block = padded_file[index1:index2]
        index1 = index1 + 16
        index2 = index2 + 16
        counter = counter - 1
        # output_to_encrypt = output + block WE NEED TO XOR HERE INSTEAD
        output_to_encrypt = byte_xor(output, block)
        output = output + cipher.encrypt(output_to_encrypt, None)
        # output = cipher.encrypt(output, None) + block

    return output
    


def pad(filedata):
    # each array slot is 8 bits
    # so 16 array slots is 128 bits
    # len(b) % 16 = how many slots to pad
    # print(type(filedata))
    bytesToPad = ( 16 - (os.path.getsize('mustang.bmp') - HEADER_SIZE) % 16 )
    # print(os.path.getsize('mustang.bmp'))
    counter = 0
    bytes = []
    while counter < bytesToPad:
        bytes.append(bytesToPad)
        counter = counter + 1
    byte_array = bytearray(bytes)
    padded_data = filedata + byte_array
    # print(len(padded_data))
    return padded_data

    # fileheader = fileheader + byte_array
    # print(fileheader)
    # print(byte_array)
    # print(type(filedata))

def pad_string(byte_string):
    bytesToPad = ( 16 - ( len(byte_string) % 16 ) )
    # print(os.path.getsize('mustang.bmp'))
    counter = 0
    bytes = []
    while counter < bytesToPad:
        bytes.append(bytesToPad)
        counter = counter + 1
    byte_array = bytearray(bytes)
    padded_data = byte_string + byte_array
    # print(len(padded_data))
    return padded_data

def task2():
    Constant.key = get_random_bytes(16)
    Constant.iv = os.urandom(16)
    # print(Constant.key)
    encrypted_string = submit(Constant.key, Constant.iv)
    result = verify(encrypted_string, Constant.key, Constant.iv)
    if result:
        print(" RESULT OF VERIFY() “;admin=true;” true")
    else:
        print(" RESULT OF VERIFY() “;admin=true;” not true")
    # cipher = AES.new(kkey, AES.MODE_ECB)

    result = byte_attack(encrypted_string, Constant.key, Constant.iv)
    if result:
        print(" RESULT OF BYTE FLIP ATTACK: “;admin=true;” true")
    else:
        print(" RESULT OF BYTE FLIP ATTACK: “;admin=true;” not true")

def submit(key, iv):
    
    #ENCODE URL:
    equal = "%3D"
    semicolon = "%3B"
    user_input = input('Enter a string: ')
    encoded_string = user_input.replace("=", equal)
    encoded_string = encoded_string.replace(";", semicolon )
    prepend_string = "userid=456; userdata="
    append_string = ";session-id=31337"
    new_string = prepend_string + encoded_string + append_string
    
    #PAD THE STRING:
    byte_string = bytes(new_string,  'utf-8')
    padded_data = pad_string(byte_string) 
    # print("Padded data", padded_data)

    #Encode the string:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    index1 = 0
    index2 = 16
    counter = len(padded_data) / 16
    output = bytes()

    # ENCRYPT THE FIRST BLOCK WITH IV
    block = padded_data[index1:index2]
    first_block = cipher.encrypt(block)
    output = output + first_block
    index1 = index1 + 16
    index2 = index2 + 16
    counter = counter - 1

    # ENCRYPT REMAINING BLOCKS WITHOUT IV
    while(counter > 0):
        block = padded_data[index1:index2]
        index1 = index1 + 16
        index2 = index2 + 16
        counter = counter - 1
        # output = cipher.encrypt(output, None) + block
        # output_to_encrypt = output + block
        # output = cipher.encrypt(output_to_encrypt, None)
        output_to_encrypt = byte_xor(output, block)
        output = output + cipher.encrypt(output_to_encrypt, None)
    
    print('BYTE CIPHERTEXT OF SUBMIT()', output)
    ct = b64encode(output).decode('utf-8')
    print(json.dumps({'JSON CIPHERTEXT OF SUBMIT()':ct}))
    # return output
    return new_string

def verify(ciphertext, key, iv):  
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # (1)  decrypt  the  string;  
    # equal = "%3D"
    # semicolon = "%3B"
    # user_input = input('Enter a string: ')
    # encoded_string = user_input.replace("=", equal)
    # encoded_string = encoded_string.replace(";", semicolon )
    # prepend_string = "userid=456; userdata="
    # append_string = ";session-id=31337"
    # new_string = prepend_string + encoded_string + append_string
    
    #PAD THE STRING:
    byte_string = bytes(ciphertext,  'utf-8')
    # padded_data = pad_string(byte_string) 
    padded_data = pad_string(byte_string)
    # ct_bytes = cipher.encrypt(padded_data)

    #encrypt
    ciphertext = cipher.encrypt(padded_data)
    print("Their encryption...we used their encrypt function for verify() to assure a correct decryption. We still implemented the UTF encoding:", ciphertext)

    # (1) DECRYPT AND UNPAD THE TEXT
    pt = my_decrypt(ciphertext, key, iv)
    pt = unpad(pt, AES.block_size)
    print(NEWLINE, "Resulting decryption...", pt)
    
    # pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
    parsed_string = str(pt, 'UTF-8')

    if ";admin=true;" in parsed_string:
        return True
    else:
        return False

    # (2) PARSE THE TEXT
    # pt.decode(pt, "utf-8")

def my_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ciphertext)
    return pt


def byte_attack(string_to_encrypt, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # 1.) break plaintext into blocks
    # 2.) what block the -admin-true- is in
    # 3.) what index -'s are in to flip
    # 4.) in previous block xoring occurs
    # 5.) when your xor something with itself is zeroes out and then when you xor something with zero it will become your target value
    
    #PAD THE STRING:
    byte_string = bytes(string_to_encrypt,  'utf-8') 
    padded_data = pad_string(byte_string)

    #split the plaintext to find what block -admin-true- is in
    total_blocks = len(padded_data) / 16
    split_blocks_array = split_into_blocks(padded_data, total_blocks)
    print("Plain text split into block", split_blocks_array)
    # print("With input: xxxxxxxxxxx-admin-true- our bytes to flip will be in the 3rd block of the ciphertext")


    #ENCRYPT USING THEIR FUNCTION FOR CORRECT ENCRYPTION ASSURANCE TO BYTE FLIP
    ciphertext = cipher.encrypt(padded_data)
    # print("BYTE ATTACK decryption...NEEDS TO FLIP ON BLOCK 3", ciphertext)
    split_blocks_array = split_into_blocks(ciphertext, total_blocks)
    
    cipher_array_bytes = bytearray(ciphertext)
    plain_array_bytes = bytearray(padded_data)
    # print(cipher_array_bytes[16])
    # print(chr(plain_array_bytes[16]), "correlates to ", chr(plain_array_bytes[32]) )
    # print(chr(plain_array_bytes[22]), "correlates to ", chr(plain_array_bytes[38]) )
    # print(chr(plain_array_bytes[27]), "correlates to ", chr(plain_array_bytes[43]) )
   
    # print("PADDED DATA", padded_data[16], chr(padded_data[16]))

    #FLIP THE BYTE OF THE BLOCK
    byte = ciphertext[16] ^ ord('-')
    byte = byte ^ ord(';')
    # print("XOR byte1 is...", byte)
    cipher_array_bytes[16] = byte
    
    byte = ciphertext[22] ^ ord('-')
    byte = byte ^ ord('=')
    # print("XOR byte2 is...", byte)
    cipher_array_bytes[22] = byte

    byte = ciphertext[27] ^ ord('-')
    byte = byte ^ ord(';')
    # print("XOR byte3 is...", byte)
    cipher_array_bytes[27] = byte
   

    # (1) DECRYPT AND UNPAD THE TEXT
    pt = my_decrypt(cipher_array_bytes, key, iv)
    pt = unpad(pt, AES.block_size)
    print(pt)
    
    substring = b';admin=true;'
    if substring in pt:
        print("True, ;admin=true; is in the string")
        return True
    else:
        print("False, ;admin=true; is not in the string")
        return False


def split_into_blocks(padded_data, num_blocks):
    split_blocks = []
    index1 = 0
    index2 = 16
    while num_blocks > 0:
        block = padded_data[index1:index2]
        index1 = index1 + 16
        index2 = index2 + 16
        num_blocks = num_blocks - 1
        split_blocks.append(block)
    return split_blocks



def main():
    # Task 1
    ECB()
    CBC()

    # TASK 2
    task2()



main()