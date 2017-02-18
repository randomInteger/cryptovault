#!/usr/bin/env python3
"""
cryptovault.py - A very basic tool that encrypts and decrypts text via AES-CBC
using 32 byte (256bit) keys.

Example - Encrypting a message:
(.env)cgleeson@autotron:~/src/crypto$ ./cryptovault.py -k 'FMcFGpP@A2ygsf#B6oYuTaNuG(4edE8)' -m 'This is a secret demo message'

**********PyCrypto Vault Start**********
Mode:  Encryption
Message is: This is a secret demo message
Message successfully encoded with AES-CBC.
Ciphertext init vector (raw): b'\x07\xf5\xd5\x02i\x9c\xc1s\x84C\x8f)\x15\xa7:\xf4'
Ciphertext (base64): B/XVAmmcwXOEQ48pFac69Emk97gHQLNicq15YQc5PfEEqTOhF8i938/tGSVudHCu

**********PyCrypto Vault FINISHED**********

Example - Decrypting the same message:
(.env)cgleeson@autotron:~/src/crypto$ ./cryptovault.py -k 'FMcFGpP@A2ygsf#B6oYuTaNuG(4edE8)' -c 'B/XVAmmcwXOEQ48pFac69Emk97gHQLNicq15YQc5PfEEqTOhF8i938/tGSVudHCu'

**********PyCrypto Vault Start**********
Mode:  Decryption
Ciphertext is: B/XVAmmcwXOEQ48pFac69Emk97gHQLNicq15YQc5PfEEqTOhF8i938/tGSVudHCu
Ciphertext successfully decoded with AES-CBC.
Ciphertext init vector (raw): b'\x07\xf5\xd5\x02i\x9c\xc1s\x84C\x8f)\x15\xa7:\xf4'
Decrypted message (end-padded with empty space): This is a secret demo message

**********PyCrypto Vault FINISHED**********

Alternately, you can supply the key in a file if you prefer:

(.env)cgleeson@autotron:~/src/crypto$ cat key.json
{ "32_byte_key": "FMcFGpP@A2ygsf#B6oYuTaNuG(4edE8)" }

(.env)cgleeson@autotron:~/src/crypto$ ./cryptovault.py -k ./key.json -m 'A CLOAKED NETWORK IS A SECURE NETWORK'



Authors:  Chris Gleeson.
"""
import os
import sys
import math
import json
import base64
import datetime
import getopt
from Crypto import Random
from Crypto.Cipher import AES


def usage():
    """
    Prints usage for nmapper.py
    """
    print('Usage: cryptovault.py [-h] -k <encryption key of 32 bytes> [-m <message> | -c <ciphertext>]')
    print('Usage: Encrypt mode - Supply a 32 byte key (256bits) and a message of any length')
    print('Usage: Decrypt mode - Supply a 32 byte key (256bits) and a ciphertext from the output of Encrypt Mode.')


def parse_args():
    """
    Parses input arguments and returns them to main.

    Exits on any raised exception or if any required arguments are missing.
    """
    key = ''
    message = ''
    ciphertext = ''

    #Attempt to parse args
    try:
        opts, args = getopt.getopt(sys.argv[1:],"hk:m:c:",["help","key=","message=","ciphertext="])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    #Populate local variables from args
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-k", "--key"):
            key = arg
        elif opt in ("-m", "--message"):
            message = arg
        elif opt in ("-c", "--ciphertext"):
            ciphertext = arg
    return (key, message, ciphertext)


def create_config_object(filepath):
    """
    Takes a string that holds a file path and attempts to read the file and
    parse the file as JSON.

    Returns:  Parsed json object via json.loads()

    Rasies:  IOError if the file cannot be read, TypeError on bad Type,
    ValueError on failed parsing.
    """
    try:
        json_raw = open(filepath).read()
        json_object = json.loads(json_raw)
    except IOError as err:
        print("Error:  Failed to open file %s!  Exiting..." % filepath)
        raise
    except TypeError as err:
        print("Error: Parsing of file %s failed!  Exiting..." % filepath)
        raise
    except ValueError as err:
        print("Error: Parsing of file %s failed!  Exiting..." % filepath)
        raise
    return json_object


def key_in_file(key):
    #If key is a filepath we can read, lets grab it and return it
    if os.access(key, os.R_OK):
        key_json = create_config_object(key)
        real_key = key_json["32_byte_key"]
        return real_key
    else:
        return key


def test_key(key):
    if len(key) != 32:
        print("ERROR:  The key supplied was not 32 bytes!.")
        print("ERROR:  Supplied key has length of:", len(key))
        print("ERROR:  Key was:", key)
        sys.exit(2)


def encode(key,initv,message,algo):
    print("Message is:", message)


    #If no init vector was supplied, we will create one
    if initv == '':
        initv = Random.new().read(AES.block_size)

    try:
        aes = AES.new(key, algo, initv)
    except ValueError as e:
        print("Exception caught trying to do 'AES.new(key, algo, initv)'!")
        raise e

    #The input message must be a mulitple of 16 bytes for AES
    #We will only accept a 32 byte key, so a mulitple of 32 is used here.
    block_size = AES.block_size
    multiplier = math.ceil(len(message) / block_size)
    length = block_size * multiplier
    message_padded = message.ljust(length)

    try:
        ciphertext = aes.encrypt(message_padded)
        ciphertext = base64.b64encode(initv + ciphertext)
    except ValueError as e:
        print("Exception caught trying to do 'aes.encrypt(message)'!")
        raise e

    print("Message successfully encoded with AES-CBC.")
    print("Ciphertext init vector (raw):", initv)
    ciphertext = str(ciphertext, "UTF-8")
    print("Ciphertext (base64):", ciphertext)

def decode(key,initv,ciphertext,algo):
    print("Ciphertext is:", ciphertext)

    #Decode from base64
    ciphertext = base64.b64decode(ciphertext)
    #Slice the init vector from the ciphertext
    initv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]

    try:
        aes = AES.new(key, algo, initv)
    except ValueError as e:
        print("Exception caught trying to do 'AES.new(key, algo, initv)'!")
        raise e

    try:
        message = aes.decrypt(ciphertext)
    except ValueError as e:
        print("Exception caught trying to do 'aes.encrypt(message)'!")
        raise e

    print("Ciphertext successfully decoded with AES-CBC.")
    print("Ciphertext init vector (raw):", initv)
    message = str(message, "UTF-8")
    print("Decrypted message (end-padded with empty space):", message)

def main():
    #Parse args
    (key, message, ciphertext) = parse_args()

    #Check if the key was given via a file or directly as input.
    key = key_in_file(key)

    #Validate the key length before we begin
    test_key(key)

    #Run begins
    print("\n**********PyCrypto Vault Start**********")

    #Pass in an empty init vector, we will create a random one anyway.
    #This is to potentially support a user supplied init vector in the future.
    initv = ''

    #Set CBC as the default mode, we could enable other modes like CBF later.
    algo = AES.MODE_CBC

    if ciphertext == '':
        print("Mode:  Encryption")
        encode(key, initv, message, algo)
    elif message == '':
        print("Mode:  Decryption")
        decoded = decode(key, initv, ciphertext, algo)

    #Run is complete
    print("\n**********PyCrypto Vault FINISHED**********")

if __name__ == "__main__":
    main()
