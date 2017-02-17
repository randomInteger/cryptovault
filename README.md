cryptovault.py - A very basic tool that encrypts and decrypts text via AES-CBC
using 32 byte (256bit) keys.

Please view this file in a text editor, tool output may not format well when viewed in the browser/github.

Installation steps:    
virtualenv -p /usr/bin/python3 ./.env    
source ./env/bin/activate    
pip install -r ./requirements.text    

Run this once per shell session to prep the environment:    
source ./env/bin/activate

Deactivate the environment when you are done by closing the shell or running:    
deactivate

Usage:

Usage: cryptovault.py [-h] -k <encryption key of 32 bytes> [-m <message> | -c <ciphertext>    
Usage: Encrypt mode - Supply a 32 byte key (256bits) and a message of any length    
Usage: Decrypt mode - Supply a 32 byte key (256bits) and a ciphertext from the output of Encrypt Mode.


Examples:

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
(.env)cgleeson@autotron:~/src/crypto$ ./cryptovault.py -k 'FMcFGpP@A2ygsf#B6oYuTaNuG(4edE8)' -c     'B/XVAmmcwXOEQ48pFac69Emk97gHQLNicq15YQc5PfEEqTOhF8i938/tGSVudHCu'    

**********PyCrypto Vault Start**********    

Mode:  Decryption    
Ciphertext is: B/XVAmmcwXOEQ48pFac69Emk97gHQLNicq15YQc5PfEEqTOhF8i938/tGSVudHCu    
Ciphertext successfully decoded with AES-CBC.    
Ciphertext init vector (raw): b'\x07\xf5\xd5\x02i\x9c\xc1s\x84C\x8f)\x15\xa7:\xf4'    
Decrypted message (end-padded with empty space): This is a secret demo message    

**********PyCrypto Vault FINISHED**********
