# Cryptocode
[![Downloads](https://static.pepy.tech/badge/cryptocode)](https://pepy.tech/project/cryptocode)
Python library used to encrypt and decrypt strings in the simplest possible way, while also being incredibly secure.
## Requirements


- **Python** 3 or later.
  
## Installation

Install some Python utilities along with some libraries and other stuff:

~~~
python -m pip install cryptocode
~~~

## Basic usage
Encrypting a message:

~~~
>>> import cryptocode
>>> myEncryptedMessage = cryptocode.encrypt("I like trains", "password123")
>>> print(myEncryptedMessage)
M+Wykmlub0z7FhEdmA==*PvAbXRNx0SiSDHHxLsKZ5w==*ihQM/fdkgrX3G+yOItyAUQ==*QFNDmuUP1ysgo01/P2MNpg==
~~~

The first parameter is the string you want to encrypt. The second parameter is the password, which will be used for decrypting the string.

Decrypting a message"
~~~
>>> import cryptocode
>>> myDecryptedMessage = cryptocode.decrypt("M+Wykmlub0z7FhEdmA==*PvAbXRNx0SiSDHHxLsKZ5w==*ihQM/fdkgrX3G+yOItyAUQ==*QFNDmuUP1ysgo01/P2MNpg==", "password123")
>>> print(myDecryptedMessage)
I like trains
~~~
The first parameter is the encrypted string and the second parameter is the password. If the password is incorrect, decrypt function will return `False`.

## Example
Here, we will be creating a simple "trial product key". This is useful if you have software that you would like people to use temporarily.
In this example, we will be letting the user use the product for 2 hours. The password we will be using is ``cryptocode is amazing``.

Code on the server side:
~~~
import cryptocode
import time
hours = 2
messageToEncrypt = str(time.time() + hours * 60 * 60)
## Hours * 60 * 60 is necessary because we need to turn the hours into seconds, since the timestamp is in seconds.
cryptocode.encrypt(messageToEncrypt, "cryptocode is amazing")
~~~

Code on the client side:
~~~
import cryptocode
import time
import sys
#Function to verify that the key is valid:
def check_valid(key):
    message = cryptocode.decrypt(key, 'cryptocode is amazing')
    if message == False:
        #The key is incorrect!
        return False
    if float(message) >= time.time():
        return True
    else:
        #The key has expired!
        return False
userKeyInput = input("Please enter your product key.")
keyChecked = check_valid(userKeyInput)
if keyChecked == True:
    print("You are good to go!")
if keyChecked == False:
    print("You have either entered an invalid key or your time has expired. Sorry!")
    sys.exit()
~~~
  
## Reasons for using this library

There are countless python libraries for encoding and decoding messages through various means. Why is this one better?

Cryptocode is meant for people who simply want an abstraction. This library is by far the easiest to use out of any cryptography library because there are only two functions, encode and decode.
This is an example of using AES-GCM encryption to provide encryption and integrity with a regular cryptography library:
~~~
import binascii, time
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

backend = default_backend()

def aes_gcm_encrypt(message: bytes, key: bytes) -> bytes:
    current_time = int(time.time()).to_bytes(8, 'big')
    algorithm = algorithms.AES(key)
    iv = secrets.token_bytes(algorithm.block_size // 8)
    cipher = Cipher(algorithm, modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(current_time)
    ciphertext = encryptor.update(message) + encryptor.finalize()        
    return b64e(current_time + iv + ciphertext + encryptor.tag)

def aes_gcm_decrypt(token: bytes, key: bytes, ttl=None) -> bytes:
    algorithm = algorithms.AES(key)
    try:
        data = b64d(token)
    except (TypeError, binascii.Error):
        raise InvalidToken
    timestamp, iv, tag = data[:8], data[8:algorithm.block_size // 8 + 8], data[-16:]
    if ttl is not None:
        current_time = int(time.time())
        time_encrypted, = int.from_bytes(data[:8], 'big')
        if time_encrypted + ttl < current_time or current_time + 60 < time_encrypted:
            # too old or created well before our current time + 1 h to account for clock skew
            raise InvalidToken
    cipher = Cipher(algorithm, modes.GCM(iv, tag), backend=backend)
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(timestamp)
    ciphertext = data[8 + len(iv):-16]
    return decryptor.update(ciphertext) + decryptor.finalize()
~~~

As you can see, this can be unnecessary if you only need the encoding for basic reasons. In summary, cryptocode is better for most people because it is an abstraction: it provides a simple input and output without the user needing to know how it works.
