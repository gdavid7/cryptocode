# cryptocode

Python library used to encrypt and decrypt strings in the simplest possible way, while also being incredibly secure.
## Requirements


- **Python** 3 or later.
  
## Installation

Install some Python utilities along with some libraries and other stuff:

~~~
pip install cryptocode
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
  