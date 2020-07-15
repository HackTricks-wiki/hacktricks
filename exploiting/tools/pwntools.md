# PwnTools

```text
pip3 install pwntools
```

## Pwn asm 

Get opcodes from line or file. 

```text
pwn asm "jmp esp" 
pwn asm -i <filepath>
```

**Can select:** 

* output type \(raw,hex,string,elf\)
* output file context \(16,32,64,linux,windows...\)
* avoid bytes \(new lines, null, a list\) 
* select encoder debug shellcode using gdb run the output

##   **Pwn checksec**

Checksec script 

```text
pwn checksec <executable>
```

## Pwn constgrep

## Pwn cyclic 

Get a pattern

```text
pwn cyclic 3000
pwn cyclic -l faad
```

**Can select:**    

* The used alphabet \(lowercase chars by default\)
* Length of uniq pattern \(default 4\)
* context \(16,32,64,linux,windows...\)
* Take the offset \(-l\)

## Pwn debug

Attach GDB to a process

```text
pwn debug --exec /bin/bash
pwn debug --pid 1234
pwn debug --process bash
```

**Can select:** 

* By executable, by name or by pid context \(16,32,64,linux,windows...\) 
* gdbscript to execute 
* sysrootpath

## Pwn disablenx 

Disable nx of a binary  

```text
pwn disablenx <filepath>
```

## Pwn disasm 

Disas hex opcodes

```text
pwn disasm ffe4
```

**Can select:** 

* context \(16,32,64,linux,windows...\) 
* base addres 
* color\(default\)/no color

## Pwn elfdiff 

Print differences between 2 fiels

```text
pwn elfdiff <file1> <file2>
```

## Pwn hex 

Get hexadecimal representation

```bash
pwn hex hola #Get hex of "hola" ascii
```

## Pwn phd 

Get hexdump 

```text
pwn phd <file>
```

 **Can select:** 

* Number of bytes to show 
* Number of bytes per line highlight byte 
* Skip bytes at beginning

## Pwn pwnstrip 

## Pwn scrable

## Pwn shellcraft 

Get shellcodes

```text
pwn shellcraft -l #List shellcodes 
pwn shellcraft -l amd #Shellcode with amd in the name
pwn shellcraft -f hex amd64.linux.sh #Create in C and run
pwn shellcraft -r amd64.linux.sh #Run to test. Get shell 
pwn shellcraft .r amd64.linux.bindsh 9095 #Bind SH to port
```

**Can select:**

* shellcode and arguments for the shellcode
* Out file
* output format
* debug \(attach dbg to shellcode\)
* before \(debug trap before code\) 
* after
* avoid using opcodes \(default: not null and new line\)
* Run the shellcode
* Color/no color
* list syscalls 
* list possible shellcodes 
* Generate ELF as a shared library

## Pwn template 

Get a python template 

```text
pwn template
```

**Can select:** host, port, user, pass, path and quiet

## Pwn unhex 

From hex to string 

```text
pwn unhex 686f6c61
```

## Pwn update 

To update pwntools

```text
pwn update
```

