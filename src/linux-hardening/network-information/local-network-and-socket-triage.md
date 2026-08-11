# Local Network 및 Socket Triage

{{#include ../../banners/hacktricks-training.md}}

Linux 호스트에서 shell을 획득한 후에는 가장 유용한 network target이 외부에 노출되지 않은 경우가 많습니다. loopback 전용 서비스, veth network, Unix socket, 임시 listener, packet capture 및 로컬 firewall rule은 credential이나 로컬 전용 attack surface를 노출할 수 있습니다.

이 페이지에서는 일반적인 원격 network pentesting이 아닌, 실용적인 로컬 post-exploitation 기법을 다룹니다.

## Loopback 및 로컬 Service Enumeration

먼저 listening service, 해당 bind address 및 권한이 허용되는 경우 이를 소유한 process를 식별합니다.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
주요 패턴:

- `127.0.0.1:<port>` 또는 `[::1]:<port>`: 기본적으로 호스트에서만 접근 가능.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: 필터링되지 않는 한 모든 IPv4 인터페이스에서 접근 가능.<sup>[[3]](#references)</sup>
- `veth*`, `docker*`, `br-*`, `cni*`의 `10.0.0.0/8`, `172.16.0.0/12` 또는 `192.168.0.0/16`: 컨테이너 또는 로컬 lab 네트워크일 가능성이 높음.<sup>[[23]](#references)[[24]](#references)</sup>
- `/run`, `/var/run`, `/tmp` 또는 애플리케이션 디렉터리 아래의 Unix 소켓: 로컬 IPC surface.<sup>[[5]](#references)</sup>

가벼운 probe로 로컬 포트를 매핑.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
사용 가능한 경우 로컬에서 `nmap`을 사용합니다.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## 숨겨진 veth 및 컨테이너 서브넷

컨테이너화된 환경이나 lab 환경에서는 bridge 또는 veth 서브넷에만 서비스가 노출되는 경우가 많습니다. 서비스에 연결할 수 없다고 단정하기 전에 인터페이스와 라우트를 열거하세요.<sup>[[2]](#references)</sup>
```bash
ip -br addr
ip route
ip neigh
```
가능성 높은 로컬 서브넷 찾기.<sup>[[2]](#references)</sup>
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
발견된 서브넷을 신중하게 프로브합니다.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
이 technique은 web panel, debug endpoint 또는 helper service가 external scan에서는 숨겨져 있지만 compromised host 또는 container network에서 접근 가능한 경우에 유용합니다.

## socat 또는 SSH를 사용한 Local Pivot

서비스가 loopback에 바인딩된 경우, 서비스 자체를 변경하는 대신 허용된 채널을 통해 노출합니다.

SSH를 사용하여 local-only HTTP 서비스를 forward합니다.<sup>[[11]](#references)</sup>
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
이미 shell access를 확보한 경우 `socat`으로 로컬 포트를 브리지합니다.<sup>[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
로컬 테스트를 위해 Unix socket을 TCP로 포워딩합니다.<sup>[[5]](#references)[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
이 자체로는 아무것도 exploit하지 않습니다. 로컬에서만 접근 가능한 surface를 tooling에서 접근할 수 있도록 만들어 일반적인 service처럼 상호작용할 수 있게 합니다.

## Banner Grabbing 및 Simple Protocols

모든 service가 HTTP인 것은 아닙니다. 많은 로컬 service는 banner 또는 한 줄짜리 protocol을 통해 충분한 정보를 leak합니다.

기본 probe입니다.<sup>[[13]](#references)</sup>
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
브라우저 없이 HTTP 점검.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
TLS의 경우.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
목표는 프로토콜, 인증 방식, 버전 및 서비스가 로컬 클라이언트를 신뢰하는지 여부를 식별하는 것입니다.

## Loopback 트래픽 캡처

로컬 트래픽에는 헤더, bearer 토큰, Basic Auth 자격 증명 또는 애플리케이션별 비밀 정보가 노출될 수 있습니다.<sup>[[17]](#references)[[25]](#references)</sup> 인증된 환경에서만 캡처하십시오.

Loopback HTTP 트래픽을 캡처합니다.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
특정 로컬 서비스를 캡처합니다.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
캡처되었거나 로그에 기록된 헤더에서 Basic Auth를 디코딩합니다.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
텍스트 캡처에서 찾아볼 유용한 문자열:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS 키 로깅

실험실에서 client process environment를 제어할 수 있다면, `SSLKEYLOGFILE`을 사용하여 Wireshark 또는 호환 tooling에서 TLS sessions를 decrypt할 수 있습니다.<sup>[[19]](#references)[[20]](#references)</sup> 이는 TLS 자체를 공격하지 않고 local HTTPS traffic을 이해하는 데 유용합니다.

key logging을 활성화한 상태로 client를 실행합니다.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
동시에 트래픽을 캡처합니다.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
그런 다음 `/tmp/tls.pcap` 및 `/tmp/sslkeys.log`을 Wireshark에 로드합니다. 이 방법은 client library가 NSS-style key logging을 지원하고 connection이 이루어지기 전에 environment를 설정할 수 있을 때만 작동합니다.<sup>[[20]](#references)[[21]](#references)</sup>

## Unix Socket Interaction 및 Command Injection

Unix sockets는 local IPC endpoints입니다.<sup>[[5]](#references)</sup> HTTP APIs, custom protocols 또는 안전하지 않은 command handlers를 노출할 수 있습니다.<sup>[[12]](#references)[[14]](#references)</sup>

sockets를 찾습니다.<sup>[[1]](#references)[[5]](#references)</sup>
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Unix 소켓을 통해 HTTP와 상호작용합니다.<sup>[[14]](#references)</sup>
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
raw socket과 상호작용합니다.<sup>[[12]](#references)[[13]](#references)</sup>
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
사용자가 제어하는 socket input이 shell 또는 privileged helper로 전달되면 command injection으로 이어질 수 있습니다.<sup>[[26]](#references)</sup> 집중적인 예시는 [Socket Command Injection](socket-command-injection.md)을 참조하세요.

## nftables 검토 및 승인된 규칙 변경

로컬 firewall 규칙은 서비스가 로컬에서는 표시되지만 원격에서는 차단되는 이유 또는 높은 port가 특정 interface에서 연결할 수 없는 이유를 설명할 수 있습니다.<sup>[[22]](#references)</sup>

규칙을 검토하세요.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
대상 포트에 영향을 미치는 drop을 확인합니다.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
승인된 실험실에서 handle을 사용해 특정 차단 규칙을 제거합니다.<sup>[[22]](#references)</sup>
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
전체 테이블을 flush하기보다 정확한 handle을 삭제하는 것이 좋습니다. 이 기법은 해당 동작을 유발하는 정확한 filter를 식별하고 해당 rule만 변경하는 것입니다.<sup>[[22]](#references)</sup>

## 빠른 Workflow
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
local-only이거나, 더 높은 권한의 사용자로 실행되거나, admin/debug 기능을 노출하거나, loopback/container-network 클라이언트를 신뢰하는 서비스의 우선순위를 높이세요.

## References

- [1] [ss(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: IP Version 6 주소 지정 아키텍처](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Redirections (Bash Reference Manual)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout invocation (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Port Scanning Techniques (Nmap Reference Guide)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Host Discovery (Nmap Reference Guide)](https://nmap.org/book/man-host-discovery.html)
- [10] [Port Specification and Scan Order (Nmap Reference Guide)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Linux 매뉴얼 페이지](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD 매뉴얼 페이지](https://man.openbsd.org/nc.1)
- [14] [curl command line tool manual](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL Documentation](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: 'Basic' HTTP Authentication Scheme](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64 invocation (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL Documentation](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark User’s Guide](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables manual](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Address Allocation for Private Internets (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [The OAuth 2.0 Authorization Framework: Bearer Token Usage (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: OS 명령에서 사용되는 특수 요소의 부적절한 무력화](https://cwe.mitre.org/data/definitions/78.html)
{{#include ../../banners/hacktricks-training.md}}
