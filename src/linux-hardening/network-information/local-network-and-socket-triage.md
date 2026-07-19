# Local Network 및 Socket Triage

{{#include ../../banners/hacktricks-training.md}}

Linux 호스트에서 shell을 획득한 후에는 외부에 노출되지 않은 네트워크 대상이 가장 유용한 경우가 많습니다. Loopback 전용 서비스, veth 네트워크, Unix socket, 임시 listener, packet capture 및 로컬 firewall 규칙을 통해 credential 또는 로컬 전용 attack surface가 노출될 수 있습니다.

이 페이지는 일반적인 원격 네트워크 pentesting이 아닌, 실무적인 로컬 post-exploitation 기법에 초점을 맞춥니다.

## Loopback 및 로컬 서비스 열거

먼저 listening service, 해당 bind address 및 권한이 허용되는 경우 이를 소유한 process를 식별합니다:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
중요한 패턴:

- `127.0.0.1:<port>` 또는 `[::1]:<port>`: 기본적으로 호스트에서만 접근할 수 있습니다.
- `0.0.0.0:<port>`: 필터링되지 않는 한 모든 IPv4 인터페이스에서 접근할 수 있습니다.
- `veth*`, `docker*`, `br-*`, `cni*`의 `172.x`, `10.x` 또는 `192.168.x`: 컨테이너 또는 로컬 lab 네트워크일 가능성이 높습니다.
- `/run`, `/var/run`, `/tmp` 또는 애플리케이션 디렉터리 아래의 Unix 소켓: 로컬 IPC 표면입니다.

경량 probe로 로컬 포트를 매핑합니다:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
사용 가능한 경우 로컬에서 `nmap`을 사용합니다:
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## 숨겨진 veth 및 Container 서브넷

Containerized 또는 lab 환경에서는 bridge 또는 veth 서브넷에서만 service를 노출하는 경우가 많습니다. service에 연결할 수 없다고 단정하기 전에 interface와 route를 열거하세요:
```bash
ip -br addr
ip route
ip neigh
```
가능성이 높은 로컬 서브넷 찾기:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
발견된 서브넷을 신중하게 프로브하세요:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
이 기법은 web panel, debug endpoint 또는 helper service가 외부 스캔에서는 숨겨져 있지만 compromised host 또는 container network에서 접근 가능한 경우에 유용합니다.

## socat 또는 SSH를 사용한 로컬 Pivot

서비스가 loopback에 바인딩되어 있다면 서비스 자체를 변경하는 대신 허용된 채널을 통해 노출합니다.

SSH를 사용하여 로컬 전용 HTTP 서비스를 Forward합니다:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
이미 shell access가 있는 경우 `socat`으로 local port를 bridge하기:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
로컬 테스트를 위해 Unix 소켓을 TCP로 포워딩:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
이 자체로는 아무것도 exploit하지 않습니다. local-only surface를 tooling에서 접근할 수 있게 만들어 일반적인 service처럼 상호작용할 수 있도록 합니다.

## Banner Grabbing 및 Simple Protocols

모든 service가 HTTP인 것은 아닙니다. 많은 local service는 banner 또는 한 줄짜리 protocol을 통해 충분한 정보를 leak합니다.

기본 probe:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
브라우저 없이 HTTP 확인:
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
TLS의 경우:
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
목표는 프로토콜, 인증 체계, 버전 및 서비스가 로컬 클라이언트를 신뢰하는지 여부를 식별하는 것입니다.

## 루프백 트래픽 캡처

로컬 트래픽에는 헤더, bearer token, Basic Auth 자격 증명 또는 애플리케이션별 secret이 노출될 수 있습니다. 권한이 부여된 환경에서만 캡처하세요.

루프백 HTTP 트래픽 캡처:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
특정 로컬 서비스 캡처:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
캡처되었거나 로그에 기록된 헤더에서 Basic Auth 디코딩:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
텍스트 캡처에서 찾아볼 유용한 문자열:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS 키 로깅

lab에서 client process environment를 제어할 수 있다면, `SSLKEYLOGFILE`을 사용하여 Wireshark 또는 호환 tooling에서 TLS sessions를 decrypt할 수 있습니다. 이는 TLS 자체를 공격하지 않고 local HTTPS traffic을 이해하는 데 유용합니다.

key logging을 활성화한 상태로 client를 실행합니다:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
동시에 트래픽을 캡처하세요:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
그런 다음 `/tmp/tls.pcap`과 `/tmp/sslkeys.log`를 Wireshark에 로드합니다. 이 방법은 클라이언트 라이브러리가 NSS-style key logging을 지원하고 연결이 이루어지기 전에 환경을 설정할 수 있을 때만 작동합니다.

## Unix Socket 상호작용 및 Command Injection

Unix sockets는 로컬 IPC 엔드포인트입니다. HTTP API, custom protocol 또는 안전하지 않은 command handler를 노출할 수 있습니다.

소켓 찾기:
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Unix socket을 통해 HTTP와 상호작용하기:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
raw socket과 상호작용:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
사용자가 제어하는 socket 입력이 shell 또는 권한 있는 helper에 전달되면 command injection으로 이어질 수 있습니다. 구체적인 예시는 [Socket Command Injection](socket-command-injection.md)을 참조하세요.

## nftables 검토 및 권한이 부여된 규칙 변경

Local firewall 규칙은 서비스가 로컬에서는 표시되지만 원격에서는 차단되는 이유 또는 높은 포트가 한 인터페이스에서 연결할 수 없는 이유를 설명할 수 있습니다.

규칙 검토:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
대상 포트에 영향을 미치는 drop을 찾습니다:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
허가된 실습 환경에서 handle을 사용해 특정 차단 규칙을 제거합니다:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
정확한 handle을 삭제하는 것을 전체 테이블을 flush하는 것보다 우선합니다. 이 기법은 해당 동작을 유발하는 정확한 filter를 식별하고 해당 rule만 변경하는 것입니다.

## 빠른 워크플로우
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
로컬 전용이거나, 더 높은 권한의 사용자로 실행되거나, 관리자/디버그 기능을 노출하거나, 루프백/컨테이너 네트워크 클라이언트를 신뢰하는 서비스를 우선적으로 확인합니다.
{{#include ../../banners/hacktricks-training.md}}
