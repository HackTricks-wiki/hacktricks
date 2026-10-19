# 로컬 네트워크 및 소켓 점검

{{#include ../../banners/hacktricks-training.md}}

Linux 호스트에서 shell을 확보한 후에는 외부에 노출되지 않은 네트워크 대상이 가장 유용한 경우가 많습니다. Loopback 전용 서비스, veth 네트워크, Unix 소켓, 임시 listener, 패킷 캡처, 로컬 방화벽 규칙에서 자격 증명이나 로컬 전용 공격 표면을 찾을 수 있습니다.

이 페이지에서는 일반적인 원격 네트워크 pentesting이 아닌, 실용적인 로컬 post-exploitation 기법을 다룹니다.

## Loopback 및 로컬 서비스 열거

먼저 listening 서비스와 해당 서비스의 bind 주소를 식별하고, 권한이 허용되는 경우 이를 소유한 프로세스도 확인합니다.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

중요한 패턴:

- `127.0.0.1:<port>` 또는 `[::1]:<port>`: 기본적으로 호스트에서만 접근할 수 있습니다.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: 필터링되지 않는 한 모든 IPv4 인터페이스에서 접근할 수 있습니다.<sup>[[3]](#references)</sup>
- `veth*`, `docker*`, `br-*`, `cni*`에서 `10.0.0.0/8`, `172.16.0.0/12` 또는 `192.168.0.0/16`: 컨테이너 또는 로컬 랩 네트워크일 가능성이 높습니다.<sup>[[23]](#references)[[24]](#references)</sup>
- `/run`, `/var/run`, `/tmp` 또는 애플리케이션 디렉터리 아래의 Unix socket: 로컬 IPC 표면입니다.<sup>[[5]](#references)</sup>

과거의 [snapd socket 파싱 문제, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing)의 경우, 실행 중인 daemon과 로컬 API socket을 확인하고 설치된 패키지 또는 snap revision이 해당 배포판의 수정 사항을 포함하는지 점검하세요. 이 버그는 `snap-confine`이 아니라 snapd의 peer socket 주소 검증에 있었습니다. set-user-ID `snap-confine` 파일이나 upstream 버전 문자열만으로는 취약 여부를 판단할 수 없습니다. Ubuntu는 릴리스별 패키지 버전으로 수정 사항을 제공했으며, snapd는 배포판 패키지와 별개로 snap에서 업데이트되었을 수 있습니다. 권한이 높은 API 경계를 평가하기 전에 실제 실행 중인 빌드와 로컬 socket 접근 가능성을 확인하세요. 수동 열거 중에는 조작된 socket 요청을 보내거나 snap을 설치해서는 안 됩니다.

[`EXEC`을 사용하는 `socat`](https://man7.org/linux/man-pages/man1/socat.1.html)으로 시작한 loopback listener는 로컬 클라이언트 입력을 별도 프로그램으로 전달할 수 있습니다. root 소유의 사용자 지정 서비스를 권한 상승 단서로 간주하기 전에 listener의 명령, 실행 파일 경로, 자식 프로세스의 유효 사용자, 로컬 접근 가능성 및 인증을 함께 확인하세요. 메모리 안전성 결함이나 안전하지 않은 입력-명령 전달 경로를 입증하려면 해당 바이너리와 빌드에 관한 증거가 필요합니다. 포트 번호, `socat` 프로세스 또는 root 소유 여부만으로는 결함을 입증할 수 없습니다. 수동 열거는 서비스에 입력을 보내지 말고 프로세스, socket 및 파일 메타데이터를 확인하는 데 그쳐야 합니다.

로컬 Salt master는 loopback 또는 컨테이너가 호스트에 게시한 포트를 포함해 TCP 4505 및 4506에서 수신 대기할 수 있습니다. [Salt의 3000.2 릴리스 노트](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html)에는 인증 없이 메서드에 접근할 수 있는 결함인 CVE-2020-11651이 설명되어 있으며, upstream 2019.2.4 및 3000.2에서 수정되었습니다. 권한 상승 단서로 간주하기 전에 listener를 실제 `salt-master` 프로세스, 접근 가능한 인터페이스, 설치된 패키지와 vendor 패치, 그리고 유효한 컨테이너 또는 호스트 ID와 대조해 확인하세요. 포트나 upstream 버전만으로는 증거가 되지 않습니다. master가 컨테이너 내부에서 실행된다면 호스트 root에 미치는 영향은 별도의 경계 문제입니다. 사용할 수 있는 호스트 runtime API socket이 컨테이너에 마운트되어 있고 해당 컨테이너에서 접근 가능한지 확인하세요. 노출 여부를 판단하기 위해 Salt request server에 질의하거나 컨테이너를 생성해서는 안 됩니다. [Salt의 포트 문서](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) 및 [runtime API 분류](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md)를 참조하세요.

가벼운 probe로 로컬 포트를 매핑하세요.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
for p in 80 443 8000 8080 8081 9000 5000; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```

사용할 수 있다면 로컬에서 `nmap`을 사용하세요.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```

## 숨겨진 veth 및 컨테이너 서브넷

컨테이너 또는 실습 환경에서는 서비스가 bridge 또는 veth 서브넷에서만 노출되는 경우가 많습니다. 서비스에 접근할 수 없다고 단정하기 전에 인터페이스와 라우트를 열거하세요.<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

가능성이 높은 로컬 서브넷을 찾습니다.<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

발견된 서브넷을 신중하게 탐색하세요.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

이 기법은 웹 패널, debug endpoint 또는 helper service가 외부 스캔에는 보이지 않지만 침해된 호스트나 컨테이너 네트워크에서는 접근 가능한 경우 유용합니다.

## 사용자 경계를 넘는 Notebook service 토큰

loopback notebook service는 시작 시 프로세스 출력에 표시되는 토큰으로 인증할 수 있습니다. 이 출력이 다른 로컬 계정이 읽을 수 있는 로그로 리디렉션되면 토큰이 사용자 경계를 넘어 유출되어 notebook server 계정으로 code execution이 가능해질 수 있습니다. 로그 경로를 권한 상승 단서로 간주하기 전에 수신 대기 프로세스의 소유자, 로그 대상과 권한, 현재 토큰 설정, notebook 접근 제어를 함께 확인하세요. 수동 열거 중에는 로그 메타데이터만 확인하고, 토큰을 출력하거나 호스트를 분류하기 위해서만 service에 연결하지 마세요.

Jupyter Lab service는 시작 로그뿐 아니라 읽을 수 있는 systemd `ExecStart` 또는 실행 중인 명령줄(`ps auxww`)에도 토큰을 노출할 수 있습니다. 보고된 사례에서는 `User=analyst`와 `--ServerApp.token`을 통해 자격 증명과 `127.0.0.1:8888` listener를 실행하는 계정이 모두 확인되었습니다. 호스트에 접근할 수 있는 경우, 토큰과 `ssh -L 8888:127.0.0.1:8888 user@host`를 사용해 해당 service 사용자로 Jupyter Lab의 Terminal에 접근할 수 있었습니다. 유효한 unit 사용자, 프로세스 인자, listener, 토큰 유효성을 함께 확인하세요. loopback 바인딩만으로는 권한 경계가 보장되지 않습니다.<sup>[[28]](#references)</sup>

## socat 또는 SSH를 사용한 로컬 Pivot

service가 loopback에 바인딩되어 있다면 service 자체를 변경하는 대신 허용된 채널을 통해 노출하세요.

SSH를 사용해 로컬에서만 접근 가능한 HTTP service를 포워딩합니다.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

이미 셸 접근 권한이 있는 경우 `socat`으로 로컬 포트를 브리지합니다.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

로컬 테스트를 위해 Unix socket을 TCP로 포워딩합니다.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

이것만으로는 아무것도 exploit하지 않습니다. 로컬 전용 표면을 도구에서 접근할 수 있게 만들어 일반 서비스처럼 상호작용할 수 있도록 합니다.

## Banner Grabbing 및 간단한 프로토콜

모든 서비스가 HTTP를 사용하는 것은 아닙니다. 많은 로컬 서비스는 배너나 한 줄짜리 프로토콜을 통해 충분한 정보를 leak합니다.

기본 프로브.<sup>[[13]](#references)</sup>

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

목표는 프로토콜, 인증 방식, 버전, 그리고 서비스가 로컬 클라이언트를 신뢰하는지 확인하는 것입니다.

aiohttp listener의 경우, 버전뿐 아니라 static-route 설정도 검토하세요. CVE-2024-23334는 `follow_symlinks=True`가 설정된 static route를 사용하는 aiohttp 3.9.2 미만 버전에 영향을 줍니다. 해당 route로 요청하면 static root 밖의 파일을 읽을 수 있습니다. 서비스가 root로 실행 중이라면 route에 접근할 수 있는 경우 root가 읽을 수 있는 파일이 노출될 수 있습니다. 버전 배너나 loopback 바인드만으로는 취약한 설정이나 파일 접근 가능성이 입증되지 않습니다.<sup>[[27]](#references)</sup>

## Loopback 트래픽 캡처

로컬 트래픽에서 헤더, bearer token, Basic Auth 자격 증명 또는 애플리케이션별 비밀 정보가 노출될 수 있습니다.<sup>[[17]](#references)[[25]](#references)</sup> 승인된 환경에서만 캡처하세요.

Loopback HTTP 트래픽을 캡처합니다.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

특정 로컬 서비스를 캡처합니다.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

캡처되거나 로그에 기록된 헤더에서 Basic Auth를 디코딩합니다.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

텍스트 캡처에서 찾아볼 유용한 문자열:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## TLS Key Logging

실습 환경에서 클라이언트 프로세스 환경을 제어할 수 있다면 `SSLKEYLOGFILE`을 사용해 Wireshark 또는 호환 도구에서 TLS 세션을 복호화할 수 있습니다.<sup>[[19]](#references)[[20]](#references)</sup> TLS 자체를 공격하지 않고 로컬 HTTPS 트래픽을 파악하는 데 유용합니다.

키 로깅을 활성화한 상태로 클라이언트를 실행합니다.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

동시에 트래픽을 캡처하세요.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

그런 다음 `/tmp/tls.pcap`과 `/tmp/sslkeys.log`를 Wireshark에 로드합니다. 이 방법은 클라이언트 라이브러리가 NSS 스타일 키 로깅을 지원하고 연결이 이루어지기 전에 환경을 설정할 수 있을 때만 작동합니다.<sup>[[20]](#references)[[21]](#references)</sup>

## Unix Socket 상호 작용 및 Command Injection

Unix socket은 로컬 IPC 엔드포인트입니다.<sup>[[5]](#references)</sup> HTTP API, 사용자 지정 프로토콜 또는 안전하지 않은 명령 처리기를 노출할 수 있습니다.<sup>[[12]](#references)[[14]](#references)</sup>

root 소유 socket에 그룹 쓰기 권한이 설정된 것은 그 자체로 취약점이 아니라 권한 경계입니다. 위험도를 판단하기 전에 해당 그룹 및 모드를 현재 계정과 비교하고, 리스닝 프로세스를 식별한 다음, 해당 프로세스가 클라이언트로부터 어떤 입력을 받는지 검토하세요. 특히 제출된 PHP를 실행하는 권한 있는 서비스가 호출자가 선택한 `php.ini` 경로도 신뢰하거나 호출자가 `disable_functions` 또는 `open_basedir`를 변경할 수 있도록 허용한다면, 두 번째 경계를 넘을 수 있습니다. 유효 설정과 서비스의 검증 경로를 확인하세요. [PHP 설정 가이드](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md)에서 해당 지시어를 설명합니다. Socket 메타데이터만으로는 코드 실행이 입증되지 않습니다.

Socket을 찾습니다.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Unix socket을 통해 HTTP와 통신합니다.<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

raw socket과 상호작용합니다.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

사용자가 제어하는 소켓 입력이 shell이나 권한이 높은 helper에 전달되면 command injection으로 이어질 수 있습니다.<sup>[[26]](#references)</sup> 구체적인 예시는 [Socket Command Injection](socket-command-injection.md)을 참조하세요.

## nftables 검토 및 승인된 규칙 변경

로컬 방화벽 규칙은 서비스가 로컬에서는 보이지만 원격에서는 차단되는 이유나, 특정 인터페이스에서 높은 포트에 연결할 수 없는 이유를 설명해 줄 수 있습니다.<sup>[[22]](#references)</sup>

규칙을 검토하세요.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

대상 포트에 영향을 미치는 드롭을 찾습니다.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

승인된 실습 환경에서 handle을 지정해 특정 차단 규칙을 제거합니다.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

전체 테이블을 비우기보다는 해당 handle만 정확히 삭제하는 것이 좋습니다. 이 기법은 동작을 유발하는 정확한 필터를 식별하고 해당 규칙만 변경하는 것입니다.<sup>[[22]](#references)</sup>

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

로컬 전용이거나, 더 높은 권한의 사용자로 실행되거나, 관리자/디버그 기능을 노출하거나, loopback/container-network 클라이언트를 신뢰하는 서비스를 우선적으로 살펴보세요.

## References

- [1] [ss(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: IP 버전 6 주소 지정 아키텍처](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [리디렉션 (Bash 참조 매뉴얼)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout 호출 (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Port Scanning Techniques (Nmap 참조 가이드)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Host Discovery (Nmap 참조 가이드)](https://nmap.org/book/man-host-discovery.html)
- [10] [포트 지정 및 스캔 순서 (Nmap 참조 가이드)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Linux 매뉴얼 페이지](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD 매뉴얼 페이지](https://man.openbsd.org/nc.1)
- [14] [curl 명령줄 도구 매뉴얼](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL 문서](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: 'Basic' HTTP 인증 체계](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64 호출 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL 문서](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark 사용자 가이드](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables 매뉴얼](https://netfilter.org/projects/nftables/manpage.html)
- [23] [사설 인터넷 주소 할당 (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [OAuth 2.0 인증 프레임워크: Bearer Token 사용 (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: OS 명령에서 특수 요소의 부적절한 중화](https://cwe.mitre.org/data/definitions/78.html)
- [27] [aiohttp 관리자 권고: follow_symlinks를 이용한 정적 경로 순회](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
- [28] [HTB: DevHub — systemd 및 프로세스 인수를 통해 Jupyter 토큰 노출](https://0xdf.gitlab.io/2026/10/10/htb-devhub.html)
{{#include ../../banners/hacktricks-training.md}}
