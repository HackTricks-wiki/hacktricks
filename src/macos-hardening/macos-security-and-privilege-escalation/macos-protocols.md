# macOS 네트워크 서비스 및 Protocol

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

다음은 macOS에 원격으로 액세스할 때 사용하는 일반적인 서비스입니다.\
`System Settings` --> `Sharing`에서 이러한 서비스를 활성화하거나 비활성화할 수 있습니다.

- **VNC**, “Screen Sharing”이라고도 함 (tcp:5900)
- **SSH**, “Remote Login”이라고 함 (tcp:22)
- **Apple Remote Desktop** (ARD) 또는 “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, “Remote Apple Event”이라고도 함 (tcp:3031)

다음 명령을 실행하여 활성화된 서비스가 있는지 확인합니다:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### 로컬에서 sharing configuration 열거하기

Mac에서 이미 로컬 code execution이 가능한 경우, listening sockets뿐만 아니라 **configured state도 확인해야 합니다**. `systemsetup`과 `launchctl`은 일반적으로 서비스가 관리적으로 활성화되어 있는지 알려주며, `kickstart`와 `system_profiler`는 유효한 ARD/Sharing configuration을 확인하는 데 도움이 됩니다:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD)는 macOS에 맞게 설계된 [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing)의 확장 버전으로, 추가 기능을 제공합니다. ARD의 주요 취약점 중 하나는 control screen password의 authentication 방식으로, password의 처음 8개 문자만 사용합니다. 따라서 기본 rate limit이 없기 때문에 Hydra 또는 [GoRedShell](https://github.com/ahhh/GoRedShell/)과 같은 도구를 사용한 [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html)에 취약합니다.

취약한 인스턴스는 **nmap**의 `vnc-info` script를 사용하여 식별할 수 있습니다. `VNC Authentication (2)`를 지원하는 서비스는 8문자로 password가 잘리기 때문에 특히 brute force attacks에 취약합니다.

privilege escalation, GUI access 또는 user monitoring과 같은 다양한 administrative tasks를 위해 ARD를 활성화하려면 다음 command를 사용합니다:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD는 관찰, 공유 제어, 전체 제어를 포함한 다양한 제어 수준을 제공하며, 사용자 password가 변경된 후에도 세션이 유지됩니다. Unix commands를 직접 전송할 수 있고, administrative users의 경우 root 권한으로 실행할 수 있습니다. Task scheduling 및 Remote Spotlight search도 주요 기능으로, 여러 machine에서 민감한 file을 원격으로, 시스템 영향이 적은 방식으로 검색할 수 있습니다.

운영자 관점에서 **Monterey 12.1+는 managed fleet에서 remote-enablement workflow를 변경했습니다**. 피해자의 MDM을 이미 제어하고 있다면, Apple의 `EnableRemoteDesktop` command가 최신 system에서 remote desktop 기능을 활성화하는 가장 깔끔한 방법인 경우가 많습니다. host에 foothold를 이미 확보했다면 `kickstart`는 여전히 command line에서 ARD privilege를 확인하거나 재구성하는 데 유용합니다.

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

최근 `screensharingd` research에 따르면 Apple Screen Sharing은 항상 classic VNC auth만 사용하는 것은 아닙니다. 최신 build는 **RFB `003.889`**를 사용하며 **security type `36`**을 advertise합니다. 여기서 먼저 **SRP**가 authenticate되고, `ccsrp_server_verify_session`이 성공한 후에만 **ChaCha20-Poly1305**가 설치됩니다. 공개된 write-up에 따르면 이 bug는 **macOS Tahoe 26.6** (**2026년 7월 27일**)에서 수정되었습니다.

기억해 둘 유용한 pattern은 **stale-status parser bypass**입니다. 4-byte length read가 성공한 후에는 모든 oversized/error branch가 새로운 error를 반환해야 합니다. 영향을 받는 build에서는 big-endian SRP frame length가 **`>= 32768`**이면 rejection path가 이전 `NetBufferRead` 성공 값(`0`)을 재사용합니다. 그 결과 password proof가 실행되지 않았고 transport crypto도 설치되지 않았는데도 caller가 session을 authenticated 상태로 설정합니다. 읽히지 않은 byte는 shared socket buffer에 남아 있으므로, attacker는 **malformed SRP data와 post-auth RFB message를 동일한 TCP burst에 pipeline**하여 이를 **cleartext authenticated traffic**으로 parsing하게 만들 수 있습니다.

bypass 이후 Apple의 proprietary **file-copy** message **`0x22`**는 `screensharingd`가 root로 실행되기 때문에 **root file read/write primitive**가 됩니다:
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: 임의 파일 읽기
- `kind=2` / `StartFileReceive`: 임의 파일 쓰기
- 서로 다른 `sid` 값을 사용하면 하나의 연결에서 여러 트랜잭션을 pipeline할 수 있음
- `kind=101` (`NewItem`)에서는 일반 파일의 경우 byte `14` / `arg[0]`을 `0x01`로 설정하고, payload offset `+42`를 **0이 아닌** big-endian 파일 크기로 설정하며, payload offset `+0x5a`를 원하는 Unix mode로 설정해야 함(crontab을 대상으로 하는 경우 `0600`)

쓰기 가능한 경로에서 흥미로운 post-write pivot 대상으로는 **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`**, **`/var/root/.ssh/authorized_keys`**가 있음. **SIP는 auth bypass 또는 root file read를 차단하지 않지만**, **`/var/at`**과 같은 일부 write target은 차단하므로 cron 기반 실행은 SIP가 비활성화된 경우에만 작동함. 기본 SIP 활성화 호스트에서는 즉시 code execution을 시도하기보다 **"privileged auto-consumed files에 대한 root file write"** 관점으로 접근해야 함.

같은 research에서 확인된 또 다른 SRP pitfall은 서버가 단순히 **`A > 0`**만 검사하지 말고 RFC 5054에 따라 **`A mod N != 0`**을 검증해야 한다는 점임. **`A = N`**을 허용하면 shared secret을 0으로 만들 수 있으며 password verification을 무력화할 수 있음.

**Detection ideas**

- 첫 번째 SRP frame length가 **`>= 32768`**인 Security type `36` 세션
- 성공적인 SRP proof / cipher install 전에 cleartext **`0x22`** file-copy traffic 처리를 시작하는 세션
- **TCP/5900**에 대한 반복적인 short-lived retry와 한 번의 burst에서 여러 file-copy `sid` 값 사용
- Screen Sharing 노출 이후 **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`**, 또는 **`/var/root/.ssh/authorized_keys`**가 예기치 않게 생성됨

### Pentesting Remote Apple Events (RAE / EPPC)

Apple은 modern System Settings에서 이 기능을 **Remote Application Scripting**이라고 부름. 내부적으로는 `com.apple.AEServer` service를 통해 **TCP/3031**에서 **EPPC**를 사용하여 **Apple Event Manager**를 원격으로 노출함. Palo Alto Unit 42는 valid credentials와 enabled RAE service가 있으면 operator가 remote Mac에서 scriptable applications를 제어할 수 있기 때문에 이를 실용적인 **macOS lateral movement** primitive로 다시 강조함.

Useful checks:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
이미 대상 시스템에서 admin/root 권한을 보유하고 있으며 이를 활성화하려는 경우:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
다른 Mac에서 수행하는 기본 연결 테스트:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
실제 환경에서 이 abuse case는 Finder에만 국한되지 않습니다. 필요한 Apple events를 수락하는 모든 **scriptable application**은 원격 공격 표면이 될 수 있으므로, 내부 macOS 네트워크에서 credential theft가 발생한 이후 RAE가 특히 흥미로운 대상이 됩니다.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|잘못된 세션 렌더링으로 인해 *잘못된* 데스크톱 또는 윈도우가 전송되어 민감한 정보가 leak될 수 있음|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|state-management 문제로 인해 Screen Sharing access 권한이 있는 사용자가 **다른 사용자의 화면**을 볼 수 있음|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* 반드시 필요한 경우가 아니라면 *Screen Sharing*/*Remote Management*을 비활성화합니다.
* macOS를 완전히 patch된 상태로 유지합니다(Apple은 일반적으로 최근 3개 major release에 대한 security fix를 제공합니다).
* **Strong Password**를 사용하고, 가능한 경우 *“VNC viewers may control screen with password”* 옵션을 **disabled** 상태로 적용합니다.
* TCP 5900/3283을 Internet에 노출하는 대신 VPN 뒤에 서비스를 배치합니다.
* Application Firewall rule을 추가하여 `ARDAgent`를 local subnet으로 제한합니다:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Apple이 설계한 기술인 Bonjour는 **동일한 네트워크의 디바이스가 서로가 제공하는 서비스를 탐지할 수 있도록 합니다**. Rendezvous, **Zero Configuration**, 또는 Zeroconf라고도 알려진 이 기술은 디바이스가 TCP/IP 네트워크에 연결되고, **IP address를 자동으로 선택하며**, 다른 네트워크 디바이스에 자신의 서비스를 broadcast할 수 있도록 합니다.

Bonjour가 제공하는 Zero Configuration Networking은 디바이스가 다음 작업을 수행할 수 있도록 합니다:

- **DHCP server가 없어도 IP Address를 자동으로 획득합니다.**
- DNS server 없이도 **name-to-address translation**을 수행합니다.
- 네트워크에서 사용 가능한 **서비스를 Discover**합니다.

Bonjour를 사용하는 디바이스는 **169.254/16 range의 IP address를 할당**하고 네트워크에서 해당 address의 고유성을 확인합니다. Mac은 이 subnet에 대한 routing table entry를 유지하며, `netstat -rn | grep 169`로 확인할 수 있습니다.

DNS의 경우 Bonjour는 **Multicast DNS (mDNS) protocol**을 사용합니다. mDNS는 **port 5353/UDP**에서 동작하며, **multicast address 224.0.0.251**을 대상으로 **standard DNS query**를 수행합니다. 이 방식은 네트워크에서 listening 중인 모든 디바이스가 query를 수신하고 응답할 수 있도록 하여, record를 업데이트할 수 있게 합니다.

네트워크에 연결되면 각 디바이스는 일반적으로 **.local**로 끝나는 name을 자체적으로 선택합니다. 이 name은 hostname에서 파생되거나 무작위로 생성될 수 있습니다.

네트워크 내 service discovery는 **DNS Service Discovery (DNS-SD)**를 통해 수행됩니다. DNS SRV record의 format을 활용하는 DNS-SD는 **DNS PTR record**를 사용하여 여러 service를 listing할 수 있도록 합니다. 특정 service를 찾는 client는 `<Service>.<Domain>`에 대한 PTR record를 request하며, 해당 service를 여러 host에서 사용할 수 있는 경우 `<Instance>.<Service>.<Domain>` 형식의 PTR record list를 response로 받습니다.

`dns-sd` utility는 네트워크 service를 **discover하고 advertise**하는 데 사용할 수 있습니다. 다음은 사용 예시입니다:

### Searching for SSH Services

네트워크에서 SSH service를 검색하려면 다음 command를 사용합니다:
```bash
dns-sd -B _ssh._tcp
```
이 명령은 \_ssh.\_tcp 서비스를 검색하고 timestamp, flags, interface, domain, service type, instance name 등의 세부 정보를 출력합니다.

### HTTP Service Advertising

HTTP Service를 advertise하려면 다음을 사용할 수 있습니다:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
이 명령은 포트 80에서 경로가 `/index.html`인 "Index"라는 HTTP 서비스를 등록합니다.

그런 다음 네트워크에서 HTTP 서비스를 검색하려면:
```bash
dns-sd -B _http._tcp
```
서비스가 시작되면 자신의 존재를 multicast하여 subnet의 모든 device에 availability를 알립니다. 이러한 service에 관심이 있는 device는 request를 보낼 필요 없이 이러한 announcement를 listen하기만 하면 됩니다.

더 user-friendly한 interface를 위해 Apple App Store에서 제공되는 **Discovery - DNS-SD Browser** app을 사용하면 local network에서 제공되는 service를 시각화할 수 있습니다.

또는 `python-zeroconf` library를 사용하여 service를 browse하고 discover하는 custom script를 작성할 수 있습니다. [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) script는 `_http._tcp.local.` service를 위한 service browser를 생성하고, added 또는 removed service를 출력하는 방법을 보여줍니다:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### macOS-specific Bonjour hunting

macOS 네트워크에서 Bonjour는 대상에 직접 접근하지 않고도 **remote administration surfaces**를 찾는 가장 쉬운 방법인 경우가 많습니다. Apple Remote Desktop 자체가 Bonjour를 통해 client를 검색할 수 있으므로, 동일한 discovery data가 attacker에게도 유용합니다.
```bash
# Enumerate every advertised service type first
dns-sd -B _services._dns-sd._udp local

# Then look for common macOS admin surfaces
dns-sd -B _rfb._tcp local      # Screen Sharing / VNC
dns-sd -B _ssh._tcp local      # Remote Login
dns-sd -B _eppc._tcp local     # Remote Apple Events / EPPC

# Resolve a specific instance to hostname, port and TXT data
dns-sd -L "<Instance>" _rfb._tcp local
dns-sd -L "<Instance>" _eppc._tcp local
```
더 폭넓은 **mDNS spoofing, impersonation, cross-subnet discovery** techniques은 전용 페이지를 확인하세요:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### 네트워크를 통한 Bonjour 열거

* **Nmap NSE** – 단일 host가 advertise하는 service를 discover:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

`dns-service-discovery` script는 `_services._dns-sd._udp.local` query를 전송한 다음, 각 advertise된 service type을 enumerate합니다.

* **mdns_recon** – 전체 range를 scan하여 unicast query에 응답하는 *misconfigured* mDNS responder를 찾는 Python tool입니다. (subnet/WAN을 통해 reachable한 device를 찾는 데 유용):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

이 command는 local link 외부에서 Bonjour를 통해 SSH를 expose하는 host를 반환합니다.

### Security 고려 사항 및 최근 vulnerabilities (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|*mDNSResponder*의 logic error로 인해 crafted packet이 **denial-of-service**를 trigger할 수 있었습니다.|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|*mDNSResponder*의 correctness issue가 **local privilege escalation**에 악용될 수 있었습니다.|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Mitigation guidance**

1. UDP 5353을 *link-local* scope로 제한하세요 – wireless controller, router 및 host-based firewall에서 이를 block하거나 rate-limit하세요.
2. Service discovery가 필요하지 않은 system에서는 Bonjour를 완전히 disable하세요:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Bonjour가 내부적으로 필요하지만 network boundary를 절대 넘어서는 안 되는 environment에서는 *AirPlay Receiver* profile restriction (MDM) 또는 mDNS proxy를 사용하세요.
4. **System Integrity Protection (SIP)**을 enable하고 macOS를 최신 상태로 유지하세요 – 위 두 vulnerabilities는 신속하게 patch되었지만, 완전한 protection을 위해 SIP가 enable되어 있어야 했습니다.

### Bonjour 비활성화

Security concerns 또는 기타 이유로 Bonjour를 disable해야 하는 경우, 다음 command를 사용하여 끌 수 있습니다:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## 참고 자료

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD - CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD - CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [**Palo Alto Unit 42 - macOS에서의 Lateral Movement: 고유하고 널리 사용되는 Techniques 및 실제 사례**](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [**Apple Support - macOS Sonoma 14.7.2의 security content 정보**](https://support.apple.com/en-us/121840)
- [**Apple Screen Sharing Pre-Auth RCE**](https://warez.sl0p.foo/apple-screensharing-rce/)
- [**Apple Support - macOS Tahoe 26.6의 security content 정보**](https://support.apple.com/en-us/128067)
- [**RFC 5054 - TLS Authentication에 Secure Remote Password (SRP) Protocol 사용**](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
