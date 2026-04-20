# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## 원격 접근 서비스

다음은 원격으로 접근하기 위한 일반적인 macOS 서비스들입니다.\
이 서비스들은 `System Settings` --> `Sharing`에서 활성화/비활성화할 수 있습니다.

- **VNC**, “Screen Sharing”으로 알려짐 (tcp:5900)
- **SSH**, “Remote Login”으로 불림 (tcp:22)
- **Apple Remote Desktop** (ARD), 또는 “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, “Remote Apple Event”으로 알려짐 (tcp:3031)

다음 중 활성화된 것이 있는지 확인하려면 실행:
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

이미 Mac에서 local code execution이 가능한 경우, listening sockets만 보지 말고 **configured state**를 확인하세요. `systemsetup`과 `launchctl`은 보통 해당 service가 administratively enabled인지 알려주며, `kickstart`와 `system_profiler`는 실제 적용된 ARD/Sharing configuration을 확인하는 데 도움이 됩니다:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD)는 [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing)의 macOS 맞춤형 확장 버전으로, 추가 기능을 제공합니다. ARD의 주목할 만한 취약점은 control screen password에 대한 인증 방식인데, 비밀번호의 처음 8자만 사용하므로 Hydra나 [GoRedShell](https://github.com/ahhh/GoRedShell/) 같은 도구로 [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html)에 취약합니다. 기본 rate limit도 없습니다.

취약한 인스턴스는 **nmap**의 `vnc-info` script로 식별할 수 있습니다. `VNC Authentication (2)`를 지원하는 서비스는 8자 비밀번호 truncation 때문에 특히 brute force attacks에 취약합니다.

privilege escalation, GUI access, 또는 user monitoring 같은 다양한 administrative task를 위해 ARD를 enable하려면 다음 command를 사용하세요:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD는 관찰, 공유 제어, 전체 제어를 포함한 다양한 제어 수준을 제공하며, 사용자 비밀번호가 변경된 후에도 세션이 유지됩니다. Unix 명령을 직접 전송할 수 있고, 관리자 사용자에 대해서는 root로 실행됩니다. 작업 스케줄링과 Remote Spotlight 검색은 주목할 만한 기능으로, 여러 머신에서 민감한 파일을 원격으로, 영향이 적게 검색할 수 있게 해줍니다.

운영자 관점에서 보면, **Monterey 12.1+는 관리형 플릿에서 원격 활성화 워크플로를 변경**했습니다. 이미 피해자의 MDM을 제어하고 있다면, Apple의 `EnableRemoteDesktop` 명령은 새로운 시스템에서 remote desktop 기능을 활성화하는 가장 깔끔한 방법인 경우가 많습니다. 호스트에 이미 foothold가 있다면, `kickstart`는 여전히 명령줄에서 ARD 권한을 점검하거나 재구성하는 데 유용합니다.

### Pentesting Remote Apple Events (RAE / EPPC)

Apple은 최신 System Settings에서 이 기능을 **Remote Application Scripting**이라고 부릅니다. 내부적으로는 **Apple Event Manager**를 **EPPC**를 통해 **TCP/3031**에서 원격으로 노출하며, `com.apple.AEServer` 서비스로 제공됩니다. Palo Alto Unit 42는 이것을 다시 한 번 실용적인 **macOS lateral movement** 프리미티브로 강조했습니다. 유효한 credentials와 활성화된 RAE 서비스가 있으면, 운영자가 원격 Mac에서 스크립트 가능한 애플리케이션을 제어할 수 있기 때문입니다.

유용한 확인 방법:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
이미 대상에서 admin/root 권한이 있고 이를 활성화하려면:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
다른 Mac에서의 기본 연결성 테스트:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
실제로 악용 사례는 Finder에만 국한되지 않습니다. 필요한 Apple events를 받아들이는 모든 **scriptable application**은 원격 공격 표면이 되며, 이는 내부 macOS 네트워크에서 credential theft 이후 RAE를 특히 흥미롭게 만듭니다.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|잘못된 세션 렌더링으로 인해 *잘못된* desktop 또는 window가 전송될 수 있으며, 그 결과 민감한 정보가 leak될 수 있음|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|screen sharing access가 있는 사용자가 상태 관리 문제로 인해 **다른 사용자의 화면**을 볼 수 있을 수 있음|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* *Screen Sharing*/*Remote Management*가 엄격히 필요하지 않다면 비활성화하세요.
* macOS를 최신 패치 상태로 유지하세요(Apple은 일반적으로 최근 3개 major release에 대한 security fix를 제공합니다).
* **Strong Password**를 사용하고, 가능하면 *“VNC viewers may control screen with password”* 옵션을 **비활성화**하세요.
* TCP 5900/3283을 Internet에 직접 노출하지 말고 VPN 뒤에 서비스를 두세요.
* `ARDAgent`를 로컬 subnet으로만 제한하는 Application Firewall rule을 추가하세요:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Apple이 설계한 기술인 Bonjour는 **같은 network에 있는 devices들이 서로 제공하는 services를 탐지**할 수 있게 해줍니다. Rendezvous, **Zero Configuration**, 또는 Zeroconf라고도 알려진 이 기술은 device가 TCP/IP network에 join하고, **IP address를 자동으로 선택**하며, 자신의 services를 다른 network devices에 broadcast할 수 있게 합니다.

Bonjour가 제공하는 Zero Configuration Networking은 devices가 다음을 할 수 있도록 보장합니다.

- DHCP server가 없어도 **IP Address를 자동으로 획득**할 수 있습니다.
- DNS server가 필요 없이 **name-to-address translation**을 수행할 수 있습니다.
- network에서 사용 가능한 **services를 탐색**할 수 있습니다.

Bonjour를 사용하는 devices는 **169.254/16 range의 IP address를 자체 할당**하고 network에서 그 고유성을 확인합니다. Mac은 이 subnet에 대한 routing table entry를 유지하며, `netstat -rn | grep 169`로 확인할 수 있습니다.

DNS의 경우, Bonjour는 **Multicast DNS (mDNS) protocol**을 사용합니다. mDNS는 **port 5353/UDP**에서 동작하며, **standard DNS queries**를 사용하지만 대상은 **multicast address 224.0.0.251**입니다. 이 방식은 network의 모든 listening device가 queries를 수신하고 응답할 수 있게 하여, records를 업데이트하는 데 도움이 됩니다.

network에 join하면 각 device는 자체적으로 이름을 선택하며, 보통 **.local**로 끝나고 hostname에서 파생되거나 무작위로 생성될 수 있습니다.

network 내 서비스 탐색은 **DNS Service Discovery (DNS-SD)**를 통해 이루어집니다. DNS SRV record 형식을 활용하는 DNS-SD는 여러 services를 나열할 수 있도록 **DNS PTR records**를 사용합니다. 특정 service를 찾는 client는 `<Service>.<Domain>`에 대한 PTR record를 요청하며, service가 여러 host에서 제공되는 경우 반환값으로 `<Instance>.<Service>.<Domain>` 형식의 PTR records 목록을 받습니다.

`dns-sd` utility는 **network services를 발견하고 광고**하는 데 사용할 수 있습니다. 사용 예시는 다음과 같습니다:

### Searching for SSH Services

network에서 SSH services를 검색하려면 다음 command를 사용합니다:
```bash
dns-sd -B _ssh._tcp
```
이 명령은 \_ssh.\_tcp 서비스에 대한 browsing을 시작하고 timestamp, flags, interface, domain, service type, instance name과 같은 세부 정보를 출력합니다.

### HTTP Service 광고하기

HTTP service를 광고하려면 다음을 사용할 수 있습니다:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
이 명령은 포트 80에서 `/index.html` 경로를 가진 "Index"라는 이름의 HTTP 서비스를 등록합니다.

그다음 네트워크에서 HTTP 서비스를 검색하려면:
```bash
dns-sd -B _http._tcp
```
서비스가 시작되면, 멀티캐스팅을 통해 서브넷의 모든 디바이스에 자신의 존재를 알리고 가용성을 공지합니다. 이러한 서비스에 관심 있는 디바이스는 요청을 보낼 필요 없이, 단순히 이러한 공지들을 듣기만 하면 됩니다.

더 사용자 친화적인 인터페이스를 위해, Apple App Store에서 제공되는 **Discovery - DNS-SD Browser** 앱을 사용하면 로컬 네트워크에서 제공되는 서비스들을 시각화할 수 있습니다.

또는 `python-zeroconf` 라이브러리를 사용해 서비스를 탐색하고 발견하는 커스텀 스크립트를 작성할 수 있습니다. [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) 스크립트는 `_http._tcp.local.` 서비스에 대한 service browser를 생성하고, 추가되거나 제거된 서비스를 출력하는 예시를 보여줍니다:
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
### macOS-specific Bonjour 헌팅

macOS 네트워크에서는 Bonjour가 대상에 직접 접촉하지 않고도 **원격 관리 표면**을 찾는 가장 쉬운 방법인 경우가 많습니다. Apple Remote Desktop 자체도 Bonjour를 통해 클라이언트를 발견할 수 있으므로, 같은 discovery data는 공격자에게도 유용합니다.
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
더 넓은 **mDNS spoofing, impersonation, and cross-subnet discovery** 기법은 전용 페이지를 확인하세요:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### 네트워크에서 Bonjour 열거하기

* **Nmap NSE** – 단일 호스트가 광고하는 서비스를 찾아냅니다:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

`dns-service-discovery` 스크립트는 `_services._dns-sd._udp.local` 쿼리를 전송한 뒤, 광고된 각 서비스 타입을 열거합니다.

* **mdns_recon** – 전체 범위를 스캔해 unicast 쿼리에 응답하는 *misconfigured* mDNS responder를 찾는 Python 도구입니다(서브넷/WAN 너머에서 접근 가능한 장치를 찾는 데 유용함):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

이는 Bonjour를 통해 로컬 링크 밖에서 SSH를 노출하는 호스트를 반환합니다.

### 보안 고려 사항 및 최근 취약점 (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|*mDNSResponder*의 논리 오류로 인해 조작된 패킷이 **denial-of-service**를 유발할 수 있었음|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|*mDNSResponder*의 정확성 이슈가 **local privilege escalation**에 악용될 수 있었음|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**완화 지침**

1. UDP 5353을 *link-local* 범위로 제한하세요 – 무선 컨트롤러, 라우터, 호스트 기반 방화벽에서 차단하거나 rate-limit 하세요.
2. 서비스 검색이 필요 없는 시스템에서는 Bonjour를 완전히 비활성화하세요:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. 내부에서는 Bonjour가 필요하지만 네트워크 경계를 절대 넘어서는 안 되는 환경에서는 *AirPlay Receiver* 프로파일 제한(MDM) 또는 mDNS proxy를 사용하세요.
4. **System Integrity Protection (SIP)**을 활성화하고 macOS를 최신 상태로 유지하세요 – 위 두 취약점은 빠르게 패치되었지만, 완전한 보호를 위해 SIP가 활성화되어 있어야 했습니다.

### Bonjour 비활성화

보안 문제나 다른 이유로 Bonjour를 비활성화해야 한다면, 다음 명령으로 끌 수 있습니다:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [**Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples**](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [**Apple Support - About the security content of macOS Sonoma 14.7.2**](https://support.apple.com/en-us/121840)

{{#include ../../banners/hacktricks-training.md}}
