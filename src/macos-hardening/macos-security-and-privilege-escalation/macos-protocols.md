# macOS 네트워크 서비스 및 프로토콜

{{#include ../../banners/hacktricks-training.md}}

## 원격 액세스 서비스

이들은 원격으로 액세스하기 위한 일반적인 macOS 서비스입니다.\
이 서비스는 `시스템 설정` --> `공유`에서 활성화/비활성화할 수 있습니다.

- **VNC**, "화면 공유"로 알려짐 (tcp:5900)
- **SSH**, "원격 로그인"이라고 불림 (tcp:22)
- **Apple Remote Desktop** (ARD), 또는 "원격 관리" (tcp:3283, tcp:5900)
- **AppleEvent**, "원격 Apple 이벤트"로 알려짐 (tcp:3031)

활성화된 서비스가 있는지 확인하려면 다음을 실행하세요:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD)는 macOS에 맞게 조정된 [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing)의 향상된 버전으로, 추가 기능을 제공합니다. ARD의 주목할 만한 취약점은 제어 화면 비밀번호의 인증 방법으로, 비밀번호의 처음 8자만 사용하여 [무차별 대입 공격](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html)에 취약하게 만듭니다. Hydra 또는 [GoRedShell](https://github.com/ahhh/GoRedShell/)과 같은 도구를 사용하여 공격할 수 있으며, 기본 속도 제한이 없습니다.

취약한 인스턴스는 **nmap**의 `vnc-info` 스크립트를 사용하여 식별할 수 있습니다. `VNC Authentication (2)`를 지원하는 서비스는 8자 비밀번호 잘림으로 인해 무차별 대입 공격에 특히 취약합니다.

권한 상승, GUI 접근 또는 사용자 모니터링과 같은 다양한 관리 작업을 위해 ARD를 활성화하려면 다음 명령을 사용하십시오:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD는 관찰, 공유 제어 및 전체 제어를 포함한 다양한 제어 수준을 제공하며, 사용자 비밀번호 변경 후에도 세션이 지속됩니다. 관리 사용자를 위해 루트로 직접 유닉스 명령을 전송하고 실행할 수 있습니다. 작업 예약 및 원격 Spotlight 검색은 여러 머신에서 민감한 파일에 대한 원격 저영향 검색을 용이하게 하는 주목할 만한 기능입니다.

#### 최근 화면 공유 / ARD 취약점 (2023-2025)

| 연도 | CVE | 구성 요소 | 영향 | 수정됨 |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|화면 공유|잘못된 세션 렌더링으로 인해 *잘못된* 데스크탑이나 창이 전송되어 민감한 정보가 유출될 수 있음|macOS Sonoma 14.2.1 (2023년 12월) |
|2024|CVE-2024-23296|launchservicesd / login|원격 로그인 후 체인으로 연결할 수 있는 커널 메모리 보호 우회 (실제로 악용됨)|macOS Ventura 13.6.4 / Sonoma 14.4 (2024년 3월) |

**하드닝 팁**

* 엄격히 필요하지 않을 때는 *화면 공유*/*원격 관리*를 비활성화하십시오.
* macOS를 완전히 패치 상태로 유지하십시오 (Apple은 일반적으로 최근 3개의 주요 릴리스에 대한 보안 수정 사항을 배포합니다).
* **강력한 비밀번호**를 사용하고 가능한 경우 *“VNC 뷰어가 비밀번호로 화면을 제어할 수 있음”* 옵션을 **비활성화**하십시오.
* TCP 5900/3283을 인터넷에 노출시키는 대신 VPN 뒤에 서비스를 배치하십시오.
* `ARDAgent`를 로컬 서브넷으로 제한하는 애플리케이션 방화벽 규칙을 추가하십시오:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour 프로토콜

Bonjour는 Apple이 설계한 기술로, **같은 네트워크에 있는 장치들이 서로 제공하는 서비스를 감지할 수 있게** 합니다. Rendezvous, **제로 구성** 또는 Zeroconf로도 알려진 이 기술은 장치가 TCP/IP 네트워크에 가입하고, **자동으로 IP 주소를 선택**하며, 다른 네트워크 장치에 서비스를 브로드캐스트할 수 있게 합니다.

Bonjour가 제공하는 제로 구성 네트워킹은 장치가 다음을 보장합니다:

- **DHCP 서버가 없는 경우에도 IP 주소를 자동으로 얻을 수 있습니다.**
- DNS 서버 없이 **이름-주소 변환**을 수행할 수 있습니다.
- 네트워크에서 사용 가능한 **서비스를 발견**할 수 있습니다.

Bonjour를 사용하는 장치는 **169.254/16 범위의 IP 주소를 할당**하고 네트워크에서 고유성을 확인합니다. Mac은 이 서브넷에 대한 라우팅 테이블 항목을 유지하며, `netstat -rn | grep 169`를 통해 확인할 수 있습니다.

DNS의 경우 Bonjour는 **멀티캐스트 DNS(mDNS) 프로토콜**을 사용합니다. mDNS는 **포트 5353/UDP**를 통해 작동하며, **표준 DNS 쿼리**를 사용하지만 **멀티캐스트 주소 224.0.0.251**을 대상으로 합니다. 이 접근 방식은 네트워크의 모든 수신 장치가 쿼리를 수신하고 응답할 수 있도록 하여 기록을 업데이트할 수 있게 합니다.

네트워크에 가입할 때 각 장치는 일반적으로 **.local**로 끝나는 이름을 자가 선택하며, 이는 호스트 이름에서 파생되거나 무작위로 생성될 수 있습니다.

네트워크 내 서비스 발견은 **DNS 서비스 발견(DNS-SD)**에 의해 촉진됩니다. DNS SRV 레코드의 형식을 활용하여 DNS-SD는 **DNS PTR 레코드**를 사용하여 여러 서비스의 목록을 가능하게 합니다. 특정 서비스를 찾는 클라이언트는 `<Service>.<Domain>`에 대한 PTR 레코드를 요청하며, 서비스가 여러 호스트에서 사용 가능한 경우 `<Instance>.<Service>.<Domain>` 형식의 PTR 레코드 목록을 반환받습니다.

`dns-sd` 유틸리티는 **네트워크 서비스를 발견하고 광고하는 데** 사용될 수 있습니다. 다음은 사용 예시입니다:

### SSH 서비스 검색

네트워크에서 SSH 서비스를 검색하기 위해 다음 명령을 사용합니다:
```bash
dns-sd -B _ssh._tcp
```
이 명령은 \_ssh.\_tcp 서비스 검색을 시작하고 타임스탬프, 플래그, 인터페이스, 도메인, 서비스 유형 및 인스턴스 이름과 같은 세부 정보를 출력합니다.

### HTTP 서비스 광고

HTTP 서비스를 광고하려면 다음을 사용할 수 있습니다:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
이 명령은 포트 80에서 `/index.html` 경로를 가진 "Index"라는 HTTP 서비스를 등록합니다.

그런 다음 네트워크에서 HTTP 서비스를 검색하려면:
```bash
dns-sd -B _http._tcp
```
서비스가 시작되면, 서브넷의 모든 장치에 멀티캐스트를 통해 자신의 가용성을 알립니다. 이러한 서비스에 관심이 있는 장치는 요청을 보낼 필요 없이 이러한 발표를 듣기만 하면 됩니다.

보다 사용자 친화적인 인터페이스를 위해, Apple App Store에서 제공하는 **Discovery - DNS-SD Browser** 앱은 로컬 네트워크에서 제공되는 서비스를 시각화할 수 있습니다.

또는, `python-zeroconf` 라이브러리를 사용하여 서비스를 탐색하고 발견하는 사용자 정의 스크립트를 작성할 수 있습니다. [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) 스크립트는 `_http._tcp.local.` 서비스에 대한 서비스 브라우저를 생성하고 추가되거나 제거된 서비스를 출력하는 방법을 보여줍니다:
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
### 네트워크를 통한 Bonjour 열거

* **Nmap NSE** – 단일 호스트에서 광고하는 서비스를 발견합니다:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

`dns-service-discovery` 스크립트는 `_services._dns-sd._udp.local` 쿼리를 전송한 후 각 광고된 서비스 유형을 열거합니다.

* **mdns_recon** – 잘못 구성된 mDNS 응답기를 찾기 위해 전체 범위를 스캔하는 Python 도구로, 유니캐스트 쿼리에 응답합니다 (서브넷/WAN을 통해 접근 가능한 장치를 찾는 데 유용):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

이 명령은 로컬 링크 외부에서 Bonjour를 통해 SSH를 노출하는 호스트를 반환합니다.

### 보안 고려사항 및 최근 취약점 (2024-2025)

| 연도 | CVE | 심각도 | 문제 | 패치된 버전 |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|중간|*mDNSResponder*의 논리 오류로 인해 조작된 패킷이 **서비스 거부**를 유발할 수 있음|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (2024년 9월) |
|2025|CVE-2025-31222|높음|*mDNSResponder*의 정확성 문제로 인해 **로컬 권한 상승**에 악용될 수 있음|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (2025년 5월) |

**완화 지침**

1. UDP 5353을 *링크 로컬* 범위로 제한 – 무선 컨트롤러, 라우터 및 호스트 기반 방화벽에서 차단하거나 속도 제한을 설정합니다.
2. 서비스 발견이 필요하지 않은 시스템에서 Bonjour를 완전히 비활성화합니다:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Bonjour가 내부적으로 필요하지만 네트워크 경계를 넘지 않아야 하는 환경에서는 *AirPlay Receiver* 프로필 제한(MDM) 또는 mDNS 프록시를 사용합니다.
4. **시스템 무결성 보호(SIP)**를 활성화하고 macOS를 최신 상태로 유지합니다 – 위의 두 취약점은 신속하게 패치되었지만 완전한 보호를 위해 SIP가 활성화되어 있어야 했습니다.

### Bonjour 비활성화

보안에 대한 우려나 Bonjour를 비활성화해야 하는 다른 이유가 있는 경우, 다음 명령을 사용하여 끌 수 있습니다:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)

{{#include ../../banners/hacktricks-training.md}}
