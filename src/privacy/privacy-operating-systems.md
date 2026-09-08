# Privacy Operating Systems

Privacy-focused operating systems는 routing 및 persistence 실수를 줄여 주지만, identifying behavior나 compromised hardware를 보완할 수 있는 운영체제는 없습니다.

## isolation model 선택

| System | 적합한 용도 | Persistence | Network enforcement | 주요 tradeoff |
|---|---|---|---|---|
| **Tor Browser on a maintained OS** | 가끔 수행하는 anonymous web browsing | Browser state는 일반적으로 session-scoped | Browser traffic만 적용 | 다른 앱과 host는 Tor 외부에 남음 |
| **Tails** | Portable, amnesic, single-purpose sessions | Optional encrypted Persistent Storage | Internet traffic이 Tor를 통해 강제로 라우팅됨 | Reboot 및 workflow의 불편함; firmware/hardware trust |
| **Whonix** | 강제 Tor routing이 필요한 persistent applications | Persistent VMs | Gateway/workstation split | Host/hypervisor 및 identity mixing이 여전히 가능 |
| **Qubes-Whonix** | Advanced users를 위한 강력한 compartment separation | Per-qube | Dedicated network qubes 및 Whonix | Hardware requirements 및 operational complexity |

## Tails

Tails는 removable media에서 독립적으로 boot하고, Internet traffic을 Tor를 통해 라우팅하며, local state를 최소한으로 남기도록 설계되었습니다. 자체 경고에서도 compromised BIOS/firmware/hardware, identifying disclosures, file metadata 또는 양쪽 끝을 상관 분석할 수 있는 powerful observer에 대한 보호를 제공할 수 없다고 강조합니다.<sup>[[1]](#references)</sup>

### Single-purpose Tails workflow

1. 신뢰할 수 있고 업데이트된 computer에서 official site를 통해 Tails를 다운로드하고, official verification/install process를 따릅니다.
2. 지원되는 USB drive는 Tails boot 용도로만 사용하고, general file-transfer drive로도 사용하지 않습니다.
3. 물리적으로 제어하는 hardware에서 boot합니다. live OS는 hardware keylogger나 malicious firmware를 무력화할 수 없습니다.
4. workflow에 정말 필요한 경우가 아니라면 Persistent Storage를 비활성화합니다. 활성화하는 경우 필요한 categories만 persist하고, strong passphrase를 사용합니다.
5. 합법적인 network에 연결합니다. captive portal을 피할 수 없다면 Tails' Unsafe Browser를 portal 용도로만 사용하고, 불필요한 identity를 공개하지 않으며, 즉시 종료한 뒤 민감한 activity를 수행하기 전에 Tor에 연결합니다.<sup>[[2]](#references)</sup>
6. direct Tor visibility 또는 blocking이 중요한 경우 Tor bridge를 구성합니다.
7. 각 session마다 **하나의 contextual identity/purpose만** 사용합니다. Tails는 서로 연결되지 않아야 하는 activity 사이에 restart할 것을 권장합니다.<sup>[[1]](#references)</sup>
8. publishing 전에 files를 검사하고 sanitize합니다. 의도한 context를 우회할 수 있는 application에서 downloaded active documents를 열지 않습니다.
9. 완료 후 완전히 shut down하고 USB를 물리적으로 안전하게 보관합니다.

## Whonix

Whonix는 Tor-routing **Gateway**와, applications가 external IP를 직접 알아낼 수 없는 **Workstation**을 분리합니다. 이는 proxy/DNS 실수를 상당히 줄여 주지만, host, hypervisor, behavior 및 documents는 여전히 identity를 드러낼 수 있습니다. Whonix는 하나의 workstation을 여러 identities에 사용하거나 anonymous 및 non-anonymous activity를 결합하지 말라고 명시적으로 경고합니다.<sup>[[3]](#references)</sup>

### Compartment workflow

1. official sources에서 Whonix image 및 virtualization platform을 검증합니다.
2. 사용 전에 host, hypervisor, Gateway 및 Workstation을 patch합니다.
3. 각 identity 또는 engagement마다 새 Workstation을 clone합니다. identity-bearing state가 도입된 후에는 절대 VM을 clone하지 않습니다.
4. personal accounts, host shared folders, clipboard synchronization, USB devices 및 time/location data를 Workstation에서 제외합니다.
5. snapshots는 recovery에 사용하고, backups나 identity separation의 대체 수단으로 사용하지 않습니다.
6. Gateway가 중지되었을 때 Workstation이 Internet에 접근할 수 없는지 확인합니다.
7. 특히 위험한 files에는 disposable VM/qube를 사용하고, sanitized result만 export합니다.

## Qubes OS and Qubes-Whonix

Qubes는 Xen-backed qubes를 사용하는 compartmentalization으로 security를 구현합니다. 이 설계는 한 domain에서 발생한 compromise가 다른 domain에 자동으로 도달하는 것을 제한하지만, **같은** qube 내부의 applications는 서로 격리되지 않습니다.<sup>[[4]](#references)</sup> Disposable qubes는 untrusted sites, files 및 devices를 위한 fresh state를 제공합니다.<sup>[[5]](#references)</sup>

실용적인 layout:
```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```
규칙:

- 각 qube에 하나의 trust level과 identity purpose를 부여합니다.
- secrets는 offline vault qube에 보관하고, 명시적인 inter-qube copy/file operation을 사용합니다.
- 요청하지 않은 파일과 링크는 disposables에서 엽니다.
- 의도한 qube만 Whonix 또는 전용 VPN qube를 통해 라우팅합니다.
- 창에 구분되는 레이블을 지정하고 민감한 작업 중에는 관련 없는 qube를 중지합니다.
- 두 qube가 계정, 콘텐츠, 일정 또는 결제 정보를 공유한다면 correlation을 방지한다고 가정하지 마십시오.

## Verification and maintenance

- 공식 지침에 따라 installer signature/checksum을 확인합니다.
- 먼저 template에 patch를 적용한 다음 종속 qube/VM을 재시작합니다.
- network-deny 동작, DNS, IPv6, clock, clipboard, shared directories 및 USB assignment를 확인합니다.
- Persistent Storage와 VM snapshot에서 이전 identity-bearing data를 검토합니다.
- seed/key의 암호화된 offline backup을 보관하고 격리된 환경에서 복원을 테스트합니다.
- compromise가 의심되면 compartment를 재구축합니다. egress IP를 변경하는 것만으로는 충분하지 않습니다.

## References

- [1] [Tails — 경고: Tails는 안전하지만 마법은 아닙니다](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — captive portal을 사용하여 network에 로그인하기](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Whonix와 Tor의 한계](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Security design goals](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — disposables 사용 방법](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
