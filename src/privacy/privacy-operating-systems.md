# Privacy Operating Systems

{{#include ../banners/hacktricks-training.md}}

Privacy-focused operating systems는 routing 및 persistence 실수를 줄여 주지만, identifying behavior나 compromised hardware를 보완할 수 있는 운영체제는 없습니다.

## isolation model 선택

| System | 적합한 용도 | Persistence | Network enforcement | 주요 tradeoff |
|---|---|---|---|---|
| **Tor Browser on a maintained OS** | 간헐적인 anonymous web browsing | Browser state는 일반적으로 session-scoped | Browser traffic만 적용 | 다른 앱과 host는 Tor 외부에 남음 |
| **Tails** | Portable하고 amnesic한 single-purpose sessions | 선택적 encrypted Persistent Storage | Internet traffic이 Tor를 통해 강제 routing됨 | Reboot/workflow friction; firmware/hardware trust |
| **Whonix** | 강제 Tor routing이 필요한 persistent applications | Persistent VMs | Gateway/workstation split | Host/hypervisor와 identity mixing은 여전히 남음 |
| **Qubes-Whonix** | 고급 사용자를 위한 강력한 compartment separation | Per-qube | Dedicated network qubes와 Whonix | Hardware requirements와 operational complexity |

## Tails

Tails는 removable media에서 독립적으로 boot하고, Internet traffic을 Tor를 통해 routing하며, 로컬 state를 최소한으로 남기도록 설계되었습니다. Tails 자체의 warnings는 compromised BIOS/firmware/hardware, identifying disclosures, file metadata 또는 양쪽 끝을 correlation할 수 있는 powerful observer로부터 보호할 수 없다고 강조합니다.<sup>[[1]](#references)</sup>

### Single-purpose Tails workflow

1. 신뢰할 수 있고 최신 상태인 computer에서 official site로부터 Tails를 download하고, official verification/install process를 따릅니다.
2. 지원되는 USB drive는 Tails boot에만 사용합니다. 일반적인 file-transfer drive로도 사용하지 마십시오.
3. 물리적으로 통제하는 hardware에서 boot합니다. Live OS는 hardware keylogger나 malicious firmware를 무력화할 수 없습니다.
4. Workflow에 실제로 필요한 경우가 아니라면 Persistent Storage를 비활성화합니다. 활성화할 경우 필요한 categories만 persist하고 강력한 passphrase를 사용합니다.
5. 합법적인 network에 연결합니다. Captive portal을 피할 수 없다면 Tails' Unsafe Browser는 portal에만 사용하고, 불필요한 identity를 disclose하지 말며, 즉시 닫은 뒤 sensitive activity를 수행하기 전에 Tor에 연결합니다.<sup>[[2]](#references)</sup>
6. Direct Tor visibility 또는 blocking이 중요하다면 Tor bridge를 configure합니다.
7. **세션마다 하나의 contextual identity/purpose만** 수행합니다. Tails는 서로 연결되어서는 안 되는 activities 사이에 restart할 것을 권장합니다.<sup>[[1]](#references)</sup>
8. Publishing 전에 files를 inspect하고 sanitize합니다. 의도한 context를 bypass할 수 있는 application에서 downloaded active documents를 열지 마십시오.
9. 작업이 끝나면 완전히 shut down하고 USB를 물리적으로 안전하게 보관합니다.

## Whonix

Whonix는 Tor-routing **Gateway**와, applications가 external IP를 직접 알아낼 수 없는 **Workstation**을 분리합니다. 이를 통해 proxy/DNS 실수를 상당히 줄일 수 있지만, host, hypervisor, behavior 및 documents는 여전히 identity를 reveal할 수 있습니다. Whonix는 하나의 workstation을 여러 identities에 사용하거나 anonymous 및 non-anonymous activity를 결합하지 말라고 명시적으로 경고합니다.<sup>[[3]](#references)</sup>

### Compartment workflow

1. Official sources에서 Whonix image와 virtualization platform을 verify합니다.
2. 사용하기 전에 host, hypervisor, Gateway 및 Workstation에 patch를 적용합니다.
3. 각 identity 또는 engagement마다 fresh Workstation을 clone합니다. Identity-bearing state가 도입된 후에는 VM을 절대 clone하지 마십시오.
4. Personal accounts, host shared folders, clipboard synchronization, USB devices 및 time/location data를 Workstation에서 제외합니다.
5. Snapshots는 recovery에 사용하고, backups 또는 identity separation의 대체 수단으로 사용하지 않습니다.
6. Gateway가 중지되었을 때 Workstation이 Internet에 연결할 수 없는지 확인합니다.
7. 특히 위험한 files에는 disposable VM/qube를 사용하고, sanitized result만 export합니다.

## Qubes OS 및 Qubes-Whonix

Qubes는 Xen-backed qubes를 사용한 compartmentalization으로 security를 구현합니다. 그 design은 한 domain에서 발생한 compromise가 다른 domain에 자동으로 도달하는 것을 제한하지만, **같은** qube 내부의 applications는 서로 격리되지 않습니다.<sup>[[4]](#references)</sup> Disposable qubes는 untrusted sites, files 및 devices에 사용할 fresh state를 제공합니다.<sup>[[5]](#references)</sup>

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

- 각 qube에 하나의 신뢰 수준과 신원 목적을 부여합니다.
- secrets는 offline vault qube에 보관하고, 명시적인 qube 간 복사/파일 작업을 사용합니다.
- 출처가 불분명한 파일과 링크는 disposables에서 엽니다.
- 의도한 qube만 Whonix 또는 전용 VPN qube를 통해 라우팅합니다.
- 창을 뚜렷하게 구분해 표시하고, 민감한 작업 중에는 관련 없는 qube를 중지합니다.
- 두 qube가 계정, 콘텐츠, 일정 또는 결제 정보를 공유한다면 correlation을 방지한다고 가정하지 마세요.

## Verification and maintenance

- 공식 지침에 따라 installer signature/checksum을 확인합니다.
- 먼저 template을 patch한 다음 종속 qube/VM을 재시작합니다.
- network-deny 동작, DNS, IPv6, clock, clipboard, shared directories 및 USB assignment를 확인합니다.
- Persistent Storage와 VM snapshots에서 과거의 신원 관련 데이터를 검토합니다.
- seed/key를 암호화된 offline backup으로 보관하고, 격리된 환경에서 복원을 테스트합니다.
- compromise가 의심되면 compartment를 재구축합니다. egress IP를 변경하는 것만으로는 충분하지 않습니다.

## References

- [1] [Tails — 경고: Tails는 안전하지만 마법은 아닙니다](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — captive portal을 사용하여 network에 로그인하기](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Whonix 및 Tor의 제한 사항](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Security design goals](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — disposables 사용 방법](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
{{#include ../banners/hacktricks-training.md}}
