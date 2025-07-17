# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**이 보고서에서는**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) 소프트웨어 업데이트 프로그램을 손상시켜 커널을 침해할 수 있는 여러 취약점이 설명되어 있습니다.\
[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild Kernel 0-days (CVE-2024-23225 & CVE-2024-23296)

Apple은 2024년 3월에 iOS 및 macOS에 대해 적극적으로 악용된 두 개의 메모리 손상 버그를 패치했습니다 (macOS 14.4/13.6.5/12.7.4에서 수정됨).

* **CVE-2024-23225 – Kernel**
• XNU 가상 메모리 서브시스템에서의 경계 초과 쓰기로 인해 비특권 프로세스가 PAC/KTRR를 우회하여 커널 주소 공간에서 임의의 읽기/쓰기를 얻을 수 있습니다.
• `libxpc`의 버퍼를 오버플로우하는 조작된 XPC 메시지를 통해 사용자 공간에서 트리거되며, 메시지가 구문 분석될 때 커널로 전환됩니다.
* **CVE-2024-23296 – RTKit**
• Apple Silicon RTKit(실시간 보조 프로세서)에서의 메모리 손상.
• 관찰된 악용 체인은 커널 R/W를 위해 CVE-2024-23225를 사용하고, PAC를 비활성화하고 보안 보조 프로세서 샌드박스를 탈출하기 위해 CVE-2024-23296을 사용했습니다.

Patch level detection:
```bash
sw_vers                 # ProductVersion 14.4 or later is patched
authenticate sudo sysctl kern.osversion  # 23E214 or later for Sonoma
```
업그레이드가 불가능한 경우, 취약한 서비스를 비활성화하여 완화하십시오:
```bash
launchctl disable system/com.apple.analyticsd
launchctl disable system/com.apple.rtcreportingd
```
---

## 2023: MIG 유형 혼동 – CVE-2023-41075

`mach_msg()` 요청이 권한이 없는 IOKit 사용자 클라이언트로 전송되면 MIG에서 생성된 글루 코드에서 **유형 혼동**이 발생합니다. 응답 메시지가 원래 할당된 것보다 더 큰 외부 설명자로 재해석될 때, 공격자는 커널 힙 영역에 제어된 **OOB 쓰기**를 수행하고 결국 `root`로 상승할 수 있습니다.

원시 개요 (Sonoma 14.0-14.1, Ventura 13.5-13.6):
```c
// userspace stub
typed_port_t p = get_user_client();
uint8_t spray[0x4000] = {0x41};
// heap-spray via IOSurfaceFastSetValue
io_service_open_extended(...);
// malformed MIG message triggers confusion
mach_msg(&msg.header, MACH_SEND_MSG|MACH_RCV_MSG, ...);
```
공식 익스플로잇은 버그를 무기화합니다:
1. 활성 포인터로 `ipc_kmsg` 버퍼를 스프레이합니다.
2. 댕글링 포트의 `ip_kobject`를 덮어씁니다.
3. `mprotect()`를 사용하여 PAC-위조 주소에 매핑된 셸코드로 점프합니다.

---

## 2024-2025: 서드파티 Kext를 통한 SIP 우회 – CVE-2024-44243 (일명 “Sigma”)

Microsoft의 보안 연구원들은 고권한 데몬 `storagekitd`가 **서명되지 않은 커널 확장**을 로드하도록 강제할 수 있으며, 따라서 완전히 패치된 macOS에서 **시스템 무결성 보호(SIP)**를 완전히 비활성화할 수 있음을 보여주었습니다(15.2 이전). 공격 흐름은 다음과 같습니다:

1. 개인 권한 `com.apple.storagekitd.kernel-management`를 남용하여 공격자 제어 하에 헬퍼를 생성합니다.
2. 헬퍼는 악성 kext 번들을 가리키는 조작된 정보 사전을 사용하여 `IOService::AddPersonalitiesFromKernelModule`을 호출합니다.
3. SIP 신뢰 검사가 `storagekitd`에 의해 kext가 스테이징된 *후*에 수행되기 때문에, 검증 전에 링-0에서 코드가 실행되고 `csr_set_allow_all(1)`로 SIP를 끌 수 있습니다.

탐지 팁:
```bash
kmutil showloaded | grep -v com.apple   # list non-Apple kexts
log stream --style syslog --predicate 'senderImagePath contains "storagekitd"'   # watch for suspicious child procs
```
즉각적인 수정은 macOS Sequoia 15.2 이상으로 업데이트하는 것입니다.

---

### 빠른 열거 요약표
```bash
uname -a                          # Kernel build
kmutil showloaded                 # List loaded kernel extensions
kextstat | grep -v com.apple      # Legacy (pre-Catalina) kext list
sysctl kern.kaslr_enable          # Verify KASLR is ON (should be 1)
csrutil status                    # Check SIP from RecoveryOS
spctl --status                    # Confirms Gatekeeper state
```
---

## Fuzzing & Research Tools

* **Luftrauser** – Mach 메시지 퍼저로 MIG 서브시스템을 타겟으로 함 (`github.com/preshing/luftrauser`).
* **oob-executor** – CVE-2024-23225 연구에 사용되는 IPC 아웃 오브 바운드 원시 생성기.
* **kmutil inspect** – 로딩 전에 kext를 정적으로 분석하는 내장 Apple 유틸리티 (macOS 11+): `kmutil inspect -b io.kext.bundleID`.



## References

* Apple. “macOS Sonoma 14.4의 보안 콘텐츠에 대하여.” https://support.apple.com/en-us/120895
* Microsoft Security Blog. “CVE-2024-44243 분석, 커널 확장을 통한 macOS 시스템 무결성 보호 우회.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
