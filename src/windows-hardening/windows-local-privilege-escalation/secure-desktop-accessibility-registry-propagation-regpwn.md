# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## 개요

Windows Accessibility 기능은 HKCU에 사용자 구성을 저장하고 세션별 HKLM 위치로 전파합니다. **Secure Desktop** 전환(잠금 화면 또는 UAC 프롬프트) 중에는 **SYSTEM** 구성 요소가 이러한 값을 다시 복사합니다. **세션별 HKLM 키를 사용자가 쓸 수 있다면**, 이 키는 **registry symbolic links**로 리디렉션할 수 있는 권한 상승 쓰기 choke point가 되어 **임의의 SYSTEM registry write**를 가능하게 합니다.<sup>[[1]](#references)</sup>

RegPwn technique은 이 전파 chain을 악용하며, `osk.exe`가 사용하는 파일에 설정한 **opportunistic lock (oplock)**으로 짧은 race window를 안정화합니다.<sup>[[1]](#references)</sup>

## Registry Propagation Chain (Accessibility -> Secure Desktop)

예시 feature: **On-Screen Keyboard** (`osk`). 관련 위치는 다음과 같습니다.

- **System-wide feature list**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (`winlogon.exe`가 생성하며 user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Secure desktop 전환 중 전파 과정(단순화):

1. **User `atbroker.exe`**가 `HKCU\...\ATConfig\osk`를 `HKLM\...\Session<session id>\ATConfig\osk`로 복사합니다.
2. **SYSTEM `atbroker.exe`**가 `HKLM\...\Session<session id>\ATConfig\osk`를 `HKU\.DEFAULT\...\ATConfig\osk`로 복사합니다.
3. **SYSTEM `osk.exe`**가 `HKU\.DEFAULT\...\ATConfig\osk`를 다시 `HKLM\...\Session<session id>\ATConfig\osk`로 복사합니다.

세션 HKLM subtree를 사용자가 쓸 수 있다면, 2/3단계는 사용자가 교체할 수 있는 위치를 통한 SYSTEM write를 제공합니다.<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

사용자가 쓸 수 있는 per-session key를 attacker가 선택한 destination을 가리키는 **registry symbolic link**로 교체합니다. SYSTEM copy가 발생하면 link를 따라가며 attacker가 제어하는 값을 임의의 target key에 기록합니다.

핵심 개념:

- Victim write target (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Attacker가 해당 key를 다른 key를 가리키는 **registry link**로 교체합니다.
- SYSTEM이 copy를 수행하고 SYSTEM permissions으로 attacker가 선택한 key에 기록합니다.

이를 통해 **arbitrary SYSTEM registry write** primitive를 얻습니다.<sup>[[1]](#references)</sup>

## Winning the Race Window with Oplocks

**SYSTEM `osk.exe`**가 시작된 후 per-session key에 기록하기 전까지 짧은 timing window가 존재합니다. 이를 reliable하게 만들기 위해 exploit은 다음 위치에 **oplock**을 설정합니다:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
oplock이 트리거되면 attacker는 세션별 HKLM key를 registry link로 교체하고, SYSTEM의 write가 적용되도록 한 다음 link를 제거합니다.<sup>[[1]](#references)</sup>

## Exploitation Flow 예시 (High Level)

1. access token에서 현재 **session ID**를 가져옵니다.
2. 숨겨진 `osk.exe` 인스턴스를 시작하고 잠시 sleep합니다 (oplock이 트리거되도록 보장).
3. attacker가 제어하는 값을 다음 위치에 기록합니다.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`에 **oplock**을 설정합니다.
5. **Secure Desktop**을 트리거(`LockWorkstation()`)하여 SYSTEM 권한의 `atbroker.exe` / `osk.exe`가 시작되도록 합니다.
6. oplock이 트리거되면 `HKLM\...\Session<session id>\ATConfig\osk`를 임의의 target을 가리키는 **registry link**로 교체합니다.
7. SYSTEM copy가 완료될 때까지 잠시 기다린 다음 link를 제거합니다.<sup>[[1]](#references)</sup>

## Primitive를 SYSTEM Execution으로 변환

간단한 chain은 **service configuration** 값(예: `ImagePath`)을 덮어쓴 다음 service를 시작하는 것입니다. RegPwn PoC는 **`msiserver`**의 `ImagePath`를 덮어쓰고 **MSI COM object**를 인스턴스화하여 이를 트리거하며, 그 결과 **SYSTEM** code execution이 발생합니다.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

## 관련 항목

다른 Secure Desktop / UIAccess 동작은 다음을 참조하세요.

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)
{{#include ../../banners/hacktricks-training.md}}
