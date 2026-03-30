# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## 개요

Windows Accessibility 기능은 사용자의 설정을 HKCU에 저장하고 이를 세션별 HKLM 위치로 전파합니다. 잠금 화면이나 UAC 프롬프트 같은 **Secure Desktop** 전환 시에, **SYSTEM** 구성요소가 이 값을 다시 복사합니다. 만약 **세션별 HKLM 키가 사용자에게 쓰기 가능**하다면, 이는 권한 있는 쓰기 병목 지점이 되어 **registry symbolic links**로 리다이렉트할 수 있고, 결과적으로 **임의의 SYSTEM 레지스트리 쓰기**를 얻을 수 있습니다.

RegPwn 기법은 `osk.exe`가 사용하는 파일에 대한 **opportunistic lock (oplock)**으로 작은 경쟁 조건(race) 창을 안정화하여 그 전파 체인을 악용합니다.

## 레지스트리 전파 체인 (Accessibility -> Secure Desktop)

예시 기능: **On-Screen Keyboard** (`osk`). 관련 위치는:

- **시스템 전체 기능 목록**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **사용자별 구성 (사용자 쓰기 가능)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **세션별 HKLM 구성 (`winlogon.exe`에 의해 생성, 사용자 쓰기 가능)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/기본 사용자 하이브 (SYSTEM 컨텍스트)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Secure Desktop 전환 중 전파(단순화):

1. **사용자 `atbroker.exe`**가 `HKCU\...\ATConfig\osk`를 `HKLM\...\Session<session id>\ATConfig\osk`로 복사합니다.
2. **SYSTEM `atbroker.exe`**가 `HKLM\...\Session<session id>\ATConfig\osk`를 `HKU\.DEFAULT\...\ATConfig\osk`로 복사합니다.
3. **SYSTEM `osk.exe`**가 `HKU\.DEFAULT\...\ATConfig\osk`를 다시 `HKLM\...\Session<session id>\ATConfig\osk`로 복사합니다.

세션 HKLM 하위 트리가 사용자에게 쓰기 가능하면, 2·3단계는 사용자가 교체 가능한 위치를 통해 SYSTEM 쓰기를 제공합니다.

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

사용자 쓰기 가능한 세션별 키를 공격자가 선택한 대상으로 가리키는 **registry symbolic link**로 대체합니다. SYSTEM이 복사를 수행할 때 링크를 따라가 임의의 대상 키에 공격자가 제어하는 값을 기록합니다.

핵심 아이디어:

- 피해자 쓰기 대상 (사용자 쓰기 가능):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- 공격자는 해당 키를 임의의 다른 키를 가리키는 **registry link**로 교체합니다.
- SYSTEM이 복사를 수행하면 SYSTEM 권한으로 공격자가 선택한 키에 기록합니다.

이는 **임의의 SYSTEM 레지스트리 쓰기** 프리미티브를 생성합니다.

## Winning the Race Window with Oplocks

SYSTEM `osk.exe`가 시작해 세션별 키를 쓰기까지 짧은 타이밍 창이 존재합니다. 신뢰성을 높이기 위해, 익스플로잇은 다음에 대해 **oplock**을 겁니다:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
When the oplock triggers, the attacker swaps the per-session HKLM key for a registry link, lets the SYSTEM write land, then removes the link.

## 예시 익스플로잇 흐름 (개요)

1. access token에서 현재 **session ID**를 가져옵니다.
2. 숨겨진 `osk.exe` 인스턴스를 시작하고 잠시 대기합니다 (oplock이 트리거되도록 보장).
3. 공격자가 제어하는 값을 다음에 씁니다:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`에 **oplock**을 설정합니다.
5. **Secure Desktop** (`LockWorkstation()`)을 트리거하여 SYSTEM에서 `atbroker.exe` / `osk.exe`가 시작되게 합니다.
6. oplock이 트리거되면, `HKLM\...\Session<session id>\ATConfig\osk`를 임의 대상으로 향하는 **registry link**로 교체합니다.
7. SYSTEM의 복사가 완료될 때까지 잠시 기다린 후 링크를 제거합니다.

## 프리미티브를 SYSTEM 실행으로 변환

한 가지 간단한 체인은 **service configuration** 값(예: `ImagePath`)을 덮어쓰고 서비스를 시작하는 것입니다. RegPwn PoC는 **`msiserver`**의 `ImagePath`를 덮어쓰고 **MSI COM object**를 인스턴스화하여 이를 트리거함으로써 **SYSTEM** 코드 실행을 달성합니다.

## 관련

다른 Secure Desktop / UIAccess 동작에 대해서는 다음을 참조하세요:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
