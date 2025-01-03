# 물리적 공격

{{#include ../banners/hacktricks-training.md}}

## BIOS 비밀번호 복구 및 시스템 보안

**BIOS 재설정**은 여러 방법으로 수행할 수 있습니다. 대부분의 마더보드는 **배터리**를 포함하고 있으며, 이를 약 **30분** 동안 제거하면 비밀번호를 포함한 BIOS 설정이 재설정됩니다. 또는 **마더보드의 점퍼**를 조정하여 특정 핀을 연결함으로써 이러한 설정을 재설정할 수 있습니다.

하드웨어 조정이 불가능하거나 실용적이지 않은 상황에서는 **소프트웨어 도구**가 해결책을 제공합니다. **Kali Linux**와 같은 배포판으로 **Live CD/USB**에서 시스템을 실행하면 **_killCmos_** 및 **_CmosPWD_**와 같은 도구에 접근할 수 있어 BIOS 비밀번호 복구를 도와줍니다.

BIOS 비밀번호가 알려지지 않은 경우, 잘못 입력하면 일반적으로 **세 번**의 오류 코드가 발생합니다. 이 코드는 [https://bios-pw.org](https://bios-pw.org)와 같은 웹사이트에서 사용 가능한 비밀번호를 검색하는 데 사용할 수 있습니다.

### UEFI 보안

전통적인 BIOS 대신 **UEFI**를 사용하는 현대 시스템의 경우, **chipsec** 도구를 사용하여 UEFI 설정을 분석하고 수정할 수 있으며, **Secure Boot**를 비활성화할 수 있습니다. 이는 다음 명령어로 수행할 수 있습니다:

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM 분석 및 콜드 부트 공격

RAM은 전원이 차단된 후 잠시 동안 데이터를 유지하며, 보통 **1~2분** 동안 지속됩니다. 이 지속성은 액체 질소와 같은 차가운 물질을 적용하여 **10분**으로 연장할 수 있습니다. 이 연장된 기간 동안 **메모리 덤프**를 생성하여 **dd.exe** 및 **volatility**와 같은 도구로 분석할 수 있습니다.

### 직접 메모리 접근(DMA) 공격

**INCEPTION**은 **물리적 메모리 조작**을 위한 도구로, **FireWire** 및 **Thunderbolt**와 같은 인터페이스와 호환됩니다. 이는 메모리를 패치하여 어떤 비밀번호도 수용하도록 하여 로그인 절차를 우회할 수 있게 합니다. 그러나 **Windows 10** 시스템에는 효과적이지 않습니다.

### 시스템 접근을 위한 Live CD/USB

**_sethc.exe_** 또는 **_Utilman.exe_**와 같은 시스템 바이너리를 **_cmd.exe_**의 복사본으로 변경하면 시스템 권한으로 명령 프롬프트에 접근할 수 있습니다. **chntpw**와 같은 도구를 사용하여 Windows 설치의 **SAM** 파일을 편집하여 비밀번호를 변경할 수 있습니다.

**Kon-Boot**는 Windows 커널 또는 UEFI를 일시적으로 수정하여 비밀번호를 모른 채 Windows 시스템에 로그인할 수 있도록 하는 도구입니다. 더 많은 정보는 [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)에서 확인할 수 있습니다.

### Windows 보안 기능 처리

#### 부팅 및 복구 단축키

- **Supr**: BIOS 설정에 접근합니다.
- **F8**: 복구 모드로 들어갑니다.
- Windows 배너 후 **Shift**를 누르면 자동 로그인을 우회할 수 있습니다.

#### BAD USB 장치

**Rubber Ducky** 및 **Teensyduino**와 같은 장치는 **bad USB** 장치를 생성하기 위한 플랫폼으로, 대상 컴퓨터에 연결될 때 미리 정의된 페이로드를 실행할 수 있습니다.

#### 볼륨 섀도 복사

관리자 권한을 통해 PowerShell을 사용하여 **SAM** 파일을 포함한 민감한 파일의 복사본을 생성할 수 있습니다.

### BitLocker 암호화 우회

BitLocker 암호화는 **메모리 덤프 파일**(**MEMORY.DMP**) 내에서 **복구 비밀번호**를 찾으면 우회할 수 있습니다. 이를 위해 **Elcomsoft Forensic Disk Decryptor** 또는 **Passware Kit Forensic**와 같은 도구를 사용할 수 있습니다.

### 복구 키 추가를 위한 사회 공학

사회 공학 전술을 통해 새로운 BitLocker 복구 키를 추가할 수 있으며, 사용자가 새로운 복구 키를 추가하는 명령을 실행하도록 설득하여 복호화 과정을 단순화할 수 있습니다.
{{#include ../banners/hacktricks-training.md}}
