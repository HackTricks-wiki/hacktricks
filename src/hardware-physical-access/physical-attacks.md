# 물리적 공격

{{#include ../banners/hacktricks-training.md}}

## BIOS 비밀번호 복구 및 시스템 보안

**BIOS 재설정**은 여러 방법으로 수행할 수 있습니다. 대부분의 마더보드는 **배터리**를 포함하고 있으며, 이를 약 **30분** 동안 제거하면 비밀번호를 포함한 BIOS 설정이 재설정됩니다. 또는 **마더보드의 점퍼**를 조정하여 특정 핀을 연결함으로써 이러한 설정을 재설정할 수 있습니다.

하드웨어 조정이 불가능하거나 실용적이지 않은 상황에서는 **소프트웨어 도구**가 해결책을 제공합니다. **Kali Linux**와 같은 배포판으로 **Live CD/USB**에서 시스템을 실행하면 **_killCmos_** 및 **_CmosPWD_**와 같은 도구에 접근할 수 있어 BIOS 비밀번호 복구에 도움을 줄 수 있습니다.

BIOS 비밀번호가 알려지지 않은 경우, 비밀번호를 잘못 입력하면 일반적으로 **세 번**의 오류 코드가 발생합니다. 이 코드는 [https://bios-pw.org](https://bios-pw.org)와 같은 웹사이트에서 사용 가능한 비밀번호를 검색하는 데 사용할 수 있습니다.

### UEFI 보안

전통적인 BIOS 대신 **UEFI**를 사용하는 현대 시스템의 경우, 도구 **chipsec**를 사용하여 UEFI 설정을 분석하고 수정할 수 있으며, **Secure Boot**를 비활성화하는 것도 포함됩니다. 이는 다음 명령어로 수행할 수 있습니다:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM 분석 및 콜드 부트 공격

RAM은 전원이 차단된 후 **1~2분** 동안 데이터를 잠시 유지합니다. 이 지속성은 액체 질소와 같은 차가운 물질을 적용하여 **10분**으로 연장할 수 있습니다. 이 연장된 기간 동안 **메모리 덤프**를 생성할 수 있으며, 이를 위해 **dd.exe** 및 **volatility**와 같은 도구를 사용할 수 있습니다.

---

## 직접 메모리 접근(DMA) 공격

**INCEPTION**은 **물리적 메모리 조작**을 위한 도구로, **FireWire** 및 **Thunderbolt**와 같은 인터페이스와 호환됩니다. 이 도구는 메모리를 패치하여 어떤 비밀번호도 수용하도록 하여 로그인 절차를 우회할 수 있게 해줍니다. 그러나 **Windows 10** 시스템에는 효과적이지 않습니다.

---

## 시스템 접근을 위한 라이브 CD/USB

**_sethc.exe_** 또는 **_Utilman.exe_**와 같은 시스템 바이너리를 **_cmd.exe_**의 복사본으로 변경하면 시스템 권한으로 명령 프롬프트를 제공할 수 있습니다. **chntpw**와 같은 도구를 사용하여 Windows 설치의 **SAM** 파일을 편집하여 비밀번호를 변경할 수 있습니다.

**Kon-Boot**는 Windows 커널 또는 UEFI를 일시적으로 수정하여 비밀번호를 모른 채 Windows 시스템에 로그인할 수 있도록 하는 도구입니다. 더 많은 정보는 [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)에서 확인할 수 있습니다.

---

## Windows 보안 기능 처리

### 부팅 및 복구 단축키

- **Supr**: BIOS 설정에 접근합니다.
- **F8**: 복구 모드로 들어갑니다.
- Windows 배너 후 **Shift**를 누르면 자동 로그인을 우회할 수 있습니다.

### BAD USB 장치

**Rubber Ducky** 및 **Teensyduino**와 같은 장치는 **bad USB** 장치를 생성하기 위한 플랫폼으로, 대상 컴퓨터에 연결될 때 미리 정의된 페이로드를 실행할 수 있습니다.

### 볼륨 섀도 복사

관리자 권한을 통해 PowerShell을 사용하여 **SAM** 파일을 포함한 민감한 파일의 복사본을 생성할 수 있습니다.

---

## BitLocker 암호화 우회

BitLocker 암호화는 **복구 비밀번호**가 메모리 덤프 파일(**MEMORY.DMP**) 내에서 발견될 경우 우회될 수 있습니다. 이를 위해 **Elcomsoft Forensic Disk Decryptor** 또는 **Passware Kit Forensic**와 같은 도구를 사용할 수 있습니다.

---

## 복구 키 추가를 위한 사회 공학

새로운 BitLocker 복구 키는 사회 공학 전술을 통해 추가할 수 있으며, 사용자가 제로로 구성된 새로운 복구 키를 추가하는 명령을 실행하도록 설득하여 복호화 과정을 단순화합니다.

---

## 섀시 침입/유지 보수 스위치를 이용한 BIOS 공장 초기화

많은 현대 노트북 및 소형 데스크탑에는 **섀시 침입 스위치**가 포함되어 있으며, 이는 임베디드 컨트롤러(EC)와 BIOS/UEFI 펌웨어에 의해 모니터링됩니다. 스위치의 주요 목적은 장치가 열릴 때 경고를 발생시키는 것이지만, 공급업체는 때때로 스위치를 특정 패턴으로 전환할 때 트리거되는 **문서화되지 않은 복구 단축키**를 구현합니다.

### 공격 작동 방식

1. 스위치는 EC의 **GPIO 인터럽트**에 연결되어 있습니다.
2. EC에서 실행되는 펌웨어는 **누른 횟수와 타이밍**을 추적합니다.
3. 하드코딩된 패턴이 인식되면 EC는 시스템 NVRAM/CMOS의 내용을 **지우는** *mainboard-reset* 루틴을 호출합니다.
4. 다음 부팅 시 BIOS는 기본값을 로드합니다 – **관리자 비밀번호, 보안 부팅 키 및 모든 사용자 정의 구성이 지워집니다**.

> 보안 부팅이 비활성화되고 펌웨어 비밀번호가 사라지면 공격자는 외부 OS 이미지를 부팅하여 내부 드라이브에 대한 무제한 접근을 얻을 수 있습니다.

### 실제 사례 – Framework 13 노트북

Framework 13(11세대/12세대/13세대)의 복구 단축키는:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
열 번째 사이클 후에 EC는 BIOS에 다음 재부팅 시 NVRAM을 지우라는 플래그를 설정합니다. 전체 절차는 약 40초가 소요되며 **드라이버 외에는 아무것도 필요하지 않습니다**.

### 일반적인 악용 절차

1. EC가 실행되도록 대상을 전원 켜거나 일시 중지-재개합니다.
2. 하단 커버를 제거하여 침입/유지보수 스위치를 노출합니다.
3. 공급업체별 토글 패턴을 재현합니다(문서, 포럼을 참조하거나 EC 펌웨어를 리버스 엔지니어링합니다).
4. 재조립하고 재부팅합니다 – 펌웨어 보호가 비활성화되어야 합니다.
5. 라이브 USB(예: Kali Linux)를 부팅하고 일반적인 포스트 익스플로잇 작업(자격 증명 덤핑, 데이터 유출, 악성 EFI 바이너리 주입 등)을 수행합니다.

### 탐지 및 완화

* OS 관리 콘솔에서 섀시 침입 이벤트를 기록하고 예상치 못한 BIOS 재설정과 상관관계를 분석합니다.
* 열림을 감지하기 위해 나사/커버에 **변조 방지 씰**을 사용합니다.
* 장치를 **물리적으로 통제된 영역**에 보관합니다; 물리적 접근이 전체 손상을 의미한다고 가정합니다.
* 가능할 경우 공급업체의 "유지보수 스위치 재설정" 기능을 비활성화하거나 NVRAM 재설정을 위해 추가적인 암호화 인증을 요구합니다.

---

## 참고 문헌

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)

{{#include ../banners/hacktricks-training.md}}
