# 물리적 공격

{{#include ../banners/hacktricks-training.md}}

## BIOS 비밀번호 복구 및 시스템 보안

**BIOS 재설정**은 여러 방법으로 수행할 수 있습니다. 대부분의 마더보드에는 약 **30분** 동안 제거하면 비밀번호를 포함한 BIOS 설정을 초기화하는 **배터리**가 있습니다. 또는 특정 핀을 연결하여 설정을 초기화할 수 있도록 마더보드의 **점퍼**를 조정할 수 있습니다.

하드웨어 조정이 불가능하거나 현실적이지 않은 상황에서는 **소프트웨어 도구**가 해결책이 될 수 있습니다. **Live CD/USB**로 시스템을 부팅하고 **Kali Linux**와 같은 배포판을 사용하면 **_killCmos_** 및 **_CmosPWD_**와 같은 도구에 접근하여 BIOS 비밀번호 복구를 도울 수 있습니다.

BIOS 비밀번호를 모르는 경우, 틀려서 입력을 **세 번** 하면 일반적으로 오류 코드가 발생합니다. 이 코드는 [https://bios-pw.org](https://bios-pw.org) 같은 웹사이트에서 사용해 사용 가능한 비밀번호를 얻을 수 있습니다.

### UEFI 보안

전통적인 BIOS 대신 **UEFI**를 사용하는 최신 시스템에서는 도구 **chipsec**을 사용해 UEFI 설정을 분석하고 수정할 수 있으며, **Secure Boot** 비활성화도 포함됩니다. 이는 다음 명령으로 수행할 수 있습니다:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM 분석 및 Cold Boot Attacks

RAM은 전원이 차단된 후에도 보통 **1 to 2 minutes** 동안 데이터를 유지합니다. 액체 질소와 같은 냉각 물질을 적용하면 이 지속시간을 **10 minutes**까지 연장할 수 있습니다. 이 연장된 기간 동안 **dd.exe**와 **volatility** 같은 도구를 사용하여 분석을 위한 **memory dump**를 생성할 수 있습니다.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION**은 DMA를 통해 물리적 메모리 조작을 목적으로 설계된 도구로, **FireWire**나 **Thunderbolt** 같은 인터페이스와 호환됩니다. 메모리를 패치하여 어떤 비밀번호든 통과시키도록 함으로써 로그인 절차를 우회할 수 있습니다. 다만 **Windows 10** 시스템에는 효과가 없습니다.

---

## Live CD/USB for System Access

**_sethc.exe_**나 **_Utilman.exe_** 같은 시스템 바이너리를 **_cmd.exe_** 복사본으로 교체하면 시스템 권한의 명령 프롬프트를 얻을 수 있습니다. **chntpw** 같은 도구를 사용해 Windows 설치의 **SAM** 파일을 편집하여 비밀번호를 변경할 수 있습니다.

**Kon-Boot**은 Windows 커널이나 UEFI를 일시적으로 수정하여 비밀번호를 모른 채로 Windows에 로그인할 수 있게 해주는 도구입니다. More information can be found at [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: BIOS 설정에 접근합니다.
- **F8**: Recovery 모드로 진입합니다.
- Windows 배너 이후 **Shift**를 누르면 autologon을 우회할 수 있습니다.

### BAD USB Devices

**Rubber Ducky**와 **Teensyduino** 같은 장치는 **bad USB** 장치를 만드는 플랫폼으로 사용되며, 타깃 컴퓨터에 연결되면 미리 정의된 페이로드를 실행할 수 있습니다.

### Volume Shadow Copy

관리자 권한으로 PowerShell을 통해 **SAM** 파일을 포함한 민감한 파일의 복사본을 생성할 수 있습니다.

---

## Bypassing BitLocker Encryption

BitLocker 암호화는 **recovery password**가 메모리 덤프 파일(**MEMORY.DMP**)에서 발견되면 잠재적으로 우회될 수 있습니다. **Elcomsoft Forensic Disk Decryptor**나 **Passware Kit Forensic** 같은 도구를 사용할 수 있습니다.

---

## Social Engineering for Recovery Key Addition

사용자에게 0으로 구성된 새 복구 키를 추가하는 명령을 실행하도록 설득하는 등의 소셜 엔지니어링 전술을 통해 BitLocker 복구 키를 추가할 수 있으며, 이렇게 하면 복호화 과정이 단순해집니다.

---

## Exploiting Chassis Intrusion / Maintenance Switches to Factory-Reset the BIOS

많은 최신 노트북 및 소형 폼팩터 데스크탑에는 Embedded Controller (EC)와 BIOS/UEFI 펌웨어가 모니터링하는 **chassis-intrusion switch**가 포함되어 있습니다. 스위치의 주된 목적은 장치가 열렸을 때 경고를 발생시키는 것이지만, 제조업체는 때때로 스위치가 특정 패턴으로 토글될 때 트리거되는 **undocumented recovery shortcut**을 구현하기도 합니다.

### How the Attack Works

1. 스위치는 EC의 **GPIO interrupt**에 연결되어 있습니다.
2. EC에서 실행되는 펌웨어는 **timing and number of presses**를 기록합니다.
3. 하드코딩된 패턴이 인식되면 EC는 *mainboard-reset* 루틴을 호출하여 **시스템 NVRAM/CMOS의 내용을 지웁니다**.
4. 다음 부팅에서 BIOS는 기본값을 로드합니다 – **supervisor password, Secure Boot keys, and all custom configuration are cleared**.

> Secure Boot가 비활성화되고 펌웨어 비밀번호가 제거되면, 공격자는 단순히 외부 OS 이미지를 부팅해 내부 드라이브에 대한 무제한 접근을 얻을 수 있습니다.

### Real-World Example – Framework 13 Laptop

The recovery shortcut for the Framework 13 (11th/12th/13th-gen) is:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
열 번째 사이클 이후 EC는 다음 부팅 때 BIOS에 NVRAM을 초기화하도록 지시하는 플래그를 설정합니다. 전체 절차는 ~40 s가 걸리며 **드라이버 하나만 있으면 됩니다**.

### 일반 악용 절차

1. 대상의 전원을 켜거나 suspend-resume하여 EC가 동작하도록 만듭니다.
2. 바닥 커버를 제거해 intrusion/maintenance 스위치를 노출시킵니다.
3. 공급업체별 토글 패턴을 재현합니다(문서, 포럼을 참조하거나 EC firmware를 리버스엔지니어링).
4. 다시 조립하고 재부팅합니다 – firmware 보호 기능이 비활성화되어 있어야 합니다.
5. Live USB(예: Kali Linux)로 부팅한 후 일반적인 post-exploitation(credential dumping, data exfiltration, 악성 EFI 바이너리 설치 등)을 수행합니다.

### 탐지 및 완화

* OS 관리 콘솔에 chassis-intrusion 이벤트를 기록하고 예기치 않은 BIOS 리셋과 상관관계를 확인합니다.
* 나사/커버에 **tamper-evident seals**를 사용하여 개봉을 감지합니다.
* 장치를 **physically controlled areas**에 보관하십시오; 물리적 접근은 완전한 침해와 같다고 가정합니다.
* 가능한 경우 공급업체의 “maintenance switch reset” 기능을 비활성화하거나 NVRAM 리셋에 대해 추가적인 암호화 인증을 요구합니다.

---

## Covert IR Injection Against No-Touch Exit Sensors

### 센서 특성
- 일반적인 “wave-to-exit” 센서는 near-IR LED 발광부와 TV-remote 스타일 수신 모듈을 쌍으로 사용하며, 올바른 캐리어(≈30 kHz)의 펄스를 여러 번(~4–10) 감지한 뒤에만 logic high를 보고합니다.
- 플라스틱 shroud는 발신기와 수신기가 서로를 직접 보지 못하게 하므로 컨트롤러는 검증된 캐리어가 근처 반사에서 온 것으로 가정하고 도어 스트라이크를 여는 릴레이를 구동합니다.
- 컨트롤러가 대상이 존재한다고 판단하면 종종 출력 변조(envelope)를 변경하지만, 수신기는 필터된 캐리어에 맞는 어떤 burst도 계속 수용합니다.

### 공격 워크플로
1. **방출 프로파일 캡처** – controller 핀에 logic analyser를 연결하여 내부 IR LED를 구동하는 pre-detection 및 post-detection 파형을 기록합니다.
2. **오직 “post-detection” 파형만 재생** – 기본 발신기를 제거하거나 무시하고, 처음부터 이미 트리거된 패턴으로 외부 IR LED를 구동합니다. 수신기는 펄스 수/주파수만 중요하게 생각하기 때문에 스푸핑된 캐리어를 진짜 반사로 간주하고 릴레이 라인을 활성화합니다.
3. **전송을 게이팅** – 캐리어를 조정된 burst로 전송(예: 수십 밀리초 on, 유사한 off)하여 수신기의 AGC나 간섭 처리 로직을 포화시키지 않고 최소 펄스 수를 전달합니다. 연속 방출은 센서를 빠르게 둔감하게 해 릴레이가 동작하지 않게 만듭니다.

### 장거리 반사 주입
- 벤치용 LED를 고출력 IR 다이오드, MOSFET 드라이버, 집광 광학으로 교체하면 ~6 m 거리에서 신뢰성 있게 트리거할 수 있습니다.
- 공격자는 수신기 개구부에 대한 직접 시야가 필요하지 않습니다; 유리를 통해 보이는 실내 벽면, 선반, 문틀 등을 조준하면 반사된 에너지가 약 30°의 시야각으로 들어와 근거리 손 흔들기와 유사한 효과를 냅니다.
- 수신기는 약한 반사만을 예상하기 때문에 훨씬 강한 외부 빔이 여러 표면에서 반사되어도 여전히 검출 임계값을 넘을 수 있습니다.

### 무장화된 공격용 토치
- 상용 손전등 내부에 드라이버를 내장하면 도구를 평범한 물건으로 숨길 수 있습니다. 가시 LED를 수신기 밴드에 맞는 고출력 IR LED로 교체하고, ≈30 kHz 펄스를 생성하기 위해 ATtiny412(또는 유사)를 추가하며, LED 전류를 싱크하기 위해 MOSFET을 사용합니다.
- 망원 줌 렌즈는 사거리/정밀도를 위해 빔을 좁히고, MCU 제어 하의 진동 모터는 가시광을 방출하지 않고도 변조가 활성화되었음을 햅틱으로 확인시켜줍니다.
- 약간씩 다른 캐리어 주파수와 envelopes를 가진 여러 저장된 변조 패턴을 순환하면 리브랜딩된 센서군 전반과의 호환성이 높아져, 연산자가 릴레이의 클릭 소리가 날 때까지 반사 표면을 스윕할 수 있습니다.

---

## References

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)

{{#include ../banners/hacktricks-training.md}}
