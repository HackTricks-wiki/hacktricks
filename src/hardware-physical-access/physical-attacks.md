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

#### Linux USB HID kernel info leak and KASLR bypass (CVE-2025-38494/38495)

Recent bugs in the Linux HID core allow a malicious USB HID device to trigger an out-of-bounds read and disclose kernel memory over the USB link. Two issues are involved:

- Validation bypass for certain raw HID request paths, allowing calls that skip the hid_hw_raw_request() wrapper and its length checks.
- Report-ID sizing mismatch when a reserved Report ID byte is assumed but the buffer is allocated without accounting for it, leading to an integer underflow and length/size inconsistencies.

Impact:

- Up to ~64 KB of data from a small kzalloc(7, GFP_KERNEL) allocation can be leaked to the device over USB, revealing kernel heap contents, pointers and potentially defeating mitigations like KASLR. Related sanitizers reported OOB reads and infoleaks in usbhid_raw_request()/usb_start_wait_urb.
- Other HID code paths may lead to more severe memory corruptions.

Practical exploitation setup (high level):

- Emulate a USB HID device and craft HID reports/requests that hit the vulnerable paths. The public PoC uses Raw Gadget on Linux to act as a device and receive leaked data from the host.
- This is a physical-access and device-emulation attack surface: it applies when a system accepts new USB HID devices (including via VM USB passthrough).

Hardening and detection:

- Update the kernel. Fixes landed in the following upstream commits:
  - HID: core: ensure the allocated report buffer can contain the reserved report ID (id 4f15ee98304b)
  - HID: core: ensure __hid_request reserves the report ID as the first byte (id 0d0777ccaa2d)
  - HID: core: do not bypass hid_hw_raw_request (id c2ca42f190b6)
- Restrict raw HID access so untrusted users or processes cannot open /dev/hidrawN:
  - Example udev rule to keep hidraw root-only:
    ```
    # /etc/udev/rules.d/99-hidraw-permissions.rules
    SUBSYSTEM=="hidraw", MODE="0600", GROUP="root"
    ```
    Reload rules: `udevadm control --reload-rules && udevadm trigger`.
  - Audit current exposure:
    ```bash
    ls -l /dev/hidraw*
    for d in /dev/hidraw*; do echo "== $d =="; udevadm info -q all -n "$d" | sed -n '1,12p'; done
    ```
- Require explicit authorization for new USB devices or enforce a default-deny posture:
  - usbcore.authorized_default=0 kernel parameter (or runtime via `/sys/module/usbcore/parameters/authorized_default` on some distros)
  - Deploy USBGuard to allow-list devices:
    ```bash
    sudo apt-get install usbguard
    sudo usbguard generate-policy -U | sudo tee /etc/usbguard/rules.conf
    sudo systemctl enable --now usbguard
    ```
- In virtualized environments, avoid exposing host USB devices to sensitive VMs unless strictly required.

References and PoC context:

- Trigger and discussion with syzbot reports and fixes: https://github.com/xairy/kernel-exploits/tree/master/CVE-2025-38494
- Raw Gadget device emulation required for the public trigger.

### Volume Shadow Copy

Administrator privileges allow for the creation of copies of sensitive files, including the **SAM** file, through PowerShell.

---

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

## References

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [xairy/kernel-exploits – CVE-2025-38494/38495 HID core info leak trigger](https://github.com/xairy/kernel-exploits/tree/master/CVE-2025-38494)
- [KASAN/KMSAN bug reports (syzkaller) referenced by PoC](https://syzkaller.appspot.com/bug?extid=fbe9fff1374eefadffb9)
- [HID: core fixes upstream (report-ID sizing, request validation, wrapper enforcement)](https://lore.kernel.org/linux-cve-announce/2025072818-CVE-2025-38494-63e4@gregkh/)

{{#include ../banners/hacktricks-training.md}}