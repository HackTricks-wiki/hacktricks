# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

**Resetting the BIOS** can be achieved in several ways. Most motherboards include a **battery** that, when removed for around **30 minutes**, will reset the BIOS settings, including the password. Alternatively, a **jumper on the motherboard** can be adjusted to reset these settings by connecting specific pins.

For situations where hardware adjustments are not possible or practical, **software tools** offer a solution. Running a system from a **Live CD/USB** with distributions like **Kali Linux** provides access to tools like **_killCmos_** and **_CmosPWD_**, which can assist in BIOS password recovery.

In cases where the BIOS password is unknown, entering it incorrectly **three times** will typically result in an error code. This code can be used on websites like [https://bios-pw.org](https://bios-pw.org) to potentially retrieve a usable password.

### UEFI Security

For modern systems using **UEFI** instead of traditional BIOS, the tool **chipsec** can be utilized to analyze and modify UEFI settings, including the disabling of **Secure Boot**. This can be accomplished with the following command:

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM Analysis and Cold Boot Attacks

RAM retains data briefly after power is cut, usually for **1 to 2 minutes**. This persistence can be extended to **10 minutes** by applying cold substances, such as liquid nitrogen. During this extended period, a **memory dump** can be created using tools like **dd.exe** and **volatility** for analysis.

### Direct Memory Access (DMA) Attacks

**INCEPTION** is a tool designed for **physical memory manipulation** through DMA, compatible with interfaces like **FireWire** and **Thunderbolt**. It allows for bypassing login procedures by patching memory to accept any password. However, it's ineffective against **Windows 10** systems.

### Live CD/USB for System Access

Changing system binaries like **_sethc.exe_** or **_Utilman.exe_** with a copy of **_cmd.exe_** can provide a command prompt with system privileges. Tools such as **chntpw** can be used to edit the **SAM** file of a Windows installation, allowing password changes.

**Kon-Boot** is a tool that facilitates logging into Windows systems without knowing the password by temporarily modifying the Windows kernel or UEFI. More information can be found at [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Handling Windows Security Features

#### Boot and Recovery Shortcuts

- **Supr**: Access BIOS settings.
- **F8**: Enter Recovery mode.
- Pressing **Shift** after the Windows banner can bypass autologon.

#### BAD USB Devices

Devices like **Rubber Ducky** and **Teensyduino** serve as platforms for creating **bad USB** devices, capable of executing predefined payloads when connected to a target computer.

#### Volume Shadow Copy

Administrator privileges allow for the creation of copies of sensitive files, including the **SAM** file, through PowerShell.

### Bypassing BitLocker Encryption

BitLocker encryption can potentially be bypassed if the **recovery password** is found within a memory dump file (**MEMORY.DMP**). Tools like **Elcomsoft Forensic Disk Decryptor** or **Passware Kit Forensic** can be utilized for this purpose.

### Social Engineering for Recovery Key Addition

A new BitLocker recovery key can be added through social engineering tactics, convincing a user to execute a command that adds a new recovery key composed of zeros, thereby simplifying the decryption process.

---

### Offensive Network Implant Devices (Shark Jack, RaspyJack, LAN Turtle…)

Small, head-less “plug-and-pwn” boards that expose an Ethernet (or USB-Ethernet) interface are extremely handy when you only have a few seconds of physical access to a wired network drop. Once connected they can automatically obtain an IP address, run predefined payloads, and exfiltrate loot over Wi-Fi or store it locally for later retrieval.

#### RaspyJack ‑ DIY Shark Jack clone built around Raspberry Pi Zero 2 W

**Key Features**

* Menu-driven UI on a Waveshare 1.44'' TFT (joystick + 3 buttons)
* Fully customisable `nmap` recon scans (any flags, arbitrary target ranges)
* One-tap reverse-shell payloads (Bash / Python) with local or remote listener selection
* Credential-capture modules:
  * LLMNR / NetBIOS-NS poisoning via **Responder** to grab NTLMv2 hashes
  * ARP MITM using **arpspoof** + **tcpdump** for packet capture
  * DNS-spoof phishing via **dnsspoof** to transparently redirect victims
* On-device loot viewer (Nmap, Responder, dnsspoof logs) + lightweight file browser
* Theme editor, config back-up/restore, UI restart and safe shutdown menu
* Drop-in support for custom Python scripts (`payloads/` directory)

**Required Hardware**

* Raspberry Pi Zero 2 W (or Pi Zero W + Ethernet/USB HAT)
* Waveshare 1.44'' SPI TFT LCD HAT (includes joystick & 3 push buttons)
* micro-SD card flashed with Raspberry Pi OS Lite (32-bit)

**Initial Setup** (run as **root** after enabling SSH):

```bash
sudo apt update && sudo apt install git -y
cd /root
git clone https://github.com/7h30th3r0n3/raspyjack.git
mv raspyjack Raspyjack
cd Raspyjack
chmod +x install_raspyjack.sh
./install_raspyjack.sh
reboot
```

**Updating** (back-up any loot in `/root/Raspyjack/loot/` first):

```bash
cd /root
rm -rf Raspyjack
git clone https://github.com/7h30th3r0n3/raspyjack.git
mv raspyjack Raspyjack
reboot
```

Boot-to-menu time on a Pi Zero 2 W is ~22 seconds, which makes RaspyJack perfect for quick “hit-and-run” red-team drops.

#### Other Commercial Alternatives

* **Hak5 Shark Jack** – BusyBox-based implant with switch-selectable payload modes
* **Hak5 LAN Turtle / Packet Squirrel** – USB-Ethernet adapters offering persistent SSH, AutoSSH reverse tunnels, tcpdump capture and more

RaspyJack replicates much of the above functionality using inexpensive, easily replaceable off-the-shelf hardware while remaining 100 % open-source.

## References

* [RaspyJack ‑ GitHub repository](https://github.com/7h30th3r0n3/Raspyjack)

{{#include ../banners/hacktricks-training.md}}
