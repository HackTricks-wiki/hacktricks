# Physical Attacks

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}

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
{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
{% endhint %}

