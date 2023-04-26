# Physical Attacks

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## BIOS password

### The battery

Most of the **motherbords** have a **battery**. If you **remove** it **30min** the settings of the BIOS will be **restarted** (password included).

### Jumper CMOS

Most of the **motherboards** have a **jumper** that can restart the settings. This jumper connects a central pin with another, if you **connect thoses pins the motherbord will be reseted**.

### Live Tools

If you could **run** for example a **Kali** Linux from a Live CD/USB you could use tools like _**killCmos**_ or _**CmosPWD**_ (this last one is included in Kali) you could try to **recover the password of the BIOS**.

### Online BIOS password recovery

Put the password of the BIOS **3 times wrong**, then the BIOS will **show an error messag**e and it will be blocked.\
Visit the page [https://bios-pw.org](https://bios-pw.org) and **introduce the error code** shown by the BIOS and you could be lucky and get a **valid password** (the **same search could show you different passwords and more than 1 could be valid**).

## UEFI

To check the settings of the UEFI and perform some kind of attack you should try [chipsec](https://github.com/chipsec/chipsec/blob/master/chipsec-manual.pdf).\
Using this tool you could easily disable the Secure Boot:

```
python chipsec_main.py -module exploits.secure.boot.pk
```

## RAM

### Cold boot

The **RAM memory is persistent from 1 to 2 minutes** from the time the computer is powered off. If you apply **cold** (liquid nitrogen, for example) on the memory card you can extend this time up to **10 minutes**.

Then, you can do a **memory dump** (using tools like dd.exe, mdd.exe, Memoryze, win32dd.exe or DumpIt) to analyze the memory.

You should **analyze** the memory **using volatility**.

### [INCEPTION](https://github.com/carmaa/inception)

Inception is a **physical memory manipulation** and hacking tool exploiting PCI-based DMA. The tool can attack over **FireWire**, **Thunderbolt**, **ExpressCard**, PC Card and any other PCI/PCIe HW interfaces.\
**Connect** your computer to the victim computer over one of those **interfaces** and **INCEPTION** will try to **patch** the **pyshical memory** to give you **access**.

**If INCEPTION succeeds, any password introduced will be vaid.**

**It doesn't work with Windows10.**

## Live CD/USB

### Sticky Keys and more

* **SETHC:** _sethc.exe_ is invoked when SHIFT is pressed 5 times
* **UTILMAN:** _Utilman.exe_ is invoked by pressing WINDOWS+U
* **OSK:** _osk.exe_ is invoked by pressing WINDOWS+U, then launching the on-screen keyboard
* **DISP:** _DisplaySwitch.exe_ is invoked by pressing WINDOWS+P

These binaries are located inside _**C:\Windows\System32**_. You can **change** any of them for a **copy** of the binary **cmd.exe** (also in the same folder) and any time that you invoke any of those binaries a command prompt as **SYSTEM** will appear.

### Modifying SAM

You can use the tool _**chntpw**_ to **modify the** _**SAM**_ **file** of a mounted Windows filesystem. Then, you could change the password of the Administrator user, for example.\
This tool is available in KALI.

```
chntpw -h
chntpw -l <path_to_SAM>
```

**Inside a Linux system you could modify the** _**/etc/shadow**_ **or** _**/etc/passwd**_ **file.**

### **Kon-Boot**

**Kon-Boot** is one of the best tools around which can log you into Windows without knowing the password. It works by **hooking into the system BIOS and temporarily changing the contents of the Windows kernel** while booting (new versions work also with **UEFI**). It then allows you to enter **anything as the password** during login. The next time you start the computer without Kon-Boot, the original password will be back, the temporary changes will be discarded and the system will behave as if nothing has happened.\
Read More: [https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)

It is a live CD/USB that can **patch the memory** so you **won't need to know the password to login**.\
Kon-Boot also performs the **StickyKeys** trick so you could press _**Shift**_ **5 times to get an Administrator cmd**.

## **Running Windows**

### Initial shortcuts

### Booting shortcuts

* supr - BIOS
* f8 - Recovery mode
* _supr_ - BIOS ini
* _f8_ - Recovery mode
* _Shitf_ (after the windows banner) - Go to login page instead of autologon (avoid autologon)

### **BAD USBs**

#### **Rubber Ducky tutorials**

* [Tutorial 1](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Tutorials)
* [Tutorial 2](https://blog.hartleybrody.com/rubber-ducky-guide/)

#### **Teensyduino**

* [Payloads and tutorials](https://github.com/Screetsec/Pateensy)

There are also tons of tutorials about **how to create your own bad USB**.

### Volume Shadow Copy

With administrators privileges and powershell you could make a copy of the SAM file.[ See this code](../windows-hardening/basic-powershell-for-pentesters/#volume-shadow-copy).

## Bypassing Bitlocker

Bitlocker uses **2 passwords**. The one used by the **user**, and the **recovery** password (48 digits).

If you are lucky and inside the current session of Windows exists the file _**C:\Windows\MEMORY.DMP**_ (It is a memory dump) you could try to **search inside of it the recovery password**. You can **get this file** and a **copy of the filesytem** and then use _Elcomsoft Forensic Disk Decryptor_ to get the content (this will only work if the password is inside the memory dump). You could also **force the memory dump** using _**NotMyFault**_ of _Sysinternals,_ but this will reboot the system and has to be executed as Administrator.

You could also try a **bruteforce attack** using _**Passware Kit Forensic**_.

### Social Engineering

Finally, you could make the user add a new recovery password making him executed as administrator:

```bash
schtasks /create /SC ONLOGON /tr "c:/windows/system32/manage-bde.exe -protectors -add c: -rp 000000-000000-000000-000000-000000-000000-000000-000000" /tn tarea /RU SYSTEM /f
```

This will add a new recovery key (composed of 48 zeros) in the next login.

To check the valid recovery keys you can execute:

```
manage-bde -protectors -get c:
```

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
