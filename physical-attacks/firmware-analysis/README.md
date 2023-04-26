# Firmware Analysis

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introduction

Firmware is a type of software that provides communication and control over a device’s hardware components. It’s the first piece of code that a device runs. Usually, it **boots the operating system** and provides very specific runtime services for programs by **communicating with various hardware components**. Most, if not all, electronic devices have firmware.

Devices store firmware in **nonvolatile memory**, such as ROM, EPROM, or flash memory.

It’s important to **examine** the **firmware** and then attempt to **modify** it, because we can uncover many security issues during this process.

## **Information gathering and reconnaissance**

During this stage, collect as much information about the target as possible to understand its overall composition underlying technology. Attempt to gather the following:

* Supported CPU architecture(s)
* Operating system platform
* Bootloader configurations
* Hardware schematics
* Datasheets
* Lines-of-code (LoC) estimates
* Source code repository location
* Third-party components
* Open source licenses (e.g. GPL)
* Changelogs
* FCC IDs
* Design and data flow diagrams
* Threat models
* Previous penetration testing reports
* Bug tracking tickets (e.g. Jira and bug bounty platforms such as BugCrowd or HackerOne)

Where possible, acquire data using open source intelligence (OSINT) tools and techniques. If open source software is used, download the repository and perform both manual as well as automated static analysis against the code base. Sometimes, open source software projects already use free static analysis tools provided by vendors that provide scan results such as [Coverity Scan](https://scan.coverity.com) and [Semmle’s LGTM](https://lgtm.com/#explore).

## Getting the Firmware

There are different ways with different difficulty levels to download the firmware

* **Directly** from the development team, manufacturer/vendor or client
* **Build from scratch** using walkthroughs provided by the manufacturer
* From the **vendor's support site**
* **Google dork** queries targeted towards binary file extensions and file sharing platforms such as Dropbox, Box, and Google drive
  * It’s common to come across firmware images through customers who upload contents to forums, blogs, or comment on sites where they contacted the manufacturer to troubleshoot an issue and were given firmware via a zip or flash drive sent.
  * Example: `intitle:"Netgear" intext:"Firmware Download"`
* Download builds from exposed cloud provider storage locations such as Amazon Web Services (AWS) S3 buckets (with tools such as [https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner))
* **Man-in-the-middle** (MITM) device communication during **updates**
* Extract directly **from hardware** via **UART**, **JTAG**, **PICit**, etc.
* Sniff **serial communication** within hardware components for **update server requests**
* Via a **hardcoded endpoint** within the mobile or thick applications
* **Dumping** firmware from the **bootloader** (e.g. U-boot) to flash storage or over the **network** via **tftp**
* Removing the **flash chip** (e.g. SPI) or MCU from the board for offline analysis and data extraction (LAST RESORT).
  * You will need a supported chip programmer for flash storage and/or the MCU.

## Analyzing the firmware

Now that you **have the firmware**, you need to extract information about it to know how to treat it. Different tools you can use for that:

```bash
file <bin>  
strings -n8 <bin> 
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out  
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

If you don't find much with those tools check the **entropy** of the image with `binwalk -E <bin>`, if low entropy, then it's not likely to be encrypted. If high entropy, Its likely encrypted (or compressed in some way).

Moreover, you can use these tools to extract **files embedded inside the firmware**:

{% content-ref url="../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) to inspect the file.

### Getting the Filesystem

With the previous commented tools like `binwalk -ev <bin>` you should have been able to **extract the filesystem**.\
Binwalk usually extracts it inside a **folder named as the filesystem type**, which usually is one of the following: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Sometimes, binwalk will **not have the magic byte of the filesystem in its signatures**. In these cases, use binwalk to **find the offset of the filesystem and carve the compressed filesystem** from the binary and **manually extract** the filesystem according to its type using the steps below.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Run the following **dd command** carving the Squashfs filesystem.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs 

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Alternatively, the following command could also be run.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* For squashfs (used in the example above)

`$ unsquashfs dir.squashfs`

Files will be in "`squashfs-root`" directory afterwards.

* CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* For jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

* For ubifs filesystems with NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Analyzing the Filesystem

Now that you have the filesystem is time to start looking for bad practices such as:

* Legacy **insecure network daemons** such as telnetd (sometimes manufactures rename binaries to disguise )
* **Hardcoded credentials** (usernames, passwords, API keys, SSH keys, and backdoor variants )
* **Hardcoded API** endpoints and backend server details
* **Update server functionality** that could be used as an entry point
* **Review uncompiled code and start up scripts** for remote code execution
* **Extract compiled binaries** to be used for offline analysis with a disassembler for future steps

Some **interesting things to look** for inside the firmware:

* etc/shadow and etc/passwd
* list out the etc/ssl directory
* search for SSL related files such as .pem, .crt, etc.
* search for configuration files
* look for script files
* search for other .bin files
* look for keywords such as admin, password, remote, AWS keys, etc.
* search for common web servers used on IoT devices
* search for common binaries such as ssh, tftp, dropbear, etc.
* search for banned c functions
* search for common command injection vulnerable functions
* search for URLs, email addresses and IP addresses
* and more…

Tools that search for this kind of information (even if you always should take a manual look and get comfortable with the filesystem structure, the tools can help you finding **hidden things**):

* [**LinPEAS**](https://github.com/carlospolop/PEASS-ng)**:** Awesome bash script that in this case is useful for searching **sensitive information** inside the filesystem. Just **chroot inside the firmware filesystem and run it**.
* [**Firmwalker**](https://github.com/craigz28/firmwalker)**:** Bash script to search for potential sensitive information
* [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core):
  * Identification of software components such as operating system, CPU architecture, and third-party components along with their associated version information
  * Extraction of firmware filesystem (s ) from images
  * Detection of certificates and private keys
  * Detection of weak implementations mapping to Common Weakness Enumeration (CWE)
  * Feed & signature-based detection of vulnerabilities
  * Basic static behavioral analysis
  * Comparison (diff) of firmware versions and files
  * User mode emulation of filesystem binaries using QEMU
  * Detection of binary mitigations such as NX, DEP, ASLR, stack canaries, RELRO, and FORTIFY\_SOURCE
  * REST API
  * and more...
* [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer): FwAnalyzer is a tool to analyze (ext2/3/4), FAT/VFat, SquashFS, UBIFS filesystem images, cpio archives, and directory content using a set of configurable rules.
* [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep): A Free Software IoT Firmware Security Analysis Tool
* [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go): This is a complete rewrite of the original ByteSweep project in Go.
* [**EMBA**](https://github.com/e-m-b-a/emba): _EMBA_ is designed as the central firmware analysis tool for penetration testers. It supports the complete security analysis process starting with the _firmware extraction_ process, doing _static analysis_ and _dynamic analysis_ via emulation and finally generating a report. _EMBA_ automatically discovers possible weak spots and vulnerabilities in firmware. Examples are insecure binaries, old and outdated software components, potentially vulnerable scripts or hard-coded passwords.

{% hint style="warning" %}
Inside the filesystem you can also find **source code** of programs (that you should always **check**), but also **compiled binaries**. These programs might be somehow exposed and you should **decompile** and **check** them for potential vulnerabilities.

Tools like [**checksec.sh**](https://github.com/slimm609/checksec.sh) can be useful to find unprotected binaries. For Windows binaries you could use [**PESecurity**](https://github.com/NetSPI/PESecurity).
{% endhint %}

## Emulating Firmware

The idea to emulate the Firmware is to be able to perform a **dynamic analysis** of the device **running** or of a **single program**.

{% hint style="info" %}
At times, partial or full emulation **may not work due to a hardware or architecture dependencies**. If the architecture and endianness match a device owned such as a raspberry pie, the root filesystem or specific binary can be transferred to the device for further testing. This method also applies to pre built virtual machines using the same architecture and endianness as the target.
{% endhint %}

### Binary Emulation

If you just want to emulate one program to search for vulnerabilities, you first need to identify its endianness and the CPU architecture for which it was compiled.

#### MIPS example

```bash
file ./squashfs-root/bin/busybox
./squashfs-root/bin/busybox: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
```

Now you can **emulate** the busybox executable using **QEMU**.

```bash
 sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Because the executable **is** compiled for **MIPS** and follow the **big-endian** byte ordering, we’ll use QEMU’s **`qemu-mips`** emulator. To emulate **little-endian** executables, we would have to select the emulator with the `el` suffix(`qemu-mipsel`):

```bash
qemu-mips -L ./squashfs-root/ ./squashfs-root/bin/ls
100              100.7z           15A6D2.squashfs  squashfs-root    squashfs-root-0
```

#### ARM Example

```bash
file bin/busybox                
bin/busybox: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-armhf.so.1, no section header
```

Emulation:

```bash
qemu-arm -L ./squashfs-root/ ./squashfs-root/bin/ls
1C00000.squashfs  B80B6C            C41DD6.xz         squashfs-root     squashfs-root-0
```

### Full System Emulation

There are several tools, based in **qemu** in general, that will allow you to emulate the complete firmware:

* [**https://github.com/firmadyne/firmadyne**](https://github.com/firmadyne/firmadyne)**:**
  * You need to install several things, configure postgres, then run the extractor.py script to extract the firmware, use the getArch.sh script to get the architecture. Then, use tar2db.py and makeImage.sh scripts to store information from the extracted image in the database and generate a QEMU image that we can emulate. The, use inferNetwork.sh script to get the network interfaces, and finally use the run.sh script, which is automatically created in the ./scratch/1/folder.
* [**https://github.com/attify/firmware-analysis-toolkit**](https://github.com/attify/firmware-analysis-toolkit)**:**
  * This tool depends on firmadyne and automates the process of emulating the firmware using firmadynee. you need to configure `fat.config` before using it: `sudo python3 ./fat.py IoTGoat-rpi-2.img --qemu 2.5.0`
* [**https://github.com/therealsaumil/emux**](https://github.com/therealsaumil/emux)
* [**https://github.com/getCUJO/MIPS-X**](https://github.com/getCUJO/MIPS-X)
* [**https://github.com/qilingframework/qiling#qltool**](https://github.com/qilingframework/qiling#qltool)

## **Dynamic analysis**

In this stage you should have either a device running the firmware to attack or the firmware being emulated to attack. In any case, it's highly recommended that you also have **a shell in the OS and filesystem that is running**.

Note that some times if you are emulating the firmware **some activities inside the emulation will fail** and you might need to restart emulating it. For example, a web application might need to get information from a device the original device is integrated with but the emulation is not emulating.

You should **recheck the filesystem** as we already did in a **previous step as in the running env new information might be accessible.**

If **webpages** are exposed, reading the code and having access to them you should **test them**. In hacktricks you can find a lot of information about different web hacking techniques.

If **network services** are exposed you should try to attack them. In hacktricks you can find a lot of information about different network services hacking techniques. You could also try to fuzz them with network and protocol **fuzzers** such as [Mutiny](https://github.com/Cisco-Talos/mutiny-fuzzer), [boofuzz](https://github.com/jtpereyda/boofuzz), and [kitty](https://github.com/cisco-sas/kitty).

You should check if you can **attack the bootloader** to get a root shell:

{% content-ref url="bootloader-testing.md" %}
[bootloader-testing.md](bootloader-testing.md)
{% endcontent-ref %}

You should test if the device is doing any kind of **firmware integrity tests**, if not this would allow attackers to offer backdored firmwares, install them in devices other people owns or even deploy them remotely if there is any firmware update vulnerability:

{% content-ref url="firmware-integrity.md" %}
[firmware-integrity.md](firmware-integrity.md)
{% endcontent-ref %}

Firmware update vulnerabilities usually occurs because, the **integrity** of the **firmware** might **not** be **validated**, use **unencrypted** **network** protocols, use of **hardcoded** **credentials**, an **insecure authentication** to the cloud component that hosts the firmware, and even excessive and insecure **logging** (sensitive data), allow **physical updates** without verifications.

## **Runtime analysis**

Runtime analysis involves attaching to a running process or binary while a device is running in its normal or emulated environment. Basic runtime analysis steps are provided below:

1. `sudo chroot . ./qemu-arch -L <optionalLibPath> -g <gdb_port> <binary>`
2. Attach gdb-multiarch or use IDA to emulate the binary
3. Set breakpoints for functions identified during step 4 such as memcpy, strncpy, strcmp, etc.
4. Execute large payload strings to identify overflows or process crashes using a fuzzer
5. Move to step 8 if a vulnerability is identified

Tools that may be helpful are (non-exhaustive):

* gdb-multiarch
* [Peda](https://github.com/longld/peda)
* Frida
* ptrace
* strace
* IDA Pro
* Ghidra
* Binary Ninja
* Hopper

## **Binary Exploitation**

After identifying a vulnerability within a binary from previous steps, a proper proof-of-concept (PoC) is required to demonstrate the real-world impact and risk. Developing exploit code requires programming experience in lower level languages (e.g. ASM, C/C++, shellcode, etc.) as well as background within the particular target architecture (e.g. MIPS, ARM, x86 etc.). PoC code involves obtaining arbitrary execution on a device or application by controlling an instruction in memory.

It is not common for binary runtime protections (e.g. NX, DEP, ASLR, etc.) to be in place within embedded systems however when this happens, additional techniques may be required such as return oriented programming (ROP). ROP allows an attacker to implement arbitrary malicious functionality by chaining existing code in the target process/binary's code known as gadgets. Steps will need to be taken to exploit an identified vulnerability such as a buffer overflow by forming a ROP chain. A tool that can be useful for situations like these is Capstone's gadget finder or ROPGadget- [https://github.com/JonathanSalwan/ROPgadget](https://github.com/JonathanSalwan/ROPgadget).

Utilize the following references for further guidance:

* [https://azeria-labs.com/writing-arm-shellcode/](https://azeria-labs.com/writing-arm-shellcode/)
* [https://www.corelan.be/index.php/category/security/exploit-writing-tutorials/](https://www.corelan.be/index.php/category/security/exploit-writing-tutorials/)

## Prepared OSs to analyze Firmware

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is a distro intended to help you perform security assessment and penetration testing of Internet of Things (IoT) devices. It saves you a lot of time by providing a pre-configured environment with all the necessary tools loaded.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools.

## Vulnerable firmware to practice

To practice discovering vulnerabilities in firmware, use the following vulnerable firmware projects as a starting point.

* OWASP IoTGoat
  * [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* The Damn Vulnerable Router Firmware Project
  * [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
* Damn Vulnerable ARM Router (DVAR)
  * [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
* ARM-X
  * [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
* Azeria Labs VM 2.0
  * [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
* Damn Vulnerable IoT Device (DVID)
  * [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## References

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Trainning and Cert

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
