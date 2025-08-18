# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

### Related resources

{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}


Firmware is essential software that enables devices to operate correctly by managing and facilitating communication between the hardware components and the software that users interact with. It's stored in permanent memory, ensuring the device can access vital instructions from the moment it's powered on, leading to the operating system's launch. Examining and potentially modifying firmware is a critical step in identifying security vulnerabilities.

## **Gathering Information**

**Gathering information** is a critical initial step in understanding a device's makeup and the technologies it uses. This process involves collecting data on:

- The CPU architecture and operating system it runs
- Bootloader specifics
- Hardware layout and datasheets
- Codebase metrics and source locations
- External libraries and license types
- Update histories and regulatory certifications
- Architectural and flow diagrams
- Security assessments and identified vulnerabilities

For this purpose, **open-source intelligence (OSINT)** tools are invaluable, as is the analysis of any available open-source software components through manual and automated review processes. Tools like [Coverity Scan](https://scan.coverity.com) and [Semmle’s LGTM](https://lgtm.com/#explore) offer free static analysis that can be leveraged to find potential issues.

## **Acquiring the Firmware**

Obtaining firmware can be approached through various means, each with its own level of complexity:

- **Directly** from the source (developers, manufacturers)
- **Building** it from provided instructions
- **Downloading** from official support sites
- Utilizing **Google dork** queries for finding hosted firmware files
- Accessing **cloud storage** directly, with tools like [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercepting **updates** via man-in-the-middle techniques
- **Extracting** from the device through connections like **UART**, **JTAG**, or **PICit**
- **Sniffing** for update requests within device communication
- Identifying and using **hardcoded update endpoints**
- **Dumping** from the bootloader or network
- **Removing and reading** the storage chip, when all else fails, using appropriate hardware tools

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

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

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

- For squashfs (used in the example above)

`$ unsquashfs dir.squashfs`

Files will be in "`squashfs-root`" directory afterwards.

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- For jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- For ubifs filesystems with NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyzing Firmware

Once the firmware is obtained, it's essential to dissect it for understanding its structure and potential vulnerabilities. This process involves utilizing various tools to analyze and extract valuable data from the firmware image.

### Initial Analysis Tools

A set of commands is provided for initial inspection of the binary file (referred to as `<bin>`). These commands help in identifying file types, extracting strings, analyzing binary data, and understanding the partition and filesystem details:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

To assess the encryption status of the image, the **entropy** is checked with `binwalk -E <bin>`. Low entropy suggests a lack of encryption, while high entropy indicates possible encryption or compression.

For extracting **embedded files**, tools and resources like the **file-data-carving-recovery-tools** documentation and **binvis.io** for file inspection are recommended.

### Extracting the Filesystem

Using `binwalk -ev <bin>`, one can usually extract the filesystem, often into a directory named after the filesystem type (e.g., squashfs, ubifs). However, when **binwalk** fails to recognize the filesystem type due to missing magic bytes, manual extraction is necessary. This involves using `binwalk` to locate the filesystem's offset, followed by the `dd` command to carve out the filesystem:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Afterwards, depending on the filesystem type (e.g., squashfs, cpio, jffs2, ubifs), different commands are used to manually extract the contents.

### Filesystem Analysis

With the filesystem extracted, the search for security flaws begins. Attention is paid to insecure network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts, and compiled binaries for offline analysis.

**Key locations** and **items** to inspect include:

- **etc/shadow** and **etc/passwd** for user credentials
- SSL certificates and keys in **etc/ssl**
- Configuration and script files for potential vulnerabilities
- Embedded binaries for further analysis
- Common IoT device web servers and binaries

Several tools assist in uncovering sensitive information and vulnerabilities within the filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) for sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) for comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) for static and dynamic analysis

### Security Checks on Compiled Binaries

Both source code and compiled binaries found in the filesystem must be scrutinized for vulnerabilities. Tools like **checksec.sh** for Unix binaries and **PESecurity** for Windows binaries help identify unprotected binaries that could be exploited.

## Emulating Firmware for Dynamic Analysis

The process of emulating firmware enables **dynamic analysis** either of a device's operation or an individual program. This approach can encounter challenges with hardware or architecture dependencies, but transferring the root filesystem or specific binaries to a device with matching architecture and endianness, such as a Raspberry Pi, or to a pre-built virtual machine, can facilitate further testing.

### Emulating Individual Binaries

For examining single programs, identifying the program's endianness and CPU architecture is crucial.

#### Example with MIPS Architecture

To emulate a MIPS architecture binary, one can use the command:

```bash
file ./squashfs-root/bin/busybox
```

And to install the necessary emulation tools:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

For ARM binaries, the process is similar, with the `qemu-arm` emulator being utilized for emulation.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dynamic Analysis in Practice

At this stage, either a real or emulated device environment is used for analysis. It's essential to maintain shell access to the OS and filesystem. Emulation may not perfectly mimic hardware interactions, necessitating occasional emulation restarts. Analysis should revisit the filesystem, exploit exposed webpages and network services, and explore bootloader vulnerabilities. Firmware integrity tests are critical to identify potential backdoor vulnerabilities.

## Runtime Analysis Techniques

Runtime analysis involves interacting with a process or binary in its operating environment, using tools like gdb-multiarch, Frida, and Ghidra for setting breakpoints and identifying vulnerabilities through fuzzing and other techniques.

## Binary Exploitation and Proof-of-Concept

Developing a PoC for identified vulnerabilities requires a deep understanding of the target architecture and programming in lower-level languages. Binary runtime protections in embedded systems are rare, but when present, techniques like Return Oriented Programming (ROP) may be necessary.

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) provide pre-configured environments for firmware security testing, equipped with necessary tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is a distro intended to help you perform security assessment and penetration testing of Internet of Things (IoT) devices. It saves you a lot of time by providing a pre-configured environment with all the necessary tools loaded.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Even when a vendor implements cryptographic signature checks for firmware images, **version rollback (downgrade) protection is frequently omitted**. When the boot- or recovery-loader only verifies the signature with an embedded public key but does not compare the *version* (or a monotonic counter) of the image being flashed, an attacker can legitimately install an **older, vulnerable firmware that still bears a valid signature** and thus re-introduce patched vulnerabilities.

Typical attack workflow:

1. **Obtain an older signed image**
   * Grab it from the vendor’s public download portal, CDN or support site.
   * Extract it from companion mobile/desktop applications (e.g. inside an Android APK under `assets/firmware/`).
   * Retrieve it from third-party repositories such as VirusTotal, Internet archives, forums, etc.
2. **Upload or serve the image to the device** via any exposed update channel:
   * Web UI, mobile-app API, USB, TFTP, MQTT, etc.
   * Many consumer IoT devices expose *unauthenticated* HTTP(S) endpoints that accept Base64-encoded firmware blobs, decode them server-side and trigger recovery/upgrade.
3. After the downgrade, exploit a vulnerability that was patched in the newer release (for example a command-injection filter that was added later).
4. Optionally flash the latest image back or disable updates to avoid detection once persistence is gained.

### Example: Command Injection After Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In the vulnerable (downgraded) firmware, the `md5` parameter is concatenated directly into a shell command without sanitisation, allowing injection of arbitrary commands (here – enabling SSH key-based root access). Later firmware versions introduced a basic character filter, but the absence of downgrade protection renders the fix moot.

### Extracting Firmware From Mobile Apps

Many vendors bundle full firmware images inside their companion mobile applications so that the app can update the device over Bluetooth/Wi-Fi. These packages are commonly stored unencrypted in the APK/APEX under paths like `assets/fw/` or `res/raw/`. Tools such as `apktool`, `ghidra`, or even plain `unzip` allow you to pull signed images without touching the physical hardware.

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Checklist for Assessing Update Logic

* Is the transport/authentication of the *update endpoint* adequately protected (TLS + authentication)?
* Does the device compare **version numbers** or a **monotonic anti-rollback counter** before flashing?
* Is the image verified inside a secure boot chain (e.g. signatures checked by ROM code)?
* Does userland code perform additional sanity checks (e.g. allowed partition map, model number)?
* Are *partial* or *backup* update flows re-using the same validation logic?

> 💡  If any of the above are missing, the platform is probably vulnerable to rollback attacks.

## Vulnerable firmware to practice

To practice discovering vulnerabilities in firmware, use the following vulnerable firmware projects as a starting point.

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
  - [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
  - [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
  - [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
  - [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
  - [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)

## Trainning and Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}



