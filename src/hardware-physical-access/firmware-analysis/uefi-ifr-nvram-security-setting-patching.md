# Patching ya Mipangilio ya Usalama ya UEFI IFR na NVRAM

{{#include ../../banners/hacktricks-training.md}}

Password ya setup hulinda user interface ya firmware, lakini si lazima ithibitishe bytes za configuration zilizohifadhiwa kwenye SPI flash. Kwa physical write access, assessor anaweza kuoanisha setting ya UEFI iliyofichwa au iliyofungwa kutoka kwenye **Human Interface Infrastructure (HII) Internal Forms Representation (IFR)** yake na NVRAM variable inayoiunga mkono, kubadilisha thamani hiyo offline, na kuiflash tena. Kwenye mfumo wa Dell ulioathirika, hii ilibadilisha hali ya IOMMU kabla ya boot, huku graphical setup ikiendelea kuonyesha kuwa ulinzi wa DMA umewezeshwa.<sup>[[3]](#references)</sup>

> [!CAUTION]
> Kuandika kwenye firmware kunaweza kuifanya target ishindwe kuwaka kabisa. Fanya kazi kwenye kifaa cha majaribio kilichoidhinishwa na kinachoweza kurejeshwa; hifadhi image ya awali; na pata angalau reads tatu huru ambazo cryptographic hashes zake zinalingana kabla ya kurekebisha chochote.<sup>[[3]](#references)</sup>

## Pata firmware image

Soma BIOS region pekee wakati Intel flash descriptor inaruhusu host access, au tumia voltage-correct external programmer na in-circuit clip. External programmer kwa kawaida huhitajika kurejesha mashine ambayo haiwaki tena.<sup>[[3]](#references)[[9]](#references)</sup>
```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```
Usichukulie kwamba vendor update capsule ni sawa na yaliyomo kwenye chip: inaweza kukosa NVRAM, kuwa na encapsulation, au kuwa encrypted. [UEFITool](https://github.com/LongSoft/UEFITool) inaweza kuchanganua raw UEFI image kuwa firmware volumes, files na sections.<sup>[[7]](#references)</sup>

## Map IFR question to NVRAM

[IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS) hubadilisha HII form packages kuwa maandishi na kufichua settings ambazo vendor GUI huficha, hubadilisha majina, au hukandamiza. Output yake inaweza kubainisha question, variable store, byte offset, storage width, valid values na conditional visibility.<sup>[[8]](#references)</sup>

1. Fungua dump katika UEFITool, tafuta firmware file iliyopewa jina `Setup`, ipanue hadi PE32 image section, kisha utumie **Extract body**.
2. Endesha IFRExtractor-RS kwenye EFI/PE32 body iliyotolewa, kisha tafuta katika maandishi yaliyotengenezwa controls kama `DMA`, `IOMMU`, `VT-d`, `Secure Boot`, au vendor-facing label.
3. Rekodi `VarStoreId`, `VarOffset`, `Size`, valid options na question ID. Usikadirie maana ya value kwa kutegemea `Flags` pekee.
4. Tafuta declaration ya `VarStore`/`VarStoreEfi` inayolingana na ulinganishe numeric store ID na variable **name and GUID** yake.
5. Tafuta GUID hiyo katika UEFITool hadi ufikie NVRAM object inayolingana. Fungua **Body hex view** na uende kwenye `VarOffset` ukianzia kwenye variable body—si whole flash image.<sup>[[3]](#references)</sup>
```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```
Kwa mfano, image moja ya Dell ilieleza swali husika kama `Control Iommu Pre-boot Behavior`, ikiwa na `VarStoreId: 0x1`, `VarOffset: 0x975`, na field ya biti 8. Store `0x1` ilihusishwa na variable `Setup` na GUID `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9`; differential dumps zilithibitisha kuwa `01` inawakilisha enabled na `00` inawakilisha disabled kwenye firmware hiyo.<sup>[[3]](#references)</sup>

> [!WARNING]
> GUIDs, offsets, structure layouts, duplicate variable instances, na value encodings zinaweza kubadilika kati ya models na matoleo ya firmware. Usitumie tena mfano wa offset kama thamani ya jumla kwa Dell.

## Validate with differential dumps

Wakati setup interface inapatikana kwenye test unit inayolingana, tengeneza dump ikiwa option imewashwa na nyingine ikiwa imezimwa. Linganisha variable body iliyotokana na IFR na uthibitishe kuwa field inayotarajiwa pekee ndiyo inabadilika. Hii huamua encoding halisi na kutofautisha variable inayotumika na nakala stale/default/recovery. Patch nakala ya image ya awali iliyothibitishwa, ifungue tena kwenye UEFITool, na uthibitishe kuwa edit iko nje ya authenticated au measured code ranges kabla ya kureflash.<sup>[[3]](#references)[[4]](#references)</sup>

Edit inayolenga sehemu mahususi inaweza kuwa na side effects chache kuliko kuondoa firmware password, jambo ambalo linaweza kuingiza hali ya kiwandani, kuhitaji data maalum ya device iingizwe tena, au kubadilisha vipimo vya TPM PCR. Hata hivyo, offline edit inayolenga sehemu mahususi inaweza pia kuunda **displayed-state/effective-state divergence** hatari: UI na management tooling vinaweza kuonyesha value ya zamani huku early firmware ikitumia byte iliyopatchiwa. Mabadiliko yaliyoonyeshwa hayakuomba BitLocker recovery na yaliendelea kuwepo baada ya vendor BIOS update kwa sababu update ilihifadhi hali iliyobadilishwa ya NVRAM.<sup>[[3]](#references)</sup>

[**Dell UEFI Patcher**](https://github.com/craigsblackie/Dell_UEFI_Patcher) ya mwandishi inaonyesha patcher ya model-specific inayogundua Intel Boot Guard Initial Boot Block ranges na kukataa normal writes ndani yake. Tumia analysis mode yake kabla ya `--apply`, kagua kila candidate match, na chukulia defaults zake kama mifano badala ya offsets zinazoweza kutumika kwa mifumo mingine.<sup>[[4]](#references)</sup>
```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```
## Automate mapping kwa kutumia NVRAMap

[NVRAMap](https://github.com/PN-Tester/NVRAMap) hu-automate uchanganuzi wa IFR, hutatua `VarStoreId` ya swali hadi kwenye GUID/jina la NVRAM, huonyesha thamani za sasa za options, na inaweza kuhariri field iliyochaguliwa. Inaweza kufanya kazi kutoka kwenye firmware dump kamili au kutoka kwenye EFI na NVRAM blobs zilizotolewa kando.<sup>[[5]](#references)</sup>
```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```
Automation haiondoi hitaji la dumps zinazolingana, recovery hardware, ukaguzi wa uadilifu wa region, au post-flash validation.

## Kuunganisha downgrade ya pre-boot IOMMU na ufikiaji wa Windows DMA

Ikiwa value iliyopatchiwa inaruhusu PCIe DMA kabla ya ExitBootServices, [DMAReaper](https://github.com/PN-Tester/DMAReaper) inaweza kufuata kutoka EFI System Table kupitia ACPI root tables, kutafuta table ya `DMAR`, na kuiandika upya kabla Windows haijaichanganua. Bila data inayoweza kutumika ya DMAR, Windows inaweza kushindwa kuanzisha Kernel DMA Protection inayotegemea IOMMU. DMAReaper **haizimi VBS/HVCI** yenyewe.<sup>[[1]](#references)</sup>

Katika chain iliyoonyeshwa, target iliwashwa katika Safe Mode ili kuondoa kizuizi kilichosalia cha VBS, kisha [PCILeech](https://github.com/ufrisk/pcileech) ili-patch physical memory kwa kutumia signature ya Sticky Keys:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```
Baada ya patch iliyofanikiwa na inayooana na build, kuendesha Sticky Keys kwenye skrini ya kuingia ya Windows kulianzisha command prompt kama `NT AUTHORITY\SYSTEM`. Sahihi na safu za memory zinazoweza kufikiwa hutegemea target/build/hardware; match iliyoripotiwa si ushahidi kwamba kila toleo la Windows linaweza ku-exploitishwa.<sup>[[2]](#references)[[3]](#references)</sup>

Usiitegemee firmware menu kama uthibitishaji. Angalia **System Information (`msinfo32.exe`) → Kernel DMA Protection**, thibitisha VBS kando, kagua ikiwa OS ilipokea jedwali halali la DMAR, na ujaribu DMA reachability halisi. Windows huripoti Kernel DMA Protection pekee wakati platform na firmware zinaunga mkono usanidi unaohitajika wa IOMMU.<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - Zima Kernel DMA Protection kupitia pre-boot DMAR overwrite](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Software ya mashambulizi ya Direct Memory Access](https://github.com/ufrisk/pcileech)
- [3] [MDSec - Kuzima vipengele vya usalama kwenye BIOS iliyofungwa](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - NVRAM patching inayozingatia IBB](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - Panga mipangilio ya EFI kwa thamani za NVRAM](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - Kitazamaji na parser wa picha za UEFI firmware](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - Toa UEFI IFR kuwa maandishi yanayoweza kusomeka na binadamu](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [flashrom manual - programmers na shughuli za kusoma/kuandika](https://flashrom.org/classic_cli_manpage.html)
{{#include ../../banners/hacktricks-training.md}}
