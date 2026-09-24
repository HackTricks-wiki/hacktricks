# UEFI IFR- en NVRAM-sekuriteitsinstelling-patching

{{#include ../../banners/hacktricks-training.md}}

'n Setup-wagwoord beskerm die firmware-gebruikerskoppelvlak, maar dit staaf nie noodwendig die konfigurasiegreepies wat in SPI-flash gestoor word nie. Met fisiese skryftoegang kan 'n assessor 'n versteekte of geslote UEFI-instelling vanaf sy **Human Interface Infrastructure (HII) Internal Forms Representation (IFR)** na die ondersteunende NVRAM-veranderlike karteer, daardie waarde vanlyn patch en dit weer flash. Op 'n geaffekteerde Dell-stelsel het dit die pre-boot IOMMU-toestand verander, terwyl die grafiese setup steeds DMA-beskerming as geaktiveer vertoon het.<sup>[[3]](#references)</sup>

> [!CAUTION]
> Firmware-skrywings kan die teiken permanent brick. Werk op 'n gemagtigde, herstelbare toets-toestel; hou die oorspronklike image; en verkry minstens drie onafhanklike lesings waarvan die kriptografiese hashes ooreenstem voordat enigiets gewysig word.<sup>[[3]](#references)</sup>

## Verkry die firmware-image

Lees slegs die BIOS-streek wanneer die Intel-flash descriptor host-toegang toelaat, of gebruik 'n eksterne programmer met die korrekte spanning en 'n in-circuit clip. 'n Eksterne programmer word normaalweg benodig om 'n masjien wat nie meer boot nie, te herstel.<sup>[[3]](#references)[[9]](#references)</sup>
```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```
Moenie aanvaar dat 'n vendor update capsule gelykstaande aan die chip-inhoud is nie: dit kan NVRAM weglaat, encapsulation bevat, of encrypted wees. [UEFITool](https://github.com/LongSoft/UEFITool) kan 'n raw UEFI image in firmware volumes, files en sections ontleed.<sup>[[7]](#references)</sup>

## Koppel 'n IFR-vraag aan NVRAM

[IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS) skakel HII form packages om na teks en wys settings bloot wat 'n vendor GUI versteek, hernoem of onderdruk. Die output kan die question, variable store, byte offset, storage width, geldige waardes en conditional visibility identifiseer.<sup>[[8]](#references)</sup>

1. Maak die dump in UEFITool oop, soek na die firmware file genaamd `Setup`, brei dit uit na die PE32 image section, en gebruik **Extract body**.
2. Run IFRExtractor-RS op die onttrekte EFI/PE32 body, en soek dan in die gegenereerde teks na controls soos `DMA`, `IOMMU`, `VT-d`, `Secure Boot`, of die vendor-facing label.
3. Teken `VarStoreId`, `VarOffset`, `Size`, geldige opsies en die question ID aan. Moenie value semantics slegs uit `Flags` aflei nie.
4. Vind die ooreenstemmende `VarStore`/`VarStoreEfi` declaration en koppel die numeriese store ID aan sy variable **name en GUID**.
5. Soek daardie GUID in UEFITool totdat die ooreenstemmende NVRAM-object bereik word. Maak **Body hex view** oop en navigeer na `VarOffset` relatief tot die variable body—nie die hele flash image nie.<sup>[[3]](#references)</sup>
```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```
Byvoorbeeld, een Dell-beeld het die relevante vraag beskryf as `Control Iommu Pre-boot Behavior`, met `VarStoreId: 0x1`, `VarOffset: 0x975`, en ’n 8-bis-veld. Store `0x1` is na veranderlike `Setup` en GUID `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9` gekarteer; differensiële dumps het `01` as enabled en `00` as disabled op daardie firmware vasgestel.<sup>[[3]](#references)</sup>

> [!WARNING]
> GUIDs, offsets, struktuuruitlegte, duplikaatveranderlike-instansies en waarde-enkoderings kan tussen modelle en firmware-weergawes verander. Moet nooit die voorbeeld-offset as ’n universele Dell-waarde hergebruik nie.

## Valideer met differensiële dumps

Wanneer die setup-koppelvlak op ’n ekwivalente toetstoestel beskikbaar is, skep ’n dump met die opsie enabled en nog een met dit disabled. Vergelyk die IFR-afgeleide veranderlike-liggaam en bevestig dat slegs die verwagte veld verander. Dit bepaal die werklike enkodering en onderskei ’n aktiewe veranderlike van verouderde/verstek-/recovery-kopieë. Patch ’n kopie van die geverifieerde oorspronklike beeld, maak dit weer in UEFITool oop, en bevestig dat die wysiging buite geverifieerde of gemete kodegebiede is voordat jy dit herflits.<sup>[[3]](#references)[[4]](#references)</sup>

’n Gerigte wysiging kan minder newe-effekte hê as om ’n firmware-wagwoord skoon te maak, wat ’n fabriekt toestand kan aktiveer, kan vereis dat toestelspesifieke data weer ingevoer word, of TPM PCR-metings kan verander. ’n Gerigte offline-wysiging kan egter ook ’n gevaarlike **vertoonde-toestand/effektiewe-toestand-divergensie** skep: die UI en bestuursnutsmiddels kan die ou waarde vertoon terwyl vroeë firmware die gepatchte byte gebruik. Die gedemonstreerde verandering het nie BitLocker recovery aangevra nie en het ná ’n verkoper-BIOS-opdatering behoue gebly omdat die opdatering die veranderde NVRAM-toestand behou het.<sup>[[3]](#references)</sup>

Die outeur se [Dell UEFI Patcher](https://github.com/craigsblackie/Dell_UEFI_Patcher) illustreer ’n modelspesifieke patcher wat Intel Boot Guard Initial Boot Block-reekse opspoor en normale skrywings binne hulle weier. Gebruik sy analysis-modus voordat jy `--apply` uitvoer, inspekteer elke kandidaatpassing, en behandel sy verstekwaardes as voorbeelde eerder as oordraagbare offsets.<sup>[[4]](#references)</sup>
```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```
## Outomatiseer die kartering met NVRAMap

[NVRAMap](https://github.com/PN-Tester/NVRAMap) outomatiseer IFR-ekstraksie, los ’n vraag se `VarStoreId` na die NVRAM GUID/naam op, vertoon huidige opsiewaardes en kan die gekose veld wysig. Dit kan met ’n volledige firmware dump of met afsonderlik geëkstraheerde EFI- en NVRAM-blobs werk.<sup>[[5]](#references)</sup>
```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```
Outomatisering verwyder nie die behoefte aan ooreenstemmende dumps, herstelhardeware, streek-integriteitskontroles of validasie ná flash nie.

## Koppeling van ’n pre-boot IOMMU-downgrade aan Windows DMA-toegang

As die patched waarde PCIe DMA voor ExitBootServices toelaat, kan [DMAReaper](https://github.com/PN-Tester/DMAReaper) vanaf die EFI System Table deur die ACPI-root-tabelle loop, die `DMAR`-tabel opspoor en dit oorskryf voordat Windows dit parse. Sonder bruikbare DMAR-data kan Windows moontlik nie IOMMU-gesteunde Kernel DMA Protection inisialiseer nie. DMAReaper deaktiveer nie VBS/HVCI op sy eie nie.<sup>[[1]](#references)</sup>

In die gedemonstreerde ketting is die teiken daarna in Safe Mode geboot om die oorblywende VBS-versperring te verwyder, en [PCILeech](https://github.com/ufrisk/pcileech) het fisiese geheue met ’n Sticky Keys-signature gepatch:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```
Na 'n suksesvolle, build-versoenbare patch het die gebruik van Sticky Keys by die Windows-aanmeldskerm 'n command prompt as `NT AUTHORITY\SYSTEM` geloods. Handtekeninge en bereikbare geheue-areas is teiken-, build- en hardeware-afhanklik; 'n gerapporteerde passing is nie 'n bewys dat elke Windows-weergawe kwesbaar is nie.<sup>[[2]](#references)[[3]](#references)</sup>

Moenie die firmware-kieslys as validering vertrou nie. Kontroleer **System Information (`msinfo32.exe`) → Kernel DMA Protection**, verifieer VBS afsonderlik, ondersoek of die bedryfstelsel 'n geldige DMAR-tabel ontvang het, en toets werklike DMA-bereikbaarheid. Windows rapporteer Kernel DMA Protection slegs wanneer die platform en firmware die vereiste IOMMU-konfigurasie ondersteun.<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - Deaktiveer Kernel DMA Protection deur 'n pre-boot DMAR-oorwriting](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Direct Memory Access-aanvalsagteware](https://github.com/ufrisk/pcileech)
- [3] [MDSec - Deaktivering van sekuriteitskenmerke in 'n geslote BIOS](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - IBB-bewuste NVRAM-patching](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - Koppel EFI-instellings aan NVRAM-waardes](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - UEFI-firmwarebeeldkyker en -ontleder](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - Onttrek UEFI IFR na mensleesbare teks](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [flashrom-handleiding - programmeerders en lees-/skryfbewerkings](https://flashrom.org/classic_cli_manpage.html)
{{#include ../../banners/hacktricks-training.md}}
