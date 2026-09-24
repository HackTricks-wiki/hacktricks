# UEFI IFR i patching NVRAM bezbednosnih podešavanja

{{#include ../../banners/hacktricks-training.md}}

Setup password štiti firmware korisnički interfejs, ali ne autentifikuje nužno konfiguracione bajtove sačuvane u SPI flash memoriji. Uz fizički pristup za upis, assessor može da mapira skrivenu ili zaključanu UEFI postavku iz njenog **Human Interface Infrastructure (HII) Internal Forms Representation (IFR)** prikaza do prateće NVRAM promenljive, da patch-uje tu vrednost offline i ponovo je upiše. Na pogođenom Dell sistemu, ovo je promenilo pre-boot IOMMU stanje, dok je grafički setup i dalje prikazivao da je DMA zaštita omogućena.<sup>[[3]](#references)</sup>

> [!CAUTION]
> Upisivanje firmware-a može trajno da onesposobi target. Radite na autorizovanom, oporavljivom test uređaju; sačuvajte originalnu image datoteku i pribavite najmanje tri nezavisna očitavanja čiji se kriptografski hash-evi podudaraju pre bilo kakvih izmena.<sup>[[3]](#references)</sup>

## Preuzimanje firmware image-a

Očitajte samo BIOS region kada Intel flash descriptor dozvoljava pristup hosta ili koristite eksterni programmer odgovarajućeg napona i in-circuit clip. Eksterni programmer je obično neophodan za oporavak mašine koja se više ne pokreće.<sup>[[3]](#references)[[9]](#references)</sup>
```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```
Ne pretpostavljajte da je vendor update capsule ekvivalentan sadržaju čipa: može izostavljati NVRAM, sadržati encapsulation ili biti encrypted. [UEFITool](https://github.com/LongSoft/UEFITool) može da parsira raw UEFI image u firmware volumes, files i sections.<sup>[[7]](#references)</sup>

## Mapiranje IFR pitanja na NVRAM

[IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS) konvertuje HII form packages u tekst i prikazuje settings koje vendor GUI skriva, preimenuje ili potiskuje. Njegov output može identifikovati pitanje, variable store, byte offset, storage width, valid values i conditional visibility.<sup>[[8]](#references)</sup>

1. Otvorite dump u UEFITool-u, potražite firmware file pod nazivom `Setup`, proširite ga do PE32 image section-a i upotrebite **Extract body**.
2. Pokrenite IFRExtractor-RS nad izdvojenim EFI/PE32 body-jem, a zatim u generisanom tekstu potražite controls kao što su `DMA`, `IOMMU`, `VT-d`, `Secure Boot` ili labelu koju prikazuje vendor.
3. Zabeležite `VarStoreId`, `VarOffset`, `Size`, valid options i question ID. Nemojte zaključivati o semantici vrednosti samo na osnovu `Flags`.
4. Pronađite odgovarajuću deklaraciju `VarStore`/`VarStoreEfi` i mapirajte numerički store ID na njegovo variable **name i GUID**.
5. Pretražujte taj GUID u UEFITool-u dok ne dođete do odgovarajućeg NVRAM object-a. Otvorite **Body hex view** i navigirajte do `VarOffset` u odnosu na variable body — ne na celu flash image.<sup>[[3]](#references)</sup>
```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```
Na primer, jedna Dell image je opisivala relevantno pitanje kao `Control Iommu Pre-boot Behavior`, sa `VarStoreId: 0x1`, `VarOffset: 0x975` i 8-bitnim poljem. Store `0x1` je mapiran na promenljivu `Setup` i GUID `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9`; diferencijalni dump-ovi su utvrdili da `01` znači omogućeno, a `00` onemogućeno na tom firmware-u.<sup>[[3]](#references)</sup>

> [!WARNING]
> GUID-ovi, offseti, rasporedi struktura, duplikatne instance promenljivih i kodiranja vrednosti mogu se razlikovati između modela i verzija firmware-a. Nikada nemojte ponovo koristiti primer offseta kao univerzalnu Dell vrednost.

## Validate with differential dumps

Kada je setup interfejs dostupan na ekvivalentnom testnom uređaju, napravite jedan dump sa omogućenom opcijom i drugi sa onemogućenom. Uporedite telo promenljive izvedeno iz IFR-a i potvrdite da se menja samo očekivano polje. Tako se utvrđuje stvarno kodiranje i razlikuje aktivna promenljiva od zastarelih/podrazumevanih/recovery kopija. Patch-ujte kopiju proverenog originalnog image-a, ponovo je otvorite u UEFITool-u i potvrdite da je izmena izvan autentifikovanih ili merenih opsega koda pre ponovnog flashovanja.<sup>[[3]](#references)[[4]](#references)</sup>

Ciljana izmena može imati manje neželjenih posledica od brisanja firmware lozinke, koje može pokrenuti fabričko stanje, zahtevati ponovni unos podataka specifičnih za uređaj ili promeniti TPM PCR merenja. Međutim, ciljana offline izmena takođe može stvoriti opasno **neslaganje prikazanog i efektivnog stanja**: UI i alati za upravljanje mogu prikazivati staru vrednost, dok rani firmware koristi patch-ovani bajt. Demonstrirana izmena nije zahtevala BitLocker recovery i opstala je nakon vendor BIOS update-a zato što je update sačuvao izmenjeno NVRAM stanje.<sup>[[3]](#references)</sup>

Autorov [Dell UEFI Patcher](https://github.com/craigsblackie/Dell_UEFI_Patcher) predstavlja model-specifičan patcher koji pronalazi opsege Intel Boot Guard Initial Boot Block-a i odbija normalne upise unutar njih. Koristite njegov analysis mode pre `--apply`, pregledajte svako potencijalno podudaranje i njegove podrazumevane vrednosti tretirajte kao primere, a ne kao prenosive offsete.<sup>[[4]](#references)</sup>
```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```
## Automatizujte mapiranje pomoću NVRAMap

[NVRAMap](https://github.com/PN-Tester/NVRAMap) automatizuje IFR ekstrakciju, povezuje `VarStoreId` pitanja sa NVRAM GUID-om/nazivom, prikazuje trenutne vrednosti opcija i može da izmeni izabrano polje. Može da radi sa potpunim firmware dump-om ili zasebno ekstrakovanim EFI i NVRAM blobovima.<sup>[[5]](#references)</sup>
```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```
Automatizacija ne uklanja potrebu za odgovarajućim dumpovima, recovery hardware-om, proverama integriteta regiona ili validacijom nakon flashovanja.

## Chaining pre-boot IOMMU downgrade-a u Windows DMA pristup

Ako patched vrednost dozvoljava PCIe DMA pre ExitBootServices, [DMAReaper](https://github.com/PN-Tester/DMAReaper) može da prođe od EFI System Table kroz ACPI root tables, pronađe `DMAR` tabelu i prepiše je pre nego što je Windows parsira. Bez upotrebljivih DMAR podataka, Windows možda neće uspeti da inicijalizuje Kernel DMA Protection zasnovan na IOMMU-u. DMAReaper sam po sebi **ne onemogućava VBS/HVCI**.<sup>[[1]](#references)</sup>

U prikazanom chain-u, ciljna mašina je zatim pokrenuta u Safe Mode-u kako bi se uklonila preostala VBS prepreka, a [PCILeech](https://github.com/ufrisk/pcileech) je patchovao fizičku memoriju pomoću Sticky Keys signature:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```
Nakon uspešnog patch-a kompatibilnog sa buildom, pokretanje Sticky Keys-a na Windows ekranu za prijavljivanje pokrenulo je command prompt kao `NT AUTHORITY\SYSTEM`. Potpisi i dostupni opsezi memorije zavise od cilja, builda i hardvera; prijavljeno poklapanje nije dokaz da je svaka verzija Windows-a podložna eksploataciji.<sup>[[2]](#references)[[3]](#references)</sup>

Ne verujte meniju firmvera kao potvrdi. Proverite **System Information (`msinfo32.exe`) → Kernel DMA Protection**, zasebno proverite VBS, utvrdite da li je OS primio ispravnu DMAR tabelu i testirajte stvarnu DMA dostupnost. Windows prikazuje Kernel DMA Protection samo kada platforma i firmver podržavaju zahtevanu IOMMU konfiguraciju.<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - Onemogućavanje Kernel DMA Protection-a prepisivanjem DMAR-a pre pokretanja sistema](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Softver za napade putem direktnog pristupa memoriji](https://github.com/ufrisk/pcileech)
- [3] [MDSec - Onemogućavanje bezbednosnih funkcija u zaključanom BIOS-u](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - IBB-aware patchovanje NVRAM-a](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - Mapiranje EFI podešavanja na NVRAM vrednosti](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - Pregledač i parser UEFI firmware image-a](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - Ekstrakcija UEFI IFR-a u tekst čitljiv ljudima](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [flashrom manual - Programatori i operacije čitanja/pisanja](https://flashrom.org/classic_cli_manpage.html)
{{#include ../../banners/hacktricks-training.md}}
