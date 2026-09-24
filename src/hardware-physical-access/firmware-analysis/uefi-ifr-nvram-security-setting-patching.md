# Patchowanie ustawień zabezpieczeń UEFI IFR i NVRAM

{{#include ../../banners/hacktricks-training.md}}

Hasło konfiguracji chroni interfejs użytkownika firmware, ale nie musi uwierzytelniać bajtów konfiguracji przechowywanych w pamięci flash SPI. Przy fizycznym dostępie z możliwością zapisu assessor może powiązać ukryte lub zablokowane ustawienie UEFI z jego zmienną NVRAM na podstawie **Human Interface Infrastructure (HII) Internal Forms Representation (IFR)**, zmodyfikować tę wartość offline i ponownie zapisać firmware. W przypadku podatnego systemu Dell zmieniło to stan IOMMU przed uruchomieniem systemu, mimo że graficzny interfejs konfiguracji nadal wyświetlał, że ochrona DMA jest włączona.<sup>[[3]](#references)</sup>

> [!CAUTION]
> Zapisywanie firmware może trwale zablokować urządzenie docelowe. Pracuj na autoryzowanym, możliwym do odzyskania urządzeniu testowym; zachowaj oryginalny obraz i przed wprowadzeniem zmian uzyskaj co najmniej trzy niezależne odczyty, których kryptograficzne hashe są zgodne.<sup>[[3]](#references)</sup>

## Pozyskanie obrazu firmware

Odczytaj wyłącznie region BIOS, gdy Intel flash descriptor zezwala na dostęp hosta, albo użyj zewnętrznego programatora o prawidłowym napięciu i klipsa in-circuit. Zewnętrzny programator jest zwykle wymagany do przywrócenia urządzenia, które przestało się uruchamiać.<sup>[[3]](#references)[[9]](#references)</sup>
```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```
Nie zakładaj, że aktualizacja vendora w postaci capsule jest równoważna zawartości układu: może pomijać NVRAM, zawierać encapsulation lub być zaszyfrowana. [UEFITool](https://github.com/LongSoft/UEFITool) może przeanalizować surowy obraz UEFI na volumes firmware, pliki i sekcje.<sup>[[7]](#references)</sup>

## Mapowanie pytania IFR do NVRAM

[IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS) konwertuje pakiety formularzy HII do tekstu i ujawnia ustawienia, które GUI vendora ukrywa, zmienia ich nazwy lub pomija. Jego dane wyjściowe mogą wskazać pytanie, variable store, offset bajtowy, szerokość pamięci, prawidłowe wartości oraz warunkową widoczność.<sup>[[8]](#references)</sup>

1. Otwórz dump w UEFITool, wyszukaj firmware file o nazwie `Setup`, rozwiń go do sekcji obrazu PE32 i użyj **Extract body**.
2. Uruchom IFRExtractor-RS na wyodrębnionym body EFI/PE32, a następnie wyszukaj w wygenerowanym tekście elementy takie jak `DMA`, `IOMMU`, `VT-d`, `Secure Boot` lub etykietę widoczną dla vendora.
3. Zapisz `VarStoreId`, `VarOffset`, `Size`, prawidłowe opcje oraz ID pytania. Nie wyciągaj znaczenia wartości wyłącznie na podstawie `Flags`.
4. Znajdź pasującą deklarację `VarStore`/`VarStoreEfi` i przypisz numeryczny ID store do jego **nazwy i GUID**.
5. Wyszukaj ten GUID w UEFITool, aż dotrzesz do odpowiadającego mu obiektu NVRAM. Otwórz **Body hex view** i przejdź do `VarOffset` względem body zmiennej — nie całego obrazu flash.<sup>[[3]](#references)</sup>
```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```
Na przykład jeden z obrazów firmy Dell opisywał odpowiednie pytanie jako `Control Iommu Pre-boot Behavior`, z `VarStoreId: 0x1`, `VarOffset: 0x975` oraz polem 8-bitowym. Store `0x1` był mapowany na zmienną `Setup` i GUID `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9`; zrzuty różnicowe ustaliły, że w tym firmware `01` oznacza wartość włączoną, a `00` wyłączoną.<sup>[[3]](#references)</sup>

> [!WARNING]
> Identyfikatory GUID, offsety, układy struktur, zduplikowane instancje zmiennych i kodowania wartości mogą się zmieniać między modelami i wersjami firmware. Nigdy nie używaj przykładowego offsetu jako uniwersalnej wartości dla urządzeń Dell.

## Validate with differential dumps

Jeśli interfejs setup jest dostępny na równoważnym urządzeniu testowym, utwórz jeden zrzut z włączoną opcją, a drugi z wyłączoną. Porównaj ciało zmiennej wyprowadzone z IFR i potwierdź, że zmienia się wyłącznie oczekiwane pole. Pozwala to ustalić rzeczywiste kodowanie oraz odróżnić aktywną zmienną od nieaktualnych, domyślnych lub odzyskiwania kopii. Spatchuj kopię zweryfikowanego oryginalnego obrazu, otwórz ją ponownie w UEFITool i potwierdź, że edycja znajduje się poza uwierzytelnionymi lub mierzonymi zakresami kodu przed ponownym flashowaniem.<sup>[[3]](#references)[[4]](#references)</sup>

Ukierunkowana edycja może powodować mniej skutków ubocznych niż wyczyszczenie hasła firmware, które może wprowadzić urządzenie w stan fabryczny, wymagać ponownego wprowadzenia danych specyficznych dla urządzenia lub zmienić pomiary TPM PCR. Jednak ukierunkowana edycja offline może również utworzyć niebezpieczną **rozbieżność między stanem wyświetlanym a stanem efektywnym**: interfejs użytkownika i narzędzia zarządzania mogą pokazywać starą wartość, podczas gdy wczesny firmware wykorzysta spatchowany bajt. Zademonstrowana zmiana nie wymagała odzyskiwania BitLocker i przetrwała aktualizację BIOS firmy Dell, ponieważ aktualizacja zachowała zmieniony stan NVRAM.<sup>[[3]](#references)</sup>

Narzędzie autora [Dell UEFI Patcher](https://github.com/craigsblackie/Dell_UEFI_Patcher) przedstawia patcher specyficzny dla danego modelu, który wykrywa zakresy Intel Boot Guard Initial Boot Block i odmawia wykonywania zwykłych zapisów w ich obrębie. Użyj jego trybu analizy przed `--apply`, sprawdź każde potencjalne dopasowanie i traktuj jego wartości domyślne jako przykłady, a nie przenośne offsety.<sup>[[4]](#references)</sup>
```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```
## Automatyzuj mapowanie za pomocą NVRAMap

[NVRAMap](https://github.com/PN-Tester/NVRAMap) automatyzuje ekstrakcję IFR, rozwiązuje `VarStoreId` pytania do identyfikatora GUID/nazwy NVRAM, wyświetla bieżące wartości opcji i może edytować wybrane pole. Może działać na podstawie pełnego zrzutu firmware albo osobno wyodrębnionych obiektów EFI i NVRAM.<sup>[[5]](#references)</sup>
```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```
Automatyzacja nie eliminuje potrzeby dopasowania dumpów, sprzętu do odzyskiwania, kontroli integralności regionów ani walidacji po flashowaniu.

## Łączenie obniżenia poziomu IOMMU przed uruchomieniem systemu z dostępem DMA w Windows

Jeśli spatchowana wartość zezwala na DMA PCIe przed ExitBootServices, [DMAReaper](https://github.com/PN-Tester/DMAReaper) może przejść od EFI System Table przez główne tabele ACPI, zlokalizować tabelę `DMAR` i nadpisać ją, zanim Windows ją przeanalizuje. Bez użytecznych danych DMAR Windows może nie zainicjalizować ochrony Kernel DMA Protection opartej na IOMMU. DMAReaper samodzielnie **nie wyłącza VBS/HVCI**.<sup>[[1]](#references)</sup>

W przedstawionym łańcuchu cel uruchomiono następnie w trybie awaryjnym, aby usunąć pozostałą barierę VBS, a [PCILeech](https://github.com/ufrisk/pcileech) spatchował pamięć fizyczną za pomocą sygnatury Sticky Keys:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```
Po pomyślnym patchu zgodnym z kompilacją uruchomienie Sticky Keys na ekranie logowania do Windows otwierało command prompt jako `NT AUTHORITY\SYSTEM`. Sygnatury i dostępne zakresy pamięci zależą od celu, builda i sprzętu; zgłoszone dopasowanie nie jest dowodem na to, że każda wersja Windows jest podatna na exploit.<sup>[[2]](#references)[[3]](#references)</sup>

Nie ufaj menu firmware jako metodzie weryfikacji. Sprawdź **Informacje o systemie (`msinfo32.exe`) → Ochrona DMA jądra**, osobno zweryfikuj VBS, sprawdź, czy system operacyjny otrzymał prawidłową tabelę DMAR, i przetestuj rzeczywistą dostępność DMA. Windows zgłasza ochronę DMA jądra tylko wtedy, gdy platforma i firmware obsługują wymaganą konfigurację IOMMU.<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - Wyłączanie ochrony DMA jądra poprzez nadpisanie DMAR przed uruchomieniem](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Oprogramowanie do ataków z bezpośrednim dostępem do pamięci](https://github.com/ufrisk/pcileech)
- [3] [MDSec - Wyłączanie funkcji bezpieczeństwa w zablokowanym BIOS-ie](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - Patchowanie NVRAM z uwzględnieniem IBB](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - Mapowanie ustawień EFI na wartości NVRAM](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Ochrona DMA jądra](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - Przeglądarka i parser obrazów firmware UEFI](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - Ekstrakcja IFR UEFI do tekstu czytelnego dla człowieka](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [flashrom manual - Programatory oraz operacje odczytu/zapisu](https://flashrom.org/classic_cli_manpage.html)
{{#include ../../banners/hacktricks-training.md}}
