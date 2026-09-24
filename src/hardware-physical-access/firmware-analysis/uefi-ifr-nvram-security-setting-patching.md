# UEFI-IFR- und NVRAM-Security-Setting-Patching

{{#include ../../banners/hacktricks-training.md}}

Ein Setup-Passwort schützt die Firmware-Benutzeroberfläche, authentifiziert jedoch nicht unbedingt die in SPI flash gespeicherten Konfigurations-Bytes. Bei physischem Schreibzugriff kann ein Prüfer eine verborgene oder gesperrte UEFI-Einstellung aus deren **Human Interface Infrastructure (HII) Internal Forms Representation (IFR)** der zugrunde liegenden NVRAM-Variable zuordnen, diesen Wert offline patchen und die Firmware anschließend erneut flashen. Auf einem betroffenen Dell-System änderte dies den IOMMU-Zustand vor dem Booten, während das grafische Setup den DMA-Schutz weiterhin als aktiviert anzeigte.<sup>[[3]](#references)</sup>

> [!CAUTION]
> Firmware-Schreibvorgänge können das Zielgerät dauerhaft unbrauchbar machen. Arbeite auf einem autorisierten, wiederherstellbaren Testgerät, bewahre das Original-Image auf und erstelle vor Änderungen mindestens drei unabhängige Auslesungen, deren kryptografische Hashes übereinstimmen.<sup>[[3]](#references)</sup>

## Firmware-Image beschaffen

Lies nur die BIOS-Region aus, wenn der Intel flash descriptor Hostzugriff erlaubt, oder verwende einen spannungsgerechten externen Programmer und einen In-Circuit-Clip. Ein externer Programmer ist normalerweise erforderlich, um eine Maschine wiederherzustellen, die nicht mehr bootet.<sup>[[3]](#references)[[9]](#references)</sup>
```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```
Gehen Sie nicht davon aus, dass ein Update capsule des Herstellers dem Chip-Inhalt entspricht: Sie kann NVRAM auslassen, eine Encapsulation enthalten oder verschlüsselt sein. [UEFITool](https://github.com/LongSoft/UEFITool) kann ein rohes UEFI-Image in Firmware-Volumes, Dateien und Sections zerlegen.<sup>[[7]](#references)</sup>

## Eine IFR-Frage dem NVRAM zuordnen

[IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS) konvertiert HII-Formularpakete in Text und macht Einstellungen sichtbar, die eine Hersteller-GUI verbirgt, umbenennt oder unterdrückt. Seine Ausgabe kann die Question, den Variable Store, das Byte-Offset, die Storage-Breite, gültige Werte und die bedingte Sichtbarkeit identifizieren.<sup>[[8]](#references)</sup>

1. Öffnen Sie den Dump in UEFITool, suchen Sie nach der Firmware-Datei namens `Setup`, erweitern Sie sie bis zum PE32-Image-Abschnitt und verwenden Sie **Extract body**.
2. Führen Sie IFRExtractor-RS für den extrahierten EFI/PE32-Body aus und suchen Sie anschließend im generierten Text nach Controls wie `DMA`, `IOMMU`, `VT-d`, `Secure Boot` oder dem für den Hersteller sichtbaren Label.
3. Notieren Sie `VarStoreId`, `VarOffset`, `Size`, gültige Optionen und die Question-ID. Leiten Sie die Bedeutung der Werte nicht allein aus `Flags` ab.
4. Suchen Sie die passende Deklaration `VarStore`/`VarStoreEfi` und ordnen Sie die numerische Store-ID dem Variablen-**Namen und der GUID** zu.
5. Suchen Sie diese GUID in UEFITool, bis das entsprechende NVRAM-Objekt erreicht ist. Öffnen Sie die **Body hex view** und navigieren Sie zu `VarOffset` relativ zum Variablen-Body – nicht zum gesamten Flash-Image.<sup>[[3]](#references)</sup>
```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```
Beispielsweise beschrieb ein Dell-Image die relevante Frage als `Control Iommu Pre-boot Behavior`, mit `VarStoreId: 0x1`, `VarOffset: 0x975` und einem 8-Bit-Feld. Der Store `0x1` war der Variable `Setup` und der GUID `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9` zugeordnet; Differenz-Dumps bestätigten für diese Firmware `01` als aktiviert und `00` als deaktiviert.<sup>[[3]](#references)</sup>

> [!WARNING]
> GUIDs, Offsets, Struktur-Layouts, doppelte Variableninstanzen und Wertkodierungen können sich zwischen Modellen und Firmware-Versionen ändern. Verwende den Beispiel-Offset niemals als universellen Dell-Wert.

## Mit Differenz-Dumps validieren

Wenn die Setup-Oberfläche auf einem gleichwertigen Testgerät verfügbar ist, erstelle einen Dump mit aktivierter Option und einen weiteren mit deaktivierter Option. Vergleiche den aus dem IFR abgeleiteten Variablen-Body und bestätige, dass sich nur das erwartete Feld ändert. Dadurch lässt sich die tatsächliche Kodierung bestimmen und eine aktive Variable von veralteten, Standard- oder Recovery-Kopien unterscheiden. Patche eine Kopie des verifizierten Original-Images, öffne sie erneut in UEFITool und bestätige, dass sich die Änderung außerhalb authentifizierter oder gemessener Codebereiche befindet, bevor du sie erneut flashst.<sup>[[3]](#references)[[4]](#references)</sup>

Eine gezielte Änderung kann weniger Nebeneffekte haben als das Löschen eines Firmware-Passworts, wodurch möglicherweise ein Werkszustand aktiviert wird, gerätespezifische Daten erneut eingegeben werden müssen oder sich TPM-PCR-Messungen ändern. Eine gezielte Offline-Änderung kann jedoch auch eine gefährliche **Divergenz zwischen angezeigtem und effektivem Zustand** erzeugen: Die Benutzeroberfläche und Management-Tools zeigen möglicherweise den alten Wert an, während die frühe Firmware das gepatchte Byte verwendet. Die demonstrierte Änderung forderte keine BitLocker-Recovery an und blieb nach einem BIOS-Update des Herstellers bestehen, da das Update den geänderten NVRAM-Zustand beibehielt.<sup>[[3]](#references)</sup>

Der [Dell UEFI Patcher](https://github.com/craigsblackie/Dell_UEFI_Patcher) des Autors veranschaulicht einen modellspezifischen Patcher, der die Bereiche des Intel Boot Guard Initial Boot Block erkennt und normale Schreibvorgänge innerhalb dieser Bereiche verweigert. Verwende seinen Analysemodus vor `--apply`, prüfe jeden möglichen Treffer und betrachte seine Standardwerte als Beispiele und nicht als übertragbare Offsets.<sup>[[4]](#references)</sup>
```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```
## Mapping mit NVRAMap automatisieren

[NVRAMap](https://github.com/PN-Tester/NVRAMap) automatisiert die IFR-Extraktion, ordnet die `VarStoreId` einer Frage der NVRAM-GUID bzw. dem NVRAM-Namen zu, zeigt die aktuellen Optionswerte an und kann das ausgewählte Feld bearbeiten. Es kann mit einem vollständigen Firmware-Dump oder mit separat extrahierten EFI- und NVRAM-Blobs arbeiten.<sup>[[5]](#references)</sup>
```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```
Automatisierung beseitigt nicht die Notwendigkeit übereinstimmender Dumps, Recovery-Hardware, Prüfungen der Regionsintegrität oder einer Validierung nach dem Flashen.

## Verkettung eines Pre-Boot-IOMMU-Downgrades mit Windows-DMA-Zugriff

Wenn der gepatchte Wert PCIe-DMA vor ExitBootServices erlaubt, kann [DMAReaper](https://github.com/PN-Tester/DMAReaper) von der EFI System Table aus die ACPI-Root-Tabellen durchlaufen, die `DMAR`-Tabelle finden und sie überschreiben, bevor Windows sie analysiert. Ohne nutzbare DMAR-Daten kann Windows möglicherweise den IOMMU-basierten Kernel DMA Protection nicht initialisieren. DMAReaper deaktiviert VBS/HVCI nicht selbst.<sup>[[1]](#references)</sup>

In der demonstrierten Verkettung wurde das Ziel anschließend im Abgesicherten Modus gestartet, um die verbleibende VBS-Schranke zu entfernen, und [PCILeech](https://github.com/ufrisk/pcileech) patchte den physischen Speicher mit einer Sticky-Keys-Signatur:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```
Nach einem erfolgreichen, build-kompatiblen Patch öffnete das Aufrufen von Sticky Keys am Windows-Anmeldebildschirm eine Eingabeaufforderung als `NT AUTHORITY\SYSTEM`. Signaturen und erreichbare Speicherbereiche hängen vom Ziel, Build und der Hardware ab; ein gemeldeter Treffer ist kein Beweis dafür, dass jede Windows-Version exploitable ist.<sup>[[2]](#references)[[3]](#references)</sup>

Vertraue dem Firmware-Menü nicht als Validierung. Prüfe **System Information (`msinfo32.exe`) → Kernel DMA Protection**, verifiziere VBS separat, untersuche, ob das Betriebssystem eine gültige DMAR-Tabelle erhalten hat, und teste die tatsächliche DMA-Erreichbarkeit. Windows meldet Kernel DMA Protection nur, wenn Plattform und Firmware die erforderliche IOMMU-Konfiguration unterstützen.<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - Kernel DMA Protection via Pre-Boot-DMAR-Überschreibung deaktivieren](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Software für Direct-Memory-Access-Angriffe](https://github.com/ufrisk/pcileech)
- [3] [MDSec - Sicherheitsfunktionen in einem gesperrten BIOS deaktivieren](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - IBB-bewusstes NVRAM-Patching](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - EFI-Einstellungen auf NVRAM-Werte abbilden](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - UEFI-Firmware-Image-Viewer und -Parser](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - UEFI-IFR in menschenlesbaren Text extrahieren](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [flashrom-Handbuch - Programmer sowie Lese-/Schreibvorgänge](https://flashrom.org/classic_cli_manpage.html)
{{#include ../../banners/hacktricks-training.md}}
