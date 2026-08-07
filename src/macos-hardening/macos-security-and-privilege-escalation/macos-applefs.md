# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Proprietäres Apple-Dateisystem (APFS)

**Apple File System (APFS)** ist ein modernes Dateisystem, das als Ersatz für das Hierarchical File System Plus (HFS+) entwickelt wurde. Seine Entwicklung wurde durch den Bedarf an **verbesserter Leistung, Sicherheit und Effizienz** vorangetrieben.

Zu den bemerkenswerten Funktionen von APFS gehören:<sup>[[1]](#references)</sup>

1. **Space Sharing**: APFS ermöglicht es mehreren Volumes, **denselben zugrunde liegenden freien Speicherplatz** auf einem einzelnen physischen Gerät gemeinsam zu nutzen. Dies ermöglicht eine effizientere Speichernutzung, da die Volumes dynamisch vergrößert und verkleinert werden können, ohne dass eine manuelle Größenänderung oder Neupartitionierung erforderlich ist.
1. Das bedeutet, dass bei APFS im Vergleich zu herkömmlichen Partitionen auf Datenträgern **verschiedene Partitionen (Volumes) den gesamten Speicherplatz des Datenträgers gemeinsam nutzen**, während eine reguläre Partition normalerweise eine feste Größe hatte.
2. **Snapshots**: APFS unterstützt das **Erstellen von Snapshots**, bei denen es sich um **schreibgeschützte** Momentaufnahmen des Dateisystems handelt. Snapshots ermöglichen effiziente Backups und einfache System-Rollbacks, da sie nur minimal zusätzlichen Speicherplatz benötigen und schnell erstellt oder zurückgesetzt werden können.
3. **Clones**: APFS kann **Datei- oder Verzeichnis-Clones erstellen, die denselben Speicherplatz** wie das Original nutzen, bis entweder der Clone oder die Originaldatei geändert wird. Diese Funktion bietet eine effiziente Möglichkeit, Kopien von Dateien oder Verzeichnissen zu erstellen, ohne den Speicherplatz zu duplizieren.
4. **Verschlüsselung**: APFS **unterstützt nativ die vollständige Festplattenverschlüsselung** sowie die Verschlüsselung einzelner Dateien und Verzeichnisse und erhöht dadurch die Datensicherheit in verschiedenen Anwendungsfällen.
5. **Absturzschutz**: APFS verwendet ein **Copy-on-Write-Metadatenschema, das die Konsistenz des Dateisystems sicherstellt**, selbst bei einem plötzlichen Stromausfall oder Systemabsturz, wodurch das Risiko einer Datenbeschädigung reduziert wird.

Insgesamt bietet APFS ein moderneres, flexibleres und effizienteres Dateisystem für Apple-Geräte mit einem Schwerpunkt auf verbesserter Leistung, Zuverlässigkeit und Sicherheit.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Das Volume `Data` ist unter **`/System/Volumes/Data`** eingehängt (du kannst dies mit `diskutil apfs list` überprüfen).

Die Liste der Firmlinks befindet sich in der Datei **`/usr/share/firmlinks`**.
```bash

```
## Referenzen

- [1] [APFS Guide - Features - Apple Developer Documentation](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/Features/Features.html)

{{#include ../../banners/hacktricks-training.md}}
