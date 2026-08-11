# Android-Forensik

{{#include ../banners/hacktricks-training.md}}

## Gesperrtes Gerät

Bevorzugen Sie Erfassungsmethoden, die den Zustand des Geräts bewahren, und dokumentieren Sie jede Aktion. Wenn das Gerät gesperrt ist, hängen die verfügbaren Optionen vom Modell, der Android-Version, dem Patch-Level und davon ab, ob der Zugriff vor der Sicherstellung konfiguriert wurde. NIST empfiehlt, eine Methode entsprechend dem Gerät und der Befugnis für die Untersuchung auszuwählen.<sup>[[1]](#references)</sup>

- Prüfen Sie, ob USB debugging aktiviert war und ob die Acquisition-Workstation bereits autorisiert ist. Der ADB-Zugriff erfordert normalerweise, dass der Benutzer das Gerät entsperrt und den RSA-Schlüssel der Workstation bestätigt.<sup>[[3]](#references)</sup>
- Prüfen Sie, ob biometrischer Zugriff gemäß den geltenden rechtlichen und verfahrensrechtlichen Bestimmungen weiterhin verfügbar ist.
- Ein **smudge attack** kann ein grafisches Entsperrmuster anhand von Rückständen auf dem Bildschirm offenlegen, obwohl spätere Berührungen und eine Reinigung die Zuverlässigkeit verringern.<sup>[[2]](#references)</sup>
- Verwenden Sie kommerzielle oder für Forschungszwecke entwickelte Lock-Bypass-Tools nur, wenn sie das exakte Gerät und den Software-Build ausdrücklich unterstützen.

## Datenerfassung

Auf älteren Geräten kann ein älteres [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) eine `.backup`-Datei erzeugen, die Android Backup Extractor entpacken kann:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Gehen Sie nicht davon aus, dass damit jede Anwendung erfasst wird. ADB kennzeichnet den Befehl als veraltet, und Android 12 schließt Daten von Apps aus, die auf API-Level 31 oder höher abzielen, sofern die App nicht debuggable ist.<sup>[[4]](#references)</sup>

### Root- oder physischer Debug-Zugriff

Bei Root-Zugriff auf ein laufendes Gerät sollten Sie zunächst die Partitionen und Mounts inventarisieren; die folgenden Befehle gelten nicht direkt für eine physische JTAG-Erfassung. Das korrekte Blockgerät hängt von der Hardware ab. Gehen Sie daher nicht davon aus, dass es immer `mmcblk0` ist. Erstellen Sie ein Image nur von der verifizierten Quelle auf einem separaten Speicher:<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Hash das Ergebnis und dokumentiere den exakten Befehl, die Gerätekennungen, den Zeitpunkt sowie alle während der Erfassung vorgenommenen Änderungen.<sup>[[1]](#references)</sup>

### Arbeitsspeicher

LiME kann physischen Arbeitsspeicher von Linux- und einigen Android-Geräten erfassen, aber sein kernel module muss für den Zielkernel erstellt und mit ausreichenden Berechtigungen geladen werden. Module signing, kernel lockdown und moderne Android-Härtungsmaßnahmen können das Laden verhindern.<sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Richtlinien zur Forensik mobiler Geräte](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smudge Attacks auf Smartphone-Touchscreens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android-12-ADB-Backup-Einschränkung](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
