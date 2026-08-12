# Android-Forensik

{{#include ../banners/hacktricks-training.md}}

## Gesperrtes Gerät

Bevorzuge Erfassungsmethoden, die den Zustand des Geräts bewahren, und dokumentiere jede Aktion. Wenn das Gerät gesperrt ist, hängen die verfügbaren Optionen vom Modell, der Android-Version, dem Patch-Level und davon ab, ob der Zugriff vor der Beschlagnahmung konfiguriert wurde. NIST empfiehlt, eine Methode entsprechend dem Gerät und der Befugnis für die Untersuchung auszuwählen.<sup>[[1]](#references)</sup>

- Prüfe, ob USB debugging aktiviert war und ob die Erfassungs-Workstation bereits autorisiert ist. Der ADB-Zugriff erfordert normalerweise, dass der Benutzer das Gerät entsperrt und den RSA-Schlüssel der Workstation bestätigt.<sup>[[3]](#references)</sup>
- Prüfe, ob der biometrische Zugriff gemäß den geltenden rechtlichen und verfahrensrechtlichen Regelungen weiterhin verfügbar ist.
- Ein **smudge attack** kann ein grafisches Entsperrmuster anhand von Rückständen auf dem Bildschirm erkennen lassen, obwohl spätere Berührungen und eine Reinigung seine Zuverlässigkeit verringern.<sup>[[2]](#references)</sup>
- Wenn autorisierte Tools das exakte Gerät und den Software-Build unterstützen, können sie versuchen, eine PIN, ein Passwort oder ein Muster wiederherzustellen oder per Brute Force zu ermitteln. Hardwaregestützte Anmeldeinformationsprüfung, Verzögerungen zwischen Versuchen und Löschrichtlinien machen dies stark geräteabhängig. Verwende daher keine iPhone-Technik oder kein iPhone-Ergebnis als Nachweis dafür, dass ein Android-Gerät unterstützt wird.<sup>[[1]](#references)</sup>

## Datenerfassung

Auf älteren Geräten kann ein veraltetes [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) eine `.backup`-Datei erzeugen, die Android Backup Extractor entpacken kann:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Gehe nicht davon aus, dass damit jede Anwendung erfasst wird. ADB kennzeichnet den Befehl als veraltet, und Android 12 schließt Daten von Apps aus, die auf API level 31 oder höher ausgerichtet sind, sofern die App nicht debuggable ist.<sup>[[4]](#references)</sup>

### Root- oder physischer Debug-Zugriff

Mit Root-Zugriff auf einem aktiven Gerät solltest du zuerst die Partitionen und Mounts inventarisieren; die folgenden Befehle gelten nicht direkt für eine physische JTAG-Erfassung. Das korrekte Blockgerät hängt von der Hardware ab. Gehe daher nicht davon aus, dass es immer `mmcblk0` ist. Erstelle nur vom verifizierten Quellgerät ein Image und speichere es auf einem separaten Datenträger:<sup>[[1]](#references)</sup>

Eine JTAG-Erfassung verwendet stattdessen die Hardware-Testzugriffsschnittstelle des Geräts und kompatible Erfassungsgeräte, um auf den zugänglichen Speicher zuzugreifen. Pinbelegung, Chipsatzunterstützung, Gerätezustand sowie die Unterscheidung zwischen flüchtigen und nichtflüchtigen Zielen sind gerätespezifisch. Dokumentiere den Hardwarepfad und verwende ein für dieses Modell validiertes Verfahren.<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Wenn das Partitionsinventar beispielsweise bestätigt, dass `/dev/block/mmcblk0` das gesamte Flash-Gerät ist und das Ziel über ausreichend Speicherplatz verfügt, lautet der ursprüngliche Erfassungsbefehl:<sup>[[1]](#references)</sup>
```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```
Hier hilft `df /data` dabei, `/data` seinem gemounteten Dateisystem zuzuordnen; es sollte jedoch nicht als Beweis dafür betrachtet werden, dass `mmcblk0` die korrekte Quelle für das gesamte Gerät ist oder dass `4096` die einzig gültige Blockgröße für `dd` ist.

Hashen Sie das Ergebnis und dokumentieren Sie den exakten Befehl, die Gerätekennungen, den Zeitpunkt sowie alle während der Erfassung vorgenommenen Änderungen.<sup>[[1]](#references)</sup>

### Speicher

LiME kann physischen Speicher von Linux- und einigen Android-Geräten erfassen, aber sein Kernelmodul muss für den Zielkernel erstellt und mit ausreichenden Rechten geladen werden. Modulsignierung, Kernel Lockdown und moderne Android-Härtung können verhindern, dass es geladen wird.<sup>[[5]](#references)</sup>

Der Android-Workflow des Projekts überträgt das passende Modul mit ADB, leitet einen TCP-Port weiter, lädt das Modul aus einer root shell und erfasst den Datenstrom auf dem Untersuchungsrechner:<sup>[[5]](#references)</sup>
```bash
adb push lime.ko /sdcard/lime.ko
adb forward tcp:4444 tcp:4444
adb shell
su
insmod /sdcard/lime.ko "path=tcp:4444 format=lime"
```

```bash
nc localhost 4444 > ram.lime
```
LiME kann stattdessen mit `path=/sdcard/ram.lime` in den Gerätespeicher schreiben, wodurch der Gerätespeicher verändert wird und ausreichend freier Speicherplatz erforderlich ist. Dokumentieren Sie diesen Nebeneffekt und hashen Sie das erfasste Abbild.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Richtlinien zur Forensik mobiler Geräte](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smudge-Angriffe auf Smartphone-Touchscreens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB-Backup-Einschränkung](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
