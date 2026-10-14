# Android-Forensik

{{#include ../../banners/hacktricks-training.md}}

## Gesperrtes Gerät

Bevorzugen Sie Erfassungsmethoden, die den Zustand des Geräts bewahren, und dokumentieren Sie jede Maßnahme. Ist das Gerät gesperrt, hängen die verfügbaren Optionen vom Modell, der Android-Version, dem Patch-Level und davon ab, ob vor der Beschlagnahme bereits ein Zugriff eingerichtet wurde. NIST empfiehlt, eine Methode entsprechend dem Gerät und der rechtlichen Grundlage der Untersuchung auszuwählen.<sup>[[1]](#references)</sup>

- Prüfen Sie, ob USB-Debugging aktiviert war und ob die Erfassungs-Workstation bereits autorisiert ist. Für den ADB-Zugriff muss der Benutzer das Gerät normalerweise entsperren und den RSA-Schlüssel der Workstation bestätigen.<sup>[[3]](#references)</sup>
- Prüfen Sie, ob der biometrische Zugriff gemäß den geltenden rechtlichen und verfahrensbezogenen Vorgaben weiterhin verfügbar ist.
- Ein **smudge attack** kann anhand von Rückständen auf dem Bildschirm ein grafisches Entsperrmuster offenlegen. Spätere Berührungen und eine Reinigung verringern jedoch die Zuverlässigkeit.<sup>[[2]](#references)</sup>
- Wenn autorisierte Tools das konkrete Gerät und den Software-Build unterstützen, können sie versuchen, PIN, Passwort oder Muster wiederherzustellen oder per Brute Force zu ermitteln. Die hardwaregestützte Überprüfung von Zugangsdaten, Verzögerungen bei wiederholten Versuchen und Löschrichtlinien machen dies stark geräteabhängig. Ersetzen Sie daher nicht den Nachweis, dass ein Android-Gerät unterstützt wird, durch eine iPhone-Technik oder ein iPhone-Ergebnis.<sup>[[1]](#references)</sup>

## Datenerfassung

Bei älteren Geräten kann ein veraltetes [ADB backup](../../mobile-pentesting/android-app-pentesting/adb-commands.md#legacy-adb-backup) eine `.backup`-Datei erzeugen, die sich mit Android Backup Extractor entpacken lässt:<sup>[[6]](#references)</sup>

```bash
java -jar abe.jar unpack file.backup file.tar
```

Gehe nicht davon aus, dass damit jede Anwendung erfasst wird. ADB kennzeichnet den Befehl als veraltet, und Android 12 schließt Daten von Apps aus, die auf API-Level 31 oder höher ausgerichtet sind, sofern die App nicht debuggable ist.<sup>[[4]](#references)</sup>

### Root- oder physischer Debug-Zugriff

Bei Root-Zugriff auf ein laufendes Gerät solltest du zuerst die Partitionen und Mounts erfassen; die folgenden Befehle lassen sich nicht direkt auf eine physische JTAG-Erfassung anwenden. Das korrekte Blockgerät hängt von der Hardware ab. Gehe also nicht davon aus, dass es immer `mmcblk0` ist. Erstelle nur vom verifizierten Quellgerät ein Abbild und speichere es auf einem separaten Datenträger:<sup>[[1]](#references)</sup>

Bei einer JTAG-Erfassung wird stattdessen die Hardware-Testzugriffsschnittstelle des Geräts mit kompatibler Erfassungsausrüstung verwendet, um auf den zugänglichen Speicher zuzugreifen. Pinbelegung, Chipsatzunterstützung, Gerätezustand und die Unterscheidung zwischen flüchtigen und nichtflüchtigen Speicherzielen sind gerätespezifisch. Dokumentiere den Hardwarepfad und verwende ein validiertes Verfahren für das jeweilige Modell.<sup>[[1]](#references)</sup>

```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```

Wenn beispielsweise das Partitionsverzeichnis bestätigt, dass `/dev/block/mmcblk0` das gesamte Flash-Gerät ist und am Ziel ausreichend Speicherplatz zur Verfügung steht, lautet der ursprüngliche Erfassungsbefehl:<sup>[[1]](#references)</sup>

```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```

Hier hilft `df /data` dabei, `/data` dem eingebundenen Dateisystem zuzuordnen; es sollte nicht als Beweis dafür gelten, dass `mmcblk0` die richtige Quelle für das gesamte Gerät ist oder dass `4096` die einzig gültige Blockgröße für `dd` ist.

Hashen Sie das Ergebnis und halten Sie den genauen Befehl, die Gerätekennungen, den Zeitpunkt und alle während der Erfassung vorgenommenen Änderungen fest.<sup>[[1]](#references)</sup>

### Arbeitsspeicher

LiME kann physischen Arbeitsspeicher von Linux- und einigen Android-Geräten erfassen, aber sein Kernelmodul muss für den Zielkernel gebaut und mit ausreichenden Berechtigungen geladen werden. Modulsignierung, Kernel Lockdown und moderne Android-Härtung können das Laden verhindern.<sup>[[5]](#references)</sup>

Der Android-Workflow des Projekts überträgt das passende Modul per ADB, leitet einen TCP-Port weiter, lädt das Modul über eine Root-Shell und erfasst den Datenstrom auf dem Untersuchungsrechner:<sup>[[5]](#references)</sup>

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

LiME kann stattdessen mit `path=/sdcard/ram.lime` in den Gerätespeicher schreiben. Dadurch wird der Speicher des Geräts verändert und es ist ausreichend freier Speicherplatz erforderlich. Dokumentieren Sie diese Nebenwirkung und hashen Sie das erfasste Abbild.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Leitlinien zur Forensik mobiler Geräte](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smudge Attacks on Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android-12-ADB-Backup-Einschränkung](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../../banners/hacktricks-training.md}}
