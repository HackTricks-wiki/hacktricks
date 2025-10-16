# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite dokumentiert einen praktischen secure-boot break auf mehreren MediaTek-Plattformen, indem eine Verifikationslücke ausgenutzt wird, wenn die Bootloader-Konfiguration des Geräts (seccfg) auf "unlocked" gesetzt ist. Der Fehler erlaubt das Ausführen eines gepatchten bl2_ext auf ARM EL3, um die nachgelagerte Signaturprüfung zu deaktivieren, die Vertrauenskette zusammenbrechen zu lassen und das Laden beliebiger nicht signierter TEE/GZ/LK/Kernel zu ermöglichen.

> Vorsicht: Early-boot patching can permanently brick devices if offsets are wrong. Always keep full dumps and a reliable recovery path.

## Betroffener Bootablauf (MediaTek)

- Normaler Ablauf: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Verwundbarer Ablauf: Wenn seccfg auf "unlocked" gesetzt ist, kann der Preloader das Verifizieren von bl2_ext überspringen. Der Preloader springt trotzdem in bl2_ext bei EL3, sodass ein manipuliertes bl2_ext anschließend nicht verifizierte Komponenten laden kann.

Wichtige Vertrauensgrenze:
- bl2_ext läuft auf EL3 und ist verantwortlich für die Überprüfung von TEE, GenieZone, LK/AEE und dem Kernel. Wenn bl2_ext selbst nicht authentifiziert ist, kann der Rest der Kette trivial umgangen werden.

## Ursache

Auf betroffenen Geräten erzwingt der Preloader keine Authentifizierung der bl2_ext-Partition, wenn seccfg einen "unlocked"-Zustand anzeigt. Dadurch ist es möglich, ein vom Angreifer kontrolliertes bl2_ext zu flashen, das auf EL3 läuft.

Innerhalb von bl2_ext kann die Funktion der Verifikationsrichtlinie gepatcht werden, sodass sie bedingungslos meldet, dass keine Verifikation erforderlich ist. Ein minimales konzeptionelles Patch ist:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Mit dieser Änderung werden alle nachfolgenden Images (TEE, GZ, LK/AEE, Kernel) ohne kryptografische Prüfungen akzeptiert, wenn sie vom gepatchten bl2_ext, das auf EL3 läuft, geladen werden.

## Wie man ein Ziel triagiert (expdb logs)

Dump/inspect boot logs (e.g., expdb) rund um den bl2_ext-Ladevorgang. Wenn img_auth_required = 0 ist und die certificate verification time etwa 0 ms beträgt, ist enforcement wahrscheinlich deaktiviert und das Gerät exploitable.

Beispiel-Logauszug:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Hinweis: Einige Geräte überspringen Berichten zufolge die bl2_ext-Überprüfung selbst bei einem gesperrten bootloader, was die Auswirkungen verschärft.

## Praktischer Exploitation-Workflow (Fenrir PoC)

Fenrir ist ein reference exploit/patching toolkit für diese Klasse von Problemen. Es unterstützt Nothing Phone (2a) (Pacman) und ist bekannt dafür, auf CMF Phone 1 (Tetris) zu funktionieren (teilweise unterstützt). Das Portieren auf andere Modelle erfordert reverse engineering der gerätespezifischen bl2_ext.

High-level process:
- Beschaffe das bootloader image des Geräts für deinen Ziel-Codename und lege es als bin/<device>.bin ab
- Baue ein gepatchtes Image, das die bl2_ext-Verifikationsrichtlinie deaktiviert
- Flashe die resultierende payload auf das Gerät (fastboot wird vom helper script vorausgesetzt)

Commands:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
Wenn fastboot nicht verfügbar ist, müssen Sie eine geeignete alternative Flash-Methode für Ihre Plattform verwenden.

## Laufzeit-Payload-Fähigkeiten (EL3)

Ein gepatchtes bl2_ext payload kann:
- Benutzerdefinierte fastboot-Befehle registrieren
- Boot-Modus steuern/überschreiben
- Zur Laufzeit dynamisch eingebaute Bootloader-Funktionen aufrufen
- Den „lock state“ als gesperrt vortäuschen, während tatsächlich entsperrt, um stärkere Integritätschecks zu bestehen (einige Umgebungen können trotzdem Anpassungen an vbmeta/AVB erfordern)

Einschränkung: Aktuelle PoCs stellen fest, dass Laufzeit-Speicheränderungen aufgrund von MMU-Einschränkungen zu Fehlern führen können; payloads vermeiden im Allgemeinen Live-Speicherschreibvorgänge, bis dies behoben ist.

## Portierungstipps

- Reverse engineer das gerätespezifische bl2_ext, um die Verifizierungs-Policy-Logik zu lokalisieren (z. B. sec_get_vfy_policy).
- Identifiziere die Policy-Rückgabestelle oder Entscheidungszweig und patch sie zu „no verification required“ (return 0 / unconditional allow).
- Behalte Offsets geräte- und firmware-spezifisch; verwende Adressen nicht zwischen Varianten wieder.
- Validieren Sie zuerst an einer opfereinheit. Bereiten Sie einen Recovery-Plan vor (z. B. EDL/BootROM loader/SoC-spezifischer Download-Modus), bevor Sie flashen.

## Sicherheitsauswirkung

- EL3-Codeausführung nach Preloader und vollständiger Zusammenbruch der Chain-of-Trust für den restlichen Boot-Pfad.
- Möglichkeit, unsigned TEE/GZ/LK/Kernel zu booten, wodurch secure/verified boot-Erwartungen umgangen und persistente Kompromittierungen ermöglicht werden.

## Erkennung und Härtungsmaßnahmen

- Sicherstellen, dass Preloader bl2_ext unabhängig vom seccfg-Status verifiziert.
- Authentifizierungsergebnisse erzwingen und Audit-Beweise sammeln (Timings > 0 ms, strikte Fehler bei Abweichungen).
- Lock-state-Spoofing sollte für Attestation wirkungslos gemacht werden (Lock-State an AVB/vbmeta-Verifizierungsentscheidungen und fuse-gesicherten Status koppeln).

## Gerätehinweise

- Bestätigt unterstützt: Nothing Phone (2a) (Pacman)
- Bekannt funktionierend (inkomplette Unterstützung): CMF Phone 1 (Tetris)
- Beobachtet: Vivo X80 Pro hat Berichten zufolge bl2_ext selbst im gesperrten Zustand nicht verifiziert

## Referenzen

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
