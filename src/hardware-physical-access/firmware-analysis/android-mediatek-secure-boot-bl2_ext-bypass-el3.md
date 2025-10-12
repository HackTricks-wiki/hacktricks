# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite dokumentiert einen praktischen secure-boot break auf mehreren MediaTek-Plattformen, der eine Verifikationslücke ausnutzt, wenn die Bootloader-Konfiguration des Geräts (seccfg) auf "unlocked" gesetzt ist. Der Fehler erlaubt das Ausführen eines gepatchten bl2_ext auf ARM EL3, um die nachgelagerte Signaturprüfung zu deaktivieren, die chain of trust zusammenbrechen zu lassen und beliebiges unsigned TEE/GZ/LK/Kernel-Loading zu ermöglichen.

> Vorsicht: Patches in der frühen Boot-Phase können Geräte dauerhaft bricken, wenn Offsets falsch sind. Bewahren Sie stets vollständige Dumps und einen verlässlichen Wiederherstellungsweg auf.

## Betroffener Boot-Ablauf (MediaTek)

- Normaler Pfad: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Verwundbarer Pfad: Wenn seccfg auf "unlocked" gesetzt ist, kann der Preloader das Verifizieren von bl2_ext überspringen. Der Preloader springt dennoch in bl2_ext auf EL3, sodass ein manipuliertes bl2_ext anschließend nicht verifizierte Komponenten laden kann.

Wichtige Vertrauensgrenze:
- bl2_ext läuft auf EL3 und ist verantwortlich für die Verifikation von TEE, GenieZone, LK/AEE und dem Kernel. Wenn bl2_ext selbst nicht authentifiziert ist, lässt sich der Rest der Vertrauenskette trivial umgehen.

## Ursache

Auf betroffenen Geräten erzwingt der Preloader keine Authentifizierung der bl2_ext-Partition, wenn seccfg einen "unlocked"-Zustand anzeigt. Dadurch ist es möglich, ein vom Angreifer kontrolliertes bl2_ext zu flashen, das auf EL3 ausgeführt wird.

Innerhalb von bl2_ext kann die Funktion für die Verifikationspolicy so gepatcht werden, dass sie bedingungslos meldet, dass eine Verifikation nicht erforderlich ist. Ein minimales konzeptionelles Patch ist:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Durch diese Änderung werden alle nachfolgenden Images (TEE, GZ, LK/AEE, Kernel) ohne kryptografische Prüfungen akzeptiert, wenn sie vom gepatchten bl2_ext geladen werden, das auf EL3 läuft.

## Wie man ein Ziel triagiert (expdb logs)

Dump/inspect boot logs (z. B. expdb) rund um den bl2_ext-Ladevorgang. Wenn img_auth_required = 0 und die Zertifikatsverifizierungszeit ~0 ms beträgt, ist enforcement wahrscheinlich deaktiviert und das Gerät ist exploitable.

Beispiel-Logauszug:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Hinweis: Es wird berichtet, dass einige Geräte die bl2_ext verification selbst bei gesperrtem Bootloader überspringen, was die Auswirkungen verschärft.

## Praktischer exploitation workflow (Fenrir PoC)

Fenrir ist ein Referenz exploit/patching toolkit für diese Klasse von Problemen. Es unterstützt Nothing Phone (2a) (Pacman) und ist bekanntermaßen (teilweise unterstützt) auf CMF Phone 1 (Tetris) funktionsfähig. Die Portierung auf andere Modelle erfordert reverse engineering der gerätespezifischen bl2_ext.

Hochrangiger Ablauf:
- Beschaffe das Bootloader-Image des Geräts für deinen Ziel-Codename und lege es als bin/<device>.bin ab
- Erstelle ein gepatchtes Image, das die bl2_ext verification policy deaktiviert
- Flash die resultierende payload auf das Gerät (fastboot wird vom Hilfsskript vorausgesetzt)

Commands:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
Wenn fastboot nicht verfügbar ist, müssen Sie eine geeignete alternative Methode zum Flashen für Ihre Plattform verwenden.

## Runtime payload capabilities (EL3)

Ein gepatchtes bl2_ext-Payload kann:
- benutzerdefinierte fastboot-Befehle registrieren
- den Boot‑Modus steuern/überschreiben
- zur Laufzeit eingebaute Bootloader-Funktionen dynamisch aufrufen
- den „lock state“ als locked vortäuschen, obwohl tatsächlich unlocked, um stärkere Integritätsprüfungen zu bestehen (einige Umgebungen können weiterhin Anpassungen an vbmeta/AVB erfordern)

Einschränkung: Aktuelle PoCs vermerken, dass Laufzeit‑Speichermodifikationen aufgrund von MMU‑Einschränkungen zu Fehlern führen können; Payloads vermeiden daher im Allgemeinen Live‑Memory‑Writes, bis dies behoben ist.

## Portierungstipps

- Reverse‑engineeren Sie das gerätespezifische bl2_ext, um die Logik der Verifikationspolitik zu finden (z. B. sec_get_vfy_policy).
- Identifizieren Sie die Stelle, an der die Policy zurückgegeben wird oder der Entscheidungszweig liegt, und patchen Sie sie auf „keine Verifikation erforderlich“ (return 0 / unconditional allow).
- Behalten Sie Offsets vollständig geräte‑ und firmware‑spezifisch; verwenden Sie keine Adressen zwischen Varianten wieder.
- Validieren Sie zuerst an einem Opfergerät. Bereiten Sie einen Wiederherstellungsplan vor (z. B. EDL/BootROM loader/SoC‑spezifischer Download‑Modus), bevor Sie flashen.

## Security impact

- EL3‑Codeausführung nach Preloader und vollständiger Zusammenbruch der chain‑of‑trust für den restlichen Boot‑Pfad.
- Möglichkeit, unsigned TEE/GZ/LK/Kernel zu booten, secure/verified boot‑Erwartungen zu umgehen und eine persistente Kompromittierung zu ermöglichen.

## Detection and hardening ideas

- Sicherstellen, dass der Preloader bl2_ext unabhängig vom seccfg‑Status verifiziert.
- Authentifizierungsergebnisse durchsetzen und Audit‑Beweise sammeln (Timings > 0 ms, strikte Fehler bei Nichtübereinstimmung).
- Lock‑state‑Spoofing für Attestation unwirksam machen (den Lock‑State an AVB/vbmeta‑Verifikationsentscheidungen und fuse‑gesicherte Zustände binden).

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
