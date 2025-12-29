# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite dokumentiert einen praktischen Secure-Boot-Break auf mehreren MediaTek-Plattformen, indem eine Verifikationslücke ausgenutzt wird, wenn die Bootloader-Konfiguration (seccfg) des Geräts auf "unlocked" gesetzt ist. Die Schwachstelle erlaubt das Ausführen einer gepatchten bl2_ext auf ARM EL3, um die nachgelagerte Signaturprüfung zu deaktivieren, die Vertrauenskette zusammenbrechen zu lassen und das Laden beliebiger unsignierter TEE/GZ/LK/Kernel zu ermöglichen.

> Caution: Frühzeitiges Patchen des Bootvorgangs kann Geräte dauerhaft unbrauchbar machen, wenn Offsets falsch sind. Sichern Sie immer vollständige Dumps und einen zuverlässigen Wiederherstellungsweg.

## Affected boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Key trust boundary:
- bl2_ext executes at EL3 and is responsible for verifying TEE, GenieZone, LK/AEE and the kernel. If bl2_ext itself is not authenticated, the rest of the chain is trivially bypassed.

## Root cause

On affected devices, the Preloader does not enforce authentication of the bl2_ext partition when seccfg indicates an "unlocked" state. This allows flashing an attacker-controlled bl2_ext that runs at EL3.

Inside bl2_ext, the verification policy function can be patched to unconditionally report that verification is not required. A minimal conceptual patch is:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Mit dieser Änderung werden alle nachfolgenden Images (TEE, GZ, LK/AEE, Kernel) ohne kryptografische Prüfungen akzeptiert, wenn sie vom gepatchten bl2_ext, das auf EL3 läuft, geladen werden.

## Wie man ein Ziel triagiert (expdb-Logs)

Dump/inspect boot logs (z. B. expdb) rund um das Laden von bl2_ext. Wenn img_auth_required = 0 und die Zertifikatsüberprüfungszeit ~0 ms beträgt, ist die Durchsetzung wahrscheinlich deaktiviert und das Gerät ist exploitable.

Beispiel-Logauszug:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Note: Bei einigen Geräten wird Berichten zufolge die bl2_ext-Verifizierung selbst bei einem locked bootloader übersprungen, was die Auswirkungen verschärft.

Bei Geräten, die den lk2 sekundären bootloader ausliefern, wurde dieselbe Logiklücke beobachtet. Sammle daher expdb logs für die bl2_ext- und lk2-Partitionen, um zu bestätigen, ob einer der Pfade Signaturen erzwingt, bevor du mit dem Portieren beginnst.

## Praktischer Exploit-Workflow (Fenrir PoC)

Fenrir ist ein Referenz-exploit/patching-Toolkit für diese Fehlerklasse. Es unterstützt Nothing Phone (2a) (Pacman) und funktioniert nachweislich (teilweise unterstützt) auf CMF Phone 1 (Tetris). Das Portieren auf andere Modelle erfordert reverse engineering der gerätespezifischen bl2_ext.

High-level process:
- Beschaffe das bootloader-Image des Zielgeräts für deinen Ziel-Codename und lege es als `bin/<device>.bin` ab
- Erstelle ein gepatchtes Image, das die bl2_ext-Verifizierungsrichtlinie deaktiviert
- Flashe das resultierende payload auf das Gerät (fastboot wird vom helper script vorausgesetzt)

Commands:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
Wenn fastboot nicht verfügbar ist, müssen Sie eine geeignete alternative Flash-Methode für Ihre Plattform verwenden.

### Build-Automatisierung & Payload-Debugging

- `build.sh` lädt jetzt beim ersten Ausführen automatisch die Arm GNU Toolchain 14.2 (aarch64-none-elf) herunter und exportiert sie, sodass Sie Cross-Compiler nicht manuell jonglieren müssen.
- Exportieren Sie `DEBUG=1`, bevor Sie `build.sh` aufrufen, um payloads mit ausführlichen seriellen Ausgaben zu kompilieren, was enorm hilft, wenn Sie EL3-Codepfade blind patchen.
- Erfolgreiche Builds erzeugen sowohl `lk.patched` als auch `<device>-fenrir.bin`; letztere enthält bereits die injizierte payload und ist das, was Sie flashen/boot-testen sollten.

## Laufzeitfähigkeiten von payloads (EL3)

Eine gepatchte bl2_ext-payload kann:
- Eigene fastboot-Befehle registrieren
- Boot-Modus steuern/überschreiben
- Zur Laufzeit dynamisch eingebaute Bootloader-Funktionen aufrufen
- Den "lock state" als locked vortäuschen, während tatsächlich unlocked, um strengere Integritätsprüfungen zu bestehen (in einigen Umgebungen können dennoch Anpassungen an vbmeta/AVB erforderlich sein)

Einschränkung: Aktuelle PoCs weisen darauf hin, dass Laufzeit-Speichermodifikationen aufgrund von MMU-Einschränkungen fehlschlagen können; payloads vermeiden im Allgemeinen Live-Speicherschreibvorgänge, bis dies behoben ist.

## Payload-Staging-Muster (EL3)

Fenrir teilt seine Instrumentierung in drei Compile‑Time-Stages auf: stage1 läuft vor `platform_init()`, stage2 läuft bevor LK den fastboot-Eintritt signalisiert, und stage3 wird unmittelbar ausgeführt, bevor LK Linux lädt. Jeder Device-Header unter `payload/devices/` gibt die Adressen für diese Hooks sowie fastboot-Hilfssymbole an, daher halten Sie diese Offsets mit Ihrem Ziel-Build synchron.

Stage2 ist ein geeigneter Ort, um beliebige `fastboot oem`-Verben zu registrieren:
```c
void cmd_r0rt1z2(const char *arg, void *data, unsigned int sz) {
video_printf("r0rt1z2 was here...\n");
fastboot_info("pwned by r0rt1z2");
fastboot_okay("");
}

__attribute__((section(".text.main"))) void main(void) {
fastboot_register("oem r0rt1z2", cmd_r0rt1z2, true, false);
notify_enter_fastboot();
}
```
Stage3 demonstriert, wie man vorübergehend page-table attributes umschaltet, um immutable strings wie Android’s “Orange State” warning zu patchen, ohne downstream kernel access zu benötigen:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Weil stage1 vor der Plattform-Inbetriebnahme ausgelöst wird, ist es der richtige Ort, OEM power/reset primitives aufzurufen oder zusätzliches Integritäts-Logging einzufügen, bevor die verified boot chain abgebaut wird.

## Portierungstipps

- Reverse-engineere das gerätespezifische bl2_ext, um die Logik der Verifizierungsrichtlinie zu finden (z. B. sec_get_vfy_policy).
- Identifiziere die Policy-Rückgabestelle oder den Entscheidungszweig und patch ihn zu “no verification required” (return 0 / unconditional allow).
- Behalte Offsets vollständig geräte- und firmware-spezifisch; verwende Adressen nicht zwischen verschiedenen Varianten wieder.
- Überprüfe zuerst an einer Opfer-/Ersatz‑Einheit. Bereite einen Wiederherstellungsplan vor (z. B. EDL/BootROM loader/SoC-specific download mode), bevor du flashst.
- Geräte, die den lk2 secondary bootloader verwenden oder “img_auth_required = 0” für bl2_ext melden, selbst wenn sie gesperrt sind, sollten als verwundbare Exemplare dieser Bugklasse behandelt werden; beim Vivo X80 Pro wurde bereits beobachtet, dass die Verifizierung übersprungen wurde, obwohl ein gesperrter Zustand gemeldet wurde.
- Vergleiche expdb logs aus gesperrten und entsperrten Zuständen — wenn das Zertifikat‑Timing von 0 ms auf einen Nicht‑Null‑Wert springt, sobald du wieder sperrst, hast du wahrscheinlich den richtigen Entscheidungs-Punkt gepatcht, musst aber noch das Lock‑State‑Spoofing härten, um die Modifikation zu verbergen.

## Sicherheitsauswirkung

- EL3-Codeausführung nach Preloader und vollständiger Zusammenbruch der chain-of-trust für den restlichen Boot‑Pfad.
- Möglichkeit, unsigned TEE/GZ/LK/Kernel zu booten, wodurch secure/verified boot‑Erwartungen umgangen werden und eine persistente Kompromittierung ermöglicht wird.

## Gerätenotizen

- Bestätigt unterstützt: Nothing Phone (2a) (Pacman)
- Bekannt funktionierend (unvollständige Unterstützung): CMF Phone 1 (Tetris)
- Beobachtet: Vivo X80 Pro reportedly did not verify bl2_ext even when locked
- Branchendeckung hebt weitere lk2‑basierte Anbieter hervor, die denselben Logikfehler ausliefern, daher ist mit weiterer Überschneidung über die MTK‑Releases 2024–2025 zu rechnen.

## Referenzen

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)

{{#include ../../banners/hacktricks-training.md}}
