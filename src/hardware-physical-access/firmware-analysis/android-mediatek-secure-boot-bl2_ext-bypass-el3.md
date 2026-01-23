# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite dokumentiert einen praktischen Secure-Boot-Bruch auf mehreren MediaTek-Plattformen, indem eine Verifizierungs-Lücke ausgenutzt wird, wenn die Bootloader-Konfiguration (seccfg) auf "unlocked" gesetzt ist. Der Fehler erlaubt das Ausführen eines gepatchten bl2_ext auf ARM EL3, um die nachgelagerte Signaturprüfung zu deaktivieren, die Vertrauenskette zusammenbrechen zu lassen und das Laden beliebiger nicht signierter TEE/GZ/LK/Kernel zu ermöglichen.

> Achtung: Early-boot-Patching kann Geräte dauerhaft unbrauchbar machen, wenn Offsets falsch sind. Bewahre immer vollständige Dumps und einen verlässlichen Wiederherstellungsweg auf.

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
Durch diese Änderung werden alle nachfolgenden Images (TEE, GZ, LK/AEE, Kernel) ohne kryptografische Prüfungen akzeptiert, wenn sie vom gepatchten bl2_ext geladen werden, das auf EL3 läuft.

## Wie man ein Ziel triagiert (expdb logs)

Dump/inspect boot logs (z. B. expdb) rund um den bl2_ext-Ladevorgang. Wenn img_auth_required = 0 und die Zeit für die Zertifikatverifizierung ~0 ms beträgt, ist die Durchsetzung wahrscheinlich deaktiviert und das Gerät ausnutzbar.

Beispiel-Logauszug:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Hinweis: Bei einigen Geräten wird angeblich die bl2_ext-Verifikation übersprungen, selbst bei gesperrtem Bootloader, was die Auswirkungen verschärft.

Bei Geräten, die den sekundären Bootloader lk2 ausliefern, wurde dieselbe Logiklücke beobachtet. Sammle daher expdb-Logs für die Partitionen bl2_ext und lk2, um zu bestätigen, ob einer der Pfade Signaturen erzwingt, bevor du mit dem Portieren beginnst.

Wenn ein Post-OTA Preloader jetzt img_auth_required = 1 für bl2_ext protokolliert, obwohl seccfg entsperrt ist, hat der Vendor die Lücke wahrscheinlich geschlossen — siehe die OTA-Persistenzhinweise unten.

## Praktischer Exploit-Workflow (Fenrir PoC)

Fenrir ist ein Referenz-Exploit-/Patch-Toolkit für diese Art von Problem. Es unterstützt Nothing Phone (2a) (Pacman) und funktioniert (teilweise unterstützt) bekanntlich auf CMF Phone 1 (Tetris). Das Portieren auf andere Modelle erfordert Reverse Engineering der gerätespezifischen bl2_ext.

Grober Ablauf:
- Beschaffe das Bootloader-Image des Geräts für deinen Ziel-Codename und lege es als `bin/<device>.bin` ab
- Erstelle ein gepatchtes Image, das die bl2_ext-Verifikationsrichtlinie deaktiviert
- Flashe die resultierende Payload auf das Gerät (das Hilfsskript erwartet fastboot)

Befehle:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
Wenn fastboot nicht verfügbar ist, müssen Sie eine geeignete alternative flashing-Methode für Ihre Plattform verwenden.

### OTA-gepatchte Firmware: Umgehung am Leben erhalten (NothingOS 4, Ende 2025)

Nothing hat den Preloader in der NothingOS 4 Stable-OTA vom November 2025 (Build BP2A.250605.031.A3) gepatcht, um die bl2_ext-Verifikation durchzusetzen, selbst wenn seccfg entsperrt ist. Fenrir `pacman-v2.0` funktioniert wieder, indem der verwundbare Preloader aus dem NOS 4 beta mit dem stabilen LK-Payload gemischt wird:
```bash
# on Nothing Phone (2a), unlocked bootloader, in bootloader (not fastbootd)
fastboot flash preloader_a preloader_raw.img   # beta Preloader bundled with fenrir release
fastboot flash lk pacman-fenrir.bin            # patched LK containing stage hooks
fastboot reboot                                # factory reset may be needed
```
Wichtig:
- Flashen Sie den bereitgestellten Preloader **nur** auf das passende Gerät/Slot; ein falscher preloader führt sofort zu einem hard brick.
- Prüfen Sie expdb nach dem Flashen; img_auth_required sollte für bl2_ext wieder auf 0 zurückgehen und bestätigen, dass der verwundbare Preloader vor Ihrem gepatchten LK ausgeführt wird.
- Wenn zukünftige OTAs sowohl Preloader als auch LK patchen, behalten Sie eine lokale Kopie eines verwundbaren Preloader, um die Lücke wieder einzuführen.

### Build automation & payload debugging

- `build.sh` lädt beim ersten Ausführen automatisch die Arm GNU Toolchain 14.2 (aarch64-none-elf) herunter und exportiert sie, sodass Sie Cross-Compiler nicht manuell jonglieren müssen.
- Exportieren Sie `DEBUG=1` vor dem Aufrufen von `build.sh`, um payloads mit ausführlichen seriellen Ausgaben zu kompilieren; das hilft erheblich beim blind-patching von EL3-Codepfaden.
- Erfolgreiche Builds erzeugen sowohl `lk.patched` als auch `<device>-fenrir.bin`; letztere enthält bereits den injizierten payload und ist das, was Sie flashen/boot-testen sollten.

## Runtime payload capabilities (EL3)

Ein gepatchter bl2_ext payload kann:
- benutzerdefinierte fastboot-Befehle registrieren
- den Boot-Modus steuern/überschreiben
- eingebaute bootloader-Funktionen zur Laufzeit dynamisch aufrufen
- den „lock state“ als locked vortäuschen, während tatsächlich unlocked, um strengere Integritätsprüfungen zu passieren (in manchen Umgebungen sind weiterhin vbmeta/AVB-Anpassungen erforderlich)

Einschränkung: Aktuelle PoCs weisen darauf hin, dass Laufzeit-Speicheränderungen aufgrund von MMU-Beschränkungen fehlschlagen können; payloads vermeiden im Allgemeinen Live-Speicher-Schreibvorgänge, bis dies behoben ist.

## Payload staging patterns (EL3)

Fenrir teilt seine Instrumentierung in drei Compile-Time-Stufen auf: stage1 läuft vor `platform_init()`, stage2 läuft bevor LK fastboot entry signalisiert, und stage3 wird unmittelbar bevor LK Linux lädt ausgeführt. Jeder Device-Header unter `payload/devices/` liefert die Adressen für diese Hooks sowie fastboot-Hilfssymbole, daher halten Sie diese Offsets mit Ihrem Ziel-Build synchron.

Stage2 ist ein bequemer Ort, um beliebige `fastboot oem` Verben zu registrieren:
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
Stage3 demonstriert, wie man vorübergehend Seitentabellenattribute umschaltet, um unveränderliche Strings wie Android’s “Orange State” warning zu patchen, ohne Zugriff auf den nachgelagerten Kernel zu benötigen:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Da stage1 vor dem Platform-Bring-up ausgeführt wird, ist es der richtige Ort, um OEM power/reset primitives aufzurufen oder zusätzliches Integritäts-Logging einzufügen, bevor die verified boot chain abgebaut wird.

## Porting-Tipps

- Reverse-engineere das gerätespezifische bl2_ext, um die Logik der verification policy zu lokalisieren (z. B. sec_get_vfy_policy).
- Identifiziere die Policy-Rückgabestelle oder den Entscheidungszweig und patche ihn zu “no verification required” (return 0 / unconditional allow).
- Behalte Offsets vollständig geräte- und firmware-spezifisch; verwende Adressen nicht zwischen Varianten wieder.
- Validiere zuerst an einer Opfert-Einheit. Bereite einen Recovery-Plan vor (z. B. EDL/BootROM loader/SoC-specific download mode), bevor du flashst.
- Geräte, die den lk2 secondary bootloader verwenden oder für bl2_ext sogar im gesperrten Zustand “img_auth_required = 0” melden, sollten als anfällige Exemplare dieser Bug-Klasse behandelt werden; beim Vivo X80 Pro wurde bereits beobachtet, dass die Verification trotz gemeldetem Sperrstatus übersprungen wurde.
- Wenn ein OTA damit beginnt, bl2_ext-Signaturen (img_auth_required = 1) im entsperrten Zustand zu erzwingen, prüfe, ob ein älterer Preloader (oft in Beta-OTAs verfügbar) geflasht werden kann, um die Lücke wieder zu öffnen, und führe dann fenrir mit aktualisierten Offsets für den neueren LK erneut aus.

## Sicherheitsauswirkung

- EL3-Codeausführung nach dem Preloader und vollständiger Zusammenbruch der chain-of-trust für den restlichen Boot-Pfad.
- Fähigkeit, unsigned TEE/GZ/LK/Kernel zu booten, dabei secure/verified boot-Erwartungen zu umgehen und eine persistente Kompromittierung zu ermöglichen.

## Gerätehinweise

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) re-enabled bl2_ext verification; fenrir `pacman-v2.0` restores the bypass by flashing the beta Preloader plus patched LK as shown above
- Industry coverage highlights additional lk2-based vendors shipping the same logic flaw, so expect further overlap across 2024–2025 MTK releases.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)

{{#include ../../banners/hacktricks-training.md}}
