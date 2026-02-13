# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite dokumentiert einen praktischen secure-boot Break auf mehreren MediaTek-Plattformen, indem eine Verifikationslücke ausgenutzt wird, wenn die Bootloader-Konfiguration (seccfg) des Geräts auf "unlocked" gesetzt ist. Die Schwachstelle erlaubt das Ausführen eines gepatchten bl2_ext auf ARM EL3, um die Signaturprüfung nachgelagerter Komponenten zu deaktivieren, die Vertrauenskette zum Einsturz zu bringen und das Laden beliebiger unsigned TEE/GZ/LK/Kernel zu ermöglichen.

> Vorsicht: Early-boot patching kann Geräte dauerhaft bricken, wenn Offsets falsch sind. Bewahre immer vollständige Dumps und einen verlässlichen Recovery-Pfad.

## Betroffener Bootablauf (MediaTek)

- Normaler Pfad: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Verwundbarer Pfad: Wenn seccfg auf unlocked gesetzt ist, kann der Preloader die Verifikation von bl2_ext überspringen. Der Preloader springt dennoch in bl2_ext auf EL3, sodass ein manipuliertes bl2_ext danach unverifizierte Komponenten laden kann.

Wichtige Vertrauensgrenze:
- bl2_ext läuft auf EL3 und ist verantwortlich für die Verifikation von TEE, GenieZone, LK/AEE und dem Kernel. Wenn bl2_ext selbst nicht authentifiziert ist, lässt sich der Rest der Kette trivial umgehen.

## Root cause

Auf betroffenen Geräten erzwingt der Preloader keine Authentifizierung der bl2_ext-Partition, wenn seccfg einen "unlocked"-Zustand anzeigt. Dadurch ist es möglich, ein vom Angreifer kontrolliertes bl2_ext zu flashen, das auf EL3 ausgeführt wird.

Innerhalb von bl2_ext kann die Verifikations-Policy-Funktion so gepatcht werden, dass sie bedingungslos meldet, dass keine Verifikation erforderlich ist (oder immer erfolgreich ist), wodurch die Boot-Kette gezwungen wird, unsigned TEE/GZ/LK/Kernel-Images zu akzeptieren. Da dieser Patch auf EL3 läuft, ist er wirksam, selbst wenn nachgelagerte Komponenten eigene Prüfungen implementieren.

## Practical exploit chain

1. Bootloader-Partitionen (Preloader, bl2_ext, LK/AEE usw.) über OTA/firmware-Pakete, EDL/DA readback oder Hardware-Dumps beschaffen.
2. Die bl2_ext Verifikationsroutine identifizieren und so patchen, dass sie Verifikation immer überspringt/akzeptiert.
3. Das modifizierte bl2_ext über fastboot, DA oder ähnliche Wartungskanäle flashen, die auf unlocked Geräten weiterhin erlaubt sind.
4. Neustarten; der Preloader springt zu dem gepatchten bl2_ext auf EL3, welches dann unsigned nachgelagerte Images (gepatchtes TEE/GZ/LK/Kernel) lädt und die Signaturprüfung deaktiviert.

Wenn das Gerät als locked konfiguriert ist (seccfg locked), wird vom Preloader erwartet, dass er bl2_ext verifiziert. In dieser Konfiguration schlägt dieser Angriff fehl, es sei denn eine andere Schwachstelle erlaubt das Laden eines unsigned bl2_ext.

## Triage (expdb boot logs)

- Boot/expdb-Logs rund um das Laden von bl2_ext dumpen. Wenn `img_auth_required = 0` und die Zertifikatsverifikationszeit etwa 0 ms beträgt, wird die Verifikation wahrscheinlich übersprungen.

Example log excerpt:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Einige Geräte überspringen die bl2_ext-Verifizierung selbst wenn gesperrt; lk2-Secondary-Bootloader-Pfade haben dieselbe Lücke gezeigt. Wenn ein Post-OTA Preloader `img_auth_required = 1` für bl2_ext protokolliert, während das Gerät entsperrt ist, wurde die Durchsetzung wahrscheinlich wiederhergestellt.

## Verification logic locations

- Die relevante Prüfung befindet sich typischerweise innerhalb des bl2_ext-Images in Funktionen mit Namen ähnlich `verify_img` oder `sec_img_auth`.
- Die gepatchte Version zwingt die Funktion, Erfolg zurückzugeben, oder umgeht den Verifizierungsaufruf vollständig.

Example patch approach (conceptual):
- Finde die Funktion, die `sec_img_auth` für TEE-, GZ-, LK- und Kernel-Images aufruft.
- Ersetze ihren Body durch einen Stub, der sofort Erfolg zurückgibt, oder überschreibe den konditionalen Branch, der Verifizierungsfehler behandelt.

Stelle sicher, dass der Patch das Stack/Frame-Setup bewahrt und die erwarteten Statuscodes an Aufrufer zurückgibt.

## Fenrir PoC workflow (Nothing/CMF)

Fenrir ist ein Referenz-Patching-Toolkit für dieses Problem (Nothing Phone (2a) vollständig unterstützt; CMF Phone 1 teilweise). Auf hoher Ebene:
- Lege das Bootloader-Image des Geräts als `bin/<device>.bin` ab.
- Erzeuge ein gepatchtes Image, das die bl2_ext-Verifizierungsrichtlinie deaktiviert.
- Flashe die resultierende Payload (fastboot helper wird bereitgestellt).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Verwende einen anderen Flashing-Kanal, wenn fastboot nicht verfügbar ist.

## Hinweise zum EL3-Patching

- bl2_ext läuft in ARM EL3. Abstürze hier können ein Gerät bricken, bis es per EDL/DA oder über Testpunkte neu geflasht wird.
- Verwende board-spezifisches Logging/UART, um den Ausführungspfad zu validieren und Abstürze zu diagnostizieren.
- Erstelle Sicherungen aller zu ändernden Partitionen und teste zunächst an entbehrlicher Hardware.

## Auswirkungen

- EL3-Codeausführung nach dem Preloader und vollständiger Zusammenbruch der Vertrauenskette für den restlichen Boot-Pfad.
- Möglichkeit, unsigned TEE/GZ/LK/Kernel zu booten, wodurch secure/verified boot-Erwartungen umgangen werden und eine persistente Kompromittierung ermöglicht wird.

## Gerätehinweise

- Bestätigt unterstützt: Nothing Phone (2a) (Pacman)
- Bekannt funktionierend (unvollständige Unterstützung): CMF Phone 1 (Tetris)
- Beobachtet: Beim Vivo X80 Pro wurde berichtet, dass bl2_ext nicht verifiziert wurde, selbst wenn das Gerät gesperrt war
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) hat die Verifikation von bl2_ext wieder aktiviert; fenrir `pacman-v2.0` stellt den Bypass wieder her, indem es den Beta-Preloader mit einem gepatchten LK mischt
- Branchendeckung hebt weitere lk2-basierte Anbieter hervor, die denselben Logikfehler ausliefern, daher ist mit weiterer Überschneidung in den MTK-Releases 2024–2025 zu rechnen.

## MTK DA-Auslesung und seccfg-Manipulation mit Penumbra

Penumbra ist eine Rust crate/CLI/TUI, die die Interaktion mit dem MTK Preloader/Bootrom über USB für DA-mode-Operationen automatisiert. Mit physischem Zugriff auf ein verwundbares Handy (DA extensions erlaubt) kann es den MTK-USB-Port erkennen, einen Download Agent (DA)-Blob laden und privilegierte Befehle ausführen, wie z. B. das Umschalten des seccfg-Locks und das Auslesen von Partitionen.

- **Umgebung/Treiber-Setup**: Unter Linux `libudev` installieren, den Benutzer zur Gruppe `dialout` hinzufügen und udev-Regeln erstellen oder mit `sudo` ausführen, falls das Gerätedatei nicht zugänglich ist. Die Windows-Unterstützung ist unzuverlässig; manchmal funktioniert es erst, nachdem der MTK-Treiber gemäß Projektanleitung mit WinUSB über Zadig ersetzt wurde.
- **Ablauf**: Lese eine DA-Payload (z. B. `std::fs::read("../DA_penangf.bin")`), poll den MTK-Port mit `find_mtk_port()`, und baue eine Session mit `DeviceBuilder::with_mtk_port(...).with_da_data(...)` auf. Nachdem `init()` den Handshake abgeschlossen und Geräteinformationen gesammelt hat, überprüfe Schutzmechanismen über die Bitfelder von `dev_info.target_config()` (Bit 0 gesetzt → SBC aktiviert). Wechsle in den DA-Modus und versuche `set_seccfg_lock_state(LockFlag::Unlock)` — dies gelingt nur, wenn das Gerät Extensions akzeptiert. Partitionen können mit `read_partition("lk_a", &mut progress_cb, &mut writer)` gedumpt werden für Offline-Analyse oder Patchen.
- **Sicherheitsauswirkung**: Erfolgreiches Entsperren von seccfg öffnet die Flash-Pfade für unsigned Boot-Images wieder und ermöglicht persistente Kompromittierungen wie das oben beschriebene bl2_ext EL3-Patching. Das Auslesen von Partitionen liefert Firmware-Artefakte für Reverse Engineering und das Erstellen modifizierter Images.

<details>
<summary>Rust DA-Session + seccfg-Unlock + Partition-Dump (Penumbra)</summary>
```rust
use tokio::fs::File;
use anyhow::Result;
use penumbra::{DeviceBuilder, LockFlag, find_mtk_port};
use tokio::io::{AsyncWriteExt, BufWriter};

#[tokio::main]
async fn main() -> Result<()> {
let da = std::fs::read("../DA_penangf.bin")?;
let mtk_port = loop {
if let Some(port) = find_mtk_port().await {
break port;
}
};

let mut dev = DeviceBuilder::default()
.with_mtk_port(mtk_port)
.with_da_data(da)
.build()?;

dev.init().await?;
let cfg = dev.dev_info.target_config().await;
println!("SBC: {}", (cfg & 0x1) != 0);

dev.set_seccfg_lock_state(LockFlag::Unlock).await?;

let mut progress = |_read: usize, _total: usize| {};
let mut writer = BufWriter::new(File::create("lk_a.bin")?);
dev.read_partition("lk_a", &mut progress, &mut writer).await?;
writer.flush().await?;
Ok(())
}
```
</details>

## Quellen

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
