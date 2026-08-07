# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite dokumentiert einen praktischen Secure-Boot-Break auf mehreren MediaTek-Plattformen, bei dem eine Verifizierungslücke ausgenutzt wird, wenn die Bootloader-Konfiguration des Geräts (seccfg) „unlocked“ ist. Die Schwachstelle ermöglicht die Ausführung eines gepatchten bl2_ext auf ARM EL3, um die nachgelagerte Signaturverifizierung zu deaktivieren, wodurch die Vertrauenskette zusammenbricht und das Laden beliebiger unsignierter TEE/GZ/LK/Kernel ermöglicht wird.<sup>[[1]](#references)</sup>

> Vorsicht: Patching während des frühen Bootvorgangs kann Geräte dauerhaft unbrauchbar machen, wenn Offsets falsch sind. Bewahre immer vollständige Dumps und einen zuverlässigen Recovery-Pfad auf.

## Betroffener Bootablauf (MediaTek)

- Normaler Pfad: BootROM → Preloader → bl2_ext (EL3, verifiziert) → TEE → GenieZone (GZ) → LK/AEE → Linux-Kernel (EL1)
- Verwundbarer Pfad: Wenn seccfg auf unlocked gesetzt ist, überspringt der Preloader möglicherweise die Verifizierung von bl2_ext. Der Preloader springt weiterhin zu bl2_ext auf EL3, sodass ein speziell erstelltes bl2_ext danach nicht verifizierte Komponenten laden kann.

Wichtige Vertrauensgrenze:
- bl2_ext wird auf EL3 ausgeführt und ist für die Verifizierung von TEE, GenieZone, LK/AEE und dem Kernel verantwortlich. Wenn bl2_ext selbst nicht authentifiziert ist, kann der Rest der Vertrauenskette trivial umgangen werden.<sup>[[1]](#references)</sup>

## Ursache

Auf betroffenen Geräten erzwingt der Preloader keine Authentifizierung der bl2_ext-Partition, wenn seccfg einen „unlocked“-Zustand anzeigt. Dadurch kann ein Angreifer ein kontrolliertes bl2_ext flashen, das auf EL3 ausgeführt wird.

Innerhalb von bl2_ext kann die Funktion für die Verifizierungspolitik so gepatcht werden, dass sie unbedingt meldet, dass keine Verifizierung erforderlich ist (oder dass sie immer erfolgreich war). Dadurch akzeptiert die Bootkette unsignierte TEE/GZ/LK/Kernel-Images. Da dieser Patch auf EL3 ausgeführt wird, ist er auch dann wirksam, wenn nachgelagerte Komponenten eigene Prüfungen implementieren.<sup>[[1]](#references)</sup>

## Praktische Exploit-Kette

1. Bootloader-Partitionen (Preloader, bl2_ext, LK/AEE usw.) über OTA-/Firmware-Pakete, EDL/DA-Readback oder Hardware-Dumping beschaffen.
2. Die bl2_ext-Verifizierungsroutine identifizieren und so patchen, dass die Verifizierung immer übersprungen oder akzeptiert wird.
3. Das modifizierte bl2_ext über fastboot, DA oder ähnliche Wartungskanäle flashen, die auf entsperrten Geräten weiterhin verfügbar sind.
4. Neustarten; der Preloader springt zu dem gepatchten bl2_ext auf EL3, das anschließend unsignierte nachgelagerte Images (gepatchtes TEE/GZ/LK/Kernel) lädt und die Durchsetzung der Signaturprüfung deaktiviert.<sup>[[1]](#references)</sup>

Wenn das Gerät als locked konfiguriert ist (seccfg locked), wird erwartet, dass der Preloader bl2_ext verifiziert. In dieser Konfiguration schlägt der Angriff fehl, sofern keine andere Schwachstelle das Laden eines unsignierten bl2_ext ermöglicht.

## Triage (expdb-Bootlogs)

- Boot-/expdb-Logs rund um das Laden von bl2_ext dumpen. Wenn `img_auth_required = 0` und die Zertifikatsverifizierungszeit ungefähr 0 ms beträgt, wurde die Verifizierung wahrscheinlich übersprungen.<sup>[[1]](#references)</sup>

Beispiel eines Log-Auszugs:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Einige Geräte überspringen die bl2_ext-Verifizierung, selbst wenn sie gesperrt sind; bei sekundären lk2-Bootloader-Pfaden wurde dieselbe Lücke festgestellt. Wenn ein Preloader nach einem OTA-Update bei entsperrtem Zustand `img_auth_required = 1` für bl2_ext protokolliert, wurde die Durchsetzung wahrscheinlich wiederhergestellt.<sup>[[1]](#references)[[2]](#references)</sup>

## Orte der Verifizierungslogik

- Die relevante Prüfung befindet sich typischerweise innerhalb des bl2_ext-Images in Funktionen mit ähnlichen Namen wie `verify_img` oder `sec_img_auth`.
- Die gepatchte Version erzwingt, dass die Funktion Erfolg zurückgibt, oder umgeht den Verifizierungsaufruf vollständig.<sup>[[1]](#references)</sup>

Beispiel für einen Patch-Ansatz (konzeptionell):
- Finde die Funktion, die `sec_img_auth` für TEE-, GZ-, LK- und Kernel-Images aufruft.
- Ersetze ihren Body durch einen Stub, der sofort Erfolg zurückgibt, oder überschreibe den Conditional Branch, der den Verifizierungsfehler verarbeitet.

Stelle sicher, dass der Patch das Stack-/Frame-Setup beibehält und den von den aufrufenden Funktionen erwarteten Statuscode zurückgibt.<sup>[[1]](#references)</sup>

## Fenrir-PoC-Workflow (Nothing/CMF)

Fenrir ist ein Referenz-Toolkit zum Patchen für dieses Problem (Nothing Phone (2a) vollständig unterstützt; CMF Phone 1 teilweise).<sup>[[1]](#references)</sup> Auf hoher Ebene:
- Platziere das Bootloader-Image des Geräts als `bin/<device>.bin`.
- Erstelle ein gepatchtes Image, das die bl2_ext-Verifizierungsrichtlinie deaktiviert.
- Flash das resultierende Payload (fastboot helper wird bereitgestellt).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Verwende einen anderen Flash-Kanal, wenn fastboot nicht verfügbar ist.

## Hinweise zum Patching von EL3

- bl2_ext wird in ARM EL3 ausgeführt. Abstürze an dieser Stelle können ein Gerät unbrauchbar machen, bis es über EDL/DA oder Testpunkte neu geflasht wird.
- Verwende boardspezifisches Logging/UART, um den Ausführungspfad zu überprüfen und Abstürze zu diagnostizieren.
- Erstelle Backups aller Partitionen, die geändert werden, und teste zunächst auf wegwerfbarer Hardware.<sup>[[1]](#references)</sup>

## Auswirkungen

- EL3-Codeausführung nach Preloader sowie ein vollständiger Zusammenbruch der Chain-of-Trust für den restlichen Bootpfad.
- Möglichkeit, unsignierte TEE/GZ/LK/Kernel zu booten, wodurch Erwartungen an Secure/Verified Boot umgangen und persistente Kompromittierungen ermöglicht werden.<sup>[[1]](#references)</sup>

## Gerätehinweise

- Bestätigt unterstützt: Nothing Phone (2a) (Pacman)
- Bekanntermaßen funktionsfähig (unvollständige Unterstützung): CMF Phone 1 (Tetris)
- Beobachtung: Beim Vivo X80 Pro wurde bl2_ext Berichten zufolge selbst im gesperrten Zustand nicht verifiziert<sup>[[1]](#references)</sup>
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) hat die bl2_ext-Verifizierung wieder aktiviert; fenrir `pacman-v2.0` stellt den Bypass wieder her, indem der Beta-Preloader mit einem gepatchten LK kombiniert wird<sup>[[3]](#references)</sup>
- Die Berichterstattung aus der Branche hebt zusätzliche lk2-basierte Anbieter hervor, die denselben Logikfehler ausliefern. Daher ist mit weiterer Überschneidung bei MTK-Releases aus den Jahren 2024–2025 zu rechnen.<sup>[[2]](#references)[[4]](#references)</sup>

## MTK-DA-Readback und seccfg-Manipulation mit Penumbra

Penumbra ist eine Rust-Crate/CLI/TUI, die die Interaktion mit MTK-Preloader/Bootrom über USB für DA-mode-Operationen automatisiert. Mit physischem Zugriff auf ein verwundbares Mobilgerät (DA extensions erlaubt) kann sie den MTK-USB-Port erkennen, ein Download-Agent-(DA-)Blob laden und privilegierte Befehle wie das Ändern des seccfg-Sperrstatus sowie das Auslesen von Partitionen ausführen.<sup>[[5]](#references)</sup>

- **Umgebungs-/Treiberkonfiguration**: Installiere unter Linux `libudev`, füge den Benutzer zur Gruppe `dialout` hinzu und erstelle udev-Regeln oder führe das Programm mit `sudo` aus, wenn der Geräteknoten nicht zugänglich ist. Die Windows-Unterstützung ist unzuverlässig; laut Projekthinweisen funktioniert sie manchmal erst, nachdem der MTK-Treiber mit Zadig durch WinUSB ersetzt wurde.
- **Workflow**: Lies eine DA-Nutzlast ein (z. B. `std::fs::read("../DA_penangf.bin")`), frage mit `find_mtk_port()` nach dem MTK-Port und erstelle mit `DeviceBuilder::with_mtk_port(...).with_da_data(...)` eine Session. Nachdem `init()` den Handshake abgeschlossen und Geräteinformationen gesammelt hat, überprüfe den Schutz über die Bitfelder von `dev_info.target_config()` (Bit 0 gesetzt → SBC aktiviert). Wechsle in den DA-mode und versuche `set_seccfg_lock_state(LockFlag::Unlock)` – dies ist nur erfolgreich, wenn das Gerät extensions akzeptiert. Partitionen können mit `read_partition("lk_a", &mut progress_cb, &mut writer)` für die Offline-Analyse oder zum Patchen ausgelesen werden.
- **Sicherheitsauswirkungen**: Ein erfolgreiches seccfg-Unlocking öffnet Flashing-Pfade für unsignierte Boot-Images erneut und ermöglicht persistente Kompromittierungen wie das oben beschriebene bl2_ext-EL3-Patching. Das Auslesen von Partitionen liefert Firmware-Artefakte für Reverse Engineering und die Erstellung modifizierter Images.

<details>
<summary>Rust-DA-Session + seccfg-Unlock + Partitionsdump (Penumbra)</summary>
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

## Referenzen

- [1] [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [2] [Cyber Security News – PoC Exploit für Code Execution-Schwachstelle auf Nothing Phone veröffentlicht](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [3] [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [4] [The Cyber Express – Fenrir PoC bricht secure boot auf Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [5] [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
