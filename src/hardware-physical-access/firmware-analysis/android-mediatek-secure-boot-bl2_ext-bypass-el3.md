# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina documenta una compromissione pratica del secure-boot su più piattaforme MediaTek sfruttando una lacuna di verifica quando la configurazione del bootloader del dispositivo (seccfg) è "unlocked". La vulnerabilità consente di eseguire un bl2_ext patchato a ARM EL3 per disabilitare la verifica delle firme a valle, collassando la catena di fiducia e permettendo il caricamento arbitrario di TEE/GZ/LK/Kernel non firmati.

> Avvertenza: La patch delle prime fasi di boot può brickare permanentemente i dispositivi se gli offset sono errati. Conserva sempre dump completi e una procedura di recovery affidabile.

## Affected boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Confine di fiducia chiave:
- bl2_ext esegue a EL3 ed è responsabile della verifica di TEE, GenieZone, LK/AEE e del kernel. Se bl2_ext stesso non è autenticato, il resto della catena viene banalmente bypassato.

## Root cause

Su dispositivi interessati, il Preloader non applica l'autenticazione della partizione bl2_ext quando seccfg indica uno stato "unlocked". Questo permette il flashing di un bl2_ext controllato dall'attaccante che viene eseguito a EL3.

All'interno di bl2_ext, la funzione di policy di verifica può essere patchata per riportare incondizionatamente che la verifica non è richiesta (o che ha sempre successo), costringendo la catena di boot ad accettare immagini TEE/GZ/LK/Kernel non firmate. Poiché questa patch viene eseguita a EL3, è efficace anche se i componenti a valle implementano i propri controlli.

## Practical exploit chain

1. Ottenere le partizioni del bootloader (Preloader, bl2_ext, LK/AEE, ecc.) tramite OTA/firmware packages, EDL/DA readback o dump hardware.
2. Identificare la routine di verifica in bl2_ext e patcharla per saltare/accettare sempre la verifica.
3. Flashare il bl2_ext modificato usando fastboot, DA o canali di manutenzione simili ancora permessi su dispositivi unlocked.
4. Reboot; il Preloader salta al bl2_ext patchato a EL3 che poi carica immagini downstream non firmate (TEE/GZ/LK/Kernel patchati) e disabilita l'enforcement delle firme.

Se il dispositivo è configurato come locked (seccfg locked), il Preloader dovrebbe verificare bl2_ext. In quella configurazione, questo attacco fallirà a meno che un'altra vulnerabilità non permetta il caricamento di un bl2_ext non firmato.

## Triage (expdb boot logs)

- Dump dei log di boot/expdb attorno al caricamento di bl2_ext. Se `img_auth_required = 0` e il tempo di verifica del certificato è ~0 ms, è probabile che la verifica venga saltata.

Esempio di estratto dei log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Alcuni dispositivi saltano la verifica di bl2_ext anche quando il bootloader è bloccato; i percorsi del secondary bootloader lk2 hanno mostrato la stessa lacuna. Se un Preloader post-OTA registra `img_auth_required = 1` per bl2_ext mentre è sbloccato, è probabile che l'enforcement sia stato ripristinato.

## Verification logic locations

- Il controllo rilevante risiede tipicamente all'interno dell'immagine bl2_ext in funzioni chiamate in modo simile a `verify_img` o `sec_img_auth`.
- La versione patchata forza la funzione a restituire successo oppure evita completamente la chiamata di verifica.

Example patch approach (conceptual):
- Individua la funzione che chiama `sec_img_auth` su immagini TEE, GZ, LK e kernel.
- Sostituisci il suo corpo con uno stub che restituisce immediatamente successo, oppure sovrascrivi il ramo condizionale che gestisce il fallimento della verifica.

Assicurati che la patch preservi la configurazione di stack/frame e restituisca ai chiamanti i codici di stato attesi.

## Fenrir PoC workflow (Nothing/CMF)

Fenrir è un toolkit di patching di riferimento per questo problema (Nothing Phone (2a) pienamente supportato; CMF Phone 1 parzialmente). In breve:
- Posiziona l'immagine del bootloader del dispositivo in `bin/<device>.bin`.
- Costruisci un'immagine patchata che disabiliti la policy di verifica di bl2_ext.
- Flasha il payload risultante (fastboot helper fornito).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Usare un altro canale di flashing se fastboot non è disponibile.

## Note sul patching EL3

- bl2_ext viene eseguito in ARM EL3. I crash a questo livello possono brickare il dispositivo fino a quando non viene riflashato tramite EDL/DA o test points.
- Usare il logging/UART specifico della board per validare il percorso di esecuzione e diagnosticare i crash.
- Conservare backup di tutte le partizioni modificate e testare prima su hardware usa-e-getta.

## Implicazioni

- Esecuzione di codice a EL3 dopo il Preloader e collasso completo della chain-of-trust per il resto del percorso di boot.
- Possibilità di avviare TEE/GZ/LK/Kernel non firmati, bypassando le aspettative di secure/verified boot e permettendo un compromesso persistente.

## Note sui dispositivi

- Supportato confermato: Nothing Phone (2a) (Pacman)
- Funzionante noto (supporto incompleto): CMF Phone 1 (Tetris)
- Osservato: Vivo X80 Pro risulta non verificare bl2_ext anche quando è locked
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) ha riattivato la verifica di bl2_ext; fenrir `pacman-v2.0` ripristina il bypass mescolando il Preloader beta con un LK patchato
- La copertura del settore evidenzia ulteriori vendor basati su lk2 che distribuiscono la stessa falla logica, quindi aspettarsi ulteriori casi simili nelle release MTK 2024–2025.

## Lettura MTK DA e manipolazione di seccfg con Penumbra

Penumbra è un crate/CLI/TUI Rust che automatizza l'interazione con MTK preloader/bootrom via USB per operazioni in modalità DA. Con accesso fisico a un handset vulnerabile (DA extensions consentite), può scoprire la porta USB MTK, caricare un Download Agent (DA) blob e inviare comandi privilegiati quali l'inversione dello seccfg lock e la lettura delle partizioni.

- **Ambiente/configurazione driver**: Su Linux installare `libudev`, aggiungere l'utente al gruppo `dialout`, e creare regole udev o eseguire con `sudo` se il device node non è accessibile. Il supporto Windows è inaffidabile; a volte funziona solo dopo aver sostituito il driver MTK con WinUSB usando Zadig (secondo le indicazioni del progetto).
- **Flusso di lavoro**: Leggere un payload DA (es., `std::fs::read("../DA_penangf.bin")`), sondare la porta MTK con `find_mtk_port()`, e costruire una sessione usando `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Dopo che `init()` completa l'handshake e raccoglie le info del device, verificare le protezioni tramite i bitfields di `dev_info.target_config()` (bit 0 impostato → SBC enabled). Entrare in modalità DA e tentare `set_seccfg_lock_state(LockFlag::Unlock)`—questo ha successo solo se il dispositivo accetta le extensions. Le partizioni possono essere dumpate con `read_partition("lk_a", &mut progress_cb, &mut writer)` per analisi offline o patching.
- **Impatto sulla sicurezza**: Un successo nello sblocco di seccfg riapre le vie di flashing per boot image non firmate, permettendo compromessi persistenti come il patching bl2_ext EL3 descritto sopra. La lettura delle partizioni fornisce artefatti firmware per reverse engineering e per creare immagini modificate.

<details>
<summary>Rust DA session + seccfg unlock + partition dump (Penumbra)</summary>
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

## Riferimenti

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
