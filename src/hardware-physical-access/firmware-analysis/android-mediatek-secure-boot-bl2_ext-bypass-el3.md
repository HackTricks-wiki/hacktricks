# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina documenta una violazione pratica del secure boot su diverse piattaforme MediaTek, sfruttando una lacuna nella verifica quando la configurazione del bootloader del dispositivo (seccfg) è "unlocked". La flaw consente di eseguire un bl2_ext modificato ad ARM EL3 per disabilitare la verifica delle firme successive, facendo crollare la chain of trust e abilitando il caricamento arbitrario di TEE/GZ/LK/Kernel non firmati.<sup>[[1]](#references)</sup>

> Attenzione: il patching nelle fasi iniziali del boot può brickare permanentemente i dispositivi se gli offset sono errati. Conservare sempre dump completi e una procedura di recovery affidabile.

## Flusso di boot interessato (MediaTek)

- Percorso normale: BootROM → Preloader → bl2_ext (EL3, verificato) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Percorso vulnerabile: quando seccfg è impostato su unlocked, il Preloader può saltare la verifica di bl2_ext. Il Preloader esegue comunque il jump verso bl2_ext ad EL3, quindi un bl2_ext appositamente creato può caricare i componenti successivi senza verifica.

Confine di trust principale:
- bl2_ext viene eseguito ad EL3 ed è responsabile della verifica di TEE, GenieZone, LK/AEE e kernel. Se bl2_ext non è autenticato, il resto della chain viene banalmente bypassato.<sup>[[1]](#references)</sup>

## Causa principale

Sui dispositivi interessati, il Preloader non applica l'autenticazione della partizione bl2_ext quando seccfg indica uno stato "unlocked". Ciò consente di flashare un bl2_ext controllato dall'attaccante, che viene eseguito ad EL3.

All'interno di bl2_ext, la funzione della policy di verifica può essere patchata per restituire incondizionatamente che la verifica non è necessaria (o che ha sempre esito positivo), forzando la chain di boot ad accettare immagini TEE/GZ/LK/Kernel non firmate. Poiché questa patch viene eseguita ad EL3, è efficace anche se i componenti successivi implementano i propri controlli.<sup>[[1]](#references)</sup>

## Catena di exploit pratica

1. Ottenere le partizioni del bootloader (Preloader, bl2_ext, LK/AEE, ecc.) tramite pacchetti OTA/firmware, readback EDL/DA o dumping hardware.
2. Identificare la routine di verifica di bl2_ext e patcharla affinché salti sempre la verifica o la accetti.
3. Flashare il bl2_ext modificato usando fastboot, DA o canali di manutenzione simili ancora consentiti sui dispositivi unlocked.
4. Riavviare; il Preloader esegue il jump verso il bl2_ext patchato ad EL3, che quindi carica immagini successive non firmate (TEE/GZ/LK/Kernel patchati) e disabilita l'applicazione delle firme.<sup>[[1]](#references)</sup>

Se il dispositivo è configurato come locked (seccfg locked), il Preloader dovrebbe verificare bl2_ext. In questa configurazione, l'attacco fallirà a meno che un'altra vulnerabilità non consenta di caricare un bl2_ext non firmato.

## Triage (log di boot expdb)

- Eseguire il dump dei log di boot/expdb relativi al caricamento di bl2_ext. Se `img_auth_required = 0` e il tempo di verifica del certificato è di circa 0 ms, è probabile che la verifica sia stata saltata.<sup>[[1]](#references)</sup>

Estratto di log di esempio:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Alcuni dispositivi saltano la verifica di bl2_ext anche quando sono bloccati; i percorsi del bootloader secondario lk2 hanno mostrato la stessa lacuna. Se un Preloader post-OTA registra `img_auth_required = 1` per bl2_ext mentre il dispositivo è sbloccato, probabilmente l'enforcement è stato ripristinato.<sup>[[1]](#references)[[2]](#references)</sup>

## Posizioni della logica di verifica

- Il controllo rilevante si trova tipicamente all'interno dell'immagine bl2_ext, in funzioni denominate in modo simile a `verify_img` o `sec_img_auth`.
- La versione patchata forza la funzione a restituire un esito positivo oppure bypassa completamente la chiamata di verifica.<sup>[[1]](#references)</sup>

Approccio di patch esemplificativo (concettuale):
- Individuare la funzione che chiama `sec_img_auth` sulle immagini TEE, GZ, LK e kernel.
- Sostituire il relativo body con uno stub che restituisca immediatamente un esito positivo oppure sovrascrivere il branch condizionale che gestisce il fallimento della verifica.

Assicurarsi che la patch preservi la configurazione dello stack/frame e restituisca ai chiamanti i codici di stato previsti.<sup>[[1]](#references)</sup>

## Workflow PoC di Fenrir (Nothing/CMF)

Fenrir è un toolkit di riferimento per il patching relativo a questo problema (Nothing Phone (2a) completamente supportato; CMF Phone 1 parzialmente).<sup>[[1]](#references)</sup> In sintesi:
- Posizionare l'immagine del bootloader del dispositivo come `bin/<device>.bin`.
- Creare un'immagine patchata che disabiliti la policy di verifica di bl2_ext.
- Flashare il payload risultante (è disponibile un helper fastboot).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Usa un altro canale di flashing se fastboot non è disponibile.

## Note sul patching di EL3

- bl2_ext viene eseguito in ARM EL3. I crash in questa fase possono rendere inutilizzabile un dispositivo fino a quando non viene riflashato tramite EDL/DA o test points.
- Usa logging/UART specifici della scheda per convalidare il percorso di esecuzione e diagnosticare i crash.
- Conserva i backup di tutte le partizioni modificate ed esegui prima i test su hardware sacrificabile.<sup>[[1]](#references)</sup>

## Implicazioni

- Esecuzione di codice in EL3 dopo Preloader e completo collasso della chain-of-trust per il resto del percorso di boot.
- Possibilità di avviare TEE/GZ/LK/Kernel non firmati, aggirando le aspettative di secure/verified boot e consentendo una compromissione persistente.<sup>[[1]](#references)</sup>

## Note sui dispositivi

- Supporto confermato: Nothing Phone (2a) (Pacman)
- Funzionante noto (supporto incompleto): CMF Phone 1 (Tetris)
- Osservato: secondo quanto riportato, Vivo X80 Pro non verificava bl2_ext neppure quando era bloccato<sup>[[1]](#references)</sup>
- NothingOS 4 stable (BP2A.250605.031.A3, novembre 2025) ha riattivato la verifica di bl2_ext; `pacman-v2.0` di fenrir ripristina il bypass combinando il Preloader beta con un LK patchato<sup>[[3]](#references)</sup>
- La copertura del settore evidenzia ulteriori vendor basati su lk2 che distribuiscono la stessa flaw logica; sono quindi previste ulteriori sovrapposizioni nelle release MTK del 2024–2025.<sup>[[2]](#references)[[4]](#references)</sup>

## Lettura MTK DA e manipolazione di seccfg con Penumbra

Penumbra è una crate/CLI/TUI Rust che automatizza l'interazione con Preloader/bootrom MTK tramite USB per operazioni in modalità DA. Con accesso fisico a un handset vulnerabile (con estensioni DA consentite), può individuare la porta USB MTK, caricare un blob Download Agent (DA) ed eseguire comandi privilegiati come il cambio dello stato di lock di seccfg e la lettura delle partizioni.<sup>[[5]](#references)</sup>

- **Configurazione dell'ambiente/driver**: su Linux installa `libudev`, aggiungi l'utente al gruppo `dialout` e crea regole udev oppure esegui con `sudo` se il device node non è accessibile. Il supporto Windows è inaffidabile; a volte funziona solo dopo aver sostituito il driver MTK con WinUSB usando Zadig (secondo le indicazioni del progetto).
- **Workflow**: leggi un payload DA (ad esempio, `std::fs::read("../DA_penangf.bin")`), esegui il polling della porta MTK con `find_mtk_port()` e crea una sessione usando `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Dopo che `init()` completa l'handshake e raccoglie le informazioni sul dispositivo, verifica le protezioni tramite i bitfield di `dev_info.target_config()` (bit 0 impostato → SBC abilitato). Entra in modalità DA e prova `set_seccfg_lock_state(LockFlag::Unlock)` — l'operazione ha successo solo se il dispositivo accetta le estensioni. Le partizioni possono essere scaricate con `read_partition("lk_a", &mut progress_cb, &mut writer)` per l'analisi offline o il patching.
- **Impatto sulla sicurezza**: lo sblocco riuscito di seccfg riapre i percorsi di flashing per immagini di boot non firmate, consentendo compromissioni persistenti come il patching EL3 di bl2_ext descritto sopra. La lettura delle partizioni fornisce artefatti firmware per il reverse engineering e la creazione di immagini modificate.

<details>
<summary>Sessione Rust DA + sblocco seccfg + dump della partizione (Penumbra)</summary>
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

- [1] [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [2] [Cyber Security News – Rilasciato il PoC dell'exploit per la vulnerabilità di code execution di Nothing Phone](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [3] [Release pacman-v2.0 di Fenrir (bundle di bypass per NothingOS 4)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [4] [The Cyber Express – Il PoC di Fenrir compromette il secure boot su Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [5] [Penumbra – tooling MTK per DA flash/readback e seccfg](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
