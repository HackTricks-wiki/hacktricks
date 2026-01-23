# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina documenta una compromissione pratica del secure-boot su più piattaforme MediaTek sfruttando una lacuna di verifica quando la configurazione del bootloader del dispositivo (seccfg) è "unlocked". Il difetto permette di eseguire un bl2_ext patchato su ARM EL3 per disabilitare la verifica delle firme a valle, collassando la chain of trust e consentendo il caricamento arbitrario di TEE/GZ/LK/Kernel non firmati.

> Attenzione: il patching in early-boot può brickare permanentemente i dispositivi se gli offset sono errati. Conserva sempre dump completi e un percorso di recupero affidabile.

## Flusso di boot interessato (MediaTek)

- Percorso normale: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Percorso vulnerabile: Quando seccfg è impostato su unlocked, il Preloader può saltare la verifica di bl2_ext. Il Preloader comunque salta in bl2_ext a EL3, quindi un bl2_ext creato ad arte può caricare componenti non verificati successivamente.

Confine chiave della fiducia:
- bl2_ext viene eseguito a EL3 ed è responsabile della verifica di TEE, GenieZone, LK/AEE e del kernel. Se lo stesso bl2_ext non è autenticato, il resto della chain of trust viene facilmente bypassato.

## Causa

Sui dispositivi interessati, il Preloader non applica l'autenticazione della partizione bl2_ext quando seccfg indica uno stato "unlocked". Questo permette di flashare un bl2_ext controllato dall'attaccante che viene eseguito a EL3.

All'interno di bl2_ext, la funzione di policy di verifica può essere patchata per restituire incondizionatamente che la verifica non è richiesta. Una patch concettuale minima è:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Con questa modifica, tutte le immagini successive (TEE, GZ, LK/AEE, Kernel) vengono accettate senza controlli crittografici quando vengono caricate dal bl2_ext patchato in esecuzione a EL3.

## Come effettuare il triage di un target (expdb logs)

Esegui il dump/ispeziona i log di avvio (es., expdb) intorno al caricamento di bl2_ext. Se img_auth_required = 0 e il tempo di verifica del certificato è ~0 ms, è probabile che l'enforcement sia disabilitato e il dispositivo sia sfruttabile.

Esempio di estratto del log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Nota: Alcuni dispositivi riportano di saltare la verifica di bl2_ext anche con il bootloader bloccato, il che aggrava l'impatto.

I dispositivi che includono il bootloader secondario lk2 sono stati osservati con la stessa lacuna logica, quindi acquisisci i log expdb per entrambe le partizioni bl2_ext e lk2 per confermare se uno dei due percorsi applica le firme prima di tentare il porting.

Se un Preloader post-OTA ora registra img_auth_required = 1 per bl2_ext anche mentre seccfg è sbloccato, il vendor probabilmente ha chiuso la falla — vedi le note sulla persistenza OTA qui sotto.

## Flusso di sfruttamento pratico (Fenrir PoC)

Fenrir è un toolkit di riferimento per exploit/patching per questa classe di problemi. Supporta Nothing Phone (2a) (Pacman) ed è noto funzionare (con supporto incompleto) su CMF Phone 1 (Tetris). Il porting ad altri modelli richiede il reverse engineering del bl2_ext specifico del dispositivo.

Processo ad alto livello:
- Ottieni l'immagine del bootloader del dispositivo per il tuo codename target e posizionala come `bin/<device>.bin`
- Costruisci un'immagine patchata che disabiliti la policy di verifica di bl2_ext
- Flasha il payload risultante sul dispositivo (lo script helper presume fastboot)

Comandi:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
Se fastboot non è disponibile, devi usare un metodo di flashing alternativo adatto alla tua piattaforma.

### OTA-patched firmware: mantenere il bypass attivo (NothingOS 4, fine 2025)

Nothing ha corretto il Preloader nella OTA stabile NothingOS 4 di novembre 2025 (build BP2A.250605.031.A3) per far rispettare la verifica di bl2_ext anche quando seccfg è sbloccato. Fenrir `pacman-v2.0` funziona di nuovo mescolando il Preloader vulnerabile della beta NOS 4 con il payload LK stabile:
```bash
# on Nothing Phone (2a), unlocked bootloader, in bootloader (not fastbootd)
fastboot flash preloader_a preloader_raw.img   # beta Preloader bundled with fenrir release
fastboot flash lk pacman-fenrir.bin            # patched LK containing stage hooks
fastboot reboot                                # factory reset may be needed
```
Importante:
- Flashare il Preloader fornito **solo** sul dispositivo/slot corrispondente; un preloader sbagliato provoca un hard brick immediato.
- Controlla expdb dopo il flashing; img_auth_required dovrebbe tornare a 0 per bl2_ext, confermando che il Preloader vulnerabile viene eseguito prima del tuo LK patchato.
- Se future OTAs patchano sia Preloader che LK, mantieni una copia locale di un Preloader vulnerabile per reintrodurre la lacuna.

### Build automation & payload debugging

- `build.sh` ora scarica automaticamente ed esporta l'Arm GNU Toolchain 14.2 (aarch64-none-elf) la prima volta che lo esegui, così non devi gestire manualmente i cross-compiler.
- Esporta `DEBUG=1` prima di invocare `build.sh` per compilare i payload con stampe seriali verbose, che aiutano molto quando stai blind-patching i percorsi di codice EL3.
- Build riusciti producono sia `lk.patched` che `<device>-fenrir.bin`; quest'ultimo ha già il payload iniettato ed è ciò che dovresti flashare/testare all'avvio.

## Runtime payload capabilities (EL3)

Un payload patchato per bl2_ext può:
- Registrare comandi fastboot personalizzati
- Controllare/sovrascrivere la modalità di boot
- Chiamare dinamicamente funzioni integrate del bootloader a runtime
- Spoofare lo “stato di lock” come locked mentre in realtà è unlocked per superare controlli di integrità più stringenti (alcuni ambienti potrebbero comunque richiedere aggiustamenti a vbmeta/AVB)

Limitazione: le PoCs attuali notano che le modifiche in memoria a runtime possono causare fault a causa di vincoli MMU; i payload generalmente evitano scritture in memoria live finché questo non è risolto.

## Payload staging patterns (EL3)

Fenrir divide la sua strumentazione in tre stage al momento della compilazione: stage1 viene eseguito prima di `platform_init()`, stage2 prima che LK segnali l'entrata in fastboot, e stage3 si esegue immediatamente prima che LK carichi Linux. Ogni header dispositivo sotto `payload/devices/` fornisce gli indirizzi per questi hook oltre ai simboli helper di fastboot, quindi mantieni quegli offset sincronizzati con la tua build target.

Stage2 è un punto comodo per registrare verbi arbitrari `fastboot oem`:
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
Stage3 dimostra come invertire temporaneamente gli attributi della page-table per patchare stringhe immutabili come l’avviso “Orange State” di Android senza necessitare di accesso al kernel a valle:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Poiché stage1 viene eseguito prima dell'avvio della piattaforma, è il punto giusto per richiamare le primitive OEM di alimentazione/reset o per inserire logging di integrità aggiuntivo prima che la catena di boot verificato venga smantellata.

## Porting tips

- Eseguire reverse engineering del bl2_ext specifico del dispositivo per individuare la logica della policy di verifica (es. sec_get_vfy_policy).
- Individuare il sito di ritorno della policy o il ramo decisionale e patcharlo in modo da “no verification required” (return 0 / unconditional allow).
- Mantenere gli offset completamente specifici per dispositivo e firmware; non riutilizzare indirizzi tra varianti.
- Validare prima su un'unità sacrificabile. Preparare un piano di recovery (es. EDL/BootROM loader/modalità di download specifica SoC) prima di effettuare il flash.
- I dispositivi che usano il secondary bootloader lk2 o che riportano “img_auth_required = 0” per bl2_ext anche quando sono locked dovrebbero essere trattati come copie vulnerabili di questa classe di bug; è stato osservato che Vivo X80 Pro salta la verifica nonostante lo stato di lock riportato.
- Quando un OTA inizia a far rispettare le firme di bl2_ext (img_auth_required = 1) nello stato unlocked, verificare se è possibile flashare un Preloader più vecchio (spesso disponibile nelle beta OTA) per riaprire la falla, quindi rieseguire fenrir con offset aggiornati per il nuovo LK.

## Security impact

- Esecuzione di codice a EL3 dopo il Preloader e collasso completo della catena di fiducia per il resto del percorso di boot.
- Possibilità di eseguire TEE/GZ/LK/Kernel non firmati, bypassando le aspettative di secure/verified boot e permettendo una compromissione persistente.

## Device notes

- Confermato supportato: Nothing Phone (2a) (Pacman)
- Funzionante noto (supporto incompleto): CMF Phone 1 (Tetris)
- Osservato: Vivo X80 Pro riportato come non aver verificato bl2_ext anche quando locked
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) ha riabilitato la verifica di bl2_ext; fenrir `pacman-v2.0` ripristina il bypass flashando il Preloader beta più il LK patchato come mostrato sopra
- La copertura del settore evidenzia ulteriori vendor basati su lk2 che distribuiscono la stessa falla logica, quindi aspettati ulteriori sovrapposizioni nelle release MTK 2024–2025.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)

{{#include ../../banners/hacktricks-training.md}}
