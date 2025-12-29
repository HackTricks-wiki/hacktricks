# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina documenta una compromissione pratica del secure-boot su più piattaforme MediaTek sfruttando una lacuna di verifica quando la configurazione del bootloader del dispositivo (seccfg) è "unlocked". La falla permette di eseguire un bl2_ext patchato a ARM EL3 per disabilitare la verifica delle firme a valle, compromettendo la catena di trust e consentendo il caricamento arbitrario di TEE/GZ/LK/Kernel non firmati.

> Attenzione: le patch in early-boot possono brickare permanentemente i dispositivi se gli offset sono sbagliati. Conservare sempre dump completi e una via di recupero affidabile.

## Flusso di boot interessato (MediaTek)

- Percorso normale: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Percorso vulnerabile: Quando seccfg è impostato su unlocked, il Preloader può saltare la verifica di bl2_ext. Il Preloader comunque salta in bl2_ext a EL3, quindi un bl2_ext costruito ad arte può caricare componenti non verificati successivamente.

Confine di fiducia chiave:
- bl2_ext esegue a EL3 ed è responsabile della verifica di TEE, GenieZone, LK/AEE e del kernel. Se lo stesso bl2_ext non è autenticato, il resto della catena può essere bypassato in modo banale.

## Causa principale

Sui dispositivi interessati, il Preloader non applica l'autenticazione della partizione bl2_ext quando seccfg indica uno stato "unlocked". Questo permette di flashare un bl2_ext controllato dall'attaccante che gira a EL3.

All'interno di bl2_ext, la funzione di policy di verifica può essere patchata per riportare in modo incondizionato che la verifica non è richiesta. Una patch concettuale minimale è:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Con questa modifica, tutte le immagini successive (TEE, GZ, LK/AEE, Kernel) vengono accettate senza controlli crittografici quando caricate dal bl2_ext patchato in esecuzione a EL3.

## Come effettuare il triage di un target (expdb logs)

Eseguire il dump/ispezionare i boot log (es., expdb) attorno al caricamento di bl2_ext. Se img_auth_required = 0 e il tempo di verifica del certificato è ~0 ms, l'enforcement è probabilmente disattivato e il dispositivo è sfruttabile.

Esempio di estratto del log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Nota: Alcuni dispositivi sembrano saltare la verifica di bl2_ext anche con il bootloader bloccato, il che acuisce l'impatto.

I dispositivi che montano il lk2 secondary bootloader hanno mostrato lo stesso gap logico, quindi acquisisci i log expdb per entrambe le partizioni bl2_ext e lk2 per confermare se uno dei due percorsi applica le firme prima di tentare il porting.

## Workflow pratico di sfruttamento (Fenrir PoC)

Fenrir è un toolkit di riferimento per exploit/patching per questa classe di problema. Supporta Nothing Phone (2a) (Pacman) ed è noto funzionare (con supporto incompleto) su CMF Phone 1 (Tetris). Il porting ad altri modelli richiede reverse engineering del bl2_ext specifico del dispositivo.

High-level process:
- Ottieni l'immagine del bootloader del dispositivo per il tuo codename target e posizionala come `bin/<device>.bin`
- Costruisci un'immagine patchata che disabiliti la policy di verifica di bl2_ext
- Flasha il payload risultante sul dispositivo (fastboot assunto dallo script helper)

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

### Build automation & payload debugging

- `build.sh` ora scarica automaticamente ed esporta Arm GNU Toolchain 14.2 (aarch64-none-elf) la prima volta che lo esegui, così non devi gestire manualmente più cross-compiler.
- Esporta `DEBUG=1` prima di invocare `build.sh` per compilare i payload con stampe seriali verbose, cosa che aiuta molto quando esegui blind-patching dei percorsi di codice EL3.
- Le build riuscite producono sia `lk.patched` che `<device>-fenrir.bin`; quest'ultimo ha già il payload iniettato ed è ciò che dovresti flashare/testare all'avvio.

## Runtime payload capabilities (EL3)

Un payload bl2_ext patchato può:
- Registrare comandi fastboot personalizzati
- Controllare/sovrascrivere la modalità di avvio
- Chiamare dinamicamente funzioni built‑in del bootloader a runtime
- Falsare lo “stato di lock” impostandolo su locked mentre è effettivamente unlocked per superare controlli di integrità più stringenti (alcuni ambienti potrebbero comunque richiedere aggiustamenti a vbmeta/AVB)

Limitazione: le PoCs attuali segnalano che la modifica della memoria a runtime può causare fault a causa di vincoli MMU; i payload in genere evitano scritture di memoria live finché questo non viene risolto.

## Payload staging patterns (EL3)

Fenrir divide la sua strumentazione in tre stage a tempo di compilazione: stage1 viene eseguito prima di `platform_init()`, stage2 viene eseguito prima che LK segnali l'entrata in fastboot, e stage3 viene eseguito immediatamente prima che LK carichi Linux. Ogni header di dispositivo sotto `payload/devices/` fornisce gli indirizzi per questi hook oltre ai simboli helper di fastboot, quindi mantieni quegli offset sincronizzati con la tua build target.

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
Stage3 dimostra come invertire temporaneamente gli attributi della page-table per patchare stringhe immutabili come l'avviso “Orange State” di Android senza aver bisogno dell'accesso al kernel downstream:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Poiché stage1 viene eseguito prima del bring-up della piattaforma, è il punto giusto per invocare le primitive OEM di power/reset o per inserire logging aggiuntivo di integrità prima che la catena di boot verificata venga smontata.

## Porting tips

- Reverse engineer the device-specific bl2_ext to locate verification policy logic (e.g., sec_get_vfy_policy).
- Identify the policy return site or decision branch and patch it to “no verification required” (return 0 / unconditional allow).
- Mantieni gli offsets completamente specifici per dispositivo e firmware; non riutilizzare indirizzi tra varianti.
- Valida prima su un'unità sacrificiale. Prepara un piano di recovery (e.g., EDL/BootROM loader/SoC-specific download mode) prima di flashare.
- I dispositivi che usano il secondary bootloader lk2 o che riportano “img_auth_required = 0” per bl2_ext anche quando locked dovrebbero essere considerati copie vulnerabili di questa classe di bug; Vivo X80 Pro è già stato osservato saltare la verification nonostante lo stato di lock riportato.
- Confronta i log expdb sia dallo stato locked che unlocked — se il certificate timing passa da 0 ms a un valore non zero dopo che hai relockato, probabilmente hai patchato il punto decisionale giusto ma devi comunque rafforzare il lock-state spoofing per nascondere la modifica.

## Security impact

- Esecuzione di codice EL3 dopo il Preloader e collasso completo della chain-of-trust per il resto del percorso di boot.
- Capacità di bootare TEE/GZ/LK/Kernel non firmati, bypassando le aspettative del secure/verified boot e permettendo un compromesso persistente.

## Device notes

- Supportato confermato: Nothing Phone (2a) (Pacman)
- Funzionante noto (supporto incompleto): CMF Phone 1 (Tetris)
- Osservato: Vivo X80 Pro reportedly did not verify bl2_ext even when locked
- La copertura dell'industria evidenzia ulteriori vendor basati su lk2 che distribuiscono lo stesso difetto logico, quindi aspettati ulteriori sovrapposizioni nelle release MTK 2024–2025.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)

{{#include ../../banners/hacktricks-training.md}}
