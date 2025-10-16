# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina documenta una compromissione pratica del secure boot su più piattaforme MediaTek sfruttando una lacuna di verifica quando la configurazione del bootloader del dispositivo (seccfg) è "unlocked". La falla permette di eseguire un bl2_ext patchato a ARM EL3 per disabilitare la verifica delle firme a valle, rompendo la catena di fiducia e consentendo il caricamento arbitrario di TEE/GZ/LK/Kernel non firmati.

> Attenzione: modifiche all'early-boot possono brickare permanentemente i dispositivi se gli offset sono sbagliati. Conserva sempre dump completi e una procedura di recovery affidabile.

## Affected boot flow (MediaTek)

- Percorso normale: BootROM → Preloader → bl2_ext (EL3, verificato) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Percorso vulnerabile: Quando seccfg è impostato su unlocked, Preloader può saltare la verifica di bl2_ext. Preloader comunque salta in bl2_ext a EL3, quindi un bl2_ext costruito ad arte può caricare componenti non verificati successivamente.

Punto critico della catena di fiducia:
- bl2_ext viene eseguito a EL3 ed è responsabile della verifica di TEE, GenieZone, LK/AEE e del kernel. Se lo stesso bl2_ext non è autenticato, il resto della catena viene bypassato in modo banale.

## Root cause

Sui dispositivi interessati, il Preloader non applica l'autenticazione della partizione bl2_ext quando seccfg indica uno stato "unlocked". Questo permette di flashare un bl2_ext controllato dall'attaccante che viene eseguito a EL3.

All'interno di bl2_ext, la funzione di policy di verifica può essere patchata per restituire incondizionatamente che la verifica non è richiesta. Una patch concettuale minima è:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Con questa modifica, tutte le immagini successive (TEE, GZ, LK/AEE, Kernel) vengono accettate senza controlli crittografici quando vengono caricate dal bl2_ext patchato in esecuzione a EL3.

## Come fare il triage di un target (expdb logs)

Eseguire il dump/ispezionare i boot logs (es. expdb) intorno al caricamento di bl2_ext. Se img_auth_required = 0 e il tempo di verifica del certificato è ~0 ms, l'enforcement è probabilmente disabilitato e il dispositivo è sfruttabile.

Esempio di estratto di log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Nota: Alcuni dispositivi, secondo le segnalazioni, saltano la verifica di bl2_ext anche con il bootloader bloccato, aggravando l'impatto.

## Flusso di sfruttamento pratico (Fenrir PoC)

Fenrir è un toolkit di riferimento per exploit/patching per questa classe di vulnerabilità. Supporta Nothing Phone (2a) (Pacman) ed è noto funzionare (supporto incompleto) su CMF Phone 1 (Tetris). Il porting su altri modelli richiede il reverse engineering del bl2_ext specifico del dispositivo.

Processo ad alto livello:
- Ottieni l'immagine del bootloader del dispositivo per il tuo codename e salvala in bin/<device>.bin
- Crea un'immagine patchata che disabilita la policy di verifica di bl2_ext
- Flasha il payload risultante sul dispositivo (lo script helper presuppone fastboot)

Comandi:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
Se fastboot non è disponibile, devi usare un metodo di flashing alternativo adatto alla tua piattaforma.

## Runtime payload capabilities (EL3)

Un payload bl2_ext patchato può:
- Registrare comandi fastboot personalizzati
- Controllare/sostituire la modalità di boot
- Chiamare dinamicamente funzioni integrate del bootloader a runtime
- Falsificare lo “stato di lock” come locked mentre in realtà è unlocked per superare controlli di integrità più stringenti (alcuni ambienti potrebbero comunque richiedere aggiustamenti a vbmeta/AVB)

Limitazione: PoC attuali riportano che la modifica della memoria a runtime può causare fault a causa di vincoli MMU; i payload evitano generalmente scritture in memoria live finché questo non è risolto.

## Porting tips

- Eseguire reverse engineering del bl2_ext specifico del dispositivo per individuare la logica della policy di verifica (es., sec_get_vfy_policy).
- Identificare il sito di ritorno della policy o il ramo decisionale e patcharlo per “nessuna verifica richiesta” (return 0 / consentire incondizionatamente).
- Mantieni gli offset completamente specifici per dispositivo e firmware; non riutilizzare indirizzi tra varianti.
- Valida prima su un'unità sacrificabile. Prepara un piano di recovery (es., EDL/BootROM loader/modalità di download specifica per SoC) prima di flashare.

## Security impact

- Esecuzione di codice a EL3 dopo il Preloader e collasso completo della catena di trust per il resto del percorso di boot.
- Capacità di avviare TEE/GZ/LK/Kernel non firmati, bypassando le aspettative di secure/verified boot e abilitando compromissioni persistenti.

## Detection and hardening ideas

- Garantire che il Preloader verifichi bl2_ext indipendentemente dallo stato di seccfg.
- Applicare i risultati di autenticazione e raccogliere evidenze di audit (timings > 0 ms, errori rigorosi in caso di mismatch).
- La falsificazione dello stato di lock dovrebbe essere resa inefficace per l'attestazione (collega lo stato di lock alle decisioni di verifica AVB/vbmeta e allo stato supportato da fuse).

## Device notes

- Supportato confermato: Nothing Phone (2a) (Pacman)
- Funzionante noto (supporto incompleto): CMF Phone 1 (Tetris)
- Osservato: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
