# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina documenta una compromissione pratica del secure-boot su più piattaforme MediaTek sfruttando una lacuna di verifica quando la configurazione del bootloader del dispositivo (seccfg) è "unlocked". Il difetto permette di eseguire una bl2_ext patchata su ARM EL3 per disabilitare la verifica delle firme a valle, collassando la catena di fiducia e consentendo il caricamento arbitrario di TEE/GZ/LK/Kernel non firmati.

> Avvertenza: Il patching in fase di early-boot può rendere i dispositivi permanentemente inutilizzabili se gli offset sono errati. Conservare sempre dump completi e una via di recupero affidabile.

## Affected boot flow (MediaTek)

- Percorso normale: BootROM → Preloader → bl2_ext (EL3, verificato) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Percorso vulnerabile: Quando seccfg è impostato su unlocked, Preloader può saltare la verifica di bl2_ext. Preloader comunque salta in bl2_ext a EL3, quindi una bl2_ext appositamente costruita può caricare componenti non verificati successivamente.

Confine critico della catena di fiducia:
- bl2_ext esegue a EL3 ed è responsabile della verifica di TEE, GenieZone, LK/AEE e del kernel. Se bl2_ext stesso non è autenticato, il resto della catena viene banalmente bypassato.

## Causa principale

Su dispositivi interessati, il Preloader non applica l'autenticazione della partizione bl2_ext quando seccfg indica uno stato "unlocked". Questo permette di flashare una bl2_ext controllata dall'attaccante che viene eseguita a EL3.

Nella bl2_ext, la funzione di policy di verifica può essere patchata per riportare in modo incondizionato che la verifica non è richiesta. Una patch concettuale minima è:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Con questa modifica, tutte le immagini successive (TEE, GZ, LK/AEE, Kernel) vengono accettate senza controlli crittografici quando caricate dal bl2_ext patchato in esecuzione a EL3.

## Come eseguire il triage di un target (expdb logs)

Esegui il dump/ispeziona i boot log (es., expdb) intorno al caricamento di bl2_ext. Se img_auth_required = 0 e il tempo di verifica del certificato è ~0 ms, l'enforcement è probabilmente disattivato e il dispositivo è sfruttabile.

Esempio di estratto di log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Nota: si segnala che alcuni dispositivi saltano la verifica di bl2_ext anche con bootloader bloccato, il che aggrava l'impatto.

## Flusso di sfruttamento pratico (Fenrir PoC)

Fenrir è un toolkit di riferimento per exploit/patching per questa classe di problemi. Supporta Nothing Phone (2a) (Pacman) ed è noto funzionare (con supporto incompleto) su CMF Phone 1 (Tetris). Il porting su altri modelli richiede l'ingegneria inversa del bl2_ext specifico del dispositivo.

Processo ad alto livello:
- Ottieni l'immagine del bootloader del dispositivo per il tuo nome in codice e posizionala come bin/<device>.bin
- Crea un'immagine patchata che disabiliti la politica di verifica del bl2_ext
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

## Capacità del payload a runtime (EL3)

Un payload bl2_ext patchato può:
- Registrare comandi fastboot personalizzati
- Controllare/sovrascrivere la modalità di boot
- Chiamare dinamicamente funzioni integrate del bootloader a runtime
- Falsificare lo “lock state” come locked pur essendo effettivamente unlocked per superare controlli di integrità più stringenti (alcuni ambienti potrebbero comunque richiedere aggiustamenti a vbmeta/AVB)

Limitazione: le PoC attuali segnalano che la modifica della memoria a runtime può generare fault a causa di vincoli della MMU; i payload evitano generalmente scritture in memoria live fino alla risoluzione.

## Suggerimenti per il porting

- Eseguire reverse engineering del bl2_ext specifico del dispositivo per individuare la logica della policy di verifica (es., sec_get_vfy_policy).
- Individuare il sito di ritorno della policy o il ramo di decisione e patcharlo in “no verification required” (return 0 / unconditional allow).
- Mantieni gli offset completamente specifici per dispositivo e firmware; non riutilizzare indirizzi tra varianti.
- Valida prima su un'unità sacrificabile. Prepara un piano di recupero (es., EDL/BootROM loader/modo di download specifico SoC) prima di flashare.

## Impatto sulla sicurezza

- Esecuzione di codice a EL3 dopo il Preloader e collasso completo della catena di fiducia per il resto del percorso di boot.
- Capacità di bootare TEE/GZ/LK/Kernel non firmati, bypassando le aspettative di secure/verified boot e consentendo compromissioni persistenti.

## Idee per rilevamento e hardening

- Assicurarsi che il Preloader verifichi bl2_ext indipendentemente dallo stato di seccfg.
- Forzare i risultati di autenticazione e raccogliere evidenze di audit (timings > 0 ms, errori rigorosi in caso di mismatch).
- Il lock-state spoofing dovrebbe essere reso inefficace per l'attestazione (collegare il lock state alle decisioni di verifica AVB/vbmeta e allo stato fuse-backed).

## Note sui dispositivi

- Confermato supportato: Nothing Phone (2a) (Pacman)
- Funzionante noto (supporto incompleto): CMF Phone 1 (Tetris)
- Osservato: Vivo X80 Pro risulta non verificare bl2_ext anche quando locked

## Riferimenti

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
