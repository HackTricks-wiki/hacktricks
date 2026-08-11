# Integrità del firmware

{{#include ../../banners/hacktricks-training.md}}

Quando una valutazione autorizzata rileva una verifica della firma del firmware debole o assente, un'immagine del firmware modificata può dimostrare l'impatto sull'integrità. Il seguente workflow di laboratorio aggiunge una bind shell mantenendo i passaggi originali di estrazione, emulazione e repackaging.<sup>[[2]](#references)[[3]](#references)</sup>

1. Il firmware può essere estratto usando firmware-mod-kit (FMK).
2. È necessario identificare l'architettura e l'endianness del firmware target.
3. È possibile creare un cross compiler usando Buildroot o altri metodi adatti all'ambiente.
4. La backdoor può essere compilata usando il cross compiler.
5. La backdoor può essere copiata nella directory /usr/bin del firmware estratto.
6. Il binario QEMU appropriato può essere copiato nel rootfs del firmware estratto.
7. La backdoor può essere emulata usando chroot e QEMU.
8. È possibile accedere alla backdoor tramite netcat.
9. Il binario QEMU deve essere rimosso dal rootfs del firmware estratto.
10. Il firmware modificato può essere riconfezionato usando FMK.
11. Il firmware con backdoor può essere testato emulandolo con firmware analysis toolkit (FAT) e connettendosi all'IP e alla porta della backdoor target usando netcat.

Se una root shell è già stata ottenuta tramite analisi dinamica, manipolazione del bootloader o test di sicurezza hardware, è possibile eseguire binari di test precompilati come implant o reverse shell. `msfvenom` di Metasploit può generare un payload specifico per l'architettura per questo workflow di validazione:<sup>[[4]](#references)</sup>

1. È necessario identificare l'architettura e l'endianness del firmware target.
2. Msfvenom può essere usato per specificare il payload target, l'indirizzo IP dell'host dell'attaccante, il numero di porta in ascolto, il tipo di file, l'architettura, la piattaforma e il file di output.
3. Il payload può essere trasferito sul dispositivo compromesso, assicurandosi che disponga dei permessi di esecuzione.
4. Metasploit può essere preparato per gestire le richieste in ingresso avviando msfconsole e configurando le impostazioni in base al payload.
5. La reverse shell meterpreter può essere eseguita sul dispositivo compromesso.

## Bridge di trasporto non autenticati verso protocolli di aggiornamento privilegiati

Un errore comune nella progettazione dei sistemi embedded consiste nell'esporre **lo stesso protocollo di comandi interno attraverso diversi transport**, applicando però l'autenticazione solo su uno di essi. Ad esempio, l'USB può richiedere una challenge-response, mentre BLE inoltra semplicemente **scritture GATT** non autenticate allo stesso handler privilegiato per l'aggiornamento del firmware.<sup>[[1]](#references)</sup>

Workflow offensivo tipico:

1. Enumerare il database GATT BLE e identificare le characteristic scrivibili usate dall'app mobile ufficiale.
2. Sniffare il traffico dell'app e cercare **magic bytes / opcode** che corrispondano al protocollo cablato.
3. Riprodurre i comandi privilegiati tramite BLE **senza pairing** e verificare se le operazioni sensibili funzionano ancora.
4. Se gli opcode per l'upgrade del firmware, la scrittura della configurazione, il debug o i factory test sono raggiungibili, considerare BLE come una **porta admin raggiungibile via radio**.

Controlli rapidi:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Cose da verificare durante il reversing:

- BLE richiede **pairing/bonding** o solo una connessione semplice?
- Tutti i transport vengono instradati alla stessa tabella di dispatcher interna?
- Gli opcode privilegiati vengono filtrati diversamente su USB / BLE / UART / Wi-Fi?
- L'app mobile può attivare da remoto gli handler di aggiornamento firmware, recovery o diagnostica?

## I container firmware protetti solo da checksum sono comunque firmware controllati dall'attaccante

Un container firmware protetto solo da un **checksum non keyed** (CRC32, SHA-256, MD5, ecc.) rileva la corruzione, **non garantisce l'autenticità**. Se l'attaccante può raggiungere la routine di aggiornamento, può modificare l'immagine, ricalcolare il checksum e flashare codice arbitrario.<sup>[[1]](#references)</sup>

Segnali d'allarme durante la RE:

- Il codice di aggiornamento valida solo un blob di checksum finale come `CHK2`, `CRC` o `SHA256`.
- Non è presente alcuna verifica della firma né una root of trust per il secure boot.
- Non vengono utilizzati MAC / HMAC associati al dispositivo o authenticated encryption.
- La recovery mode accetta lo stesso formato di immagine non autenticato.

Flusso pratico di validazione:

1. Estrai il container firmware e identifica bootloader, firmware principale e metadati di integrità.
2. Modifica una stringa o un banner innocuo nell'immagine.
3. Ricalcola il checksum esattamente come previsto dall'updater.
4. Esegui il reflash dell'immagine attraverso il normale percorso di aggiornamento.
5. Conferma la modifica al boot per dimostrare la sostituzione arbitraria del firmware.

Se questo funziona tramite un transport raggiungibile da remoto, come BLE/Wi-Fi, il bug equivale di fatto a una **sostituzione OTA del firmware non autenticata**.

## Trasformare una periferica USB affidabile in BadUSB tramite reflash del firmware

Quando il dispositivo target è già considerato affidabile dall'host tramite USB, il firmware malevolo potrebbe non dover implementare un nuovo USB stack completo. Spesso è molto più semplice **riutilizzare il supporto HID esistente**.<sup>[[1]](#references)</sup>

Pattern utile:

1. Verifica se il dispositivo viene già enumerato come interfaccia **HID Consumer Control** / media / vendor HID.
2. Individua nel firmware l'**HID report descriptor** esistente.
3. Aggiungi o sostituisci le voci del descriptor in modo che il dispositivo esponga anche la funzionalità **keyboard**.
4. Riutilizza le routine firmware esistenti che inviano già report HID invece di scrivere una nuova implementazione del transport.
5. Inietta report di pressione + rilascio dei tasti per digitare comandi sull'host.

In questo modo la compromissione del firmware diventa una **compromissione dell'host**, perché il PC considererà la periferica riflashata una tastiera legittima.

### Checklist di assessment minima

- `dmesg`, Device Manager o i descriptor USB mostrano un'interfaccia HID esistente?
- C'è spazio libero vicino al report descriptor o una descriptor table rilocabile?
- Le routine esistenti per l'invio dei controlli multimediali possono essere riutilizzate per i report della tastiera?
- L'host accetta automaticamente la nuova interfaccia keyboard dopo il reflash?

## Esecuzione affidabile del payload nel firmware RTOS

Invece di inserire trampoline fragili in percorsi di codice casuali, cerca **task RTOS esistenti** inutilizzati o a basso impatto durante il normale funzionamento.<sup>[[1]](#references)</sup>

Perché è utile:

- Lo scheduler avvia il payload naturalmente durante il boot.
- Eviti di corrompere il control flow critico.
- I payload ritardati hanno meno probabilità di attivare reset del watchdog rispetto a quelli eseguiti all'interno di un handler USB/network sensibile alla latenza.

Buoni target sono i task di diagnostica, factory-test, telemetria o servizio del coprocessore che risultano inattivi durante l'uso normale.

## Iterazione rapida degli exploit: riutilizzare handler di protocollo innocui

Quando è possibile applicare patch al firmware, un metodo compatto per accelerare la RE consiste nel sovrascrivere un command handler innocuo (per esempio un **opcode echo/debug**) con primitive personalizzate di **memory read / write / execute**. Questo evita di eseguire un reflash completo per ogni esperimento ed è particolarmente utile quando il dispositivo supporta l'handler modificato tramite un transport cablato veloce.<sup>[[1]](#references)</sup>

Usalo per:

- Verificare le memory map scatter-loaded
- Ispezionare live lo stato di heap/task
- Testare piccoli payload prima di scriverli nella flash
- Recuperare in sicurezza function pointer, stringhe e descriptor table

## References

- [1] [Pwnd Blaster: Hacking il tuo PC usando il tuo speaker senza mai toccarlo](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Toolkit di analisi del firmware](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - Come usare `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
{{#include ../../banners/hacktricks-training.md}}
