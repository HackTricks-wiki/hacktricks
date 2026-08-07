# Integrità del firmware

{{#include ../../banners/hacktricks-training.md}}

Il **custom firmware e/o i binari compilati possono essere caricati per sfruttare vulnerabilità nell'integrità o nella verifica delle firme**. Per la compilazione di una bind shell backdoor, è possibile seguire i passaggi seguenti:

1. Il firmware può essere estratto usando firmware-mod-kit (FMK).
2. È necessario identificare l'architettura e l'endianness del firmware target.
3. È possibile creare un cross compiler usando Buildroot o altri metodi adatti all'ambiente.
4. La backdoor può essere compilata usando il cross compiler.
5. La backdoor può essere copiata nella directory /usr/bin del firmware estratto.
6. Il binario QEMU appropriato può essere copiato nel rootfs del firmware estratto.
7. La backdoor può essere emulata usando chroot e QEMU.
8. È possibile accedere alla backdoor tramite netcat.
9. Il binario QEMU dovrebbe essere rimosso dal rootfs del firmware estratto.
10. Il firmware modificato può essere riconfezionato usando FMK.
11. Il firmware con backdoor può essere testato emulandolo con firmware analysis toolkit (FAT) e connettendosi all'IP e alla porta della backdoor target usando netcat.

Se una root shell è già stata ottenuta tramite analisi dinamica, manipolazione del bootloader o security testing dell'hardware, è possibile eseguire binari malevoli precompilati, come implant o reverse shell. Gli strumenti automatizzati per payload/implant, come il framework Metasploit e 'msfvenom', possono essere sfruttati usando i passaggi seguenti:

1. È necessario identificare l'architettura e l'endianness del firmware target.
2. Msfvenom può essere usato per specificare il payload target, l'indirizzo IP dell'host dell'attaccante, il numero di porta in ascolto, il tipo di file, l'architettura, la piattaforma e il file di output.
3. Il payload può essere trasferito sul dispositivo compromesso, verificando che disponga dei permessi di esecuzione.
4. Metasploit può essere preparato per gestire le richieste in arrivo avviando msfconsole e configurando le impostazioni in base al payload.
5. La reverse shell meterpreter può essere eseguita sul dispositivo compromesso.

## Unauthenticated transport bridges to privileged update protocols

Un errore comune nella progettazione dei dispositivi embedded consiste nell'esporre **lo stesso protocollo di comandi interno tramite diversi transport**, applicando però l'autenticazione solo su uno di essi. Ad esempio, l'USB può richiedere una challenge-response mentre BLE inoltra semplicemente **scritture GATT** non autenticate allo stesso gestore privilegiato degli aggiornamenti del firmware.<sup>[[1]](#references)</sup>

Workflow offensivo tipico:

1. Enumerare il database GATT BLE e identificare le characteristic scrivibili usate dall'app mobile ufficiale.
2. Analizzare il traffico dell'app e cercare **magic bytes / opcodes** che corrispondano al protocollo cablato.
3. Riprodurre i comandi privilegiati tramite BLE **senza pairing** e verificare se le operazioni sensibili continuano a funzionare.
4. Se gli opcode per l'upgrade del firmware, la scrittura della configurazione, il debug o i factory test sono raggiungibili, trattare BLE come una **porta admin raggiungibile via radio**.

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
- L'app mobile può attivare da remoto gli handler di firmware update, recovery o diagnostica?

## I container firmware protetti solo da checksum sono comunque firmware sotto il controllo dell'attaccante

Un container firmware protetto solo da un **checksum non keyed** (CRC32, SHA-256, MD5, ecc.) fornisce rilevamento della corruzione, **non autenticità**. Se l'attaccante può raggiungere la routine di update, può modificare l'immagine, ricalcolare il checksum e flashare codice arbitrario.<sup>[[1]](#references)</sup>

Segnali d'allarme durante il RE:

- Il codice di update valida solo un blob di checksum finale come `CHK2`, `CRC` o `SHA256`.
- Non è presente alcuna verifica della firma né una root of trust per secure-boot.
- Non viene utilizzato alcun MAC / HMAC device-bound né authenticated encryption.
- La recovery mode accetta lo stesso formato di immagine non autenticato.

Flusso di validazione pratico:

1. Estrai il container firmware e identifica bootloader, firmware principale e metadati di integrità.
2. Modifica una stringa o un banner innocuo nell'immagine.
3. Ricalcola il checksum esattamente come previsto dall'updater.
4. Esegui il reflash dell'immagine tramite il normale percorso di update.
5. Conferma la modifica al boot per dimostrare la sostituzione arbitraria del firmware.

Se funziona tramite un transport raggiungibile da remoto come BLE/Wi-Fi, il bug equivale di fatto a una **sostituzione OTA del firmware non autenticata**.

## Trasformare una periferica USB trusted in BadUSB tramite reflash del firmware

Quando il dispositivo target è già trusted dall'host tramite USB, il firmware malevolo potrebbe non dover implementare un nuovo stack USB completo. Un pivot molto più semplice consiste spesso nel **riutilizzare il supporto HID esistente**.<sup>[[1]](#references)</sup>

Pattern utile:

1. Verifica se il dispositivo viene già enumerato come interfaccia **HID Consumer Control** / media / vendor HID.
2. Individua l'**HID report descriptor** esistente nel firmware.
3. Aggiungi o sostituisci le voci del descriptor affinché il dispositivo esponga anche la capacità **keyboard**.
4. Riutilizza le routine firmware esistenti che inviano già report HID invece di scrivere una nuova implementazione del transport.
5. Inietta report di pressione + rilascio dei tasti per digitare comandi sull'host.

Questo trasforma la compromissione del firmware in **compromissione dell'host**, perché il PC considererà la periferica sottoposta a reflash una keyboard legittima.

### Checklist minima di assessment

- `dmesg`, Device Manager o i descriptor USB mostrano un'interfaccia HID esistente?
- C'è spazio libero vicino al report descriptor o una tabella di descriptor rilocabile?
- Le routine esistenti per l'invio dei comandi media possono essere riutilizzate per i report keyboard?
- L'host accetta automaticamente la nuova interfaccia keyboard dopo il reflash?

## Esecuzione affidabile del payload all'interno del firmware RTOS

Invece di inserire trampoline fragili in percorsi di codice casuali, cerca **task RTOS esistenti** inutilizzati o a basso impatto durante il normale funzionamento.<sup>[[1]](#references)</sup>

Perché è utile:

- Lo scheduler avvia naturalmente il payload durante il boot.
- Eviti di corrompere il control flow critico.
- I payload ritardati hanno meno probabilità di attivare reset del watchdog rispetto a quando vengono eseguiti all'interno di un handler USB/network sensibile alla latenza.

Buoni target sono i task di diagnostica, factory-test, telemetria o servizi del coprocessore che sembrano dormienti durante il normale utilizzo.

## Iterazione rapida dell'exploit: riutilizzare handler di protocollo benigni

Una volta possibile patchare il firmware, un modo compatto per accelerare il RE consiste nel sovrascrivere un command handler innocuo (ad esempio un **echo/debug opcode**) con primitive custom di **memory read / write / execute**. Questo evita un reflash completo per ogni esperimento ed è particolarmente utile quando il dispositivo supporta l'handler modificato tramite un transport cablato veloce.<sup>[[1]](#references)</sup>

Usalo per:

- Verificare le memory map scatter-loaded
- Ispezionare heap/task state in tempo reale
- Testare piccoli payload prima di scriverli nella flash
- Recuperare in sicurezza function pointer, stringhe e tabelle di descriptor

## Riferimenti

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
