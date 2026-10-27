# Integrità del firmware

{{#include ../../banners/hacktricks-training.md}}

Quando una valutazione autorizzata rileva una verifica delle firme del firmware debole o assente, un'immagine firmware modificata può dimostrare l'impatto sull'integrità. Il seguente workflow di laboratorio aggiunge una bind shell mantenendo i passaggi originali di estrazione, emulazione e repackaging.<sup>[[2]](#references)[[3]](#references)</sup>

1. Il firmware può essere estratto usando firmware-mod-kit (FMK).
2. È necessario identificare l'architettura e l'endianness del firmware di destinazione.
3. È possibile creare un cross compiler usando Buildroot o altri metodi adatti all'ambiente.
4. È possibile compilare la backdoor usando il cross compiler.
5. È possibile copiare la backdoor nella directory /usr/bin del firmware estratto.
6. È possibile copiare il binario QEMU appropriato nella rootfs del firmware estratto.
7. È possibile emulare la backdoor usando chroot e QEMU.
8. È possibile accedere alla backdoor tramite netcat.
9. È necessario rimuovere il binario QEMU dalla rootfs del firmware estratto.
10. È possibile riconfezionare il firmware modificato usando FMK.
11. È possibile testare il firmware con backdoor emulandolo con firmware analysis toolkit (FAT) e connettendosi all'IP e alla porta della backdoor di destinazione usando netcat.

Se è già stata ottenuta una root shell tramite analisi dinamica, manipolazione del bootloader o test di sicurezza hardware, è possibile eseguire binari di test precompilati, come implant o reverse shell. `msfvenom` di Metasploit può generare un payload specifico per l'architettura per questo workflow di convalida:<sup>[[4]](#references)</sup>

1. È necessario identificare l'architettura e l'endianness del firmware di destinazione.
2. È possibile usare Msfvenom per specificare il payload di destinazione, l'IP dell'host dell'attaccante, il numero di porta in ascolto, il filetype, l'architettura, la piattaforma e il file di output.
3. È possibile trasferire il payload al dispositivo compromesso e verificare che disponga dei permessi di esecuzione.
4. È possibile preparare Metasploit a gestire le richieste in arrivo avviando msfconsole e configurando le impostazioni in base al payload.
5. È possibile eseguire la meterpreter reverse shell sul dispositivo compromesso.

## Bridge di trasporto non autenticati verso protocolli di aggiornamento privilegiati

Un errore comune nella progettazione di sistemi embedded consiste nell'esporre **lo stesso protocollo di comando interno su più trasporti**, ma applicare l'autenticazione solo su uno di essi. Per esempio, l'USB può richiedere una challenge-response, mentre il BLE inoltra semplicemente **scritture GATT** non autenticate allo stesso handler privilegiato per l'aggiornamento del firmware.<sup>[[1]](#references)</sup>

Workflow offensivo tipico:

1. Enumerare il database BLE GATT e identificare le caratteristiche scrivibili usate dall'app mobile ufficiale.
2. Intercettare il traffico dell'app e cercare **magic byte / opcode** che corrispondono al protocollo cablato.
3. Riprodurre i comandi privilegiati tramite BLE **senza pairing** e verificare se le operazioni sensibili funzionano comunque.
4. Se sono raggiungibili opcode per l'aggiornamento del firmware, la scrittura della configurazione, il debug o i test di fabbrica, considerare il BLE una **porta di amministrazione raggiungibile via radio**.

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
- Tutti i trasporti vengono instradati alla stessa tabella del dispatcher interno?
- Gli opcode privilegiati vengono filtrati in modo diverso su USB / BLE / UART / Wi-Fi?
- L'app mobile può attivare da remoto handler di aggiornamento firmware, recovery o diagnostica?

## I container firmware protetti solo da checksum restano firmware sotto il controllo dell'attaccante

Un container firmware protetto solo da un **checksum non keyed** (CRC32, SHA-256, MD5, ecc.) rileva la corruzione, ma **non garantisce l'autenticità**. Se l'attaccante può raggiungere la routine di aggiornamento, può modificare l'immagine, ricalcolare il checksum e flashare codice arbitrario.<sup>[[1]](#references)</sup>

Segnali d'allarme durante la RE:

- Il codice di aggiornamento convalida solo un blob di checksum finale, come `CHK2`, `CRC` o `SHA256`.
- Non è presente la verifica della firma né una root of trust per il secure boot.
- Non vengono usati MAC / HMAC legati al dispositivo né la cifratura autenticata.
- La recovery mode accetta lo stesso formato di immagine non autenticato.

Procedura pratica di verifica:

1. Estrai il container firmware e identifica bootloader, firmware principale e metadati d'integrità.
2. Modifica una stringa o un banner innocuo nell'immagine.
3. Ricalcola il checksum esattamente come previsto dall'updater.
4. Riflash l'immagine tramite il normale percorso di aggiornamento.
5. Verifica la modifica al boot per dimostrare la sostituzione arbitraria del firmware.

Se funziona tramite un trasporto raggiungibile da remoto, come BLE/Wi-Fi, il bug equivale di fatto alla **sostituzione non autenticata del firmware OTA**.

## Stato di aggiornamento frammentato e metadati d'integrità scrivibili

Un updater può verificare un header firmware firmato durante l'installazione, ma avviare comunque le immagini usando solo un hash d'integrità memorizzato. Sul Cypherock X1, il Bootloader invocava task Firewall separati per verificare l'header e inserire versione/dimensione in RAM, memorizzare la firma del firmware in RAM, verificare l'immagine scritta e infine calcolare l'hash dell'immagine nei dati persistenti del Primary Bootloader. La firma stessa non veniva resa persistente. Questi task potevano essere chiamati singolarmente, senza imporre un'unica transazione di aggiornamento autenticata.<sup>[[5]](#references)</sup>

Con l'esecuzione di codice sul MCU e l'accesso in scrittura alla Flash, l'attacco descritto riscriveva l'immagine dell'applicazione, modificava i valori di versione/dimensione nella RAM del Bootloader condivisa con il Firewall, quindi chiamava il task finale dei metadati per memorizzare l'hash dell'immagine malevola e ripristinare il normale stato di boot. Il controllo d'integrità al normale avvio accettava quell'hash senza verificare nuovamente la firma. Quando analizzi un updater simile, traccia **quale componente può invocare ciascun task**, dove risiedono i valori verificati e se la decisione al boot autentica *la stessa immagine* il cui hash è memorizzato. Questo caso è più specifico di un formato d'immagine protetto solo da checksum: la verifica della firma esisteva, ma la transizione di stato non era vincolata a essa.<sup>[[5]](#references)</sup>

## Firme del secure element su misurazioni firmware non attendibili

Un secure element non attesta il codice in esecuzione semplicemente firmando un hash fornito da quel codice. Nello stesso wallet, il secure element firmava il numero di serie del dispositivo e poi lo XOR di un nonce del cloud e di un hash firmware fornito tramite il MCU. Un firmware compromesso poteva fornire l'hash atteso da firmare mentre eseguiva byte diversi. Anche il client associato inviava al cloud la versione del firmware, quindi il confronto dell'hash atteso da parte del verificatore si basava comunque su una misurazione proveniente dal MCU, invece che su una lettura indipendente della Flash.<sup>[[5]](#references)</sup>

Il risultato lato dispositivo definiva un confine di fiducia separato: il cloud verificava il dispositivo, ma il dispositivo non autenticava il verdetto del cloud. Un client modificato poteva segnalare un esito positivo locale a un dispositivo manomesso. Verifica separatamente la provenienza della misurazione e l'autenticazione della risposta: una firma valida del secure element e una schermata di successo, da sole, non dimostrano che l'applicazione installata sia autentica.<sup>[[5]](#references)</sup>

Per la divulgazione del codice protetto che ha reso possibile l'analisi di questo updater, vedi [acquisizione firmware tramite il task copy del Firewall](index.html#disclosing-protected-code-through-a-firewall-copy-task).<sup>[[5]](#references)</sup>

## Trasformare una periferica USB attendibile in BadUSB riflashandone il firmware

Quando il dispositivo target è già considerato attendibile dall'host tramite USB, il firmware malevolo potrebbe non dover implementare un intero nuovo stack USB. Spesso, una soluzione molto più semplice è **riutilizzare il supporto HID esistente**.<sup>[[1]](#references)</sup>

Procedura utile:

1. Verifica se il dispositivo viene già enumerato come interfaccia **HID Consumer Control** / multimediale / HID vendor-specific.
2. Individua nel firmware il **descrittore di report HID** esistente.
3. Aggiungi o sostituisci voci del descrittore, in modo che il dispositivo dichiari anche la capacità **keyboard**.
4. Riutilizza le routine firmware esistenti che inviano già report HID, invece di scrivere una nuova implementazione del trasporto.
5. Inietta report di pressione + rilascio dei tasti per digitare comandi sull'host.

In questo modo, la compromissione del firmware diventa **compromissione dell'host**, perché il PC considererà la periferica riflashata una tastiera legittima.

### Checklist minima di valutazione

- `dmesg`, Device Manager o i descrittori USB mostrano un'interfaccia HID esistente?
- C'è spazio libero vicino al descrittore di report o una tabella di descrittori rilocabile?
- È possibile riutilizzare le routine esistenti per inviare i controlli multimediali per generare report da tastiera?
- Dopo il reflashing, l'host accetta automaticamente la nuova interfaccia di tastiera?

## Esecuzione affidabile del payload nel firmware RTOS

Invece di inserire trampoline fragili in punti casuali del codice, cerca **task RTOS esistenti** che non vengono usati o hanno un impatto ridotto durante il normale funzionamento.<sup>[[1]](#references)</sup>

Perché è utile:

- Lo scheduler avvia il payload naturalmente durante il boot.
- Eviti di corrompere il flusso di controllo critico.
- È meno probabile che i payload ritardati attivino reset del watchdog rispetto a quelli eseguiti all'interno di un handler USB/rete sensibile alla latenza.

Tra i buoni candidati ci sono task di diagnostica, test di fabbrica, telemetria o servizi del coprocessore che sembrano inattivi durante il normale utilizzo.

## Iterazione rapida degli exploit: riutilizzare handler di protocollo innocui

Una volta possibile patchare il firmware, un modo compatto per accelerare la RE consiste nel sovrascrivere un handler di comando innocuo (per esempio un **opcode echo/debug**) con primitive personalizzate di **lettura / scrittura / esecuzione della memoria**. In questo modo si evita di riflashare tutto a ogni esperimento; è particolarmente utile quando il dispositivo supporta l'handler modificato tramite un trasporto cablato veloce.<sup>[[1]](#references)</sup>

Usalo per:

- Verificare le mappe di memoria scatter-loaded
- Esaminare heap/stato dei task in tempo reale
- Testare payload di piccole dimensioni prima di scriverli nella flash
- Recuperare in sicurezza puntatori a funzioni, stringhe e tabelle di descrittori

## References

- [1] [Pwnd Blaster: Hacking il tuo PC usando il suo speaker senza mai toccarlo](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - Come usare `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [5] [Come e perché abbiamo hackerato l'hardware wallet Cypherock: la storia completa](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
