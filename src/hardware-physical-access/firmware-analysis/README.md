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


Il firmware è un software essenziale che permette ai dispositivi di funzionare correttamente gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui gli utenti interagiscono. Viene memorizzato in memoria permanente, garantendo che il dispositivo possa accedere a istruzioni vitali dal momento dell'accensione, portando all'avvio del sistema operativo. Esaminare e potenzialmente modificare il firmware è un passaggio critico per identificare vulnerabilità di sicurezza.

## **Raccolta informazioni**

**La raccolta informazioni** è un passaggio iniziale cruciale per comprendere la composizione di un dispositivo e le tecnologie che utilizza. Questo processo comporta la raccolta di dati su:

- L'architettura della CPU e il sistema operativo su cui gira
- Dettagli del bootloader
- Layout hardware e datasheet
- Metriche del codebase e posizioni del codice sorgente
- Librerie esterne e tipi di licenza
- Storico degli update e certificazioni regolatorie
- Diagrammi architetturali e di flusso
- Valutazioni di sicurezza e vulnerabilità identificate

A tal fine, gli strumenti di open-source intelligence (OSINT) sono preziosi, così come l'analisi di qualsiasi componente software open-source disponibile tramite processi di revisione manuale e automatizzata. Strumenti come [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) offrono analisi statiche gratuite che possono essere sfruttate per trovare potenziali problemi.

## **Acquisizione del firmware**

L'ottenimento del firmware può avvenire in vari modi, ognuno con il proprio livello di complessità:

- **Direttamente** dalla fonte (sviluppatori, produttori)
- **Costruendolo** dalle istruzioni fornite
- **Scaricandolo** dai siti di supporto ufficiali
- **Utilizzando** query Google dork per trovare file firmware ospitati
- **Accedendo** direttamente a cloud storage, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
- **Intercettando** aggiornamenti tramite tecniche man-in-the-middle
- **Estraendo** dal dispositivo tramite connessioni come UART, JTAG, o PICit
- **Sniffing** per le richieste di update nelle comunicazioni del dispositivo
- **Identificando e usando** endpoint di update hardcoded
- **Dumping** dal bootloader o dalla rete
- **Rimuovendo e leggendo** il chip di storage, quando tutto il resto fallisce, usando gli strumenti hardware adeguati

## Analisi del firmware

Ora che hai il firmware, devi estrarne informazioni per capire come trattarlo. Diversi strumenti che puoi utilizzare per questo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se non trovi molto con quegli strumenti, controlla l'**entropy** dell'immagine con `binwalk -E <bin>`; se l'entropy è bassa, allora probabilmente non è cifrata. Se è alta, è probabile che sia cifrata (o compressa in qualche modo).

Inoltre, puoi usare questi strumenti per estrarre **file embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oppure [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) per ispezionare il file.

### Ottenere il Filesystem

Con gli strumenti menzionati sopra, come `binwalk -ev <bin>`, dovresti essere riuscito a **estrarre il filesystem**.\
Binwalk di solito lo estrae all'interno di una **cartella nominata come il filesystem type**, che di solito è uno dei seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Estrazione manuale del filesystem

A volte binwalk **non ha il magic byte del filesystem nelle sue signatures**. In questi casi, usa binwalk per **trovare l'offset del filesystem e carve il compressed filesystem** dal binario e **estrarre manualmente** il filesystem in base al suo tipo usando i passaggi sotto.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Esegui il seguente **dd command** per il carving del Squashfs filesystem.
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

I file si troveranno poi nella directory "`squashfs-root`".

- File archivio CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Per filesystem jffs2

`$ jefferson rootfsfile.jffs2`

- Per filesystem ubifs con NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisi del firmware

Una volta ottenuto il firmware, è essenziale analizzarlo per comprenderne la struttura e le potenziali vulnerabilità. Questo processo comporta l'utilizzo di vari strumenti per analizzare ed estrarre dati utili dall'immagine del firmware.

### Strumenti per l'analisi iniziale

Di seguito sono forniti alcuni comandi per l'ispezione iniziale del file binario (indicato come `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre stringhe, analizzare dati binari e comprendere i dettagli di partizioni e filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Per valutare lo stato di cifratura dell'immagine, si controlla l'**entropia** con `binwalk -E <bin>`. Un'entropia bassa suggerisce assenza di cifratura, mentre un'entropia alta indica possibile cifratura o compressione.

Per l'estrazione dei **file embedded**, si raccomandano strumenti e risorse come la documentazione **file-data-carving-recovery-tools** e **binvis.io** per l'ispezione dei file.

### Estrazione del filesystem

Usando `binwalk -ev <bin>`, è possibile solitamente estrarre il filesystem, spesso in una directory chiamata come il tipo di filesystem (es., squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem a causa di magic bytes mancanti, è necessario l'estrazione manuale. Questo comporta l'uso di `binwalk` per localizzare l'offset del filesystem, seguito dal comando `dd` per ritagliare il filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Successivamente, a seconda del tipo di filesystem (e.g., squashfs, cpio, jffs2, ubifs), vengono usati comandi diversi per estrarre manualmente il contenuto.

### Analisi del filesystem

Con il filesystem estratto, inizia la ricerca di vulnerabilità di sicurezza. Si presta attenzione a network daemons insicuri, hardcoded credentials, API endpoints, funzionalità dell'update server, codice non compilato, startup scripts e compiled binaries per analisi offline.

**Posizioni chiave** e **elementi** da ispezionare includono:

- **etc/shadow** e **etc/passwd** per le credenziali utente
- Certificati e chiavi SSL in **etc/ssl**
- File di configurazione e script per potenziali vulnerabilità
- Embedded binaries per ulteriori analisi
- Web server e binaries comuni dei device IoT

Diversi tool aiutano a scovare informazioni sensibili e vulnerabilità all'interno del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per la ricerca di informazioni sensibili
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) per analisi firmware completa
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), e [**EMBA**](https://github.com/e-m-b-a/emba) per analisi statiche e dinamiche

### Controlli di sicurezza sui binari compilati

Sia il source code che i binari compilati trovati nel filesystem devono essere esaminati per vulnerabilità. Tool come **checksec.sh** per binari Unix e **PESecurity** per binari Windows aiutano a identificare binari non protetti che potrebbero essere sfruttati.

## Emulare firmware per l'analisi dinamica

Il processo di emulazione del firmware consente l'**analisi dinamica** sia del funzionamento di un device sia di singoli programmi. Questo approccio può incontrare ostacoli legati a dipendenze hardware o di architettura, ma trasferire il root filesystem o specifici binari su un dispositivo con architettura e endianness corrispondenti, come un Raspberry Pi, o su una virtual machine già pronta, può facilitare ulteriori test.

### Emulare singoli binari

Per analizzare singoli programmi, è cruciale identificare l'endianness e l'architettura CPU del programma.

#### Esempio con architettura MIPS

Per emulare un binario per architettura MIPS, si può usare il comando:
```bash
file ./squashfs-root/bin/busybox
```
E per installare gli strumenti di emulazione necessari:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Per MIPS (big-endian), `qemu-mips` è utilizzato, e per i binari little-endian la scelta sarebbe `qemu-mipsel`.

#### Emulazione dell'architettura ARM

Per i binari ARM, il processo è simile, con l'emulatore `qemu-arm` utilizzato per l'emulazione.

### Emulazione completa del sistema

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e altri facilitano l'emulazione completa del firmware, automatizzando il processo e aiutando nell'analisi dinamica.

## Analisi dinamica nella pratica

A questo stadio si utilizza un ambiente dispositivo reale o emulato per l'analisi. È essenziale mantenere accesso alla shell dell'OS e al filesystem. L'emulazione potrebbe non riprodurre perfettamente le interazioni hardware, rendendo necessari riavvii occasionali dell'emulazione. L'analisi dovrebbe riesaminare il filesystem, sfruttare pagine web esposte e servizi di rete, ed esplorare vulnerabilità del bootloader. I test di integrità del firmware sono critici per identificare possibili backdoor.

## Tecniche di analisi a runtime

L'analisi a runtime implica l'interazione con un processo o un binario nel suo ambiente operativo, usando strumenti come gdb-multiarch, Frida e Ghidra per impostare breakpoint e identificare vulnerabilità tramite fuzzing e altre tecniche.

## Sfruttamento binario e Proof-of-Concept

Sviluppare un PoC per vulnerabilità identificate richiede una profonda comprensione dell'architettura target e della programmazione in linguaggi a basso livello. Le protezioni runtime sui binari nei sistemi embedded sono rare, ma quando presenti tecniche come Return Oriented Programming (ROP) possono essere necessarie.

## Sistemi operativi pronti per l'analisi del firmware

Sistemi operativi come [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) forniscono ambienti pre-configurati per il testing di sicurezza del firmware, dotati degli strumenti necessari.

## OS preconfigurati per analizzare il firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distro pensata per aiutarti a eseguire security assessment e penetration testing dei dispositivi Internet of Things (IoT). Ti fa risparmiare molto tempo fornendo un ambiente pre-configurato con tutti gli strumenti necessari caricati.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo per embedded security testing basato su Ubuntu 18.04, pre-caricato con strumenti per firmware security testing.

## Attacchi di downgrade del firmware e meccanismi di aggiornamento insicuri

Anche quando un vendor implementa controlli di firma crittografica per le immagini firmware, **la protezione contro il version rollback (downgrade) è frequentemente omessa**. Se il boot- o recovery-loader verifica solo la firma con una chiave pubblica embedded ma non confronta la *versione* (o un contatore monotono) dell'immagine da flashare, un attaccante può installare legittimamente un **firmware più vecchio e vulnerabile che porta ancora una firma valida** e così reintrodurre vulnerabilità già patchate.

Flusso tipico dell'attacco:

1. **Ottenere un'immagine firmata più vecchia**
* Recuperarla dal portale di download pubblico del vendor, CDN o sito di supporto.
* Estrarla dalle applicazioni companion mobile/desktop (es. all'interno di un Android APK sotto `assets/firmware/`).
* Recuperarla da repository di terze parti come VirusTotal, archivi Internet, forum, ecc.
2. **Caricare o servire l'immagine al dispositivo** via qualsiasi canale di aggiornamento esposto:
* Web UI, mobile-app API, USB, TFTP, MQTT, ecc.
* Molti dispositivi IoT consumer espongono endpoint HTTP(S) *non autenticati* che accettano blob firmware codificati in Base64, li decodificano server-side e innescano recovery/upgrade.
3. Dopo il downgrade, sfruttare una vulnerabilità che è stata patchata nella release più recente (per esempio un filtro di command-injection aggiunto successivamente).
4. Facoltativamente flashare di nuovo l'immagine più recente o disabilitare gli aggiornamenti per evitare il rilevamento una volta ottenuta la persistenza.

### Esempio: Command Injection dopo il downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Nel firmware vulnerabile (downgradato), il parametro `md5` viene concatenato direttamente in un comando shell senza alcuna sanitizzazione, permettendo l'iniezione di comandi arbitrari (qui — abilitando l'accesso root tramite chiave SSH). Versioni successive del firmware hanno introdotto un filtro di caratteri di base, ma l'assenza di protezione contro il downgrade rende la correzione inutile.

### Estrazione del firmware dalle app mobili

Molti vendor includono immagini firmware complete all'interno delle loro app companion per dispositivi mobili in modo che l'app possa aggiornare il dispositivo via Bluetooth/Wi‑Fi. Questi pacchetti sono comunemente memorizzati non cifrati nell'APK/APEX sotto percorsi come `assets/fw/` o `res/raw/`. Strumenti come `apktool`, `ghidra` o perfino il semplice `unzip` consentono di estrarre immagini firmate senza dover toccare l'hardware fisico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checklist per valutare la logica di update

* Il trasporto/l'autenticazione dell'*update endpoint* è adeguatamente protetto (TLS + authentication)?
* Il dispositivo confronta **version numbers** o un **monotonic anti-rollback counter** prima del flashing?
* L'immagine è verificata all'interno di una secure boot chain (es. signatures checked by ROM code)?
* Il userland code esegue ulteriori sanity checks (es. allowed partition map, model number)?
* I flussi di update *partial* o *backup* riutilizzano la stessa validation logic?

> 💡  Se uno qualsiasi dei punti sopra manca, la piattaforma è probabilmente vulnerabile a rollback attacks.

## Firmware vulnerabile per esercitarsi

Per esercitarti a scoprire vulnerabilità nel firmware, usa i seguenti progetti di firmware vulnerabile come punto di partenza.

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

## Training e Certificazioni

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
