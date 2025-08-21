# Analisi del Firmware

{{#include ../../banners/hacktricks-training.md}}

## **Introduzione**

### Risorse correlate

{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

Il firmware è un software essenziale che consente ai dispositivi di funzionare correttamente gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui gli utenti interagiscono. È memorizzato in memoria permanente, garantendo che il dispositivo possa accedere a istruzioni vitali dal momento in cui viene acceso, portando al lancio del sistema operativo. Esaminare e potenzialmente modificare il firmware è un passo critico per identificare vulnerabilità di sicurezza.

## **Raccolta di Informazioni**

**Raccogliere informazioni** è un passo iniziale critico per comprendere la composizione di un dispositivo e le tecnologie che utilizza. Questo processo implica la raccolta di dati su:

- L'architettura della CPU e il sistema operativo in esecuzione
- Specifiche del bootloader
- Layout hardware e schede tecniche
- Metriche del codice sorgente e posizioni
- Librerie esterne e tipi di licenza
- Storico degli aggiornamenti e certificazioni normative
- Diagrammi architettonici e di flusso
- Valutazioni di sicurezza e vulnerabilità identificate

A questo scopo, gli strumenti di **intelligence open-source (OSINT)** sono inestimabili, così come l'analisi di eventuali componenti software open-source disponibili attraverso processi di revisione manuale e automatizzati. Strumenti come [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) offrono analisi statica gratuita che possono essere sfruttate per trovare potenziali problemi.

## **Acquisizione del Firmware**

Ottenere il firmware può essere affrontato attraverso vari mezzi, ognuno con il proprio livello di complessità:

- **Direttamente** dalla fonte (sviluppatori, produttori)
- **Costruendolo** dalle istruzioni fornite
- **Scaricandolo** dai siti di supporto ufficiali
- Utilizzando query di **Google dork** per trovare file firmware ospitati
- Accedendo direttamente allo **storage cloud**, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercettando **aggiornamenti** tramite tecniche man-in-the-middle
- **Estraendo** dal dispositivo attraverso connessioni come **UART**, **JTAG** o **PICit**
- **Sniffando** le richieste di aggiornamento all'interno della comunicazione del dispositivo
- Identificando e utilizzando **endpoint di aggiornamento hardcoded**
- **Dumping** dal bootloader o dalla rete
- **Rimuovendo e leggendo** il chip di memoria, quando tutto il resto fallisce, utilizzando strumenti hardware appropriati

## Analizzando il firmware

Ora che **hai il firmware**, devi estrarre informazioni su di esso per sapere come trattarlo. Diversi strumenti che puoi utilizzare per questo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se non trovi molto con quegli strumenti, controlla l'**entropia** dell'immagine con `binwalk -E <bin>`, se l'entropia è bassa, allora è improbabile che sia crittografata. Se l'entropia è alta, è probabile che sia crittografata (o compressa in qualche modo).

Inoltre, puoi utilizzare questi strumenti per estrarre **file incorporati nel firmware**:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oppure [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) per ispezionare il file.

### Ottenere il Filesystem

Con gli strumenti precedentemente commentati come `binwalk -ev <bin>` dovresti essere stato in grado di **estrarre il filesystem**.\
Binwalk di solito lo estrae all'interno di una **cartella chiamata come il tipo di filesystem**, che di solito è uno dei seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Estrazione Manuale del Filesystem

A volte, binwalk **non avrà il byte magico del filesystem nelle sue firme**. In questi casi, usa binwalk per **trovare l'offset del filesystem e ricavare il filesystem compresso** dal binario e **estrarre manualmente** il filesystem secondo il suo tipo utilizzando i passaggi seguenti.
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
Alternativamente, il seguente comando potrebbe essere eseguito.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Per squashfs (utilizzato nell'esempio sopra)

`$ unsquashfs dir.squashfs`

I file saranno nella directory "`squashfs-root`" successivamente.

- File di archivio CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Per filesystem jffs2

`$ jefferson rootfsfile.jffs2`

- Per filesystem ubifs con NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisi del Firmware

Una volta ottenuto il firmware, è essenziale disegnarlo per comprendere la sua struttura e le potenziali vulnerabilità. Questo processo implica l'utilizzo di vari strumenti per analizzare ed estrarre dati preziosi dall'immagine del firmware.

### Strumenti di Analisi Iniziale

Un insieme di comandi è fornito per l'ispezione iniziale del file binario (denominato `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre stringhe, analizzare dati binari e comprendere i dettagli delle partizioni e del filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Per valutare lo stato della crittografia dell'immagine, si controlla l'**entropia** con `binwalk -E <bin>`. Un'entropia bassa suggerisce una mancanza di crittografia, mentre un'entropia alta indica una possibile crittografia o compressione.

Per estrarre i **file incorporati**, si raccomandano strumenti e risorse come la documentazione **file-data-carving-recovery-tools** e **binvis.io** per l'ispezione dei file.

### Estrazione del Filesystem

Utilizzando `binwalk -ev <bin>`, è possibile solitamente estrarre il filesystem, spesso in una directory chiamata con il tipo di filesystem (ad esempio, squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem a causa di byte magici mancanti, è necessaria un'estrazione manuale. Questo comporta l'uso di `binwalk` per localizzare l'offset del filesystem, seguito dal comando `dd` per estrarre il filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Dopo, a seconda del tipo di filesystem (ad es., squashfs, cpio, jffs2, ubifs), vengono utilizzati comandi diversi per estrarre manualmente i contenuti.

### Analisi del Filesystem

Con il filesystem estratto, inizia la ricerca di vulnerabilità di sicurezza. Si presta attenzione a demoni di rete insicuri, credenziali hardcoded, endpoint API, funzionalità del server di aggiornamento, codice non compilato, script di avvio e binari compilati per analisi offline.

**Posizioni chiave** e **elementi** da ispezionare includono:

- **etc/shadow** e **etc/passwd** per le credenziali degli utenti
- Certificati SSL e chiavi in **etc/ssl**
- File di configurazione e script per potenziali vulnerabilità
- Binari incorporati per ulteriori analisi
- Server web e binari comuni dei dispositivi IoT

Diverse strumenti assistono nel rivelare informazioni sensibili e vulnerabilità all'interno del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per la ricerca di informazioni sensibili
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) per un'analisi completa del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) e [**EMBA**](https://github.com/e-m-b-a/emba) per analisi statica e dinamica

### Controlli di Sicurezza sui Binari Compilati

Sia il codice sorgente che i binari compilati trovati nel filesystem devono essere scrutinati per vulnerabilità. Strumenti come **checksec.sh** per binari Unix e **PESecurity** per binari Windows aiutano a identificare binari non protetti che potrebbero essere sfruttati.

## Emulazione del Firmware per Analisi Dinamica

Il processo di emulazione del firmware consente un'**analisi dinamica** sia del funzionamento di un dispositivo che di un programma individuale. Questo approccio può incontrare sfide con dipendenze hardware o architetturali, ma trasferire il filesystem root o binari specifici su un dispositivo con architettura e endianness corrispondenti, come un Raspberry Pi, o su una macchina virtuale pre-costruita, può facilitare ulteriori test.

### Emulazione di Binari Individuali

Per esaminare singoli programmi, è cruciale identificare l'endianness e l'architettura CPU del programma.

#### Esempio con Architettura MIPS

Per emulare un binario con architettura MIPS, si può utilizzare il comando:
```bash
file ./squashfs-root/bin/busybox
```
E per installare gli strumenti di emulazione necessari:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Per MIPS (big-endian), si utilizza `qemu-mips`, e per i binari little-endian, la scelta sarebbe `qemu-mipsel`.

#### Emulazione dell'Architettura ARM

Per i binari ARM, il processo è simile, con l'emulatore `qemu-arm` utilizzato per l'emulazione.

### Emulazione Completa del Sistema

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e altri, facilitano l'emulazione completa del firmware, automatizzando il processo e aiutando nell'analisi dinamica.

## Analisi Dinamica in Pratica

A questo stadio, viene utilizzato un ambiente di dispositivo reale o emulato per l'analisi. È essenziale mantenere l'accesso shell al sistema operativo e al filesystem. L'emulazione potrebbe non imitare perfettamente le interazioni hardware, rendendo necessari occasionali riavvii dell'emulazione. L'analisi dovrebbe riesaminare il filesystem, sfruttare le pagine web e i servizi di rete esposti, ed esplorare le vulnerabilità del bootloader. I test di integrità del firmware sono critici per identificare potenziali vulnerabilità di backdoor.

## Tecniche di Analisi Runtime

L'analisi runtime implica l'interazione con un processo o un binario nel suo ambiente operativo, utilizzando strumenti come gdb-multiarch, Frida e Ghidra per impostare breakpoint e identificare vulnerabilità attraverso fuzzing e altre tecniche.

## Sfruttamento Binario e Proof-of-Concept

Sviluppare un PoC per vulnerabilità identificate richiede una profonda comprensione dell'architettura target e programmazione in linguaggi di basso livello. Le protezioni runtime binarie nei sistemi embedded sono rare, ma quando presenti, tecniche come il Return Oriented Programming (ROP) possono essere necessarie.

## Sistemi Operativi Preparati per l'Analisi del Firmware

Sistemi operativi come [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) forniscono ambienti preconfigurati per il testing della sicurezza del firmware, dotati degli strumenti necessari.

## OS Preparati per Analizzare il Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distribuzione destinata ad aiutarti a eseguire valutazioni di sicurezza e penetration testing di dispositivi Internet of Things (IoT). Ti fa risparmiare molto tempo fornendo un ambiente preconfigurato con tutti gli strumenti necessari caricati.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo per il testing della sicurezza embedded basato su Ubuntu 18.04 pre-caricato con strumenti per il testing della sicurezza del firmware.

## Attacchi di Downgrade del Firmware e Meccanismi di Aggiornamento Insicuri

Anche quando un fornitore implementa controlli di firma crittografica per le immagini del firmware, **la protezione contro il rollback della versione (downgrade) è frequentemente omessa**. Quando il boot- o recovery-loader verifica solo la firma con una chiave pubblica incorporata ma non confronta la *versione* (o un contatore monotono) dell'immagine che viene flashata, un attaccante può legittimamente installare un **firmware più vecchio e vulnerabile che ha ancora una firma valida** e quindi reintrodurre vulnerabilità corrette.

Flusso di attacco tipico:

1. **Ottenere un'immagine firmata più vecchia**
* Ottenerla dal portale di download pubblico del fornitore, CDN o sito di supporto.
* Estrarla da applicazioni mobili/desktop companion (ad esempio, all'interno di un APK Android sotto `assets/firmware/`).
* Recuperarla da repository di terze parti come VirusTotal, archivi di Internet, forum, ecc.
2. **Caricare o servire l'immagine al dispositivo** tramite qualsiasi canale di aggiornamento esposto:
* Interfaccia Web, API dell'app mobile, USB, TFTP, MQTT, ecc.
* Molti dispositivi IoT consumer espongono endpoint HTTP(S) *non autenticati* che accettano blob di firmware codificati in Base64, li decodificano lato server e attivano il ripristino/aggiornamento.
3. Dopo il downgrade, sfruttare una vulnerabilità che è stata corretta nella versione più recente (ad esempio, un filtro di injection di comandi che è stato aggiunto successivamente).
4. Facoltativamente, flashare l'immagine più recente o disabilitare gli aggiornamenti per evitare il rilevamento una volta ottenuta la persistenza.

### Esempio: Iniezione di Comandi Dopo il Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Nel firmware vulnerabile (downgradato), il parametro `md5` è concatenato direttamente in un comando shell senza sanificazione, consentendo l'iniezione di comandi arbitrari (qui – abilitando l'accesso root basato su chiave SSH). Le versioni firmware successive hanno introdotto un filtro di caratteri di base, ma l'assenza di protezione contro il downgrade rende la correzione inutile.

### Estrazione del Firmware da App Mobili

Molti fornitori includono immagini firmware complete all'interno delle loro applicazioni mobili companion in modo che l'app possa aggiornare il dispositivo tramite Bluetooth/Wi-Fi. Questi pacchetti sono comunemente memorizzati non crittografati nell'APK/APEX sotto percorsi come `assets/fw/` o `res/raw/`. Strumenti come `apktool`, `ghidra`, o anche il semplice `unzip` ti consentono di estrarre immagini firmate senza toccare l'hardware fisico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checklist per valutare la logica di aggiornamento

* Il trasporto/l'autenticazione dell'*endpoint di aggiornamento* è adeguatamente protetto (TLS + autenticazione)?
* Il dispositivo confronta i **numeri di versione** o un **contatore anti-rollback monotono** prima di eseguire il flashing?
* L'immagine è verificata all'interno di una catena di avvio sicura (ad es. firme controllate dal codice ROM)?
* Il codice userland esegue controlli di sanità aggiuntivi (ad es. mappa delle partizioni consentite, numero di modello)?
* I flussi di aggiornamento *parziali* o *di backup* riutilizzano la stessa logica di convalida?

> 💡  Se uno qualsiasi dei punti sopra è mancante, la piattaforma è probabilmente vulnerabile ad attacchi di rollback.

## Firmware vulnerabile per esercitarsi

Per esercitarti a scoprire vulnerabilità nel firmware, utilizza i seguenti progetti di firmware vulnerabili come punto di partenza.

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

## Formazione e Certificazione

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
