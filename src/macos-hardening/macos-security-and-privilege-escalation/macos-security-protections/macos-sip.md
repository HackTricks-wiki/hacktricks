# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Informazioni di base**

**System Integrity Protection (SIP)** in macOS è un meccanismo progettato per impedire anche agli utenti con i privilegi più elevati di apportare modifiche non autorizzate a cartelle di sistema importanti. Questa funzionalità svolge un ruolo fondamentale nel preservare l'integrità del sistema, limitando azioni come l'aggiunta, la modifica o l'eliminazione di file nelle aree protette. Le cartelle principali protette da SIP includono:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Le regole che definiscono il comportamento di SIP sono specificate nel file di configurazione situato in **`/System/Library/Sandbox/rootless.conf`**. All'interno di questo file, i percorsi preceduti da un asterisco (\*) sono indicati come eccezioni alle rigide restrizioni di SIP.

Considera l'esempio seguente:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Questo frammento implica che, sebbene SIP protegga generalmente la directory **`/usr`**, esistono sottodirectory specifiche (`/usr/libexec/cups`, `/usr/local` e `/usr/share/man`) in cui sono consentite modifiche, come indicato dall'asterisco (\*) che precede i relativi percorsi.

Per verificare se una directory o un file è protetto da SIP, puoi usare il comando **`ls -lOd`** per controllare la presenza del flag **`restricted`** o **`sunlnk`**. Ad esempio:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
In questo caso, il flag **`sunlnk`** indica che la directory `/usr/libexec/cups` stessa **non può essere eliminata**, sebbene sia possibile creare, modificare o eliminare file al suo interno.

D'altra parte:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Qui, il flag **`restricted`** indica che la directory `/usr/libexec` è protetta da SIP. In una directory protetta da SIP, non è possibile creare, modificare o eliminare file.

Inoltre, se un file contiene l'**attributo** esteso **`com.apple.rootless`**, anche quel file sarà **protetto da SIP**.

> [!TIP]
> Nota che l'hook **`hook_vnode_check_setextattr`** di **Sandbox** impedisce qualsiasi tentativo di modificare l'attributo esteso **`com.apple.rootless`.**

**SIP limita anche altre azioni di root**, come:

- Caricare kernel extensions non attendibili
- Ottenere task-ports per processi firmati da Apple
- Modificare le variabili NVRAM
- Consentire il kernel debugging

Le opzioni sono mantenute nella variabile nvram come bitflag (`csr-active-config` su Intel e `lp-sip0` viene letto dal Device Tree utilizzato all'avvio su ARM). Puoi trovare i flag nel codice sorgente di XNU in `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### Stato di SIP

Puoi verificare se SIP è abilitato sul tuo sistema con il seguente comando:
```bash
csrutil status
```
Se devi disabilitare SIP, devi riavviare il computer in modalità di ripristino (premendo Command+R durante l'avvio), quindi eseguire il seguente comando:
```bash
csrutil disable
```
Se desideri mantenere SIP abilitato ma rimuovere le protezioni di debugging, puoi farlo con:
```bash
csrutil enable --without debug
```
### Altre restrizioni

- **Impedisce il caricamento di kernel extensions non firmate** (kexts), garantendo che solo extensions verificate interagiscano con il kernel del sistema.
- **Impedisce il debugging** dei processi di sistema di macOS, proteggendo i componenti fondamentali del sistema da accessi e modifiche non autorizzati.
- **Impedisce a strumenti** come dtrace di ispezionare i processi di sistema, proteggendo ulteriormente l'integrità del funzionamento del sistema.

[**Scopri maggiori informazioni su SIP in questo talk**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[[1]](#references)</sup>

### **Entitlements correlati a SIP**

- `com.apple.rootless.xpc.bootstrap`: Controllo di launchd
- `com.apple.rootless.install[.heritable]`: Accesso al file system
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Gestione di UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: Funzionalità di configurazione XPC
- `com.apple.rootless.xpc.effective-root`: Root tramite launchd XPC
- `com.apple.rootless.restricted-block-devices`: Accesso ai raw block devices
- `com.apple.rootless.internal.installer-equivalent`: Accesso illimitato al file system
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Accesso completo a NVRAM
- `com.apple.rootless.storage.label`: Modifica dei file limitati dall'xattr com.apple.rootless con la label corrispondente
- `com.apple.rootless.volume.VM.label`: Gestione dello swap della VM sul volume

## SIP Bypasses

Il bypass di SIP consente a un attacker di:

- **Accedere ai dati degli utenti**: Leggere dati sensibili degli utenti, come email, messaggi e cronologia di Safari, da tutti gli account utente.
- **TCC Bypass**: Manipolare direttamente il database TCC (Transparency, Consent, and Control) per concedere accessi non autorizzati alla webcam, al microfono e ad altre risorse.
- **Stabilire la persistenza**: Posizionare malware in percorsi protetti da SIP, rendendolo resistente alla rimozione, anche con privilegi root. Questo include anche la possibilità di manomettere il Malware Removal Tool (MRT).
- **Caricare kernel extensions**: Sebbene siano presenti ulteriori protezioni, il bypass di SIP semplifica il caricamento di kernel extensions non firmate.

### Pacchetti Installer

I **pacchetti Installer firmati con il certificato di Apple** possono bypassare le relative protezioni. Ciò significa che anche i pacchetti firmati da developer standard verranno bloccati se tentano di modificare directory protette da SIP.

### File SIP inesistente

Una possibile vulnerabilità consiste nel fatto che, se un file è specificato in **`rootless.conf` ma attualmente non esiste**, può essere creato. Il malware potrebbe sfruttare questa possibilità per **stabilire la persistenza** sul sistema. Ad esempio, un programma malevolo potrebbe creare un file .plist in `/System/Library/LaunchDaemons` se questo è elencato in `rootless.conf` ma non è presente.

### com.apple.rootless.install.heritable

> [!CAUTION]
> L'entitlement **`com.apple.rootless.install.heritable`** consente di bypassare SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

È stato scoperto che era possibile **sostituire il pacchetto Installer dopo che il sistema ne aveva verificato la firma** del codice, dopodiché il sistema avrebbe installato il pacchetto malevolo invece di quello originale. Poiché queste azioni venivano eseguite da **`system_installd`**, ciò consentiva di bypassare SIP.<sup>[[2]](#references)</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Se un pacchetto veniva installato da un'immagine montata o da un'unità esterna, **l'installer** avrebbe **eseguito** il binario da **quel file system** (anziché da un percorso protetto da SIP), facendo sì che **`system_installd`** eseguisse un binario arbitrario.<sup>[[3]](#references)</sup>

#### CVE-2021-30892 - Shrootless

I [**ricercatori di questo blog post**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) hanno scoperto una vulnerabilità nel meccanismo System Integrity Protection (SIP) di macOS, denominata vulnerabilità "Shrootless". Questa vulnerabilità riguarda il daemon **`system_installd`**, che dispone dell'entitlement **`com.apple.rootless.install.heritable`**, il quale consente a tutti i processi figlio di bypassare le restrizioni del file system imposte da SIP.<sup>[[4]](#references)</sup>

Il daemon **`system_installd`** installerà i pacchetti firmati da **Apple**.

I ricercatori hanno scoperto che, durante l'installazione di un pacchetto firmato da Apple (file .pkg), **`system_installd`** **esegue** tutti gli script **post-install** inclusi nel pacchetto. Questi script vengono eseguiti dalla shell predefinita, **`zsh`**, che **esegue** automaticamente i comandi dal file **`/etc/zshenv`**, se esiste, anche in modalità non interattiva. Questo comportamento poteva essere sfruttato dagli attacker: creando un file `/etc/zshenv` malevolo e aspettando che **`system_installd` invochi `zsh`**, era possibile eseguire operazioni arbitrarie sul dispositivo.<sup>[[4]](#references)</sup>

Inoltre, è stato scoperto che **`/etc/zshenv` poteva essere usato come tecnica di attacco generica**, non solo per un SIP bypass. Ogni profilo utente dispone di un file `~/.zshenv`, che si comporta allo stesso modo di `/etc/zshenv`, ma non richiede permessi root. Questo file poteva essere usato come meccanismo di persistenza, attivandosi ogni volta che `zsh` viene avviata, oppure come meccanismo di privilege escalation. Se un utente admin acquisisce i privilegi root usando `sudo -s` o `sudo <command>`, il file `~/.zshenv` verrebbe attivato, effettuando di fatto una privilege escalation a root.<sup>[[4]](#references)</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

In [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) è stato scoperto che lo stesso processo **`system_installd`** poteva ancora essere sfruttato perché inseriva lo **script post-install in una directory con nome casuale protetta da SIP all'interno di `/tmp`**. Il problema è che **`/tmp` non è protetta da SIP**, quindi era possibile **montarvi** una **virtual image**, dopodiché **l'installer** vi avrebbe inserito lo **script post-install**, avrebbe **smontato** la virtual image, **ricreato** tutte le **directory** e **aggiunto** lo script **post-install** con il **payload** da eseguire.<sup>[[5]](#references)</sup>

#### [utility fsck_cs](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

È stata identificata una vulnerabilità per cui **`fsck_cs`** veniva indotto a corrompere un file cruciale, a causa della sua capacità di seguire i **symbolic links**. In particolare, gli attacker creavano un link da _`/dev/diskX`_ al file `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. L'esecuzione di **`fsck_cs`** su _`/dev/diskX`_ causava la corruzione di `Info.plist`. L'integrità di questo file è fondamentale per il SIP (System Integrity Protection) del sistema operativo, che controlla il caricamento delle kernel extensions. Una volta corrotto, il controllo delle esclusioni del kernel da parte di SIP risulta compromesso.<sup>[[6]](#references)</sup>

I comandi per sfruttare questa vulnerabilità sono:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Lo sfruttamento di questa vulnerabilità ha implicazioni gravi. Il file `Info.plist`, normalmente responsabile della gestione dei permessi per le estensioni del kernel, diventa inefficace. Ciò include l'impossibilità di inserire nella blacklist determinate estensioni, come `AppleHWAccess.kext`. Di conseguenza, con il meccanismo di controllo di SIP fuori uso, questa estensione può essere caricata, concedendo accesso non autorizzato in lettura e scrittura alla RAM del sistema.<sup>[[6]](#references)</sup>

#### [Mount sulle cartelle protette da SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Era possibile montare un nuovo file system sulle **cartelle protette da SIP per bypassare la protezione**.<sup>[[1]](#references)</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Il sistema è configurato per eseguire l'avvio da un'immagine disco installer incorporata all'interno di `Install macOS Sierra.app` per aggiornare l'OS, utilizzando l'utility `bless`. Il comando utilizzato è il seguente:<sup>[[7]](#references)</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
La sicurezza di questo processo può essere compromessa se un attacker modifica l'immagine di upgrade (`InstallESD.dmg`) prima del boot. La strategia consiste nel sostituire un dynamic loader (dyld) con una versione malevola (`libBaseIA.dylib`). Questa sostituzione comporta l'esecuzione del codice dell'attacker quando viene avviato l'installer.<sup>[[7]](#references)</sup>

Il codice dell'attacker ottiene il controllo durante il processo di upgrade, sfruttando la fiducia del sistema nell'installer. L'attacco procede modificando l'immagine `InstallESD.dmg` tramite method swizzling, prendendo di mira in particolare il metodo `extractBootBits`. Ciò consente l'iniezione di codice malevolo prima che venga utilizzata l'immagine disco.<sup>[[7]](#references)</sup>

Inoltre, all'interno di `InstallESD.dmg` è presente un `BaseSystem.dmg`, che funge da root file system per il codice di upgrade. L'iniezione di una dynamic library al suo interno consente al codice malevolo di operare all'interno di un processo in grado di modificare file a livello di OS, aumentando significativamente il potenziale di compromissione del sistema.<sup>[[7]](#references)</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

In questo talk della [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), viene mostrato come **`systemmigrationd`** (che può bypassare SIP) esegua uno script **bash** e uno script **perl**, che possono essere sfruttati tramite le variabili d'ambiente **`BASH_ENV`** e **`PERL5OPT`**.<sup>[[8]](#references)</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Come [**descritto in dettaglio in questo blog post**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), era possibile eseguire uno script `postinstall` dai package `InstallAssistant.pkg` consentiti:<sup>[[9]](#references)</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
e che fosse possibile creare un symlink in `${SHARED_SUPPORT_PATH}/SharedSupport.dmg`, consentendo a un utente di **rimuovere le restrizioni da qualsiasi file, eludendo la protezione SIP**.<sup>[[9]](#references)</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> L'entitlement **`com.apple.rootless.install`** consente di eludere SIP

L'entitlement `com.apple.rootless.install` è noto per consentire di eludere System Integrity Protection (SIP) su macOS. Questo è stato menzionato in particolare in relazione a [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).<sup>[[10]](#references)</sup>

In questo caso specifico, il servizio XPC di sistema situato in `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` possiede questo entitlement. Ciò consente al processo correlato di aggirare i vincoli SIP. Inoltre, questo servizio espone un metodo che consente di spostare file senza applicare alcuna misura di sicurezza.<sup>[[10]](#references)</sup>

## Snapshot di sistema sigillati

Gli Snapshot di sistema sigillati sono una funzionalità introdotta da Apple in **macOS Big Sur (macOS 11)** come parte del meccanismo **System Integrity Protection (SIP)**, per fornire un ulteriore livello di sicurezza e stabilità del sistema. Sono essenzialmente versioni di sola lettura del volume di sistema.

Ecco un'analisi più dettagliata:

1. **Sistema immutabile**: gli Snapshot di sistema sigillati rendono il volume di sistema macOS "immutabile", ovvero non modificabile. Ciò impedisce modifiche non autorizzate o accidentali al sistema che potrebbero compromettere la sicurezza o la stabilità del sistema.
2. **Aggiornamenti del software di sistema**: quando installi aggiornamenti o upgrade di macOS, macOS crea un nuovo snapshot di sistema. Il volume di avvio di macOS utilizza quindi **APFS (Apple File System)** per passare a questo nuovo snapshot. L'intero processo di applicazione degli aggiornamenti diventa più sicuro e affidabile, poiché il sistema può sempre tornare allo snapshot precedente se qualcosa va storto durante l'aggiornamento.
3. **Separazione dei dati**: insieme al concetto di separazione tra volume Data e volume System introdotto in macOS Catalina, la funzionalità Snapshot di sistema sigillato garantisce che tutti i tuoi dati e le tue impostazioni siano archiviati su un volume "**Data**" separato. Questa separazione rende i dati indipendenti dal sistema, semplificando il processo di aggiornamento del sistema e migliorando la sicurezza del sistema.

Ricorda che questi snapshot sono gestiti automaticamente da macOS e non occupano spazio aggiuntivo sul disco, grazie alle funzionalità di condivisione dello spazio di APFS. È inoltre importante notare che questi snapshot sono diversi dagli **snapshot di Time Machine**, che sono backup dell'intero sistema accessibili all'utente.

### Verificare gli snapshot

Il comando **`diskutil apfs list`** elenca i **dettagli dei volumi APFS** e il relativo layout:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-< Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

Nel precedente output è possibile vedere che le **posizioni accessibili all'utente** sono montate in `/System/Volumes/Data`.

Inoltre, lo **snapshot del volume di sistema macOS** è montato in `/` ed è **sigillato** (firmato crittograficamente dal sistema operativo). Pertanto, se SIP viene eluso e il volume viene modificato, **il sistema operativo non si avvierà più**.

È inoltre possibile **verificare che la sigillatura sia abilitata** eseguendo:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Inoltre, il disco snapshot è montato anch'esso in modalità **sola lettura**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Riferimenti

- [1] [SyScan360 - Stefan Esser - OS X El Capitan che fa affondare la S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Blog di Objective-See](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: "Unauthd" (tre) logic bugs ftw! - Blog di Objective-See](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft trova una nuova vulnerabilità in macOS, Shrootless, che potrebbe bypassare la System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Analisi tecnica: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [La sicurezza rootless di Apple, priva di frutti, viene compromessa da codice contenuto in un tweet - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Bypassing della System Integrity Protection di Apple - Blog di Objective-See](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Avere un'emicrania - Unique SIP Bypass su MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple mitiga le vulnerabilità negli script dell'Installer - Blog di Kandji](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: la POC per il SIP-Bypass è persino pubblicabile in un tweet](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
