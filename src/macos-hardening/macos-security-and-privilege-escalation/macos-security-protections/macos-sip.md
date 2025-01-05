# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Informazioni di base**

**System Integrity Protection (SIP)** in macOS è un meccanismo progettato per impedire anche agli utenti più privilegiati di apportare modifiche non autorizzate a cartelle di sistema chiave. Questa funzione gioca un ruolo cruciale nel mantenere l'integrità del sistema limitando azioni come l'aggiunta, la modifica o la cancellazione di file in aree protette. Le cartelle principali protette da SIP includono:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Le regole che governano il comportamento di SIP sono definite nel file di configurazione situato in **`/System/Library/Sandbox/rootless.conf`**. All'interno di questo file, i percorsi che sono preceduti da un asterisco (\*) sono indicati come eccezioni alle altrimenti rigorose restrizioni di SIP.

Considera l'esempio qui sotto:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Questo frammento implica che mentre SIP generalmente protegge la directory **`/usr`**, ci sono sottodirectory specifiche (`/usr/libexec/cups`, `/usr/local` e `/usr/share/man`) dove le modifiche sono consentite, come indicato dall'asterisco (\*) che precede i loro percorsi.

Per verificare se una directory o un file è protetto da SIP, puoi utilizzare il comando **`ls -lOd`** per controllare la presenza del flag **`restricted`** o **`sunlnk`**. Ad esempio:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
In questo caso, il flag **`sunlnk`** indica che la directory `/usr/libexec/cups` **non può essere eliminata**, anche se i file al suo interno possono essere creati, modificati o eliminati.

D'altra parte:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Qui, il flag **`restricted`** indica che la directory `/usr/libexec` è protetta da SIP. In una directory protetta da SIP, i file non possono essere creati, modificati o eliminati.

Inoltre, se un file contiene l'attributo **`com.apple.rootless`** come **attributo** esteso, quel file sarà anche **protetto da SIP**.

> [!TIP]
> Nota che il hook **Sandbox** **`hook_vnode_check_setextattr`** impedisce qualsiasi tentativo di modificare l'attributo esteso **`com.apple.rootless`.**

**SIP limita anche altre azioni di root** come:

- Caricamento di estensioni del kernel non affidabili
- Ottenere task-ports per processi firmati da Apple
- Modificare le variabili NVRAM
- Consentire il debug del kernel

Le opzioni sono mantenute nella variabile nvram come un bitflag (`csr-active-config` su Intel e `lp-sip0` viene letto dall'albero dei dispositivi avviato per ARM). Puoi trovare i flag nel codice sorgente di XNU in `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### Stato di SIP

Puoi controllare se SIP è abilitato sul tuo sistema con il seguente comando:
```bash
csrutil status
```
Se è necessario disabilitare SIP, è necessario riavviare il computer in modalità di recupero (premendo Command+R durante l'avvio), quindi eseguire il seguente comando:
```bash
csrutil disable
```
Se desideri mantenere SIP abilitato ma rimuovere le protezioni di debug, puoi farlo con:
```bash
csrutil enable --without debug
```
### Altre Restrizioni

- **Disabilita il caricamento di estensioni del kernel non firmate** (kexts), garantendo che solo le estensioni verificate interagiscano con il kernel di sistema.
- **Previene il debugging** dei processi di sistema macOS, proteggendo i componenti core del sistema da accessi e modifiche non autorizzate.
- **Inibisce strumenti** come dtrace dall'ispezionare i processi di sistema, proteggendo ulteriormente l'integrità del funzionamento del sistema.

[**Scopri di più sulle informazioni SIP in questo talk**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

### **Autorizzazioni relative a SIP**

- `com.apple.rootless.xpc.bootstrap`: Controlla launchd
- `com.apple.rootless.install[.heritable]`: Accesso al file system
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Gestisci UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: Capacità di configurazione XPC
- `com.apple.rootless.xpc.effective-root`: Root tramite launchd XPC
- `com.apple.rootless.restricted-block-devices`: Accesso a dispositivi a blocchi raw
- `com.apple.rootless.internal.installer-equivalent`: Accesso illimitato al file system
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Accesso completo a NVRAM
- `com.apple.rootless.storage.label`: Modifica file limitati da com.apple.rootless xattr con l'etichetta corrispondente
- `com.apple.rootless.volume.VM.label`: Mantieni lo swap VM su volume

## Bypass di SIP

Il bypass di SIP consente a un attaccante di:

- **Accedere ai dati dell'utente**: Leggere dati sensibili dell'utente come email, messaggi e cronologia di Safari da tutti gli account utente.
- **Bypass TCC**: Manipolare direttamente il database TCC (Trasparenza, Consenso e Controllo) per concedere accesso non autorizzato alla webcam, al microfono e ad altre risorse.
- **Stabilire persistenza**: Posizionare malware in posizioni protette da SIP, rendendolo resistente alla rimozione, anche da privilegi di root. Questo include anche la possibilità di manomettere lo strumento di rimozione malware (MRT).
- **Caricare estensioni del kernel**: Sebbene ci siano ulteriori misure di sicurezza, bypassare SIP semplifica il processo di caricamento di estensioni del kernel non firmate.

### Pacchetti di Installazione

**I pacchetti di installazione firmati con il certificato di Apple** possono bypassare le sue protezioni. Ciò significa che anche i pacchetti firmati da sviluppatori standard verranno bloccati se tentano di modificare directory protette da SIP.

### File SIP inesistente

Una potenziale falla è che se un file è specificato in **`rootless.conf` ma attualmente non esiste**, può essere creato. Il malware potrebbe sfruttare questo per **stabilire persistenza** sul sistema. Ad esempio, un programma malevolo potrebbe creare un file .plist in `/System/Library/LaunchDaemons` se è elencato in `rootless.conf` ma non presente.

### com.apple.rootless.install.heritable

> [!CAUTION]
> L'autorizzazione **`com.apple.rootless.install.heritable`** consente di bypassare SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

È stato scoperto che era possibile **scambiare il pacchetto di installazione dopo che il sistema aveva verificato la sua firma** e poi, il sistema avrebbe installato il pacchetto malevolo invece di quello originale. Poiché queste azioni venivano eseguite da **`system_installd`**, ciò avrebbe consentito di bypassare SIP.

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Se un pacchetto veniva installato da un'immagine montata o da un'unità esterna, l'**installer** avrebbe **eseguito** il binario da **quella file system** (invece che da una posizione protetta da SIP), facendo eseguire a **`system_installd`** un binario arbitrario.

#### CVE-2021-30892 - Shrootless

[**I ricercatori di questo post del blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) hanno scoperto una vulnerabilità nel meccanismo di Protezione dell'Integrità di Sistema (SIP) di macOS, soprannominata vulnerabilità 'Shrootless'. Questa vulnerabilità si concentra sul demone **`system_installd`**, che ha un'autorizzazione, **`com.apple.rootless.install.heritable`**, che consente a qualsiasi dei suoi processi figli di bypassare le restrizioni del file system di SIP.

Il demone **`system_installd`** installerà pacchetti che sono stati firmati da **Apple**.

I ricercatori hanno scoperto che durante l'installazione di un pacchetto firmato da Apple (.pkg file), **`system_installd`** **esegue** qualsiasi **script post-installazione** incluso nel pacchetto. Questi script vengono eseguiti dalla shell predefinita, **`zsh`**, che esegue automaticamente **comandi dal file** **`/etc/zshenv`**, se esiste, anche in modalità non interattiva. Questo comportamento potrebbe essere sfruttato dagli attaccanti: creando un file `/etc/zshenv` malevolo e aspettando che **`system_installd` invochi `zsh`**, potrebbero eseguire operazioni arbitrarie sul dispositivo.

Inoltre, è stato scoperto che **`/etc/zshenv` potrebbe essere utilizzato come una tecnica di attacco generale**, non solo per un bypass di SIP. Ogni profilo utente ha un file `~/.zshenv`, che si comporta allo stesso modo di `/etc/zshenv` ma non richiede permessi di root. Questo file potrebbe essere utilizzato come meccanismo di persistenza, attivandosi ogni volta che `zsh` si avvia, o come meccanismo di elevazione dei privilegi. Se un utente admin si eleva a root usando `sudo -s` o `sudo <command>`, il file `~/.zshenv` verrebbe attivato, elevando effettivamente a root.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

In [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) è stato scoperto che lo stesso processo **`system_installd`** poteva ancora essere abusato perché stava mettendo lo **script post-installazione all'interno di una cartella con nome casuale protetta da SIP all'interno di `/tmp`**. Il fatto è che **`/tmp` stesso non è protetto da SIP**, quindi era possibile **montare** un **immagine virtuale su di esso**, poi l'**installer** avrebbe messo lì lo **script post-installazione**, **smontato** l'immagine virtuale, **ricreato** tutte le **cartelle** e **aggiunto** lo **script di post installazione** con il **payload** da eseguire.

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

È stata identificata una vulnerabilità in cui **`fsck_cs`** è stato ingannato a corrompere un file cruciale, a causa della sua capacità di seguire **link simbolici**. In particolare, gli attaccanti hanno creato un link da _`/dev/diskX`_ al file `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Eseguire **`fsck_cs`** su _`/dev/diskX`_ ha portato alla corruzione di `Info.plist`. L'integrità di questo file è vitale per la SIP (Protezione dell'Integrità di Sistema) del sistema operativo, che controlla il caricamento delle estensioni del kernel. Una volta corrotto, la capacità di SIP di gestire le esclusioni del kernel è compromessa.

I comandi per sfruttare questa vulnerabilità sono:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
L'exploitation de cette vulnérabilité a de graves implications. Le fichier `Info.plist`, normalement responsable de la gestion des autorisations pour les extensions du noyau, devient inefficace. Cela inclut l'incapacité de mettre sur liste noire certaines extensions, telles que `AppleHWAccess.kext`. Par conséquent, avec le mécanisme de contrôle de SIP hors service, cette extension peut être chargée, accordant un accès en lecture et en écriture non autorisé à la RAM du système.

#### [Mount over SIP protected folders](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

È stato possibile montare un nuovo file system su **SIP protected folders to bypass the protection**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Il sistema è impostato per avviarsi da un'immagine disco di installazione incorporata all'interno di `Install macOS Sierra.app` per aggiornare il sistema operativo, utilizzando l'utilità `bless`. Il comando utilizzato è il seguente:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
La sicurezza di questo processo può essere compromessa se un attaccante altera l'immagine di aggiornamento (`InstallESD.dmg`) prima dell'avvio. La strategia prevede la sostituzione di un loader dinamico (dyld) con una versione malevola (`libBaseIA.dylib`). Questa sostituzione porta all'esecuzione del codice dell'attaccante quando viene avviato l'installer.

Il codice dell'attaccante guadagna il controllo durante il processo di aggiornamento, sfruttando la fiducia del sistema nell'installer. L'attacco procede alterando l'immagine `InstallESD.dmg` tramite il metodo swizzling, mirando in particolare al metodo `extractBootBits`. Questo consente l'iniezione di codice malevolo prima che l'immagine del disco venga utilizzata.

Inoltre, all'interno di `InstallESD.dmg`, c'è un `BaseSystem.dmg`, che funge da file system radice per il codice di aggiornamento. Iniettare una libreria dinamica in questo consente al codice malevolo di operare all'interno di un processo in grado di alterare file a livello di OS, aumentando significativamente il potenziale di compromissione del sistema.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

In questo intervento di [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), viene mostrato come **`systemmigrationd`** (che può bypassare SIP) esegue uno **script bash** e uno **script perl**, che possono essere abusati tramite variabili d'ambiente **`BASH_ENV`** e **`PERL5OPT`**.

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Come [**dettagliato in questo post del blog**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), uno script `postinstall` dai pacchetti `InstallAssistant.pkg` consentiva di eseguire:
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
e era possibile creare un symlink in `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` che consentirebbe a un utente di **rimuovere le restrizioni da qualsiasi file, eludendo la protezione SIP**.

### **com.apple.rootless.install**

> [!CAUTION]
> L'attributo **`com.apple.rootless.install`** consente di eludere SIP

L'attributo `com.apple.rootless.install` è noto per eludere la Protezione dell'Integrità di Sistema (SIP) su macOS. Questo è stato menzionato in particolare in relazione a [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

In questo caso specifico, il servizio XPC di sistema situato in `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` possiede questo attributo. Questo consente al processo correlato di eludere i vincoli SIP. Inoltre, questo servizio presenta un metodo che consente il movimento di file senza applicare alcuna misura di sicurezza.

## Sealed System Snapshots

I Sealed System Snapshots sono una funzionalità introdotta da Apple in **macOS Big Sur (macOS 11)** come parte del meccanismo di **Protezione dell'Integrità di Sistema (SIP)** per fornire un ulteriore livello di sicurezza e stabilità del sistema. Sono essenzialmente versioni di sola lettura del volume di sistema.

Ecco uno sguardo più dettagliato:

1. **Sistema Immutabile**: I Sealed System Snapshots rendono il volume di sistema macOS "immutabile", il che significa che non può essere modificato. Questo previene qualsiasi cambiamento non autorizzato o accidentale al sistema che potrebbe compromettere la sicurezza o la stabilità del sistema.
2. **Aggiornamenti del Software di Sistema**: Quando installi aggiornamenti o upgrade di macOS, macOS crea un nuovo snapshot di sistema. Il volume di avvio di macOS utilizza quindi **APFS (Apple File System)** per passare a questo nuovo snapshot. L'intero processo di applicazione degli aggiornamenti diventa più sicuro e affidabile poiché il sistema può sempre tornare allo snapshot precedente se qualcosa va storto durante l'aggiornamento.
3. **Separazione dei Dati**: In concomitanza con il concetto di separazione dei volumi Dati e Sistema introdotto in macOS Catalina, la funzionalità Sealed System Snapshot garantisce che tutti i tuoi dati e le impostazioni siano memorizzati su un volume separato "**Dati**". Questa separazione rende i tuoi dati indipendenti dal sistema, semplificando il processo di aggiornamenti di sistema e migliorando la sicurezza del sistema.

Ricorda che questi snapshot sono gestiti automaticamente da macOS e non occupano spazio aggiuntivo sul tuo disco, grazie alle capacità di condivisione dello spazio di APFS. È anche importante notare che questi snapshot sono diversi dagli **snapshot di Time Machine**, che sono backup accessibili dall'utente dell'intero sistema.

### Controlla gli Snapshot

Il comando **`diskutil apfs list`** elenca i **dettagli dei volumi APFS** e il loro layout:

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
|   |   Encrypted:                 No
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

Nell'output precedente è possibile vedere che le **posizioni accessibili all'utente** sono montate sotto `/System/Volumes/Data`.

Inoltre, lo **snapshot del volume di sistema macOS** è montato in `/` ed è **sigillato** (firmato crittograficamente dal sistema operativo). Quindi, se SIP viene eluso e viene modificato, il **sistema operativo non si avvierà più**.

È anche possibile **verificare che il sigillo sia abilitato** eseguendo:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Inoltre, il disco snapshot è montato anche come **sola lettura**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
{{#include ../../../banners/hacktricks-training.md}}
