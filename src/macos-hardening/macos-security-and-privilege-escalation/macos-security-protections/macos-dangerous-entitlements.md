# Entitlement pericolosi di macOS e permessi TCC

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Nota che gli entitlement che iniziano con **`com.apple`** non sono disponibili per terze parti: solo Apple può concederli... Oppure, se utilizzi un certificato enterprise, potresti effettivamente creare entitlement personalizzati che iniziano con **`com.apple`** e bypassare le protezioni basate su di essi.

## High

### `com.apple.rootless.install.heritable`

L'entitlement **`com.apple.rootless.install.heritable`** consente di **bypassare SIP**. Consulta [qui per maggiori informazioni](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

L'entitlement **`com.apple.rootless.install`** consente di **bypassare SIP**. Consulta[ qui per maggiori informazioni](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (precedentemente chiamato `task_for_pid-allow`)**

Questo entitlement consente di ottenere la **task port per qualsiasi** processo, eccetto il kernel. Consulta [**qui per maggiori informazioni**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Questo entitlement consente ad altri processi con l'entitlement **`com.apple.security.cs.debugger`** di ottenere la task port del processo eseguito dal binary con questo entitlement e **iniettare codice al suo interno**. Consulta [**qui per maggiori informazioni**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Le app con il Debugging Tool Entitlement possono chiamare `task_for_pid()` per recuperare una task port valida per app non firmate e di terze parti con l'entitlement `Get Task Allow` impostato su `true`. Tuttavia, anche con il debugging tool entitlement, un debugger **non può ottenere le task port** dei processi che **non dispongono dell'entitlement `Get Task Allow`** e che sono quindi protetti da System Integrity Protection. Consulta [**qui per maggiori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Questo entitlement consente di **caricare framework, plug-in o librerie senza che siano firmati da Apple o con lo stesso Team ID** dell'eseguibile principale; pertanto, un attacker potrebbe abusare di un caricamento arbitrario di librerie per iniettare codice. Consulta [**qui per maggiori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Questo entitlement è molto simile a **`com.apple.security.cs.disable-library-validation`**, ma **anziché disabilitare direttamente** la validazione delle librerie, consente al processo di **chiamare una system call `csops` per disabilitarla** a runtime.

Il nome dell'entitlement è hardcoded in XNU accanto all'operazione `csops` che lo utilizza:<sup>[2]</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Il kernel handler per `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) mostra esattamente quanto sia limitata la primitiva:<sup>[3]</sup>
```c
case CS_OPS_CLEAR_LV: {
#if !defined(XNU_TARGET_OS_OSX)
// We only support dropping library validation on macOS
error = ENOTSUP;
#else
if (forself == 1 && IOTaskHasEntitlement(proc_task(pt), CLEAR_LV_ENTITLEMENT)) {
proc_lock(pt);
if (!(proc_getcsflags(pt) & CS_INSTALLER) && (pt->p_subsystem_root_path == NULL)) {
proc_csflags_clear(pt, CS_REQUIRE_LV | CS_FORCED_LV);
error = 0;
```
Quindi l'operazione:

- È **solo per macOS** (`ENOTSUP` su ogni altra piattaforma).
- Funziona solo su **se stesso** (`forself == 1`) — non è possibile rimuovere la library validation da un altro processo con questa operazione.
- Richiede che il processo **possieda effettivamente l'entitlement** e rifiuta l'operazione se il processo è contrassegnato con `CS_INSTALLER` o è in esecuzione sotto un subsystem root path.
- Cancella **`CS_REQUIRE_LV | CS_FORCED_LV`** dai code-signing flags del processo.

Il commento di XNU spiega il caso d'uso previsto e anche perché è interessante per un attacker:

> Questa opzione viene utilizzata per rimuovere la library validation da un processo in esecuzione. Viene utilizzata nelle architetture a plugin quando un programma deve caricare librerie non attendibili. [...] Una volta che un processo ha caricato la libreria non attendibile, affidarsi alla library validation in futuro non sarà efficace.

In altre parole, **qualsiasi binary che possieda questo entitlement è un dylib-injection target**: fai eseguire del codice al suo interno (oppure convinci il processo a caricare il tuo plug-in) dopo che ha rimosso `CS_REQUIRE_LV`, e erediti tutto ciò che l'host process è autorizzato a fare.

### `com.apple.security.cs.allow-dyld-environment-variables`

Questo entitlement consente di **utilizzare le variabili d'ambiente DYLD**, che potrebbero essere utilizzate per injectare librerie e codice. Consulta [**questo link per maggiori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` o `com.apple.rootless.storage`.`TCC`

[**Secondo questo blog**](https://objective-see.org/blog/blog_0x4C.html) **e** [**questo blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), questi entitlement consentono di **modificare** il database **TCC**.

### **`system.install.apple-software`** e **`system.install.apple-software.standar-user`**

Questi entitlement consentono di **installare software senza chiedere il permesso** all'utente, cosa che può essere utile per una **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement necessario per chiedere al **kernel di caricare una kernel extension**.

### **`com.apple.private.icloud-account-access`**

Con l'entitlement **`com.apple.private.icloud-account-access`** è possibile comunicare con il servizio XPC **`com.apple.iCloudHelper`**, che **fornirà i token iCloud**.

**iMovie** e **Garageband** possedevano questo entitlement.

Per maggiori **informazioni** sull'exploit per **ottenere i token iCloud** tramite questo entitlement, consulta il talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: non so cosa consenta di fare

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**questo report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **viene menzionato che potrebbe essere utilizzato per** aggiornare i contenuti protetti da SSV dopo un reboot. Se sai come funziona, invia una PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**questo report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **viene menzionato che potrebbe essere utilizzato per** aggiornare i contenuti protetti da SSV dopo un reboot. Se sai come funziona, invia una PR!

### `keychain-access-groups`

Questo entitlement elenca i gruppi **keychain** a cui l'applicazione ha accesso:
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

Concede i permessi di **Full Disk Access**, uno dei permessi TCC più elevati che si possano ottenere.

### **`kTCCServiceAppleEvents`**

Consente all'app di inviare eventi ad altre applicazioni comunemente utilizzate per **automatizzare le attività**. Controllando altre app, può abusare dei permessi concessi a queste ultime.

Ad esempio, facendole chiedere all'utente la propria password:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Oppure indurli a eseguire **azioni arbitrarie**.

### **`kTCCServiceEndpointSecurityClient`**

Consente, tra gli altri permessi, di **scrivere nel database TCC dell'utente**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Consente di **modificare** l'attributo **`NFSHomeDirectory`** di un utente, modificando il percorso della sua home e consentendo quindi di **bypassare TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Consente di modificare i file all'interno degli app bundle (dentro app.app), operazione **negata per impostazione predefinita**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

È possibile verificare chi dispone di questo accesso in _Impostazioni di Sistema_ > _Privacy e Sicurezza_ > _Gestione delle app._

### `kTCCServiceAccessibility`

Il processo sarà in grado di **abusare delle funzionalità di accessibilità di macOS**, il che significa, ad esempio, che potrà simulare la pressione di tasti. Potrebbe quindi richiedere l'accesso per controllare un'app come Finder e approvare la finestra di dialogo con questo permesso.

## Entitlement relativi a Trustcache/CDhash

Esistono alcuni entitlement che potrebbero essere utilizzati per bypassare le protezioni Trustcache/CDhash, che impediscono l'esecuzione di versioni downgraded dei binari Apple.

## Medio

### `com.apple.security.cs.allow-jit`

Questo entitlement consente di **creare memoria scrivibile ed eseguibile** passando il flag `MAP_JIT` alla funzione di sistema `mmap()`. Consulta [**questo approfondimento**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Questo entitlement consente di **sovrascrivere o applicare patch al codice C**, utilizzare la **`NSCreateObjectFileImageFromMemory`**, ormai deprecata da tempo (e fondamentalmente insicura), oppure utilizzare il framework **DVDPlayback**. Consulta [**questo approfondimento**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Includere questo entitlement espone la tua app alle vulnerabilità comuni dei linguaggi di programmazione non sicuri per la memoria. Valuta attentamente se la tua app necessita di questa eccezione.

### `com.apple.security.cs.disable-executable-page-protection`

Questo entitlement consente di **modificare su disco le sezioni dei propri file eseguibili** per forzarne l'uscita. Consulta [**questo approfondimento**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> L'Entitlement Disable Executable Memory Protection è un entitlement estremo che rimuove una protezione di sicurezza fondamentale dalla tua app, rendendo possibile per un attacker riscrivere il codice eseguibile della tua app senza essere rilevato. Se possibile, preferisci entitlement più circoscritti.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Questo entitlement consente di montare un file system nullfs (vietato per impostazione predefinita). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Secondo questo blogpost, questo permesso TCC si trova solitamente nella forma:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Consente al processo di **richiedere tutte le autorizzazioni TCC**.

### **`kTCCServicePostEvent`**

Consente di **iniettare eventi sintetici da tastiera e mouse** a livello di sistema tramite `CGEventPost()`. Un processo con questa autorizzazione può simulare pressioni di tasti, clic del mouse ed eventi di scorrimento in qualsiasi applicazione, fornendo di fatto il **controllo remoto** del desktop.

È particolarmente pericoloso se combinato con `kTCCServiceAccessibility` o `kTCCServiceListenEvent`, poiché consente sia di leggere che di iniettare input.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Consente di **intercettare tutti gli eventi della tastiera e del mouse** a livello di sistema (input monitoring / keylogging). Un processo può registrare un `CGEventTap` per acquisire ogni tasto premuto in qualsiasi applicazione, incluse password, numeri di carte di credito e messaggi privati.

Per tecniche di exploitation dettagliate, vedere:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Consente di **leggere il buffer del display**, acquisendo screenshot e registrando video dello schermo di qualsiasi applicazione, inclusi i campi di testo sicuri. In combinazione con l'OCR, può estrarre automaticamente password e dati sensibili dallo schermo.

> [!WARNING]
> A partire da macOS Sonoma, la cattura dello schermo mostra un indicatore persistente nella barra dei menu. Nelle versioni precedenti, la registrazione dello schermo può essere completamente silenziosa.

### **`kTCCServiceCamera`**

Consente di **acquisire foto e video** dalla fotocamera integrata o da fotocamere USB collegate. Il code injection in un binary con entitlement per la fotocamera consente una sorveglianza visiva silenziosa.

### **`kTCCServiceMicrophone`**

Consente di **registrare audio** da tutti i dispositivi di input. I demoni in background con accesso al microfono forniscono una sorveglianza audio ambientale persistente senza alcuna finestra applicativa visibile.

### **`kTCCServiceLocation`**

Consente di interrogare la **posizione fisica** del dispositivo tramite triangolazione Wi-Fi o beacon Bluetooth. Il monitoraggio continuo rivela indirizzi di casa e di lavoro, spostamenti e abitudini quotidiane.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Accesso a **Contatti** (nomi, email, numeri di telefono — utili per lo spear-phishing), **Calendario** (programmi delle riunioni, elenchi dei partecipanti) e **Foto** (foto personali, screenshot che possono contenere credenziali, metadati sulla posizione).

Per tecniche complete di credential theft tramite permessi TCC, vedere:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

Le **eccezioni temporanee della Sandbox** indeboliscono l'App Sandbox consentendo la comunicazione con i servizi Mach/XPC a livello di sistema che la Sandbox normalmente blocca. Questa è la **principale primitiva di sandbox escape**: un'app compromessa sottoposta a Sandbox può utilizzare le eccezioni mach-lookup per raggiungere demoni privilegiati e sfruttare le loro interfacce XPC.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Per una catena di exploitation dettagliata: app in sandbox → eccezione mach-lookup → daemon vulnerabile → sandbox escape, vedere:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

Le **entitlements DriverKit** consentono ai binary dei driver in user-space di comunicare direttamente con il kernel tramite le interfacce IOKit. I binary DriverKit gestiscono l'hardware: USB, Thunderbolt, PCIe, dispositivi HID, audio e networking.

Compromettere un binary DriverKit consente:
- **Superficie di attacco del kernel** tramite chiamate `IOConnectCallMethod` malformate
- **Spoofing di dispositivi USB** (emulare una tastiera per l'HID injection)
- **Attacchi DMA** tramite interfacce PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Per un'analisi dettagliata dell'exploitation di IOKit/DriverKit, consulta:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## Riferimenti

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h` (operazioni `CS_OPS_*` e `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (handler `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
