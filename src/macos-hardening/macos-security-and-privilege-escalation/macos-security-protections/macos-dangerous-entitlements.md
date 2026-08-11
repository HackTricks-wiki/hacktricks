# Entitlements pericolosi di macOS e permessi TCC

{{#include ../../../banners/hacktricks-training.md}}

Gli entitlements dichiarano capacità ed eccezioni di sicurezza che il sistema operativo concede al codice firmato. Le voci riportate di seguito si concentrano su quelle particolarmente utili durante una revisione offensiva.<sup>[[13]](#references)</sup>

> [!WARNING]
> Nota che gli entitlements che iniziano con **`com.apple`** non sono disponibili a terze parti: solo Apple può concederli... Oppure, se utilizzi un certificato enterprise, potresti effettivamente creare i tuoi entitlements che iniziano con **`com.apple`** e bypassare le protezioni basate su questo.

## Alto

### `com.apple.rootless.install.heritable`

L'entitlement **`com.apple.rootless.install.heritable`** consente a un processo di **bypassare SIP**. Consulta [questo approfondimento](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

L'entitlement **`com.apple.rootless.install`** consente a un processo di **bypassare SIP**. Consulta [questo approfondimento](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (precedentemente chiamato `task_for_pid-allow`)**

Questo entitlement consente a un processo di ottenere la **task port di qualsiasi** processo, ad eccezione del kernel. Consulta [**questo approfondimento**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Questo entitlement consente ad altri processi con l'entitlement **`com.apple.security.cs.debugger`** di ottenere la task port del processo eseguito dal binary con questo entitlement e di **iniettare codice al suo interno**. Consulta [**questo approfondimento**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Le app con il Debugging Tool Entitlement possono chiamare `task_for_pid()` per recuperare una task port valida per app non firmate e di terze parti con l'entitlement `Get Task Allow` impostato su `true`. Tuttavia, anche con il debugging tool entitlement, un debugger **non può ottenere le task port** dei processi che **non hanno l'entitlement `Get Task Allow`** e che sono quindi protetti da System Integrity Protection. Consulta [**questo approfondimento**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Questo entitlement consente a un'applicazione di **caricare framework, plug-in o librerie senza richiedere che siano firmati da Apple o con lo stesso Team ID** dell'eseguibile principale; un attacker potrebbe quindi abusare di un caricamento arbitrario di librerie per iniettare codice. Consulta [**questo approfondimento**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Questo entitlement è molto simile a **`com.apple.security.cs.disable-library-validation`**, ma **invece di disabilitare direttamente** la validazione delle librerie, consente al processo di **chiamare una system call `csops` per disabilitarla** a runtime.

Il nome dell'entitlement è hardcoded in XNU accanto all'operazione `csops` che lo utilizza:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Il gestore del kernel per `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) mostra esattamente quanto sia limitata la primitive:<sup>[[2]](#references)</sup>
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
- Funziona solo su **sé stesso** (`forself == 1`) — non è possibile rimuovere la library validation da un altro processo con questa operazione.
- Richiede che il processo **detenga effettivamente l'entitlement** e rifiuta l'operazione se il processo è contrassegnato come `CS_INSTALLER` o è in esecuzione sotto un subsystem root path.
- Cancella **`CS_REQUIRE_LV | CS_FORCED_LV`** dai code-signing flags del processo.

Il commento di XNU spiega il caso d'uso previsto e anche perché è interessante per un attacker:

> Questa opzione viene utilizzata per rimuovere la library validation da un processo in esecuzione. Viene usata nelle architetture basate su plugin quando un programma deve caricare librerie non attendibili. [...] Una volta che un processo ha caricato la libreria non attendibile, fare affidamento sulla library validation in futuro non sarà efficace.

In altre parole, **qualsiasi binary che include questo entitlement è un dylib-injection target**: è sufficiente riuscire a eseguire codice al suo interno (o convincerlo a caricare il proprio plug-in) dopo che ha rimosso `CS_REQUIRE_LV`, per ereditare tutto ciò che il processo host è autorizzato a fare.

### `com.apple.security.cs.allow-dyld-environment-variables`

Questo entitlement consente di **utilizzare le variabili d'ambiente DYLD**, che potrebbero essere usate per injectare librerie e codice. Consulta [**questo documento per ulteriori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` o `com.apple.rootless.storage`.`TCC`

[**Secondo questo blog**](https://objective-see.org/blog/blog_0x4C.html) **e** [**questo blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), questi entitlement consentono a un processo di **modificare** il database **TCC**.<sup>[[6]](#references)[[7]](#references)</sup>

### Authorization rights **`system.install.apple-software`** e **`system.install.apple-software.standard-user`**

Questi Authorization Services rights regolano l'installazione del software fornito da Apple. Un processo autorizzato a ottenerli potrebbe bypassare il consueto authorization flow, cosa che può essere utile per la **privilege escalation**.<sup>[[14]](#references)</sup>

### `com.apple.private.security.kext-management`

Entitlement necessario per chiedere al **kernel di caricare un kernel extension**.

### **`com.apple.private.icloud-account-access`**

L'entitlement **`com.apple.private.icloud-account-access`** consente di comunicare con il servizio XPC **`com.apple.iCloudHelper`**, che **fornirà iCloud token**.

**iMovie** e **Garageband** disponevano di questo entitlement.

Per ulteriori **informazioni** sull'exploit per **ottenere iCloud token** tramite questo entitlement, consulta il talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: non so cosa consenta di fare

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Questo report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) menziona che questo entitlement potrebbe essere utilizzato per aggiornare contenuti protetti da SSV dopo un reboot. Se sai come fare, invia una PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**Lo stesso report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) menziona che la creazione di uno sealed snapshot potrebbe essere utilizzata per aggiornare contenuti protetti da SSV dopo un reboot. Se sai come fare, invia una PR!<sup>[[9]](#references)</sup>

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

Concede i permessi di **Accesso completo al disco**, uno dei permessi TCC più elevati che si possano ottenere.

### **`kTCCServiceAppleEvents`**

Consente all'app di inviare eventi ad altre applicazioni comunemente utilizzate per **automatizzare le attività**. Controllando altre app, può abusare dei permessi concessi a queste applicazioni.

Ad esempio, inducendole a chiedere all'utente la propria password:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
O facendogli eseguire **azioni arbitrarie**.

### **`kTCCServiceEndpointSecurityClient`**

Consente, tra gli altri permessi, di **scrivere nel database TCC dell'utente**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Consente di **modificare** l'attributo **`NFSHomeDirectory`** di un utente, cambiando il percorso della sua cartella home e consentendo quindi di **bypassare TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Consente di modificare i file all'interno dei bundle delle app (dentro app.app), operazione **vietata per impostazione predefinita**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

È possibile verificare chi dispone di questo accesso in _Impostazioni di Sistema_ > _Privacy e sicurezza_ > _Gestione app._

### `kTCCServiceAccessibility`

Il processo sarà in grado di **abusare delle funzionalità di accessibilità di macOS**, il che significa, ad esempio, che potrà simulare la pressione di tasti. Potrebbe quindi richiedere l'accesso per controllare un'app come Finder e approvare la finestra di dialogo con questo permesso.

## Entitlements relativi a Trustcache/CDhash

Esistono alcuni entitlements che potrebbero essere utilizzati per bypassare le protezioni Trustcache/CDhash, che impediscono l'esecuzione di versioni precedenti dei binari Apple.

## Medio

### `com.apple.security.cs.allow-jit`

Questo entitlement consente a un processo di **creare memoria scrivibile ed eseguibile** passando il flag `MAP_JIT` alla funzione di sistema `mmap()`. Consulta [**questa pagina per ulteriori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Questo entitlement consente di **sovrascrivere o applicare patch al codice C**, utilizzare la funzione **`NSCreateObjectFileImageFromMemory`** deprecata da molto tempo (fondamentalmente insicura) o utilizzare il framework **DVDPlayback**. Consulta [**questa pagina per ulteriori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> L'inclusione di questo entitlement espone la tua app alle vulnerabilità comuni dei linguaggi di programmazione non sicuri per la memoria. Valuta attentamente se la tua app necessita di questa eccezione.

### `com.apple.security.cs.disable-executable-page-protection`

Questo entitlement consente di **modificare su disco le sezioni dei propri file eseguibili** per forzarne l'uscita. Consulta [**questa pagina per ulteriori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> L'entitlement Disable Executable Memory Protection è un entitlement estremo che rimuove una protezione di sicurezza fondamentale dalla tua app, consentendo a un attaccante di riscrivere il codice eseguibile della tua app senza essere rilevato. Se possibile, preferisci entitlements più specifici.

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

Consente di **iniettare eventi sintetici da tastiera e mouse** a livello globale tramite `CGEventPost()`. Un processo con questa autorizzazione può simulare pressioni di tasti, clic del mouse ed eventi di scorrimento in qualsiasi applicazione, fornendo di fatto il **controllo remoto** del desktop.

È particolarmente pericoloso se combinato con `kTCCServiceAccessibility` o `kTCCServiceListenEvent`, poiché consente sia di leggere che di iniettare input.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Consente di **intercettare tutti gli eventi della tastiera e del mouse** a livello di sistema (monitoraggio degli input / keylogging). Un processo può registrare un `CGEventTap` per catturare ogni tasto premuto in qualsiasi applicazione, incluse password, numeri di carte di credito e messaggi privati.

Per tecniche di exploitation dettagliate, vedere:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Consente di **leggere il buffer del display** — acquisire screenshot e registrare video dello schermo di qualsiasi applicazione, inclusi i campi di testo sicuri. In combinazione con l'OCR, può estrarre automaticamente password e dati sensibili dallo schermo.

> [!WARNING]
> A partire da macOS Sonoma, la cattura dello schermo mostra un indicatore persistente nella barra dei menu. Nelle versioni precedenti, la registrazione dello schermo può essere completamente silenziosa.

### **`kTCCServiceCamera`**

Consente di **acquisire foto e video** dalla fotocamera integrata o da fotocamere USB collegate. Il code injection in un binary con entitlement per la fotocamera consente una sorveglianza visiva silenziosa.

### **`kTCCServiceMicrophone`**

Consente di **registrare audio** da tutti i dispositivi di input. I daemon in background con accesso al microfono forniscono una sorveglianza audio ambientale persistente senza alcuna finestra dell'applicazione visibile.

### **`kTCCServiceLocation`**

Consente di interrogare la **posizione fisica** del dispositivo tramite triangolazione Wi-Fi o beacon Bluetooth. Il monitoraggio continuo rivela indirizzi di casa e lavoro, percorsi di viaggio e routine quotidiane.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Accesso a **Contatti** (nomi, email, numeri di telefono — utili per lo spear-phishing), **Calendario** (orari delle riunioni, elenchi dei partecipanti) e **Foto** (foto personali, screenshot che possono contenere credenziali, metadati sulla posizione).

Per le tecniche complete di credential theft tramite permessi TCC, vedere:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Entitlements di Sandbox e Code Signing

### `com.apple.security.temporary-exception.mach-lookup.global-name`

Le **eccezioni temporanee della Sandbox** indeboliscono l'App Sandbox consentendo la comunicazione con i servizi Mach/XPC a livello di sistema che la Sandbox normalmente blocca. Questa è la **principale primitive per il sandbox escape** — un'app compromessa in Sandbox può usare le eccezioni mach-lookup per raggiungere daemon privilegiati e sfruttare le loro interfacce XPC.
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

Gli **entitlement DriverKit** consentono ai binari dei driver in user space di comunicare direttamente con il kernel tramite le interfacce IOKit. I binari DriverKit gestiscono l’hardware: dispositivi USB, Thunderbolt, PCIe, HID, audio e networking.

La compromissione di un binario DriverKit consente:
- **Superficie di attacco del kernel** tramite chiamate `IOConnectCallMethod` malformate
- **Spoofing di dispositivi USB** (emulazione di una tastiera per HID injection)
- **Attacchi DMA** tramite interfacce PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Per informazioni dettagliate sullo sfruttamento di IOKit/DriverKit, consulta:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (operazioni `CS_OPS_*` e `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (handler `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Entitlement per il debugging tool (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement per disabilitare la library validation](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement per consentire le variabili d'ambiente DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Bypass di TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Riprodurre la musica e bypassare TCC, ovvero CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "Ciò che accade sul tuo Mac rimane su iCloud di Apple?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [L'incubo dell'aggiornamento OTA di Apple: bypassare la verifica della firma e ottenere il controllo del kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement per consentire l'esecuzione di codice compilato con JIT (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement per consentire memoria eseguibile non firmata](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement per disabilitare la protezione della memoria eseguibile](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [14] [Apple Developer Archive — Guida alla programmazione di Authorization Services](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/01introduction/introduction.html)
{{#include ../../../banners/hacktricks-training.md}}
