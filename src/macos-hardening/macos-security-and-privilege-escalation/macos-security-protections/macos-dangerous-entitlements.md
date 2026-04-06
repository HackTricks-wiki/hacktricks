# macOS Entitlements pericolosi & permessi TCC

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Nota che gli entitlements che iniziano con **`com.apple`** non sono disponibili a terze parti, solo Apple può concederli... Oppure, se stai usando un certificato enterprise, potresti effettivamente creare i tuoi entitlements che iniziano con **`com.apple`** e bypassare protezioni basate su questo.

## Alto

### `com.apple.rootless.install.heritable`

L'entitlement **`com.apple.rootless.install.heritable`** permette di **bypassare SIP**. Controlla [questo per maggiori informazioni](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

L'entitlement **`com.apple.rootless.install`** permette di **bypassare SIP**. Controlla [questo per maggiori informazioni](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Questo entitlement permette di ottenere il **task port di qualsiasi** processo, eccetto il kernel. Controlla [**questo per maggiori informazioni**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Questo entitlement permette ad altri processi con l'entitlement **`com.apple.security.cs.debugger`** di ottenere il task port del processo eseguito dal binario con questo entitlement e di **iniettare codice al suo interno**. Controlla [**questo per maggiori informazioni**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Le app con il Debugging Tool Entitlement possono chiamare `task_for_pid()` per ottenere un task port valido per app non firmate e di terze parti con l'entitlement `Get Task Allow` impostato su `true`. Tuttavia, anche con il Debugging Tool Entitlement, un debugger **non può ottenere i task port** dei processi che **non hanno l'entitlement `Get Task Allow`**, e che sono quindi protetti da System Integrity Protection. Controlla [**questo per maggiori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Questo entitlement permette di **caricare framework, plug-in o librerie senza che siano firmati da Apple o con lo stesso Team ID** dell'eseguibile principale, quindi un attacker potrebbe abusare di un caricamento arbitrario di librerie per iniettare codice. Controlla [**questo per maggiori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Questo entitlement è molto simile a **`com.apple.security.cs.disable-library-validation`** ma **invece** di **disabilitare direttamente** la validazione delle librerie, permette al processo di **chiamare la system call `csops` per disabilitarla**.\
Controlla [**questo per maggiori informazioni**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Questo entitlement permette di **usare le DYLD environment variables** che potrebbero essere usate per iniettare librerie e codice. Controlla [**questo per maggiori informazioni**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**Secondo questo blog**](https://objective-see.org/blog/blog_0x4C.html) **e** [**questo blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), questi entitlements permettono di **modificare** il database **TCC**.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

Questi entitlements permettono di **installare software senza chiedere permessi all'utente**, il che può essere utile per una escalation di privilegi.

### `com.apple.private.security.kext-management`

Entitlement necessario per richiedere al **kernel di caricare una kernel extension**.

### **`com.apple.private.icloud-account-access`**

Con l'entitlement **`com.apple.private.icloud-account-access`** è possibile comunicare con il servizio XPC **`com.apple.iCloudHelper`**, che fornirà token di iCloud.

**iMovie** e **Garageband** avevano questo entitlement.

Per maggiori **informazioni** sull'exploit per **ottenere i token iCloud** da questo entitlement, consulta la talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Non so cosa permetta di fare

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **è menzionato che questo potrebbe essere usato per** aggiornare i contenuti protetti da SSV dopo un reboot. Se sai come farlo, invia una PR per favore!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **è menzionato che questo potrebbe essere usato per** aggiornare i contenuti protetti da SSV dopo un reboot. Se sai come farlo, invia una PR per favore!

### `keychain-access-groups`

Questo entitlement elenca i gruppi di keychain a cui l'applicazione ha accesso:
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

Concede i permessi **Full Disk Access**, uno dei permessi TCC più elevati che puoi avere.

### **`kTCCServiceAppleEvents`**

Consente all'app di inviare eventi ad altre applicazioni comunemente usate per **automatizzare attività**. Controllando altre app, può abusare dei permessi concessi a queste altre app.

Ad esempio, può far sì che chiedano all'utente la password:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
O farli eseguire **azioni arbitrarie**.

### **`kTCCServiceEndpointSecurityClient`**

Consente, tra le altre autorizzazioni, di **scrivere nel database TCC dell'utente**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Consente di **modificare** l'attributo **`NFSHomeDirectory`** di un utente che modifica il percorso della sua cartella home e pertanto permette di **bypass TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Consente di modificare file all'interno dei bundle delle app (all'interno di app.app), operazione **non consentita per impostazione predefinita**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

È possibile verificare chi ha questo accesso in _Impostazioni di Sistema_ > _Privacy e Sicurezza_ > _Gestione app._

### `kTCCServiceAccessibility`

Il processo sarà in grado di **abusare delle funzionalità di accessibilità di macOS**, il che significa che, ad esempio, potrà simulare la pressione dei tasti. Quindi potrebbe richiedere l'accesso per controllare un'app come Finder e approvare il dialogo con questo permesso.

## Entitlements relativi a Trustcache/CDhash

Esistono alcuni entitlements che possono essere usati per bypassare le protezioni Trustcache/CDhash, le quali impediscono l'esecuzione di versioni meno recenti dei binari Apple.

## Medio

### `com.apple.security.cs.allow-jit`

Questo entitlement consente di **creare memoria scrivibile ed eseguibile** passando il flag `MAP_JIT` alla funzione di sistema `mmap()`. Vedi [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Questo entitlement permette di **sovrascrivere o patchare codice C**, usare la ormai deprecata **`NSCreateObjectFileImageFromMemory`** (che è fondamentalmente insicura), o usare il framework **DVDPlayback**. Vedi [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> L'inclusione di questo entitlement espone la tua app a vulnerabilità comuni nei linguaggi di programmazione non sicuri per la memoria. Valuta attentamente se la tua app necessita di questa eccezione.

### `com.apple.security.cs.disable-executable-page-protection`

Questo entitlement consente di **modificare sezioni dei propri file eseguibili** su disco in modo da forzarne l'uscita. Vedi [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Il 'Disable Executable Memory Protection Entitlement' è un entitlement estremo che rimuove una protezione di sicurezza fondamentale dalla tua app, rendendo possibile per un attaccante riscrivere il codice eseguibile della tua app senza rilevamento. Preferisci entitlements più ristretti se possibile.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Questo entitlement consente di montare un file system nullfs (vietato per impostazione predefinita). Strumento: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Secondo questo post del blog, questo permesso TCC si trova di solito nella forma:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Consente al processo di **richiedere tutte le autorizzazioni TCC**.

### **`kTCCServicePostEvent`**

Permette di **iniettare eventi di tastiera e mouse sintetici** a livello di sistema tramite `CGEventPost()`. Un processo con questa autorizzazione può simulare pressioni dei tasti, clic del mouse e eventi di scorrimento in qualsiasi applicazione — fornendo di fatto il **controllo remoto** del desktop.

Questo è particolarmente pericoloso se combinato con `kTCCServiceAccessibility` o `kTCCServiceListenEvent`, poiché permette sia di leggere che di iniettare input.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Permette di **intercettare tutti gli eventi da tastiera e mouse** a livello di sistema (input monitoring / keylogging). Un processo può registrare un `CGEventTap` per catturare ogni battitura effettuata in qualsiasi applicazione, incluse password, numeri di carta di credito e messaggi privati.

Per tecniche di sfruttamento dettagliate vedi:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Permette di **leggere il buffer di display** — fare screenshot e registrare video dello schermo di qualsiasi applicazione, inclusi i campi di testo sicuri. Combinato con OCR, questo può estrarre automaticamente password e dati sensibili dallo schermo.

> [!WARNING]
> A partire da macOS Sonoma, la cattura dello schermo mostra un indicatore persistente nella barra dei menu. Nelle versioni precedenti, la registrazione dello schermo può essere completamente silenziosa.

### **`kTCCServiceCamera`**

Permette di **acquisire foto e video** dalla fotocamera integrata o da videocamere USB collegate. Code injection in un binary con entitlement per la camera consente una sorveglianza visiva silenziosa.

### **`kTCCServiceMicrophone`**

Permette di **registrare audio** da tutti i dispositivi di input. Demoni in background con accesso al microfono forniscono una sorveglianza audio ambientale persistente senza alcuna finestra applicativa visibile.

### **`kTCCServiceLocation`**

Permette di interrogare la **posizione fisica** del dispositivo tramite triangolazione Wi‑Fi o beacon Bluetooth. Il monitoraggio continuo rivela indirizzi di casa/lavoro, pattern di viaggio e routine quotidiane.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Accesso ai **Contacts** (nomi, e-mail, numeri di telefono — utile per spear-phishing), al **Calendar** (orari delle riunioni, liste dei partecipanti) e alle **Photos** (foto personali, screenshot che possono contenere credenziali, metadata di posizione).

Per tecniche complete di furto di credenziali tramite permessi TCC, vedi:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox e Entitlements di Code Signing

### `com.apple.security.temporary-exception.mach-lookup.global-name`

Le **eccezioni temporanee della Sandbox** indeboliscono l'App Sandbox consentendo la comunicazione con servizi Mach/XPC a livello di sistema che la sandbox normalmente blocca. Questo è il **primary sandbox escape primitive** — un'app sandbox compromessa può usare eccezioni mach-lookup per raggiungere demoni privilegiati e sfruttare le loro interfacce XPC.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Per una catena di exploitation dettagliata: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, vedi:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

Le DriverKit entitlements permettono ai binari driver in user-space di comunicare direttamente con il kernel tramite le interfacce IOKit. I binari DriverKit gestiscono l'hardware: USB, Thunderbolt, PCIe, dispositivi HID, audio e networking.

Compromettere un binario DriverKit consente:
- **Kernel attack surface** tramite chiamate `IOConnectCallMethod` malformate
- **USB device spoofing** (emulare una tastiera per HID injection)
- **DMA attacks** attraverso interfacce PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Per dettagli su IOKit/DriverKit exploitation, vedere:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}



{{#include ../../../banners/hacktricks-training.md}}
