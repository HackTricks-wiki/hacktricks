# Gefährliche Entitlements und TCC-Berechtigungen unter macOS

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Beachte, dass Entitlements, die mit **`com.apple`** beginnen, für Drittanbieter nicht verfügbar sind; nur Apple kann sie gewähren ... Wenn du jedoch ein Enterprise-Zertifikat verwendest, könntest du tatsächlich eigene Entitlements erstellen, die mit **`com.apple`** beginnen, und darauf basierende Schutzmaßnahmen umgehen.

## Hoch

### `com.apple.rootless.install.heritable`

Das Entitlement **`com.apple.rootless.install.heritable`** ermöglicht das **Umgehen von SIP**. Weitere Informationen findest du [hier](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Das Entitlement **`com.apple.rootless.install`** ermöglicht das **Umgehen von SIP**. Weitere Informationen findest du [hier](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (zuvor `task_for_pid-allow` genannt)**

Dieses Entitlement ermöglicht es, den **task port für jeden** Prozess außer dem Kernel zu erhalten. Weitere Informationen findest du [**hier**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Dieses Entitlement ermöglicht es anderen Prozessen mit dem Entitlement **`com.apple.security.cs.debugger`**, den task port des Prozesses zu erhalten, der von der Binary mit diesem Entitlement ausgeführt wird, und **Code in diesen zu injizieren**. Weitere Informationen findest du [**hier**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps mit dem Debugging Tool Entitlement können `task_for_pid()` aufrufen, um einen gültigen task port für unsignierte und Drittanbieter-Apps abzurufen, bei denen das Entitlement `Get Task Allow` auf `true` gesetzt ist. Selbst mit dem Debugging Tool Entitlement kann ein Debugger jedoch **nicht die task ports** von Prozessen erhalten, die **nicht über das `Get Task Allow`-Entitlement verfügen** und daher durch System Integrity Protection geschützt sind. Weitere Informationen findest du [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Dieses Entitlement ermöglicht das **Laden von Frameworks, Plug-ins oder Libraries, ohne dass diese entweder von Apple oder mit derselben Team ID** wie die Haupt-Binary signiert wurden. Ein Angreifer könnte daher einen beliebigen Library-Load missbrauchen, um Code zu injizieren. Weitere Informationen findest du [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Dieses Entitlement ist **`com.apple.security.cs.disable-library-validation`** sehr ähnlich, deaktiviert jedoch **nicht direkt** die Library-Validierung, sondern ermöglicht es dem Prozess, zur Laufzeit einen `csops`-Systemaufruf aufzurufen, um sie zu deaktivieren.

Der Name des Entitlements ist in XNU neben der `csops`-Operation, die es verwendet, fest codiert:<sup>[[2]](#references)</sup>.
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Der Kernel-Handler für `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) zeigt genau, wie begrenzt das Primitive ist:<sup>[[3]](#references)</sup>
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
Der Vorgang:

- Ist **nur unter macOS verfügbar** (`ENOTSUP` auf jeder anderen Plattform).
- Funktioniert nur auf **sich selbst** (`forself == 1`) — damit kann die library validation eines anderen Prozesses nicht entfernt werden.
- Erfordert, dass der Prozess das Entitlement tatsächlich **besitzt**, und wird verweigert, wenn der Prozess mit `CS_INSTALLER` gekennzeichnet ist oder unter einem subsystem root path ausgeführt wird.
- Entfernt **`CS_REQUIRE_LV | CS_FORCED_LV`** aus den Code-Signing-Flags des Prozesses.

Der XNU-Kommentar erklärt den vorgesehenen Anwendungsfall und auch, warum er für einen Angreifer interessant ist:

> Diese Option wird verwendet, um die library validation aus einem laufenden Prozess zu entfernen. Dies wird in Plugin-Architekturen verwendet, wenn ein Programm nicht vertrauenswürdige Libraries laden muss. [...] Sobald ein Prozess die nicht vertrauenswürdige Library geladen hat, ist es künftig nicht mehr effektiv, sich auf die library validation zu verlassen.

Mit anderen Worten: **Jedes Binary mit diesem Entitlement ist ein dylib-injection-Ziel**: Bring Code innerhalb des Prozesses zur Ausführung (oder überzeuge ihn, dein Plugin zu laden), nachdem er `CS_REQUIRE_LV` entfernt hat, und du erbst sämtliche Berechtigungen, über die der Host-Prozess verfügt.

### `com.apple.security.cs.allow-dyld-environment-variables`

Dieses Entitlement erlaubt die **Verwendung von DYLD-Umgebungsvariablen**, die zum Injizieren von Libraries und Code verwendet werden könnten. Weitere Informationen findest du [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` oder `com.apple.rootless.storage`.`TCC`

[**Laut diesem Blog**](https://objective-see.org/blog/blog_0x4C.html) **und** [**diesem Blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) ermöglichen diese Entitlements die **Änderung** der **TCC**-Datenbank.

### **`system.install.apple-software`** und **`system.install.apple-software.standar-user`**

Diese Entitlements ermöglichen die **Installation von Software, ohne den Benutzer nach Berechtigungen zu fragen**, was für eine **privilege escalation** hilfreich sein kann.

### `com.apple.private.security.kext-management`

Dieses Entitlement wird benötigt, um den **Kernel zum Laden einer Kernel-Erweiterung aufzufordern**.

### **`com.apple.private.icloud-account-access`**

Mit dem Entitlement **`com.apple.private.icloud-account-access`** ist es möglich, mit dem **`com.apple.iCloudHelper`**-XPC-Service zu kommunizieren, der **iCloud-Tokens bereitstellt**.

**iMovie** und **Garageband** verfügten über dieses Entitlement.

Weitere **Informationen** zum Exploit, mit dem sich über dieses Entitlement **iCloud-Tokens abrufen** lassen, findest du in diesem Vortrag: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ich weiß nicht, was dies ermöglicht.

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**diesem Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wird erwähnt, dass dies dazu verwendet werden könnte**, die durch SSV geschützten Inhalte nach einem Neustart zu aktualisieren. Wenn du weißt, wie das funktioniert, sende bitte einen PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**diesem Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wird erwähnt, dass dies dazu verwendet werden könnte**, die durch SSV geschützten Inhalte nach einem Neustart zu aktualisieren. Wenn du weißt, wie das funktioniert, sende bitte einen PR!

### `keychain-access-groups`

Diese Entitlement-Liste enthält die **keychain**-Gruppen, auf die die Anwendung Zugriff hat:
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

Gewährt **Full Disk Access**-Berechtigungen, eine der höchsten TCC-Berechtigungen, die man haben kann.

### **`kTCCServiceAppleEvents`**

Erlaubt der App, Ereignisse an andere Anwendungen zu senden, die häufig zur **Automatisierung von Aufgaben** verwendet werden. Durch die Steuerung anderer Apps kann sie die diesen anderen Apps gewährten Berechtigungen missbrauchen.

Zum Beispiel, indem sie diese dazu bringt, den Benutzer nach seinem Passwort zu fragen:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Oder sie dazu zu bringen, **beliebige Aktionen** auszuführen.

### **`kTCCServiceEndpointSecurityClient`**

Ermöglicht unter anderem, die **TCC-Datenbank des Benutzers zu schreiben**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Ermöglicht, das Attribut **`NFSHomeDirectory`** eines Benutzers zu **ändern**, wodurch dessen Pfad zum Home-Ordner geändert wird und somit **TCC umgangen** werden kann.

### **`kTCCServiceSystemPolicyAppBundles`**

Ermöglicht, Dateien innerhalb von App-Bundles (innerhalb von app.app) zu ändern, was **standardmäßig untersagt** ist.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Es ist möglich, unter _Systemeinstellungen_ > _Datenschutz & Sicherheit_ > _App-Verwaltung_ zu überprüfen, wer diesen Zugriff besitzt.

### `kTCCServiceAccessibility`

Der Prozess kann die **macOS-Bedienungshilfen missbrauchen**. Das bedeutet beispielsweise, dass er Tastatureingaben senden kann. Dadurch könnte er Zugriff zur Steuerung einer App wie Finder anfordern und den Dialog mit dieser Berechtigung bestätigen.

## Mit Trustcache/CDhash verbundene Entitlements

Es gibt einige Entitlements, die verwendet werden könnten, um Trustcache/CDhash-Schutzmechanismen zu umgehen, welche die Ausführung heruntergestufter Versionen von Apple-Binärdateien verhindern.

## Mittel

### `com.apple.security.cs.allow-jit`

Dieses Entitlement ermöglicht es, **beschreibbaren und ausführbaren Speicher zu erstellen**, indem das Flag `MAP_JIT` an die Systemfunktion `mmap()` übergeben wird. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Dieses Entitlement ermöglicht es, **C-Code zu überschreiben oder zu patchen**, das längst veraltete **`NSCreateObjectFileImageFromMemory`** zu verwenden (das grundsätzlich unsicher ist) oder das **DVDPlayback**-Framework zu nutzen. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Das Einbinden dieses Entitlements setzt Ihre App häufigen Schwachstellen in speicherunsicheren Programmiersprachen aus. Prüfen Sie sorgfältig, ob Ihre App diese Ausnahme benötigt.

### `com.apple.security.cs.disable-executable-page-protection`

Dieses Entitlement ermöglicht es, **Abschnitte der eigenen ausführbaren Dateien** auf dem Datenträger zu ändern, um das Beenden zu erzwingen. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Das Disable Executable Memory Protection Entitlement ist ein extremes Entitlement, das einen grundlegenden Sicherheitsschutz Ihrer App entfernt und es einem Angreifer ermöglicht, den ausführbaren Code Ihrer App unbemerkt umzuschreiben. Verwenden Sie nach Möglichkeit engere Entitlements.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Dieses Entitlement ermöglicht das Einhängen eines nullfs-Dateisystems (standardmäßig verboten). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Laut diesem Blogbeitrag wird diese TCC-Berechtigung üblicherweise in folgender Form gefunden:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Ermöglicht dem Prozess, **alle TCC-Berechtigungen anzufordern**.

### **`kTCCServicePostEvent`**

Ermöglicht das **systemweite Injizieren synthetischer Tastatur- und Mausereignisse** über `CGEventPost()`. Ein Prozess mit dieser Berechtigung kann in jeder Anwendung Tastenanschläge, Mausklicks und Scroll-Ereignisse simulieren – und dadurch effektiv eine **Fernsteuerung** des Desktops ermöglichen.

Dies ist besonders gefährlich in Kombination mit `kTCCServiceAccessibility` oder `kTCCServiceListenEvent`, da dadurch sowohl Eingaben gelesen als auch injiziert werden können.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Ermöglicht das **Abfangen aller Tastatur- und Mausereignisse** systemweit (input monitoring / keylogging). Ein Prozess kann einen `CGEventTap` registrieren, um jede in einer beliebigen Anwendung eingegebene Tastatureingabe zu erfassen, einschließlich Passwörtern, Kreditkartennummern und privaten Nachrichten.

Detaillierte Exploitation-Techniken finden Sie unter:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Ermöglicht das **Lesen des Display-Puffers** — das Erstellen von Screenshots und Aufzeichnen von Bildschirmvideos beliebiger Anwendungen, einschließlich sicherer Texteingabefelder. In Kombination mit OCR können dadurch Passwörter und sensible Daten automatisch vom Bildschirm extrahiert werden.

> [!WARNING]
> Ab macOS Sonoma zeigt screen capture einen dauerhaft sichtbaren Hinweis in der Menüleiste an. In älteren Versionen kann screen recording vollständig unbemerkt erfolgen.

### **`kTCCServiceCamera`**

Ermöglicht das **Aufnehmen von Fotos und Videos** mit der integrierten Kamera oder angeschlossenen USB-Kameras. Code injection in ein Binary mit Kamera-Entitlement ermöglicht unbemerkte visuelle Überwachung.

### **`kTCCServiceMicrophone`**

Ermöglicht das **Aufzeichnen von Audio** von allen Eingabegeräten. Hintergrund-Daemons mit Mikrofonzugriff ermöglichen eine dauerhafte Überwachung von Umgebungsgeräuschen ohne sichtbares Anwendungsfenster.

### **`kTCCServiceLocation`**

Ermöglicht das Abfragen des **physischen Standorts** des Geräts über Wi-Fi-Triangulation oder Bluetooth-Beacons. Eine kontinuierliche Überwachung gibt Aufschluss über Wohn- und Arbeitsadressen, Reisemuster und tägliche Routinen.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Zugriff auf **Kontakte** (Namen, E-Mail-Adressen, Telefonnummern — nützlich für Spear-Phishing), **Kalender** (Terminpläne, Teilnehmerlisten) und **Fotos** (persönliche Fotos, Screenshots, die Zugangsdaten enthalten können, sowie Standortmetadaten).

Vollständige Exploitation-Techniken zum Diebstahl von Zugangsdaten über TCC-Berechtigungen finden Sie unter:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox- und Code-Signing-Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Temporäre Sandbox-Ausnahmen** schwächen die App Sandbox, indem sie die Kommunikation mit systemweiten Mach/XPC-Diensten erlauben, die die Sandbox normalerweise blockiert. Dies ist das **primäre Sandbox-Escape-Primitiv** — eine kompromittierte Sandbox-Anwendung kann Mach-lookup-Ausnahmen verwenden, um privilegierte Daemons zu erreichen und deren XPC-Schnittstellen zu exploiten.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Für eine detaillierte exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, siehe:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** ermöglichen es user-space driver binaries, direkt über IOKit-Schnittstellen mit dem Kernel zu kommunizieren. DriverKit binaries verwalten Hardware: USB, Thunderbolt, PCIe, HID-Geräte, Audio und Netzwerk.

Die Kompromittierung eines DriverKit binary ermöglicht:
- **Angriffsfläche des Kernels** durch manipulierte `IOConnectCallMethod`-Aufrufe
- **USB device spoofing** (eine Tastatur für HID injection emulieren)
- **DMA attacks** über PCIe-/Thunderbolt-Schnittstellen
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Für detaillierte IOKit/DriverKit-Exploitation siehe:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## Quellen

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h` (Operationen `CS_OPS_*` und `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (Handler für `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
