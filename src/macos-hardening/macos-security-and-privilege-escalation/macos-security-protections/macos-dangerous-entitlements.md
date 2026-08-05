# Gefährliche Entitlements & TCC perms unter macOS

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Beachte, dass Entitlements, die mit **`com.apple`** beginnen, für Drittanbieter nicht verfügbar sind; nur Apple kann sie gewähren ... Wenn du jedoch ein Enterprise-Zertifikat verwendest, könntest du tatsächlich eigene Entitlements erstellen, die mit **`com.apple`** beginnen, und darauf basierende Schutzmechanismen umgehen.

## Hoch

### `com.apple.rootless.install.heritable`

Das Entitlement **`com.apple.rootless.install.heritable`** ermöglicht es, **SIP zu umgehen**. Weitere Informationen findest du [hier](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Das Entitlement **`com.apple.rootless.install`** ermöglicht es, **SIP zu umgehen**. Weitere Informationen findest du [hier](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (zuvor `task_for_pid-allow` genannt)**

Dieses Entitlement ermöglicht es, den **Task-Port für jeden** Prozess außer dem Kernel zu erhalten. Weitere Informationen findest du [**hier**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Dieses Entitlement ermöglicht es anderen Prozessen mit dem Entitlement **`com.apple.security.cs.debugger`**, den Task-Port des Prozesses zu erhalten, der von der Binary mit diesem Entitlement ausgeführt wird, und **Code in ihn zu injizieren**. Weitere Informationen findest du [**hier**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps mit dem Debugging Tool Entitlement können `task_for_pid()` aufrufen, um einen gültigen Task-Port für unsignierte und Drittanbieter-Apps abzurufen, bei denen das Entitlement `Get Task Allow` auf `true` gesetzt ist. Selbst mit dem Debugging Tool Entitlement kann ein Debugger jedoch **nicht die Task-Ports** von Prozessen erhalten, die **nicht über das `Get Task Allow`-Entitlement verfügen** und daher durch System Integrity Protection geschützt sind. Weitere Informationen findest du [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Dieses Entitlement ermöglicht es, **Frameworks, Plug-ins oder Libraries zu laden, ohne dass diese entweder von Apple oder mit derselben Team-ID** wie die Haupt-Executable signiert wurden. Dadurch könnte ein Angreifer einen beliebigen Library-Load missbrauchen, um Code zu injizieren. Weitere Informationen findest du [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Dieses Entitlement ist **`com.apple.security.cs.disable-library-validation`** sehr ähnlich, deaktiviert jedoch **nicht direkt** die Library-Validierung, sondern ermöglicht es dem Prozess, zur Laufzeit einen `csops`-Systemaufruf aufzurufen, um sie zu deaktivieren.

Der Name des Entitlements ist in XNU neben der `csops`-Operation, die es verwendet, hardcodiert:<sup>[2]</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Der Kernel-Handler für `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) zeigt genau, wie eingeschränkt das Primitive ist:<sup>[3]</sup>
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

- Ist **macOS-only** (`ENOTSUP` auf jeder anderen Plattform).
- Funktioniert nur für **sich selbst** (`forself == 1`) — damit kann keine library validation von einem anderen Prozess entfernt werden.
- Erfordert, dass der Prozess das Entitlement tatsächlich **besitzt**, und wird verweigert, wenn der Prozess mit `CS_INSTALLER` markiert ist oder unter einem subsystem root path ausgeführt wird.
- Entfernt **`CS_REQUIRE_LV | CS_FORCED_LV`** aus den Code-Signing-Flags des Prozesses.

Der XNU-Kommentar erklärt den vorgesehenen Anwendungsfall und auch, warum dieser für einen Angreifer interessant ist:

> Diese Option wird verwendet, um library validation aus einem laufenden Prozess zu entfernen. Dies wird in Plugin-Architekturen verwendet, wenn ein Programm nicht vertrauenswürdige Libraries laden muss. [...] Sobald ein Prozess die nicht vertrauenswürdige Library geladen hat, ist es künftig nicht mehr effektiv, sich auf library validation zu verlassen.

Mit anderen Worten: **Jede Binary mit diesem Entitlement ist ein Ziel für dylib-injection**: Bringe Code dazu, innerhalb der Binary ausgeführt zu werden (oder überzeuge sie, dein Plug-in zu laden), nachdem sie `CS_REQUIRE_LV` entfernt hat, und du erbst alle Aktionen, zu denen der Host-Prozess berechtigt ist.

### `com.apple.security.cs.allow-dyld-environment-variables`

Dieses Entitlement erlaubt die **Verwendung von DYLD environment variables**, die zum Injizieren von Libraries und Code verwendet werden könnten. Weitere Informationen findest du [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**Laut diesem Blog**](https://objective-see.org/blog/blog_0x4C.html) **und** [**diesem Blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) ermöglichen diese Entitlements, die **TCC**-Datenbank zu **ändern**.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

Diese Entitlements ermöglichen die **Installation von Software, ohne den Benutzer nach Berechtigungen zu fragen**, was bei einer **privilege escalation** hilfreich sein kann.

### `com.apple.private.security.kext-management`

Entitlement, das erforderlich ist, um den **Kernel zum Laden einer Kernel Extension** aufzufordern.

### **`com.apple.private.icloud-account-access`**

Mit dem Entitlement **`com.apple.private.icloud-account-access`** ist es möglich, mit dem **`com.apple.iCloudHelper`**-XPC-Service zu kommunizieren, der **iCloud-Tokens bereitstellt**.

**iMovie** und **Garageband** besaßen dieses Entitlement.

Weitere **Informationen** über den Exploit zum **Abrufen von iCloud-Tokens** über dieses Entitlement findest du in diesem Vortrag: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ich weiß nicht, was dieses Entitlement ermöglicht.

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**diesem Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wird erwähnt, dass dies verwendet werden könnte, um** die durch SSV geschützten Inhalte nach einem Neustart zu aktualisieren. Wenn du weißt, wie das funktioniert, erstelle bitte einen PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**diesem Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wird erwähnt, dass dies verwendet werden könnte, um** die durch SSV geschützten Inhalte nach einem Neustart zu aktualisieren. Wenn du weißt, wie das funktioniert, erstelle bitte einen PR!

### `keychain-access-groups`

Dieses Entitlement listet die **keychain**-Gruppen auf, auf die die Anwendung Zugriff hat:
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

Gewährt **Full Disk Access**-Berechtigungen, eine der höchsten TCC-Berechtigungsstufen, die man haben kann.

### **`kTCCServiceAppleEvents`**

Erlaubt der App, Events an andere Anwendungen zu senden, die häufig zum **Automatisieren von Aufgaben** verwendet werden. Durch die Kontrolle über andere Apps kann sie die diesen anderen Apps gewährten Berechtigungen missbrauchen.

Zum Beispiel, indem sie den Benutzer dazu auffordert, sein Passwort einzugeben:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Oder sie dazu zu bringen, **beliebige Aktionen** auszuführen.

### **`kTCCServiceEndpointSecurityClient`**

Erlaubt unter anderem, die **TCC-Datenbank des Benutzers zu schreiben**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Erlaubt, das Attribut **`NFSHomeDirectory`** eines Benutzers zu **ändern**, wodurch der Pfad zu dessen Home-Ordner geändert wird und somit ein **TCC-Bypass** möglich ist.

### **`kTCCServiceSystemPolicyAppBundles`**

Erlaubt, Dateien innerhalb von App-Bundles (innerhalb von app.app) zu ändern, was **standardmäßig nicht erlaubt** ist.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Es ist möglich zu überprüfen, wer diesen Zugriff in den _Systemeinstellungen_ > _Datenschutz & Sicherheit_ > _App-Verwaltung_ besitzt.

### `kTCCServiceAccessibility`

Der Prozess kann die **macOS-Eingabehilfefunktionen missbrauchen**, was beispielsweise bedeutet, dass er Tastenanschläge ausführen kann. Dadurch könnte er Zugriff zur Steuerung einer App wie Finder anfordern und den Dialog mit dieser Berechtigung bestätigen.

## Mit Trustcache/CDhash zusammenhängende Entitlements

Es gibt einige Entitlements, die verwendet werden könnten, um Trustcache/CDhash-Schutzmechanismen zu umgehen, die die Ausführung heruntergestufter Versionen von Apple-Binaries verhindern.

## Mittel

### `com.apple.security.cs.allow-jit`

Dieses Entitlement erlaubt es, **beschreibbaren und ausführbaren Speicher zu erstellen**, indem das Flag `MAP_JIT` an die Systemfunktion `mmap()` übergeben wird. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Dieses Entitlement erlaubt es, **C-Code zu überschreiben oder zu patchen**, das lange veraltete **`NSCreateObjectFileImageFromMemory`** zu verwenden (das grundsätzlich unsicher ist) oder das **DVDPlayback**-Framework zu verwenden. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Das Einbinden dieses Entitlements setzt Ihre App häufigen Sicherheitslücken in speicherunsicheren Programmiersprachen aus. Prüfen Sie sorgfältig, ob Ihre App diese Ausnahme benötigt.

### `com.apple.security.cs.disable-executable-page-protection`

Dieses Entitlement erlaubt es, **Abschnitte der eigenen ausführbaren Dateien** auf der Festplatte zu ändern, um das Beenden zu erzwingen. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Das Disable Executable Memory Protection Entitlement ist ein extremes Entitlement, das einen grundlegenden Sicherheitsschutz Ihrer App entfernt und es einem Angreifer ermöglicht, den ausführbaren Code Ihrer App unbemerkt umzuschreiben. Verwenden Sie nach Möglichkeit spezifischere Entitlements.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Dieses Entitlement erlaubt das Einbinden eines nullfs-Dateisystems (standardmäßig verboten). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Laut diesem Blogpost findet sich diese TCC-Berechtigung normalerweise in folgender Form:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Erlaubt dem Prozess, **alle TCC-Berechtigungen anzufordern**.

### **`kTCCServicePostEvent`**

Erlaubt das **Einschleusen synthetischer Tastatur- und Mausereignisse** systemweit über `CGEventPost()`. Ein Prozess mit dieser Berechtigung kann Tastatureingaben, Mausklicks und Scroll-Ereignisse in jeder Anwendung simulieren – und dadurch effektiv die **Fernsteuerung** des Desktops ermöglichen.

Dies ist besonders gefährlich in Kombination mit `kTCCServiceAccessibility` oder `kTCCServiceListenEvent`, da dadurch sowohl Eingaben gelesen als auch eingeschleust werden können.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Ermöglicht das **Abfangen aller Tastatur- und Mausereignisse** systemweit (Input Monitoring / Keylogging). Ein Prozess kann einen `CGEventTap` registrieren, um jeden Tastendruck in jeder Anwendung zu erfassen, einschließlich Passwörtern, Kreditkartennummern und privaten Nachrichten.

Detaillierte Exploitation-Techniken siehe:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Ermöglicht das **Lesen des Display-Puffers** — das Erstellen von Screenshots und Aufzeichnen von Bildschirmvideos jeder Anwendung, einschließlich sicherer Textfelder. In Kombination mit OCR können dadurch automatisch Passwörter und vertrauliche Daten vom Bildschirm extrahiert werden.

> [!WARNING]
> Seit macOS Sonoma zeigt die Bildschirmaufnahme einen dauerhaft sichtbaren Menüleistenindikator. In älteren Versionen kann die Bildschirmaufzeichnung vollständig unbemerkt erfolgen.

### **`kTCCServiceCamera`**

Ermöglicht das **Aufnehmen von Fotos und Videos** mit der integrierten Kamera oder verbundenen USB-Kameras. Code injection in ein Binary mit Kameraberechtigung ermöglicht unbemerkte visuelle Überwachung.

### **`kTCCServiceMicrophone`**

Ermöglicht das **Aufzeichnen von Audio** über alle Eingabegeräte. Hintergrund-Daemons mit Mikrofonzugriff ermöglichen eine dauerhafte Überwachung von Umgebungsgeräuschen ohne sichtbares Anwendungsfenster.

### **`kTCCServiceLocation`**

Ermöglicht das Abfragen des **physischen Standorts** des Geräts über Wi-Fi-Triangulation oder Bluetooth-Beacons. Eine kontinuierliche Überwachung gibt Aufschluss über Wohn- und Arbeitsadressen, Reisewege und tägliche Routinen.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Zugriff auf **Kontakte** (Namen, E-Mail-Adressen, Telefonnummern — nützlich für Spear-Phishing), **Kalender** (Besprechungspläne, Teilnehmerlisten) und **Fotos** (persönliche Fotos, Screenshots, die Zugangsdaten enthalten können, sowie Standortmetadaten).

Vollständige Exploitation-Techniken zum Diebstahl von Zugangsdaten über TCC-Berechtigungen siehe:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox- und Code-Signing-Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Temporäre Sandbox-Ausnahmen** schwächen die App Sandbox, indem sie die Kommunikation mit systemweiten Mach/XPC-Diensten erlauben, die die Sandbox normalerweise blockiert. Dies ist das **primäre Primitive für einen Sandbox Escape** — eine kompromittierte sandboxed App kann Mach-lookup-Ausnahmen verwenden, um privilegierte Daemons zu erreichen und deren XPC-Schnittstellen zu exploiten.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
For detailed exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, siehe:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** ermöglichen es User-Space-Treiber-Binaries, direkt über IOKit-Schnittstellen mit dem Kernel zu kommunizieren. DriverKit-Binaries verwalten Hardware: USB, Thunderbolt, PCIe, HID-Geräte, Audio und Netzwerk.

Die Kompromittierung einer DriverKit-Binary ermöglicht:
- **Angriffsfläche des Kernels** durch fehlerhaft formatierte `IOConnectCallMethod`-Aufrufe
- **USB-Geräte-Spoofing** (Emulation einer Tastatur für HID-Injection)
- **DMA-Angriffe** über PCIe-/Thunderbolt-Schnittstellen
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Für eine detaillierte IOKit/DriverKit exploitation siehe:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## Referenzen

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*`-Operationen und `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (Handler für `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
