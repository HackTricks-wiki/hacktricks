# Gefährliche Entitlements und TCC-Berechtigungen unter macOS

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Beachte, dass Entitlements, die mit **`com.apple`** beginnen, für Drittanbieter nicht verfügbar sind. Nur Apple kann sie gewähren ... Wenn du jedoch ein Enterprise-Zertifikat verwendest, könntest du tatsächlich eigene Entitlements erstellen, die mit **`com.apple`** beginnen, und dadurch auf diesen basierende Schutzmechanismen umgehen.

## Hoch

### `com.apple.rootless.install.heritable`

Das Entitlement **`com.apple.rootless.install.heritable`** ermöglicht das **Umgehen von SIP**. Weitere Informationen findest du [hier](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Das Entitlement **`com.apple.rootless.install`** ermöglicht das **Umgehen von SIP**. Weitere Informationen findest du [hier](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (zuvor `task_for_pid-allow` genannt)**

Dieses Entitlement ermöglicht den Zugriff auf den **Task-Port jedes** Prozesses, mit Ausnahme des Kernels. Weitere Informationen findest du [**hier**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Dieses Entitlement ermöglicht es anderen Prozessen mit dem Entitlement **`com.apple.security.cs.debugger`**, den Task-Port des Prozesses abzurufen, der von der Binärdatei mit diesem Entitlement ausgeführt wird, und **Code in diesen zu injizieren**. Weitere Informationen findest du [**hier**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps mit dem Debugging Tool Entitlement können `task_for_pid()` aufrufen, um einen gültigen Task-Port für nicht signierte und Drittanbieter-Apps abzurufen, bei denen das Entitlement `Get Task Allow` auf `true` gesetzt ist. Selbst mit dem Debugging Tool Entitlement kann ein Debugger jedoch **nicht auf die Task-Ports** von Prozessen zugreifen, die **nicht über das Entitlement `Get Task Allow` verfügen** und daher durch System Integrity Protection geschützt sind. Weitere Informationen findest du [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Dieses Entitlement ermöglicht das **Laden von Frameworks, Plug-ins oder Libraries, ohne dass diese von Apple oder mit derselben Team ID** wie die Hauptausführungsdatei signiert sein müssen. Ein Angreifer könnte daher einen beliebigen Library Load missbrauchen, um Code zu injizieren. Weitere Informationen findest du [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Dieses Entitlement ist **`com.apple.security.cs.disable-library-validation`** sehr ähnlich, deaktiviert die Library-Validierung jedoch **nicht direkt**, sondern ermöglicht es dem Prozess, zur Laufzeit einen `csops`-Systemaufruf aufzurufen, um sie zu deaktivieren.

Der Name des Entitlements ist in XNU neben der `csops`-Operation fest codiert, die es verwendet:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Der Kernel-Handler für `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) zeigt genau, wie eng begrenzt das Primitive ist:<sup>[[2]](#references)</sup>
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
- Funktioniert nur für **sich selbst** (`forself == 1`) — die library validation kann damit nicht für einen anderen Prozess entfernt werden.
- Erfordert, dass der Prozess das **Entitlement tatsächlich besitzt**, und wird verweigert, wenn der Prozess mit `CS_INSTALLER` gekennzeichnet ist oder unter einem Subsystem-Root-Pfad ausgeführt wird.
- Entfernt **`CS_REQUIRE_LV | CS_FORCED_LV`** aus den Code-Signing-Flags des Prozesses.

Der XNU-Kommentar erklärt den vorgesehenen Anwendungsfall und auch, warum dieser für einen Angreifer interessant ist:

> Diese Option wird verwendet, um die library validation aus einem laufenden Prozess zu entfernen. Dies wird in Plugin-Architekturen verwendet, wenn ein Programm nicht vertrauenswürdige Libraries laden muss. [...] Sobald ein Prozess die nicht vertrauenswürdige Library geladen hat, ist es künftig nicht mehr effektiv, sich auf die library validation zu verlassen.

Mit anderen Worten: **Jedes Binary mit diesem Entitlement ist ein dylib-injection target**: Führe Code innerhalb des Prozesses aus (oder bringe ihn dazu, dein Plug-in zu laden), nachdem er `CS_REQUIRE_LV` entfernt hat, und du erbst alle Aktionen, zu denen der Host-Prozess berechtigt ist.

### `com.apple.security.cs.allow-dyld-environment-variables`

Dieses Entitlement erlaubt die **Verwendung von DYLD-Umgebungsvariablen**, die zum Injizieren von Libraries und Code verwendet werden könnten. Weitere Informationen findest du [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` oder `com.apple.rootless.storage`.`TCC`

[**Laut diesem Blog**](https://objective-see.org/blog/blog_0x4C.html) **und** [**diesem Blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) ermöglichen diese Entitlements die **Änderung** der **TCC**-Datenbank.<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** und **`system.install.apple-software.standar-user`**

Diese Entitlements ermöglichen die **Installation von Software, ohne den Benutzer nach Berechtigungen zu fragen**, was für eine **Privilege Escalation** hilfreich sein kann.

### `com.apple.private.security.kext-management`

Dieses Entitlement wird benötigt, um den **Kernel zum Laden einer Kernel Extension aufzufordern**.

### **`com.apple.private.icloud-account-access`**

Mit dem Entitlement **`com.apple.private.icloud-account-access`** ist es möglich, mit dem **`com.apple.iCloudHelper`**-XPC-Service zu kommunizieren, der **iCloud-Tokens bereitstellt**.

**iMovie** und **Garageband** besaßen dieses Entitlement.

Weitere **Informationen** zum Exploit, mit dem sich über dieses Entitlement **iCloud-Tokens abrufen** lassen, findest du im Vortrag: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ich weiß nicht, was dies ermöglicht

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**diesem Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wird erwähnt, dass dies verwendet werden könnte, um** die SSV-geschützten Inhalte nach einem Reboot zu aktualisieren. Wenn du weißt, wie das funktioniert, erstelle bitte eine PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**diesem Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wird erwähnt, dass dies verwendet werden könnte, um** die SSV-geschützten Inhalte nach einem Reboot zu aktualisieren. Wenn du weißt, wie das funktioniert, erstelle bitte eine PR!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Dieses Entitlement listet die **Keychain**-Gruppen auf, auf die die Anwendung Zugriff hat:
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

Erlaubt der App, Ereignisse an andere Anwendungen zu senden, die üblicherweise zum **Automatisieren von Aufgaben** verwendet werden. Durch die Kontrolle über andere Apps kann sie die diesen anderen Apps gewährten Berechtigungen missbrauchen.

Zum Beispiel, indem sie den Benutzer nach seinem Passwort fragen:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Oder sie dazu zu bringen, **beliebige Aktionen** auszuführen.

### **`kTCCServiceEndpointSecurityClient`**

Erlaubt unter anderem, die **TCC-Datenbank des Benutzers zu schreiben**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Erlaubt es, das Attribut **`NFSHomeDirectory`** eines Benutzers zu **ändern**, wodurch der Pfad zu seinem Home-Ordner geändert wird und somit ein **TCC-Bypass** möglich ist.

### **`kTCCServiceSystemPolicyAppBundles`**

Erlaubt, Dateien innerhalb von App-Bundles (innerhalb von app.app) zu ändern, was standardmäßig **nicht erlaubt** ist.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Es ist möglich, unter _System Settings_ > _Privacy & Security_ > _App Management_ zu überprüfen, wer über diesen Zugriff verfügt.

### `kTCCServiceAccessibility`

Der Prozess kann die **macOS-Barrierefreiheitsfunktionen missbrauchen**, was beispielsweise bedeutet, dass er Tastatureingaben ausführen kann. Dadurch könnte er Zugriff zur Steuerung einer App wie Finder anfordern und den Dialog mit dieser Berechtigung bestätigen.

## Mit Trustcache/CDhash zusammenhängende Entitlements

Es gibt einige Entitlements, die verwendet werden könnten, um Trustcache/CDhash-Schutzmechanismen zu umgehen, die die Ausführung heruntergestufter Versionen von Apple-Binaries verhindern.

## Mittel

### `com.apple.security.cs.allow-jit`

Dieses Entitlement ermöglicht es, **beschreibbaren und ausführbaren Speicher zu erstellen**, indem das Flag `MAP_JIT` an die Systemfunktion `mmap()` übergeben wird. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Dieses Entitlement ermöglicht es, **C-Code zu überschreiben oder zu patchen**, das seit Langem veraltete **`NSCreateObjectFileImageFromMemory`** zu verwenden (was grundsätzlich unsicher ist) oder das **DVDPlayback**-Framework zu verwenden. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Das Einbinden dieses Entitlements setzt Ihre App allgemeinen Schwachstellen in speicherunsicheren Programmiersprachen aus. Prüfen Sie sorgfältig, ob Ihre App diese Ausnahme benötigt.

### `com.apple.security.cs.disable-executable-page-protection`

Dieses Entitlement ermöglicht es, **Abschnitte der eigenen ausführbaren Dateien** auf dem Datenträger zu ändern, um das Beenden zu erzwingen. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Das Entitlement „Disable Executable Memory Protection“ ist ein extremes Entitlement, das einen grundlegenden Sicherheitsschutz aus Ihrer App entfernt und es einem Angreifer ermöglicht, den ausführbaren Code Ihrer App unbemerkt umzuschreiben. Verwenden Sie nach Möglichkeit spezifischere Entitlements.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Dieses Entitlement ermöglicht das Mounten eines nullfs-Dateisystems (standardmäßig verboten). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Laut diesem Blogpost findet sich diese TCC-Berechtigung üblicherweise in der Form:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Erlaubt dem Prozess, **alle TCC-Berechtigungen anzufordern**.

### **`kTCCServicePostEvent`**

Erlaubt das **Einschleusen synthetischer Tastatur- und Mausereignisse** systemweit über `CGEventPost()`. Ein Prozess mit dieser Berechtigung kann Tastatureingaben, Mausklicks und Scrollereignisse in jeder Anwendung simulieren – und damit effektiv eine **Fernsteuerung** des Desktops ermöglichen.

Dies ist besonders gefährlich in Kombination mit `kTCCServiceAccessibility` oder `kTCCServiceListenEvent`, da dadurch sowohl Eingaben gelesen als auch eingeschleust werden können.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Erlaubt das **Abfangen aller Tastatur- und Mausereignisse** systemweit (Input Monitoring / Keylogging). Ein Prozess kann einen `CGEventTap` registrieren, um jede in einer beliebigen Anwendung eingegebene Tastatureingabe zu erfassen, einschließlich Passwörtern, Kreditkartennummern und privaten Nachrichten.

Detaillierte Exploitation-Techniken finden Sie unter:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Erlaubt das **Lesen des Display-Puffers** — das Erstellen von Screenshots und Aufzeichnen von Bildschirmvideos jeder Anwendung, einschließlich sicherer Texteingabefelder. In Kombination mit OCR können dadurch Passwörter und sensible Daten automatisch vom Bildschirm extrahiert werden.

> [!WARNING]
> Ab macOS Sonoma zeigt screen capture einen dauerhaft sichtbaren Indikator in der Menüleiste an. In älteren Versionen kann screen recording vollständig unbemerkt erfolgen.

### **`kTCCServiceCamera`**

Erlaubt das **Aufnehmen von Fotos und Videos** über die integrierte Kamera oder angeschlossene USB-Kameras. Code injection in ein Binary mit Kamera-Berechtigung ermöglicht unauffällige visuelle Überwachung.

### **`kTCCServiceMicrophone`**

Erlaubt das **Aufzeichnen von Audio** über alle Eingabegeräte. Hintergrund-Daemons mit Mikrofonzugriff ermöglichen eine dauerhafte Überwachung der Umgebungsgeräusche ohne sichtbares Anwendungsfenster.

### **`kTCCServiceLocation`**

Erlaubt das Abfragen des **physischen Standorts** des Geräts über Wi-Fi-Triangulation oder Bluetooth-Beacons. Eine kontinuierliche Überwachung offenbart Wohn- und Arbeitsadressen, Bewegungsmuster sowie tägliche Routinen.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Zugriff auf **Kontakte** (Namen, E-Mail-Adressen, Telefonnummern — nützlich für Spear-Phishing), **Kalender** (Besprechungspläne, Teilnehmerlisten) und **Fotos** (persönliche Fotos, Screenshots, die Zugangsdaten enthalten können, sowie Standortmetadaten).

Vollständige Exploitation-Techniken zum Diebstahl von Zugangsdaten über TCC-Berechtigungen finden Sie unter:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox- und Code-Signing-Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Temporäre Sandbox-Ausnahmen** schwächen die App Sandbox, indem sie die Kommunikation mit systemweiten Mach/XPC-Diensten erlauben, die die Sandbox normalerweise blockiert. Dies ist das **primäre Sandbox-Escape-Primitiv** — eine kompromittierte Sandbox-Anwendung kann Mach-Lookup-Ausnahmen verwenden, um privilegierte Daemons zu erreichen und deren XPC-Schnittstellen zu exploiten.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Für eine detaillierte exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape siehe:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** ermöglichen es User-Space-Treiber-Binaries, über IOKit-Schnittstellen direkt mit dem Kernel zu kommunizieren. DriverKit-Binaries verwalten Hardware: USB, Thunderbolt, PCIe, HID-Geräte, Audio und Netzwerke.

Die Kompromittierung einer DriverKit-Binary ermöglicht:
- **Kernel-Angriffsfläche** durch manipulierte `IOConnectCallMethod`-Aufrufe
- **USB-Geräte-Spoofing** (eine Tastatur für HID injection emulieren)
- **DMA-Angriffe** über PCIe-/Thunderbolt-Schnittstellen
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Für detaillierte IOKit/DriverKit-Exploitation siehe:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## Referenzen

- [1] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*`-Operationen und `CLEAR_LV_ENTITLEMENT)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (`csops`- / `CS_OPS_CLEAR_LV`-Handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Entitlement für Debugging-Tools (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement zum Deaktivieren der Library Validation](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement zum Zulassen von DYLD-Umgebungsvariablen](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Umgehen von TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Musik abspielen und TCC umgehen, auch bekannt als CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: „What Happens on your Mac, Stays on Apple's iCloud?!“ - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Der Albtraum von Apples OTA-Update: Umgehen der Signaturprüfung und Pwning des Kernels](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement zum Zulassen der Ausführung von JIT-kompiliertem Code (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement zum Zulassen von nicht signiertem ausführbarem Speicher](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement zum Deaktivieren des Schutzes ausführbarer Speicherseiten](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)

{{#include ../../../banners/hacktricks-training.md}}
