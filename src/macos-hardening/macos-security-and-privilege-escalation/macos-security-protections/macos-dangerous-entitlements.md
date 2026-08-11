# macOS Dangerous Entitlements & TCC-Berechtigungen

{{#include ../../../banners/hacktricks-training.md}}

Entitlements deklarieren Fähigkeiten und Sicherheitsausnahmen, die das Betriebssystem signiertem Code gewährt. Die folgenden Einträge konzentrieren sich auf diejenigen, die bei einer offensiven Überprüfung besonders nützlich sind.<sup>[[13]](#references)</sup>

> [!WARNING]
> Beachte, dass Entitlements, die mit **`com.apple`** beginnen, für Drittanbieter nicht verfügbar sind; nur Apple kann sie gewähren ... Wenn du jedoch ein Enterprise-Zertifikat verwendest, könntest du tatsächlich eigene Entitlements erstellen, die mit **`com.apple`** beginnen, und darauf basierende Schutzmechanismen umgehen.

## Hoch

### `com.apple.rootless.install.heritable`

Das Entitlement **`com.apple.rootless.install.heritable`** ermöglicht es einem Prozess, **SIP zu umgehen**. Weitere Informationen findest du [hier](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Das Entitlement **`com.apple.rootless.install`** ermöglicht es einem Prozess, **SIP zu umgehen**. Weitere Informationen findest du [hier](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (zuvor `task_for_pid-allow` genannt)**

Dieses Entitlement ermöglicht es einem Prozess, den **Task-Port jedes** Prozesses außer dem Kernel zu erhalten. Weitere Informationen findest du [**hier**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Dieses Entitlement ermöglicht es anderen Prozessen mit dem Entitlement **`com.apple.security.cs.debugger`**, den Task-Port des Prozesses zu erhalten, der von der Binärdatei mit diesem Entitlement ausgeführt wird, und **Code in diesen zu injizieren**. Weitere Informationen findest du [**hier**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps mit dem Debugging Tool Entitlement können `task_for_pid()` aufrufen, um einen gültigen Task-Port für unsignierte und Drittanbieter-Apps abzurufen, bei denen das `Get Task Allow`-Entitlement auf `true` gesetzt ist. Selbst mit dem Debugging Tool Entitlement kann ein Debugger jedoch **nicht die Task-Ports** von Prozessen abrufen, die **nicht über das `Get Task Allow`-Entitlement verfügen** und daher durch System Integrity Protection geschützt sind. Weitere Informationen findest du [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Dieses Entitlement ermöglicht es einer Anwendung, **Frameworks, Plug-ins oder Bibliotheken zu laden, ohne dass diese von Apple oder mit derselben Team ID** wie die Hauptausführungsdatei signiert sein müssen. Dadurch könnte ein Angreifer einen beliebigen Bibliotheksladevorgang missbrauchen, um Code zu injizieren. Weitere Informationen findest du [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Dieses Entitlement ist **`com.apple.security.cs.disable-library-validation`** sehr ähnlich, deaktiviert jedoch die Bibliotheksvalidierung **nicht direkt**, sondern ermöglicht es dem Prozess, zur Laufzeit einen `csops`-Systemaufruf aufzurufen, um sie zu deaktivieren.

Der Name des Entitlements ist in XNU neben dem `csops`-Vorgang, der es verwendet, fest codiert:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Der Kernel-Handler für `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) zeigt genau, wie begrenzt das Primitive ist:<sup>[[2]](#references)</sup>
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
- Funktioniert nur auf **sich selbst** (`forself == 1`) — man kann damit die library validation eines anderen Prozesses nicht entfernen.
- Erfordert, dass der Prozess das Entitlement tatsächlich **besitzt**, und wird verweigert, wenn der Prozess mit `CS_INSTALLER` gekennzeichnet ist oder unter einem Subsystem-Root-Pfad ausgeführt wird.
- Entfernt **`CS_REQUIRE_LV | CS_FORCED_LV`** aus den Code-Signing-Flags des Prozesses.

Der XNU-Kommentar erklärt den vorgesehenen Anwendungsfall und auch, warum dieser für einen Angreifer interessant ist:

> Diese Option wird verwendet, um die library validation aus einem laufenden Prozess zu entfernen. Dies wird in Plugin-Architekturen verwendet, wenn ein Programm nicht vertrauenswürdige Bibliotheken laden muss. [...] Sobald ein Prozess die nicht vertrauenswürdige Bibliothek geladen hat, ist es nicht mehr effektiv, sich künftig auf die library validation zu verlassen.

Mit anderen Worten: **Jede Binary mit diesem Entitlement ist ein dylib-injection target**: Führe Code innerhalb der Binary aus (oder bringe sie dazu, dein Plug-in zu laden), nachdem sie `CS_REQUIRE_LV` entfernt hat, und du erbst alle Aktionen, zu denen der Host-Prozess berechtigt ist.

### `com.apple.security.cs.allow-dyld-environment-variables`

Dieses Entitlement erlaubt die **Verwendung von DYLD-Umgebungsvariablen**, die zum Injizieren von Bibliotheken und Code verwendet werden könnten. Weitere Informationen findest du [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` oder `com.apple.rootless.storage`.`TCC`

[**Laut diesem Blog**](https://objective-see.org/blog/blog_0x4C.html) **und** [**diesem Blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) erlauben diese Entitlements einem Prozess, die **TCC**-Datenbank zu **ändern**.<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** und **`system.install.apple-software.standar-user`**

Diese Entitlements erlauben einem Prozess, **Software zu installieren, ohne den Benutzer um Erlaubnis zu fragen**, was bei einer **Privilege Escalation** hilfreich sein kann.

### `com.apple.private.security.kext-management`

Entitlement, das erforderlich ist, um den **Kernel zum Laden einer Kernel-Erweiterung aufzufordern**.

### **`com.apple.private.icloud-account-access`**

Das Entitlement **`com.apple.private.icloud-account-access`** ermöglicht die Kommunikation mit dem **`com.apple.iCloudHelper`**-XPC-Service, der **iCloud-Tokens bereitstellt**.

**iMovie** und **Garageband** verfügten über dieses Entitlement.

Weitere **Informationen** über den Exploit zum **Abrufen von iCloud-Tokens** über dieses Entitlement findest du im Vortrag: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ich weiß nicht, was dies ermöglicht.

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Dieser Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) erwähnt, dass dieses Entitlement dazu verwendet werden könnte, nach einem Neustart durch SSV geschützte Inhalte zu aktualisieren. Wenn du weißt, wie, sende bitte einen PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**Derselbe Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) erwähnt, dass das Erstellen eines versiegelten Snapshots dazu verwendet werden könnte, nach einem Neustart durch SSV geschützte Inhalte zu aktualisieren. Wenn du weißt, wie, sende bitte einen PR!<sup>[[9]](#references)</sup>

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

Gewährt **Full Disk Access**-Berechtigungen, eine der höchsten TCC-Berechtigungsstufen, die man haben kann.

### **`kTCCServiceAppleEvents`**

Erlaubt der App, Events an andere Anwendungen zu senden, die häufig zur **Automatisierung von Aufgaben** verwendet werden. Durch die Kontrolle über andere Apps kann sie die diesen anderen Apps gewährten Berechtigungen missbrauchen.

Zum Beispiel, indem sie den Benutzer nach seinem Passwort fragen lassen:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Oder sie **beliebige Aktionen** ausführen zu lassen.

### **`kTCCServiceEndpointSecurityClient`**

Erlaubt unter anderem, die **TCC-Datenbank des Benutzers zu schreiben**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Erlaubt es, das Attribut **`NFSHomeDirectory`** eines Benutzers zu **ändern**, wodurch der Pfad seines Home-Ordners geändert wird und somit ein **TCC-Bypass** möglich ist.

### **`kTCCServiceSystemPolicyAppBundles`**

Erlaubt es, Dateien innerhalb von App-Bundles (innerhalb von app.app) zu ändern, was **standardmäßig untersagt** ist.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Es ist möglich, unter _Systemeinstellungen_ > _Datenschutz & Sicherheit_ > _App-Verwaltung_ zu überprüfen, wer diesen Zugriff besitzt.

### `kTCCServiceAccessibility`

Der Prozess kann die **macOS-Bedienungshilfen missbrauchen**, was beispielsweise bedeutet, dass er Tastenanschläge ausführen kann. Dadurch könnte er Zugriff zur Steuerung einer App wie Finder anfordern und den Dialog mit dieser Berechtigung bestätigen.

## Mit Trustcache/CDhash verbundene Entitlements

Es gibt einige Entitlements, die zum Umgehen von Trustcache/CDhash-Schutzmechanismen verwendet werden könnten, welche die Ausführung heruntergestufter Versionen von Apple-Binärdateien verhindern.

## Mittel

### `com.apple.security.cs.allow-jit`

Dieses Entitlement ermöglicht es einem Prozess, **beschreibbaren und ausführbaren Speicher zu erstellen**, indem das Flag `MAP_JIT` an die Systemfunktion `mmap()` übergeben wird. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Dieses Entitlement ermöglicht es, **C-Code zu überschreiben oder zu patchen**, das längst veraltete **`NSCreateObjectFileImageFromMemory`** zu verwenden (das grundsätzlich unsicher ist) oder das **DVDPlayback**-Framework zu verwenden. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Das Einbinden dieses Entitlements setzt Ihre App häufigen Schwachstellen in speicherunsicheren Programmiersprachen aus. Prüfen Sie sorgfältig, ob Ihre App diese Ausnahme benötigt.

### `com.apple.security.cs.disable-executable-page-protection`

Dieses Entitlement ermöglicht es, **Abschnitte der eigenen ausführbaren Dateien** auf dem Datenträger zu ändern, um das Programm zwangsweise zu beenden. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Das Disable Executable Memory Protection Entitlement ist ein extremes Entitlement, das einen grundlegenden Sicherheitsschutz Ihrer App entfernt und es einem Angreifer ermöglicht, den ausführbaren Code Ihrer App unbemerkt umzuschreiben. Verwenden Sie nach Möglichkeit eng gefasste Entitlements.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Dieses Entitlement ermöglicht das Einbinden eines nullfs-Dateisystems (standardmäßig untersagt). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Laut diesem Blogpost ist diese TCC-Berechtigung normalerweise in folgender Form zu finden:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Erlaubt dem Prozess, **alle TCC-Berechtigungen anzufordern**.

### **`kTCCServicePostEvent`**

Erlaubt das **Einschleusen synthetischer Tastatur- und Mausereignisse** systemweit über `CGEventPost()`. Ein Prozess mit dieser Berechtigung kann in jeder Anwendung Tastenanschläge, Mausklicks und Scroll-Ereignisse simulieren – und ermöglicht damit effektiv die **Fernsteuerung** des Desktops.

Dies ist besonders gefährlich in Kombination mit `kTCCServiceAccessibility` oder `kTCCServiceListenEvent`, da dadurch sowohl Eingaben gelesen als auch eingeschleust werden können.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Erlaubt das **Abfangen aller Tastatur- und Mausereignisse** systemweit (Input Monitoring / Keylogging). Ein Prozess kann einen `CGEventTap` registrieren, um jeden in einer beliebigen Anwendung eingegebenen Tastendruck abzufangen, einschließlich Passwörtern, Kreditkartennummern und privaten Nachrichten.

Detaillierte Exploitation-Techniken finden Sie unter:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Erlaubt das **Lesen des Display-Puffers** — das Erstellen von Screenshots und Aufzeichnen von Bildschirmvideos beliebiger Anwendungen, einschließlich sicherer Textfelder. In Kombination mit OCR lassen sich dadurch Passwörter und sensible Daten automatisch vom Bildschirm extrahieren.

> [!WARNING]
> Ab macOS Sonoma zeigt die Bildschirmaufnahme einen dauerhaft sichtbaren Indikator in der Menüleiste. In älteren Versionen kann die Bildschirmaufzeichnung vollständig unbemerkt erfolgen.

### **`kTCCServiceCamera`**

Erlaubt das **Aufnehmen von Fotos und Videos** über die integrierte Kamera oder angeschlossene USB-Kameras. Code Injection in eine Binary mit Kamera-Entitlement ermöglicht unbemerkte visuelle Überwachung.

### **`kTCCServiceMicrophone`**

Erlaubt das **Aufzeichnen von Audio** über alle Eingabegeräte. Hintergrund-Daemons mit Mikrofonzugriff ermöglichen eine dauerhafte Überwachung der Umgebungsgeräusche ohne sichtbares Anwendungsfenster.

### **`kTCCServiceLocation`**

Erlaubt das Abfragen des **physischen Standorts** des Geräts über WLAN-Triangulation oder Bluetooth-Beacons. Eine kontinuierliche Überwachung offenbart Wohn- und Arbeitsadressen, Reisemuster und tägliche Routinen.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Zugriff auf **Kontakte** (Namen, E-Mail-Adressen, Telefonnummern — nützlich für Spear-Phishing), **Kalender** (Besprechungspläne, Teilnehmerlisten) und **Fotos** (persönliche Fotos, Screenshots, die möglicherweise Zugangsdaten enthalten, sowie Standortmetadaten).

Vollständige Exploitation-Techniken zum Credential Theft über TCC-Berechtigungen finden Sie unter:

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
For detaillierte exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, siehe:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** ermöglichen es user-space driver binaries, direkt über IOKit-Schnittstellen mit dem Kernel zu kommunizieren. DriverKit-Binaries verwalten Hardware: USB, Thunderbolt, PCIe, HID-Geräte, Audio und Networking.

Die Kompromittierung eines DriverKit-Binaries ermöglicht:
- **Kernel attack surface** durch manipulierte `IOConnectCallMethod`-Aufrufe
- **USB device spoofing** (eine Tastatur für HID injection emulieren)
- **DMA attacks** über PCIe-/Thunderbolt-Schnittstellen
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Für eine detaillierte Ausnutzung von IOKit/DriverKit siehe:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*`-Operationen und `CLEAR_LV_ENTITLEMENT)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV`-Handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Entitlement für Debugging-Tools (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement zum Deaktivieren der Library Validation](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement zum Zulassen von DYLD-Umgebungsvariablen](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Umgehen von TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Musik abspielen und TCC umgehen, auch bekannt als CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: „Was auf deinem Mac passiert, bleibt in Apples iCloud?!“ – Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Der Albtraum von Apples OTA-Update: Umgehen der Signaturprüfung und Pwning des Kernels](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement zum Zulassen der Ausführung von JIT-kompiliertem Code (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement zum Zulassen von nicht signiertem ausführbarem Speicher](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement zum Deaktivieren des Schutzes ausführbarer Speicherseiten](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
{{#include ../../../banners/hacktricks-training.md}}
