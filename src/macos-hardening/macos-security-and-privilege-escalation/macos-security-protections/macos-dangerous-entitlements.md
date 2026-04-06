# macOS Gefährliche Entitlements & TCC-Berechtigungen

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Beachte, dass Entitlements, die mit **`com.apple`** beginnen, Drittanbietern nicht zur Verfügung stehen — nur Apple kann sie vergeben... Oder wenn du ein enterprise certificate verwendest, könntest du tatsächlich eigene Entitlements erstellen, die mit **`com.apple`** beginnen, und dadurch Schutzmechanismen umgehen.

## Hoch

### `com.apple.rootless.install.heritable`

Das Entitlement **`com.apple.rootless.install.heritable`** ermöglicht, **SIP zu umgehen**. Check [this for more info](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Das Entitlement **`com.apple.rootless.install`** ermöglicht, **SIP zu umgehen**. Check[ this for more info](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Dieses Entitlement erlaubt, den **task port für jeden** Prozess zu bekommen, außer für den Kernel. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Dieses Entitlement erlaubt anderen Prozessen mit dem **`com.apple.security.cs.debugger`** Entitlement, den task port des Prozesses zu erhalten, der vom Binary mit diesem Entitlement ausgeführt wird, und **Code hineinzuspritzen**. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps mit dem Debugging Tool Entitlement können `task_for_pid()` aufrufen, um einen gültigen task port für unsignierte und Drittanbieter-Apps mit dem `Get Task Allow` Entitlement, das auf `true` gesetzt ist, zu erhalten. Allerdings kann ein Debugger selbst mit dem Debugging Tool Entitlement **nicht** die task ports von Prozessen erhalten, die **nicht** das `Get Task Allow` Entitlement haben und daher durch System Integrity Protection geschützt sind. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Dieses Entitlement erlaubt, **Frameworks, Plug-ins oder Libraries zu laden, ohne entweder von Apple signiert zu sein oder mit derselben Team ID** wie das Haupt-Executable signiert zu sein, sodass ein Angreifer das Laden einer beliebigen Library ausnutzen könnte, um Code zu injizieren. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Dieses Entitlement ist sehr ähnlich zu **`com.apple.security.cs.disable-library-validation`**, aber **anstatt die Library-Validierung direkt zu deaktivieren**, erlaubt es dem Prozess, einen `csops` Systemaufruf zu tätigen, um diese zu deaktivieren.\
Check [**this for more info**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Dieses Entitlement erlaubt die **Verwendung von DYLD-Umgebungsvariablen**, die genutzt werden könnten, um Libraries und Code zu injizieren. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**According to this blog**](https://objective-see.org/blog/blog_0x4C.html) **and** [**this blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), diese Entitlements erlauben, die **TCC** Datenbank zu **modifizieren**.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

Diese Entitlements erlauben, **Software zu installieren, ohne den Benutzer um Erlaubnis zu fragen**, was bei einer **Privilege Escalation** hilfreich sein kann.

### `com.apple.private.security.kext-management`

Entitlement, das benötigt wird, um den **Kernel zu bitten, eine Kernel Extension zu laden**.

### **`com.apple.private.icloud-account-access`**

Mit dem Entitlement **`com.apple.private.icloud-account-access`** ist es möglich, mit dem XPC-Service **`com.apple.iCloudHelper`** zu kommunizieren, der **iCloud tokens** bereitstellt.

**iMovie** und **Garageband** hatten dieses Entitlement.

Für mehr **Informationen** über den Exploit, um **iCloud tokens** aus diesem Entitlement zu erhalten, siehe den Talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ich weiß nicht, was das erlauben soll

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wird erwähnt, dass dies verwendet werden könnte, um** die SSV-geschützten Inhalte nach einem Reboot zu aktualisieren. Wenn du weißt, wie, sende bitte einen PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wird erwähnt, dass dies verwendet werden könnte, um** die SSV-geschützten Inhalte nach einem Reboot zu aktualisieren. Wenn du weißt, wie, sende bitte einen PR!

### `keychain-access-groups`

Dieses Entitlement listet die **keychain** Gruppen auf, auf die die Anwendung Zugriff hat:
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

Gewährt die Berechtigung **Full Disk Access**, eine der höchsten TCC-Berechtigungen, die man haben kann.

### **`kTCCServiceAppleEvents`**

Ermöglicht der App, Events an andere Anwendungen zu senden, die häufig zur **Automatisierung von Aufgaben** verwendet werden. Indem sie andere Apps kontrolliert, kann sie die diesen Apps gewährten Berechtigungen missbrauchen.

Zum Beispiel kann sie diese dazu bringen, den Benutzer nach dessen Passwort zu fragen:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Oder sie dazu zu bringen, **beliebige Aktionen** auszuführen.

### **`kTCCServiceEndpointSecurityClient`**

Erlaubt unter anderem, die **TCC-Datenbank des Benutzers zu schreiben**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Ermöglicht, das **`NFSHomeDirectory`**-Attribut eines Benutzers zu **ändern**, wodurch dessen Home-Ordner-Pfad verändert wird und somit ein **Umgehen von TCC** ermöglicht wird.

### **`kTCCServiceSystemPolicyAppBundles`**

Erlaubt das Ändern von Dateien innerhalb des App-Bundles (innerhalb von app.app), was standardmäßig **nicht erlaubt** ist.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Es ist möglich zu prüfen, wer diesen Zugriff hat in _Systemeinstellungen_ > _Datenschutz & Sicherheit_ > _App-Verwaltung_.

### `kTCCServiceAccessibility`

Der Prozess kann die **macOS-Accessibility-Funktionen missbrauchen**, was bedeutet, dass er beispielsweise Tastatureingaben auslösen kann. Somit könnte er Zugriffsrechte anfordern, um eine App wie Finder zu steuern und mit dieser Berechtigung den Dialog zu bestätigen.

## Trustcache/CDhash-bezogene Entitlements

Es gibt einige Entitlements, die verwendet werden könnten, um Trustcache/CDhash-Schutzmechanismen zu umgehen, welche die Ausführung zurückgestufter Versionen von Apple-Binaries verhindern.

## Mittel

### `com.apple.security.cs.allow-jit`

Dieses Entitlement erlaubt es, **Speicher zu erzeugen, der beschreibbar und ausführbar ist**, indem das `MAP_JIT`-Flag an die Systemfunktion `mmap()` übergeben wird. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Dieses Entitlement erlaubt es, C-Code zu **überschreiben oder zu patchen**, die längst veraltete **`NSCreateObjectFileImageFromMemory`** zu verwenden (welche grundsätzlich unsicher ist), oder das **DVDPlayback**-Framework zu nutzen. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Die Aufnahme dieses Entitlements setzt Ihre App gängigen Schwachstellen in speicherunsicheren Programmiersprachen aus. Überlegen Sie sorgfältig, ob Ihre App diese Ausnahme benötigt.

### `com.apple.security.cs.disable-executable-page-protection`

Dieses Entitlement erlaubt es, **Abschnitte seiner eigenen ausführbaren Dateien** auf dem Datenträger zu **modifizieren**, um zwangsweise Änderungen vorzunehmen. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Das Disable Executable Memory Protection Entitlement ist ein extremes Entitlement, das einen grundlegenden Sicherheitsmechanismus aus Ihrer App entfernt und es einem Angreifer ermöglicht, den ausführbaren Code Ihrer App unbemerkt umzuschreiben. Verwenden Sie, wenn möglich, engere Entitlements.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Dieses Entitlement erlaubt das Einhängen eines nullfs-Dateisystems (standardmäßig verboten). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Laut diesem Blogpost wird diese TCC-Berechtigung üblicherweise in folgender Form gefunden:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Ermöglicht dem Prozess, **alle TCC-Berechtigungen anzufordern**.

### **`kTCCServicePostEvent`**

Ermöglicht das **Einschleusen synthetischer Tastatur- und Maus-Events** systemweit über `CGEventPost()`. Ein Prozess mit dieser Berechtigung kann Tastenanschläge, Mausklicks und Scroll-Ereignisse in jeder Anwendung simulieren — und damit effektiv die **Fernsteuerung** des Desktops ermöglichen.

Das ist besonders gefährlich in Kombination mit `kTCCServiceAccessibility` oder `kTCCServiceListenEvent`, da es sowohl das Lesen als auch das Einschleusen von Eingaben erlaubt.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Ermöglicht das Abfangen aller Tastatur- und Mausereignisse systemweit (input monitoring / keylogging). Ein Prozess kann einen `CGEventTap` registrieren, um jede in einer Anwendung getippte Taste zu erfassen, einschließlich Passwörter, Kreditkartennummern und private Nachrichten.

Für detaillierte Exploitation-Techniken siehe:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Ermöglicht das Lesen des Anzeige-Puffers — das Erstellen von Screenshots und das Aufzeichnen von Bildschirmvideos beliebiger Anwendungen, einschließlich sicherer Textfelder. In Kombination mit OCR kann dies automatisch Passwörter und sensible Daten vom Bildschirm extrahieren.

> [!WARNING]
> Seit macOS Sonoma zeigt die Bildschirmaufnahme einen dauerhaften Menüleistenindikator. Bei älteren Versionen kann die Bildschirmaufnahme vollständig still erfolgen.

### **`kTCCServiceCamera`**

Ermöglicht das Aufnehmen von Fotos und Videos mit der integrierten Kamera oder angeschlossenen USB-Kameras. Code injection into a camera-entitled binary enables silent visual surveillance.

### **`kTCCServiceMicrophone`**

Ermöglicht das Aufnehmen von Audio von allen Eingabegeräten. Hintergrunddaemons mit mic access bieten persistente Ambient-Audioüberwachung ohne sichtbares Anwendungsfenster.

### **`kTCCServiceLocation`**

Ermöglicht das Abfragen des physischen Standorts des Geräts via Wi‑Fi-Triangulation oder Bluetooth-Beacons. Kontinuierliche Überwachung offenbart Wohn-/Arbeitsadressen, Reisemuster und tägliche Routinen.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Zugriff auf **Contacts** (Namen, E‑Mails, Telefonnummern — nützlich für spear-phishing), **Calendar** (Meetingpläne, Teilnehmerlisten) und **Photos** (private Fotos, Screenshots, die Anmeldeinformationen oder Standortmetadaten enthalten können).

Für vollständige Exploitation-Techniken zum Credential-Diebstahl über TCC-Berechtigungen, siehe:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox- & Code-Signing-Berechtigungen

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** schwächen die App Sandbox, indem sie die Kommunikation mit systemweiten Mach/XPC-Services erlauben, die von der Sandbox normalerweise blockiert werden. Dies ist das **primary sandbox escape primitive** — eine kompromittierte sandboxed App kann mach-lookup-Ausnahmen verwenden, um privilegierte Daemons zu erreichen und deren XPC-Schnittstellen auszunutzen.
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

DriverKit entitlements erlauben user-space driver binaries, direkt über IOKit-Schnittstellen mit dem kernel zu kommunizieren. DriverKit binaries verwalten Hardware: USB, Thunderbolt, PCIe, HID-Geräte, Audio und Netzwerk.

Compromising a DriverKit binary enables:
- **Kernel attack surface** durch fehlerhafte `IOConnectCallMethod`-Aufrufe
- **USB device spoofing** (Tastatur emulieren für HID injection)
- **DMA attacks** über PCIe/Thunderbolt-Schnittstellen
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Für detaillierte IOKit/DriverKit exploitation, siehe:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}



{{#include ../../../banners/hacktricks-training.md}}
