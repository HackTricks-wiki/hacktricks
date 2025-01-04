# macOS Gefährliche Berechtigungen & TCC-Berechtigungen

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Beachten Sie, dass Berechtigungen, die mit **`com.apple`** beginnen, nicht für Dritte verfügbar sind, nur Apple kann sie gewähren.

## Hoch

### `com.apple.rootless.install.heritable`

Die Berechtigung **`com.apple.rootless.install.heritable`** ermöglicht es, **SIP zu umgehen**. Überprüfen Sie [dies für weitere Informationen](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Die Berechtigung **`com.apple.rootless.install`** ermöglicht es, **SIP zu umgehen**. Überprüfen Sie [dies für weitere Informationen](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (früher `task_for_pid-allow` genannt)**

Diese Berechtigung ermöglicht es, den **Task-Port für jeden** Prozess, außer dem Kernel, zu erhalten. Überprüfen Sie [**dies für weitere Informationen**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Diese Berechtigung ermöglicht es anderen Prozessen mit der Berechtigung **`com.apple.security.cs.debugger**, den Task-Port des Prozesses zu erhalten, der von der Binärdatei mit dieser Berechtigung ausgeführt wird, und **Code darauf zu injizieren**. Überprüfen Sie [**dies für weitere Informationen**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps mit der Debugging-Tool-Berechtigung können `task_for_pid()` aufrufen, um einen gültigen Task-Port für nicht signierte und Drittanbieter-Apps mit der Berechtigung `Get Task Allow`, die auf `true` gesetzt ist, abzurufen. Selbst mit der Debugging-Tool-Berechtigung kann ein Debugger jedoch **die Task-Ports** von Prozessen **nicht abrufen**, die **nicht die Berechtigung `Get Task Allow` haben** und daher durch die Systemintegritätsschutz geschützt sind. Überprüfen Sie [**dies für weitere Informationen**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Diese Berechtigung ermöglicht es, **Frameworks, Plug-ins oder Bibliotheken zu laden, ohne entweder von Apple signiert zu sein oder mit derselben Team-ID** wie die Hauptanwendung signiert zu sein, sodass ein Angreifer einige beliebige Bibliotheksladungen missbrauchen könnte, um Code zu injizieren. Überprüfen Sie [**dies für weitere Informationen**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Diese Berechtigung ist sehr ähnlich zu **`com.apple.security.cs.disable-library-validation`**, aber **anstatt** die Bibliotheksvalidierung **direkt zu deaktivieren**, ermöglicht sie dem Prozess, einen **`csops`-Systemaufruf zu tätigen, um sie zu deaktivieren**.\
Überprüfen Sie [**dies für weitere Informationen**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Diese Berechtigung ermöglicht es, **DYLD-Umgebungsvariablen** zu verwenden, die zum Injizieren von Bibliotheken und Code verwendet werden könnten. Überprüfen Sie [**dies für weitere Informationen**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` oder `com.apple.rootless.storage`.`TCC`

[**Laut diesem Blog**](https://objective-see.org/blog/blog_0x4C.html) **und** [**diesem Blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) ermöglichen diese Berechtigungen, die **TCC**-Datenbank zu **modifizieren**.

### **`system.install.apple-software`** und **`system.install.apple-software.standar-user`**

Diese Berechtigungen ermöglichen es, **Software zu installieren, ohne den Benutzer um Erlaubnis zu fragen**, was für eine **Privilegieneskalation** hilfreich sein kann.

### `com.apple.private.security.kext-management`

Berechtigung, die benötigt wird, um den **Kernel zu bitten, eine Kernel-Erweiterung zu laden**.

### **`com.apple.private.icloud-account-access`**

Mit der Berechtigung **`com.apple.private.icloud-account-access`** ist es möglich, mit dem **`com.apple.iCloudHelper`** XPC-Dienst zu kommunizieren, der **iCloud-Token** bereitstellt.

**iMovie** und **Garageband** hatten diese Berechtigung.

Für weitere **Informationen** über den Exploit, um **iCloud-Token** aus dieser Berechtigung zu erhalten, überprüfen Sie den Vortrag: [**#OBTS v5.0: "Was auf Ihrem Mac passiert, bleibt in Apples iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ich weiß nicht, was dies erlaubt.

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**diesem Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wird erwähnt, dass dies verwendet werden könnte, um** die SSV-geschützten Inhalte nach einem Neustart zu aktualisieren. Wenn Sie wissen, wie, senden Sie bitte einen PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**diesem Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wird erwähnt, dass dies verwendet werden könnte, um** die SSV-geschützten Inhalte nach einem Neustart zu aktualisieren. Wenn Sie wissen, wie, senden Sie bitte einen PR!

### `keychain-access-groups`

Diese Berechtigung listet die **Keychain**-Gruppen auf, auf die die Anwendung Zugriff hat:
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

Gibt **Vollzugriff auf die Festplatte**-Berechtigungen, eine der höchsten TCC-Berechtigungen, die man haben kann.

### **`kTCCServiceAppleEvents`**

Erlaubt der App, Ereignisse an andere Anwendungen zu senden, die häufig zum **Automatisieren von Aufgaben** verwendet werden. Durch die Kontrolle anderer Apps kann es die Berechtigungen missbrauchen, die diesen anderen Apps gewährt wurden.

Wie zum Beispiel, sie dazu zu bringen, den Benutzer nach seinem Passwort zu fragen:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Oder sie dazu bringen, **willkürliche Aktionen** auszuführen.

### **`kTCCServiceEndpointSecurityClient`**

Erlaubt unter anderem, die **TCC-Datenbank der Benutzer** zu **schreiben**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Erlaubt es, das **`NFSHomeDirectory`**-Attribut eines Benutzers zu **ändern**, was seinen Home-Ordner-Pfad ändert und somit das **Umgehen von TCC** ermöglicht.

### **`kTCCServiceSystemPolicyAppBundles`**

Erlaubt das Modifizieren von Dateien innerhalb von App-Bundles (innerhalb von app.app), was **standardmäßig nicht erlaubt** ist.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Es ist möglich zu überprüfen, wer diesen Zugriff hat in _Systemeinstellungen_ > _Datenschutz & Sicherheit_ > _App-Verwaltung._

### `kTCCServiceAccessibility`

Der Prozess wird in der Lage sein, die **Zugänglichkeitsfunktionen von macOS** zu **missbrauchen**, was bedeutet, dass er beispielsweise Tastenanschläge drücken kann. Er könnte also Zugriff anfordern, um eine App wie Finder zu steuern und den Dialog mit dieser Berechtigung zu genehmigen.

## Mittel

### `com.apple.security.cs.allow-jit`

Diese Berechtigung erlaubt es, **speicher zu erstellen, der beschreibbar und ausführbar ist**, indem das `MAP_JIT`-Flag an die `mmap()`-Systemfunktion übergeben wird. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Diese Berechtigung erlaubt es, **C-Code zu überschreiben oder zu patchen**, die lange veraltete **`NSCreateObjectFileImageFromMemory`** (die grundsätzlich unsicher ist) zu verwenden oder das **DVDPlayback**-Framework zu nutzen. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Das Einfügen dieser Berechtigung setzt Ihre App gängigen Sicherheitsanfälligkeiten in speicherunsicheren Programmiersprachen aus. Überlegen Sie sorgfältig, ob Ihre App diese Ausnahme benötigt.

### `com.apple.security.cs.disable-executable-page-protection`

Diese Berechtigung erlaubt es, **Abschnitte seiner eigenen ausführbaren Dateien** auf der Festplatte zu **modifizieren**, um gewaltsam zu beenden. Weitere Informationen finden Sie [**hier**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Die Berechtigung zum Deaktivieren des Schutzes für ausführbaren Speicher ist eine extreme Berechtigung, die einen grundlegenden Sicherheitschutz Ihrer App entfernt, wodurch es einem Angreifer möglich wird, den ausführbaren Code Ihrer App unbemerkt umzuschreiben. Bevorzugen Sie, wenn möglich, engere Berechtigungen.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Diese Berechtigung erlaubt es, ein nullfs-Dateisystem zu mounten (standardmäßig verboten). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Laut diesem Blogbeitrag wird diese TCC-Berechtigung normalerweise in folgender Form gefunden:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Erlaube dem Prozess, **nach allen TCC-Berechtigungen zu fragen**.

### **`kTCCServicePostEvent`**

{{#include ../../../banners/hacktricks-training.md}}

</details>
