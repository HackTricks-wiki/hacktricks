# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- Der **User Keychain** (`~/Library/Keychains/login.keychain-db`) wird zum Speichern **benutzerspezifischer Anmeldedaten** wie Anwendungspasswörtern, Internetpasswörtern, benutzergenerierten Zertifikaten, Netzwerkpasswörtern und benutzergenerierten öffentlichen/privaten Schlüsseln verwendet.
- Der **System Keychain** (`/Library/Keychains/System.keychain`) speichert **systemweite Anmeldedaten** wie WiFi-Passwörter, System-Root-Zertifikate, private Systemschlüssel und System-Anwendungspasswörter.<sup>[[1]](#references)</sup>
  - Weitere Komponenten wie Zertifikate sind unter `/System/Library/Keychains/*` zu finden.
- Der **data protection keychain** pro Benutzer erscheint in Keychain Access als **Local Items** oder **iCloud**. Er ist von `login.keychain-db` getrennt und enthält sowohl ausschließlich lokale als auch synchronisierbare Einträge. `security` ist hauptsächlich ein dateibasierte-Keychain-Tool; ein kurzes Ergebnis von `dump-keychain` schließt Anmeldedaten an diesem Ort daher nicht aus.<sup>[[5]](#references)</sup>
- In **iOS** gibt es nur einen **Keychain**, der sich unter `/private/var/Keychains/` befindet. Dieser Ordner enthält auch Datenbanken für den `TrustStore`, Zertifizierungsstellen (`caissuercache`) und OSCP-Einträge (`ocspache`).
  - Apps sind im Keychain auf ihren privaten Bereich beschränkt, der anhand ihrer Anwendungskennung bestimmt wird.

### Password Keychain Access

Ein kopierter **dateibasierter** Keychain liegt nicht im Klartext vor. Für die Offline-Entschlüsselung seiner geschützten Einträge ist das Keychain-Passwort oder gleichwertiges Schlüsselmaterial erforderlich; [**Chainbreaker**](https://github.com/n0fate/chainbreaker) unterstützt dieses Format.<sup>[[1]](#references)</sup> Dies unterscheidet sich vom Live-Lesen in einer entsperrten Benutzersitzung, bei dem Zugriffskontrollen für Einträge das Lesen erlauben oder eine Eingabeaufforderung auslösen können, ohne dass das Anmeldepasswort erneut eingegeben werden muss. Der data protection keychain verwendet ein anderes Schutz- und Access-Group-Modell.<sup>[[5]](#references)</sup>

## Keychain Entries Protections

### ACLs dateibasierter Keychains

Die nachfolgenden `SecAccess`-ACL- und Partition-List-Regeln beschreiben **dateibasierte** Keychains. Für Einträge im data protection keychain werden stattdessen Code-Signing-Access-Groups und optionale `SecAccessControl`-Bedingungen verwendet; aus einem ACL-Dump eines dateibasierten Keychains lässt sich nicht auf deren Zugänglichkeit schließen.<sup>[[5]](#references)</sup>

Jeder Eintrag in einem dateibasierten Keychain wird durch **Access Control Lists (ACLs)** geregelt, die festlegen, wer verschiedene Aktionen für den Keychain-Eintrag ausführen darf, darunter:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Ermöglicht dem Inhaber, den Klartext des Geheimnisses abzurufen.
- **`kSecACLAuthorizationExportWrapped`**: Ermöglicht dem Inhaber, den Klartext verschlüsselt mit einem anderen angegebenen Passwort abzurufen.
- **`kSecACLAuthorizationAny`**: Ermöglicht dem Inhaber, beliebige Aktionen auszuführen.

Zu den ACLs gehört außerdem eine **Liste vertrauenswürdiger Anwendungen**, die diese Aktionen ohne Eingabeaufforderung ausführen dürfen. Diese Liste kann Folgendes enthalten:<sup>[[1]](#references)</sup>

- **N`il`** (keine Autorisierung erforderlich, **alle sind vertrauenswürdig**)
- Eine **leere** Liste (**niemand** ist vertrauenswürdig)
- Eine **Liste** bestimmter **Anwendungen**.

Der Eintrag kann außerdem den Schlüssel **`kSecACLAuthorizationPartitionID`** enthalten, der zur Identifizierung von **teamid, apple** und **cdhash** dient.<sup>[[1]](#references)[[2]](#references)</sup>

- Wenn **teamid** angegeben ist, muss die Anwendung dieselbe **teamid** haben, um ohne **Eingabeaufforderung** auf den Wert des **Eintrags** zuzugreifen.
- Wenn **apple** angegeben ist, muss die App von **Apple** **signiert** sein.
- Wenn **cdhash** angegeben ist, muss die **App** den entsprechenden **cdhash** haben.

### Erstellen eines dateibasierten Keychain-Eintrags

Wenn mit **`Keychain Access.app`** ein **neuer** **Eintrag** erstellt wird, gelten die folgenden Regeln:<sup>[[1]](#references)</sup>

- Alle Apps können verschlüsseln.
- **Keine Apps** können exportieren/entschlüsseln (ohne den Benutzer dazu aufzufordern).
- Alle Apps können die Integritätsprüfung sehen.
- Keine Apps können ACLs ändern.
- Die **partitionID** wird auf **`apple`** gesetzt.

Wenn eine **Anwendung einen Eintrag im Keychain erstellt**, gelten etwas andere Regeln:<sup>[[1]](#references)</sup>

- Alle Apps können verschlüsseln.
- Nur die **erstellende Anwendung** (oder andere ausdrücklich hinzugefügte Apps) kann exportieren/entschlüsseln (ohne den Benutzer dazu aufzufordern).
- Alle Apps können die Integritätsprüfung sehen.
- Keine Apps können die ACLs ändern.
- Die **partitionID** wird auf **`teamid:[teamID here]`** gesetzt.

## Accessing the Keychain

### `security`

```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entry's PartitionID value
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` legt die Partition-Liste des Eintrags fest, während `-k` das aktuelle Keychain-Passwort angibt, das für diese Änderung erforderlich ist; das Flag zur Passwortübergabe ist veraltet.<sup>[[4]](#references)</sup> Eine erfolgreiche Aktualisierung beweist nicht, dass ein späterer Lesezugriff ohne Rückfrage erfolgt: Bei einem beobachteten, deaktivierten Prototyp wurde dennoch eine Bestätigungsaufforderung ausgelöst, als er den Eintrag über `Security.framework` abfragte. Eine passende Partition-ID ist nur ein Teil der oben beschriebenen ACL- und Trusted-Application-Prüfungen. Überprüfe daher den tatsächlichen Lesezugriff.<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> Die **Auflistung und das Auslesen von Secrets aus dem Keychain, ohne eine Rückfrage auszulösen**, sind mit dem Tool [**LockSmith**](https://github.com/its-a-feature/LockSmith) möglich.
>
> Weitere API-Endpunkte findest du im Quellcode von [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Mit dem **Security Framework** kannst du **Informationen** zu jedem Keychain-Eintrag auflisten und abrufen. Alternativ kannst du auch das Open-Source-CLI-Tool [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)** von Apple verwenden.** Beispiele für APIs:<sup>[[1]](#references)</sup>

- Die API **`SecItemCopyMatching`** liefert Informationen zu jedem Eintrag. Bei ihrer Verwendung lassen sich einige Attribute festlegen:
  - **`kSecReturnData`**: Wenn der Wert true ist, wird versucht, die Daten zu entschlüsseln (auf false setzen, um mögliche Pop-ups zu vermeiden)
  - **`kSecReturnRef`**: Ruft eine Objektreferenz für einen Schlüssel, ein Zertifikat oder eine Identität ab; Passworteinträge haben keine solche Objektrepräsentation. Verwende `kSecReturnPersistentRef`, um ein Passwort für eine spätere, gezielte Abfrage zu identifizieren.<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`**: Ruft Metadaten zu Einträgen ab
  - **`kSecMatchLimit`**: Legt fest, wie viele Ergebnisse zurückgegeben werden
  - **`kSecClass`**: Legt fest, um welche Art von Keychain-Eintrag es sich handelt

**ACLs** für jeden Eintrag abrufen:<sup>[[1]](#references)</sup>

- Mit der API **`SecAccessCopyACLList`** kannst du die **ACL des Keychain-Eintrags** abrufen. Sie gibt eine Liste von ACLs zurück (z. B. `kSecACLAuthorizationExportClear` und die anderen zuvor genannten), wobei jeder Eintrag Folgendes enthält:<sup>[[1]](#references)[[2]](#references)</sup>
  - Beschreibung
  - **Trusted Application List**. Diese kann Folgendes enthalten:
    - Eine App: /Applications/Slack.app
    - Ein Binary: /usr/libexec/airportd
    - Eine Gruppe: group://AirPort

Daten exportieren:<sup>[[1]](#references)</sup>

- Die API **`SecKeychainItemCopyContent`** ruft den Klartext ab
- Die API **`SecItemExport`** exportiert Schlüssel und Zertifikate; möglicherweise müssen Passwörter festgelegt werden, um den Inhalt verschlüsselt zu exportieren

Dies sind die **Voraussetzungen**, um ein **Secret ohne Rückfrage exportieren** zu können:<sup>[[1]](#references)</sup>

- Wenn **mindestens eine Trusted App** aufgeführt ist:
  - Die entsprechenden **Berechtigungen** sind erforderlich (**`Nil`** oder die Zugehörigkeit zur Liste der Apps, die laut Berechtigung auf die Secret-Informationen zugreifen dürfen)
  - Die Codesignatur muss mit der **PartitionID** übereinstimmen
  - Die Codesignatur muss mit der einer **Trusted App** übereinstimmen (oder du musst Mitglied der richtigen KeychainAccessGroup sein)
- Wenn **alle Anwendungen vertrauenswürdig** sind:
  - Die entsprechenden **Berechtigungen** sind erforderlich
  - Die Codesignatur muss mit der **PartitionID** übereinstimmen
    - Wenn keine **PartitionID** vorhanden ist, ist dies nicht erforderlich

> [!CAUTION]
> Wenn also **eine Anwendung aufgeführt** ist, musst du **Code in diese Anwendung injizieren**.
>
> Wenn in der **partitionID** **apple** angegeben ist, kannst du mit **`osascript`** darauf zugreifen. Das gilt also für alles, was allen Anwendungen vertraut, sofern **apple** in der partitionID steht. Dafür lässt sich auch **`Python`** verwenden.

### Zwei zusätzliche Attribute

- **Invisible**: Ein boolesches Flag, um den Eintrag in der **UI** der Keychain-App **auszublenden**<sup>[[1]](#references)</sup>
- **General**: Dient zum Speichern von **Metadaten** (diese sind also NICHT VERSCHLÜSSELT)<sup>[[1]](#references)</sup>
  - Microsoft speicherte alle Refresh-Tokens für den Zugriff auf sensible Endpunkte im Klartext.<sup>[[1]](#references)</sup>

### Data-Protection-Keychain: Einträge auflisten, dann einen Eintrag abfragen

Führe `SecItemCopyMatching` in einer **signierten App im Login-Kontext des Zielbenutzers** mit `kSecUseDataProtectionKeychain: true` aus. Gehe nicht davon aus, dass `security dump-keychain` oder eine SecItem-Abfrage mit Standardeinstellungen diesen Speicher durchsucht hat. Der aufrufende Prozess sieht nur seine autorisierten Access Groups.<sup>[[5]](#references)</sup>

Wenn der Testcode in einem anderen Prozess ausgeführt wird, richtet sich sein Zugriff auf die Data-Protection-Keychain nach den Berechtigungen der Host-Executable. Prüfe die tatsächlichen signierten Berechtigungen mit `codesign -d --entitlements - /path/to/Target.app` und beachte [macOS-Code-Signing-Berechtigungen](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md) für verwandte Prüfungen.<sup>[[7]](#references)</sup>

Fordere zunächst **nur Attribute** für eine Entry-Klasse an. `kSecAttrSynchronizableAny` berücksichtigt sowohl lokale als auch iCloud-synchronisierbare Treffer; wenn du es weglässt, werden synchronisierbare Einträge ausgeschlossen.<sup>[[8]](#references)</sup> `kSecUseAuthenticationUISkip` verhindert die Anzeige der Authentifizierungsoberfläche während einer umfassenden Auflistung, überspringt dafür aber geschützte Treffer.<sup>[[9]](#references)</sup> Wiederhole die Abfrage bei Bedarf mit `kSecClassInternetPassword`.

```swift
import Security
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
]
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
print(status)
if status == errSecSuccess, let items = result as? [[String: Any]] {
    for item in items { print(item) }
}
```

Für einen zulässigen geheimen Lesezugriff erstellen Sie eine **neue**, eng gefasste Abfrage für das ausgewählte Element (z. B. Klasse, Service und Account), setzen Sie `kSecReturnData: true` und `kSecMatchLimit: kSecMatchLimitOne` und rechnen Sie mit einer elementspezifischen Authentifizierung oder einem Fehler. Kombinieren Sie `kSecReturnData` bei Passwortelementen **nicht** mit `kSecMatchLimitAll`.<sup>[[10]](#references)</sup> Das Ergebnis `errSecItemNotFound` kann auch auf einen falschen Speicher, einen Synchronisierungsfilter oder eine fehlende Access-Group-Berechtigung zurückzuführen sein und muss nicht bedeuten, dass keine Anmeldedaten vorhanden sind.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0: „Das macOS Keychain knacken“ – Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist – Eine neue Version des macOS-Stealers MacSync zielt auf Krypto-Enthusiasten und Entwickler ab](https://securelist.com/macsync-new-version/121383/)
- [4] [Spiegelung der Apple-security(1)-Manpage](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — Zu APIs und Implementierungen des Mac Keychain](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Apple Developer Forums — SecItem: Grundlagen](https://developer.apple.com/forums/thread/724023)
- [7] [Apple Developer Forums — SecItem: Fallstricke und Best Practices](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — Zugriff auf Keychain-Elemente mit Face ID oder Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
