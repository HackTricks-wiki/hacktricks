# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Haupt-Keychains

- Der **User Keychain** (`~/Library/Keychains/login.keychain-db`), in dem **benutzerspezifische Zugangsdaten** wie Anwendungspasswörter, Internetpasswörter, benutzergenerierte Zertifikate, Netzwerkpasswörter und benutzergenerierte öffentliche/private Schlüssel gespeichert werden.
- Der **System Keychain** (`/Library/Keychains/System.keychain`), in dem **systemweite Zugangsdaten** wie WiFi-Passwörter, System-Root-Zertifikate, private Systemschlüssel und System-Anwendungspasswörter gespeichert werden.<sup>[[1]](#references)</sup>
  - Weitere Komponenten wie Zertifikate finden sich unter `/System/Library/Keychains/*`.
- In **iOS** gibt es nur einen **Keychain**, der sich unter `/private/var/Keychains/` befindet. Dieser Ordner enthält außerdem Datenbanken für den `TrustStore`, Zertifizierungsstellen (`caissuercache`) und OSCP-Einträge (`ocspache`).
  - Apps sind im Keychain auf ihren privaten Bereich beschränkt, der anhand ihrer Anwendungskennung bestimmt wird.

### Zugriff auf den Password Keychain

Diese Dateien sind zwar nicht von sich aus geschützt und können **heruntergeladen** werden, sie sind jedoch verschlüsselt und zum Entschlüsseln ist das **Klartextpasswort des Benutzers erforderlich**. Ein Tool wie [**Chainbreaker**](https://github.com/n0fate/chainbreaker) kann zum Entschlüsseln verwendet werden.<sup>[[1]](#references)</sup>

## Schutz von Keychain-Einträgen

### ACLs

Jeder Eintrag im Keychain unterliegt **Access Control Lists (ACLs)**, die festlegen, wer verschiedene Aktionen für den Keychain-Eintrag ausführen darf, darunter:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Ermöglicht dem Inhaber, den Klartext des Geheimnisses abzurufen.
- **`kSecACLAuthorizationExportWrapped`**: Ermöglicht dem Inhaber, den Klartext verschlüsselt mit einem anderen bereitgestellten Passwort abzurufen.
- **`kSecACLAuthorizationAny`**: Ermöglicht dem Inhaber, beliebige Aktionen auszuführen.

Zusätzlich enthalten die ACLs eine **Liste vertrauenswürdiger Anwendungen**, die diese Aktionen ohne Rückfrage ausführen dürfen. Diese kann Folgendes sein:<sup>[[1]](#references)</sup>

- **N`il`** (keine Autorisierung erforderlich, **alle sind vertrauenswürdig**)
- Eine **leere** Liste (**niemand** ist vertrauenswürdig)
- Eine **Liste** bestimmter **Anwendungen**.

Der Eintrag kann außerdem den Schlüssel **`kSecACLAuthorizationPartitionID`** enthalten, der zur Identifizierung von **teamid, apple** und **cdhash** verwendet wird.<sup>[[1]](#references)[[2]](#references)</sup>

- Wenn **teamid** angegeben ist, muss die Anwendung dieselbe **teamid** haben, um auf den Wert des **Eintrags** **ohne** **Rückfrage** zuzugreifen.
- Wenn **apple** angegeben ist, muss die App von **Apple** **signiert** sein.
- Wenn **cdhash** angegeben ist, muss die **App** den spezifischen **cdhash** haben.

### Erstellen eines Keychain-Eintrags

Wenn ein **neuer** **Eintrag** mit **`Keychain Access.app`** erstellt wird, gelten die folgenden Regeln:<sup>[[1]](#references)</sup>

- Alle Apps können verschlüsseln.
- **Keine Apps** können exportieren/entschlüsseln (ohne Rückfrage beim Benutzer).
- Alle Apps können die Integritätsprüfung einsehen.
- Keine Apps können ACLs ändern.
- Die **partitionID** ist auf **`apple`** gesetzt.

Wenn eine **Anwendung einen Eintrag im Keychain erstellt**, gelten leicht abweichende Regeln:<sup>[[1]](#references)</sup>

- Alle Apps können verschlüsseln.
- Nur die **erstellende Anwendung** (oder andere ausdrücklich hinzugefügte Apps) kann exportieren/entschlüsseln (ohne Rückfrage beim Benutzer).
- Alle Apps können die Integritätsprüfung einsehen.
- Keine Apps können die ACLs ändern.
- Die **partitionID** ist auf **`teamid:[teamID here]`** gesetzt.

## Zugriff auf den Keychain

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

`-S` legt die Partition-Liste des Eintrags fest, während `-k` das aktuelle Keychain-Passwort angibt, das für diese Änderung erforderlich ist; das Flag zur Passwortübergabe ist veraltet.<sup>[[4]](#references)</sup> Eine erfolgreiche Aktualisierung beweist nicht, dass ein späterer Lesezugriff ohne Rückfrage erfolgt: Bei einem beobachteten, deaktivierten Prototyp wurde dennoch eine Bestätigungsabfrage ausgelöst, als er den Eintrag über `Security.framework` abfragte. Eine passende Partition-ID ist nur ein Teil der oben beschriebenen ACL- und Trusted-Application-Prüfungen. Überprüfen Sie daher den tatsächlichen Lesezugriff.<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> Die **Auflistung und das Auslesen von Secrets aus dem Keychain**, die **keine Rückfrage auslösen**, sind mit dem Tool [**LockSmith**](https://github.com/its-a-feature/LockSmith) möglich.
>
> Weitere API-Endpunkte finden Sie im Quellcode von [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Mit dem **Security Framework** können Sie jeden Keychain-Eintrag auflisten und **Informationen** darüber abrufen. Alternativ können Sie auch das Open-Source-CLI-Tool [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)** von Apple prüfen.** Beispiele für APIs:<sup>[[1]](#references)</sup>

- Die API **`SecItemCopyMatching`** liefert Informationen zu jedem Eintrag. Bei ihrer Verwendung können Sie verschiedene Attribute festlegen:
  - **`kSecReturnData`**: Bei true wird versucht, die Daten zu entschlüsseln (auf false setzen, um mögliche Pop-ups zu vermeiden)
  - **`kSecReturnRef`**: Ruft auch eine Referenz auf den Keychain-Eintrag ab (auf true setzen, falls Sie später feststellen, dass eine Entschlüsselung ohne Pop-up möglich ist)
  - **`kSecReturnAttributes`**: Ruft Metadaten zu den Einträgen ab
  - **`kSecMatchLimit`**: Anzahl der zurückzugebenden Ergebnisse
  - **`kSecClass`**: Art des Keychain-Eintrags

ACLs der einzelnen Einträge abrufen:<sup>[[1]](#references)</sup>

- Mit der API **`SecAccessCopyACLList`** können Sie die **ACL für den Keychain-Eintrag** abrufen. Sie gibt eine Liste von ACLs zurück (z. B. `kSecACLAuthorizationExportClear` und die anderen zuvor genannten), wobei jeder Eintrag Folgendes enthält:<sup>[[1]](#references)[[2]](#references)</sup>
  - Beschreibung
  - **Liste vertrauenswürdiger Anwendungen**. Dazu können gehören:
    - Eine App: /Applications/Slack.app
    - Eine Binärdatei: /usr/libexec/airportd
    - Eine Gruppe: group://AirPort

Daten exportieren:<sup>[[1]](#references)</sup>

- Die API **`SecKeychainItemCopyContent`** ruft den Klartext ab
- Die API **`SecItemExport`** exportiert Schlüssel und Zertifikate, möglicherweise müssen Sie jedoch Passwörter festlegen, um den Inhalt verschlüsselt zu exportieren

Dies sind die **Voraussetzungen**, um ein **Secret ohne Rückfrage exportieren** zu können:<sup>[[1]](#references)</sup>

- Wenn **mindestens eine vertrauenswürdige** App aufgeführt ist:
  - Die entsprechenden **Berechtigungen** sind erforderlich (**`Nil`** oder Mitglied der Liste der Apps, die zum Zugriff auf die vertraulichen Informationen berechtigt sind)
  - Die Codesignatur muss mit der **PartitionID** übereinstimmen
  - Die Codesignatur muss mit der einer **vertrauenswürdigen App** übereinstimmen (oder Sie müssen Mitglied der richtigen KeychainAccessGroup sein)
- Wenn **alle Anwendungen vertrauenswürdig** sind:
  - Die entsprechenden **Berechtigungen** sind erforderlich
  - Die Codesignatur muss mit der **PartitionID** übereinstimmen
    - Ist keine **PartitionID** vorhanden, ist dies nicht erforderlich

> [!CAUTION]
> Wenn also **eine Anwendung aufgeführt** ist, müssen Sie **Code in diese Anwendung injizieren**.
>
> Ist **apple** in der **partitionID** angegeben, können Sie mit **`osascript`** darauf zugreifen, wenn also allen Anwendungen vertraut wird und `apple` in der partitionID steht. Dafür kann auch **`Python`** verwendet werden.

### Zwei zusätzliche Attribute

- **Invisible**: Ein boolesches Flag, das den Eintrag in der **UI** der Keychain-App **ausblendet**<sup>[[1]](#references)</sup>
- **General**: Dient zum Speichern von **Metadaten** (ist also **NICHT VERSCHLÜSSELT**)<sup>[[1]](#references)</sup>
  - Microsoft speicherte alle Refresh-Tokens für den Zugriff auf einen sensiblen Endpunkt im Klartext.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [#OBTS v5.0: „Das macOS Keychain knacken“ – Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist – Eine neue Version des MacSync-macOS-Stealers nimmt Krypto-Enthusiasten und Entwickler ins Visier](https://securelist.com/macsync-new-version/121383/)
- [4] [Spiegel der Apple-manpage security(1)](https://keith.github.io/xcode-man-pages/security.1.html)
