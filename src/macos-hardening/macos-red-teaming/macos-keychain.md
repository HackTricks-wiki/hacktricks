# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Haupt-Keychains

- Der **Benutzer-Keychain** (`~/Library/Keychains/login.keychain-db`), der verwendet wird, um **benutzerspezifische Anmeldeinformationen** wie Anwendungskennwörter, Internetkennwörter, benutzergenerierte Zertifikate, Netzwerkkennwörter und benutzergenerierte öffentliche/private Schlüssel zu speichern.
- Der **System-Keychain** (`/Library/Keychains/System.keychain`), der **systemweite Anmeldeinformationen** wie WiFi-Kennwörter, Systemstammzertifikate, systemprivate Schlüssel und Systemanwendungskennwörter speichert.
- Es ist möglich, andere Komponenten wie Zertifikate in `/System/Library/Keychains/*` zu finden.
- In **iOS** gibt es nur einen **Keychain**, der sich in `/private/var/Keychains/` befindet. Dieser Ordner enthält auch Datenbanken für den `TrustStore`, Zertifizierungsstellen (`caissuercache`) und OSCP-Einträge (`ocspache`).
- Apps werden im Keychain nur auf ihren privaten Bereich basierend auf ihrer Anwendungskennung beschränkt.

### Passwort-Keychain-Zugriff

Diese Dateien, obwohl sie keinen inhärenten Schutz haben und **heruntergeladen** werden können, sind verschlüsselt und erfordern das **Klartextpasswort des Benutzers zur Entschlüsselung**. Ein Tool wie [**Chainbreaker**](https://github.com/n0fate/chainbreaker) könnte zur Entschlüsselung verwendet werden.

## Schutz der Keychain-Einträge

### ACLs

Jeder Eintrag im Keychain wird durch **Zugriffskontrolllisten (ACLs)** geregelt, die festlegen, wer verschiedene Aktionen auf dem Keychain-Eintrag ausführen kann, einschließlich:

- **ACLAuhtorizationExportClear**: Erlaubt dem Inhaber, den Klartext des Geheimnisses zu erhalten.
- **ACLAuhtorizationExportWrapped**: Erlaubt dem Inhaber, den Klartext, der mit einem anderen bereitgestellten Passwort verschlüsselt ist, zu erhalten.
- **ACLAuhtorizationAny**: Erlaubt dem Inhaber, jede Aktion auszuführen.

Die ACLs werden zusätzlich von einer **Liste vertrauenswürdiger Anwendungen** begleitet, die diese Aktionen ohne Aufforderung ausführen können. Dies könnte sein:

- **N`il`** (keine Autorisierung erforderlich, **jeder ist vertrauenswürdig**)
- Eine **leere** Liste (**niemand** ist vertrauenswürdig)
- **Liste** spezifischer **Anwendungen**.

Außerdem könnte der Eintrag den Schlüssel **`ACLAuthorizationPartitionID`** enthalten, der verwendet wird, um die **teamid, apple** und **cdhash** zu identifizieren.

- Wenn die **teamid** angegeben ist, muss die verwendete Anwendung, um den **Eintrag** ohne **Aufforderung** zu **zugreifen**, die **gleiche teamid** haben.
- Wenn **apple** angegeben ist, muss die App von **Apple** **signiert** sein.
- Wenn die **cdhash** angegeben ist, muss die **App** die spezifische **cdhash** haben.

### Erstellen eines Keychain-Eintrags

Wenn ein **neuer** **Eintrag** mit **`Keychain Access.app`** erstellt wird, gelten die folgenden Regeln:

- Alle Apps können verschlüsseln.
- **Keine Apps** können exportieren/entschlüsseln (ohne den Benutzer aufzufordern).
- Alle Apps können die Integritätsprüfung sehen.
- Keine Apps können ACLs ändern.
- Die **partitionID** wird auf **`apple`** gesetzt.

Wenn eine **Anwendung einen Eintrag im Keychain erstellt**, sind die Regeln etwas anders:

- Alle Apps können verschlüsseln.
- Nur die **erstellende Anwendung** (oder andere explizit hinzugefügte Apps) können exportieren/entschlüsseln (ohne den Benutzer aufzufordern).
- Alle Apps können die Integritätsprüfung sehen.
- Keine Apps können die ACLs ändern.
- Die **partitionID** wird auf **`teamid:[teamID hier]`** gesetzt.

## Zugriff auf den Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> Die **Aufzählung und das Dumping** von Geheimnissen, die **keine Eingabeaufforderung erzeugen**, kann mit dem Tool [**LockSmith**](https://github.com/its-a-feature/LockSmith) durchgeführt werden.
>
> Weitere API-Endpunkte finden Sie im Quellcode von [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Listen Sie die **Informationen** zu jedem Schlüsselbund-Eintrag mit dem **Security Framework** auf oder überprüfen Sie auch das Open-Source-CLI-Tool von Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Einige API-Beispiele:

- Die API **`SecItemCopyMatching`** gibt Informationen zu jedem Eintrag und es gibt einige Attribute, die Sie bei der Verwendung festlegen können:
- **`kSecReturnData`**: Wenn wahr, wird versucht, die Daten zu entschlüsseln (auf falsch setzen, um potenzielle Pop-ups zu vermeiden)
- **`kSecReturnRef`**: Auch Referenz auf den Schlüsselbund-Eintrag erhalten (auf wahr setzen, falls Sie später sehen, dass Sie ohne Pop-up entschlüsseln können)
- **`kSecReturnAttributes`**: Metadaten über Einträge erhalten
- **`kSecMatchLimit`**: Wie viele Ergebnisse zurückgegeben werden sollen
- **`kSecClass`**: Welche Art von Schlüsselbund-Eintrag

Erhalten Sie die **ACLs** jedes Eintrags:

- Mit der API **`SecAccessCopyACLList`** können Sie die **ACL für den Schlüsselbund-Eintrag** abrufen, und es wird eine Liste von ACLs zurückgegeben (wie `ACLAuhtorizationExportClear` und die zuvor genannten), wobei jede Liste hat:
- Beschreibung
- **Vertrauenswürdige Anwendungs-Liste**. Dies könnte sein:
- Eine App: /Applications/Slack.app
- Ein Binary: /usr/libexec/airportd
- Eine Gruppe: group://AirPort

Exportieren Sie die Daten:

- Die API **`SecKeychainItemCopyContent`** erhält den Klartext
- Die API **`SecItemExport`** exportiert die Schlüssel und Zertifikate, könnte jedoch erforderlich sein, Passwörter festzulegen, um den Inhalt verschlüsselt zu exportieren

Und dies sind die **Anforderungen**, um ein **Geheimnis ohne Eingabeaufforderung zu exportieren**:

- Wenn **1+ vertrauenswürdige** Apps aufgelistet sind:
- Benötigen Sie die entsprechenden **Berechtigungen** (**`Nil`**, oder Teil der erlaubten Liste von Apps in der Berechtigung zum Zugriff auf die geheimen Informationen sein)
- Benötigen Sie eine Codesignatur, die mit **PartitionID** übereinstimmt
- Benötigen Sie eine Codesignatur, die mit der eines **vertrauenswürdigen Apps** übereinstimmt (oder Mitglied der richtigen KeychainAccessGroup sein)
- Wenn **alle Anwendungen vertrauenswürdig** sind:
- Benötigen Sie die entsprechenden **Berechtigungen**
- Benötigen Sie eine Codesignatur, die mit **PartitionID** übereinstimmt
- Wenn **keine PartitionID**, dann ist dies nicht erforderlich

> [!CAUTION]
> Daher, wenn **1 Anwendung aufgelistet** ist, müssen Sie **Code in dieser Anwendung injizieren**.
>
> Wenn **apple** in der **partitionID** angegeben ist, könnten Sie darauf mit **`osascript`** zugreifen, sodass alles, was alle Anwendungen mit apple in der partitionID vertraut, darauf zugreifen kann. **`Python`** könnte auch dafür verwendet werden.

### Zwei zusätzliche Attribute

- **Unsichtbar**: Es ist ein boolesches Flag, um den Eintrag aus der **UI** Schlüsselbund-App **zu verbergen**
- **Allgemein**: Es dient zur Speicherung von **Metadaten** (es ist also NICHT VERSCHLÜSSELT)
- Microsoft speicherte alle Refresh-Token im Klartext, um auf sensible Endpunkte zuzugreifen.

## References

- [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
