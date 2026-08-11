# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- Der **Benutzer-Schlüsselbund** (`~/Library/Keychains/login.keychain-db`), der zum Speichern **benutzerspezifischer Anmeldedaten** wie Anwendungskennwörtern, Internetkennwörtern, benutzergenerierten Zertifikaten, Netzwerkkennwörtern sowie benutzergenerierten öffentlichen/privaten Schlüsseln verwendet wird.
- Der **System-Schlüsselbund** (`/Library/Keychains/System.keychain`), der **systemweite Anmeldedaten** wie WiFi-Kennwörter, Systemstammzertifikate, private Systemschlüssel und Kennwörter von Systemanwendungen speichert.<sup>[[1]](#references)</sup>
- Es ist möglich, weitere Komponenten wie Zertifikate in `/System/Library/Keychains/*` zu finden.
- In **iOS** gibt es nur einen **Schlüsselbund**, der sich in `/private/var/Keychains/` befindet. Dieser Ordner enthält außerdem Datenbanken für den `TrustStore`, Zertifizierungsstellen (`caissuercache`) und OSCP-Einträge (`ocspache`).
- Apps sind im Schlüsselbund anhand ihrer Anwendungskennung auf ihren privaten Bereich beschränkt.

### Password Keychain Access

Diese Dateien verfügen zwar über keinen inhärenten Schutz und können **heruntergeladen** werden, sind jedoch verschlüsselt und erfordern das **Klartextkennwort des Benutzers, um entschlüsselt zu werden**. Ein Tool wie [**Chainbreaker**](https://github.com/n0fate/chainbreaker) kann zur Entschlüsselung verwendet werden.<sup>[[1]](#references)</sup>

## Keychain Entries Protections

### ACLs

Jeder Eintrag im Schlüsselbund wird durch **Access Control Lists (ACLs)** gesteuert, die festlegen, wer verschiedene Aktionen für den Schlüsselbund-Eintrag ausführen darf, einschließlich:<sup>[[1]](#references)</sup>

- **ACLAuthorizationExportClear**: Ermöglicht dem Inhaber, den Klartext des Geheimnisses abzurufen.
- **ACLAuthorizationExportWrapped**: Ermöglicht dem Inhaber, den Klartext mit einem anderen bereitgestellten Kennwort verschlüsselt abzurufen.
- **ACLAuthorizationAny**: Ermöglicht dem Inhaber, jede Aktion auszuführen.

Die ACLs werden außerdem von einer **Liste vertrauenswürdiger Anwendungen** begleitet, die diese Aktionen ohne Rückfrage ausführen können. Dies kann Folgendes sein:<sup>[[1]](#references)</sup>

- **N`il`** (keine Autorisierung erforderlich, **jeder ist vertrauenswürdig**)
- Eine **leere** Liste (**niemand** ist vertrauenswürdig)
- Eine **Liste** bestimmter **Anwendungen**.

Der Eintrag kann außerdem den Schlüssel **`ACLAuthorizationPartitionID`** enthalten, der zur Identifizierung von **teamid, apple** und **cdhash** verwendet wird.<sup>[[1]](#references)</sup>

- Wenn **teamid** angegeben ist, muss die Anwendung dieselbe **teamid** besitzen, um auf den Wert des **Eintrags** **ohne** eine **Rückfrage** zugreifen zu können.
- Wenn **apple** angegeben ist, muss die App von **Apple** signiert sein.
- Wenn **cdhash** angegeben ist, muss die **App** über den angegebenen **cdhash** verfügen.

### Creating a Keychain Entry

Wenn ein **neuer** **Eintrag** mit **`Keychain Access.app`** erstellt wird, gelten die folgenden Regeln:<sup>[[1]](#references)</sup>

- Alle Apps können verschlüsseln.
- **Keine Apps** können exportieren/entschlüsseln (ohne den Benutzer zu fragen).
- Alle Apps können die Integritätsprüfung sehen.
- Keine Apps können ACLs ändern.
- Die **partitionID** wird auf **`apple`** gesetzt.

Wenn eine **Anwendung einen Eintrag im Schlüsselbund erstellt**, unterscheiden sich die Regeln geringfügig:<sup>[[1]](#references)</sup>

- Alle Apps können verschlüsseln.
- Nur die **erstellende Anwendung** (oder andere ausdrücklich hinzugefügte Apps) kann exportieren/entschlüsseln (ohne den Benutzer zu fragen).
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
security set-generic-password-partition-list -s "test service" -a "test account" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> Die **Enumeration und das Dumping** von Secrets aus der **Keychain**, die **keinen Prompt erzeugen**, können mit dem Tool [**LockSmith**](https://github.com/its-a-feature/LockSmith) durchgeführt werden.
>
> Weitere API-Endpunkte sind im Quellcode von [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) zu finden.

Liste und erhalte **Informationen** zu jedem Keychain-Eintrag mit dem **Security Framework** oder prüfe alternativ das Open-Source-CLI-Tool [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html) von Apple. Einige API-Beispiele:<sup>[[1]](#references)</sup>

- Die API **`SecItemCopyMatching`** liefert Informationen zu jedem Eintrag. Bei ihrer Verwendung können einige Attribute gesetzt werden:
- **`kSecReturnData`**: Wenn true, wird versucht, die Daten zu entschlüsseln (auf false setzen, um potenzielle Pop-ups zu vermeiden)
- **`kSecReturnRef`**: Gibt zusätzlich eine Referenz auf das Keychain-Element zurück (auf true setzen, falls sich später zeigt, dass die Entschlüsselung ohne Pop-up möglich ist)
- **`kSecReturnAttributes`**: Gibt Metadaten zu den Einträgen zurück
- **`kSecMatchLimit`**: Anzahl der zurückzugebenden Ergebnisse
- **`kSecClass`**: Art des Keychain-Eintrags

ACLs jedes Eintrags abrufen:<sup>[[1]](#references)</sup>

- Mit der API **`SecAccessCopyACLList`** kann die **ACL für das Keychain-Element** abgerufen werden. Sie gibt eine Liste von ACLs zurück (z. B. `ACLAuthorizationExportClear` und die anderen zuvor erwähnten), wobei jeder Eintrag Folgendes enthält:
- Beschreibung
- **Trusted Application List**. Dies kann Folgendes sein:
- Eine App: /Applications/Slack.app
- Ein Binary: /usr/libexec/airportd
- Eine Gruppe: group://AirPort

Die Daten exportieren:<sup>[[1]](#references)</sup>

- Die API **`SecKeychainItemCopyContent`** ruft den Klartext ab
- Die API **`SecItemExport`** exportiert die Schlüssel und Zertifikate, möglicherweise müssen jedoch Passwörter gesetzt werden, um den Inhalt verschlüsselt zu exportieren

Dies sind die Voraussetzungen, um ein Secret **ohne Prompt exportieren** zu können:<sup>[[1]](#references)</sup>

- Wenn **1 oder mehr vertrauenswürdige** Apps aufgelistet sind:
- Die entsprechenden **Autorisierungen** (**`Nil`** oder **Teil** der Liste der erlaubten Apps in der Autorisierung für den Zugriff auf die geheimen Informationen sein)
- Die Codesignatur muss mit der **PartitionID** übereinstimmen
- Die Codesignatur muss der einer **Trusted App** entsprechen (oder der Prozess muss Mitglied der richtigen KeychainAccessGroup sein)
- Wenn **alle Anwendungen vertrauenswürdig** sind:
- Die entsprechenden **Autorisierungen**
- Die Codesignatur muss mit der **PartitionID** übereinstimmen
- Wenn keine **PartitionID** vorhanden ist, ist dies nicht erforderlich

> [!CAUTION]
> Wenn **1 Anwendung aufgelistet** ist, musst du daher **Code in diese Anwendung injizieren**.
>
> Wenn **apple** in der **partitionID** angegeben ist, kann mit **`osascript`** darauf zugegriffen werden. Das gilt für alles, was allen Anwendungen mit apple in der partitionID vertraut. Auch **`Python`** kann dafür verwendet werden.

### Zwei zusätzliche Attribute

- **Invisible**: Ein boolescher Wert, um den Eintrag in der **UI** der Keychain-App **auszublenden**<sup>[[1]](#references)</sup>
- **General**: Dient zum Speichern von **Metadaten** (ist daher **NICHT VERSCHLÜSSELT**)<sup>[[1]](#references)</sup>
- Microsoft speicherte alle Refresh-Tokens für den Zugriff auf sensible Endpunkte im Klartext.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Knacken der macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
{{#include ../../banners/hacktricks-training.md}}
