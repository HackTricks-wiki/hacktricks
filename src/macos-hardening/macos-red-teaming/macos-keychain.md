# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Zentrale Keychains

- Der **User Keychain** (`~/Library/Keychains/login.keychain-db`), der zum Speichern **benutzerspezifischer Zugangsdaten** wie Anwendungs-Passwörtern, Internet-Passwörtern, benutzergenerierten Zertifikaten, Netzwerk-Passwörtern und benutzergenerierten öffentlichen/privaten Schlüsseln verwendet wird.
- Der **System Keychain** (`/Library/Keychains/System.keychain`), der **systemweite Zugangsdaten** wie WiFi-Passwörter, System-Root-Zertifikate, private Systemschlüssel und Passwörter von Systemanwendungen speichert.<sup>[1]</sup>
- Andere Komponenten wie Zertifikate können unter `/System/Library/Keychains/*` gefunden werden.
- In **iOS** gibt es nur einen **Keychain**, der sich unter `/private/var/Keychains/` befindet. Dieser Ordner enthält außerdem Datenbanken für den `TrustStore`, Zertifizierungsstellen (`caissuercache`) und OSCP-Einträge (`ocspache`).
- Apps werden im Keychain anhand ihrer Anwendungskennung auf ihren privaten Bereich beschränkt.

### Zugriff auf den Password Keychain

Diese Dateien verfügen zwar über keinen inhärenten Schutz und können **heruntergeladen** werden, sind jedoch verschlüsselt und erfordern das **Klartextpasswort des Benutzers**, um entschlüsselt zu werden. Ein Tool wie [**Chainbreaker**](https://github.com/n0fate/chainbreaker) kann zur Entschlüsselung verwendet werden.<sup>[1]</sup>

## Schutz von Keychain-Einträgen

### ACLs

Jeder Eintrag im Keychain wird durch **Access Control Lists (ACLs)** gesteuert, die festlegen, wer verschiedene Aktionen für den Keychain-Eintrag ausführen darf, darunter:<sup>[1]</sup>

- **ACLAuhtorizationExportClear**: Ermöglicht dem Inhaber, den Klartext des Geheimnisses abzurufen.
- **ACLAuhtorizationExportWrapped**: Ermöglicht dem Inhaber, den mit einem anderen angegebenen Passwort verschlüsselten Klartext abzurufen.
- **ACLAuhtorizationAny**: Ermöglicht dem Inhaber, jede Aktion auszuführen.

Die ACLs werden außerdem von einer **Liste vertrauenswürdiger Anwendungen** begleitet, die diese Aktionen ohne Nachfrage ausführen können. Dies kann Folgendes sein:<sup>[1]</sup>

- **N`il`** (keine Autorisierung erforderlich, **jeder ist vertrauenswürdig**)
- Eine **leere** Liste (**niemand** ist vertrauenswürdig)
- **Liste** bestimmter **Anwendungen**.

Der Eintrag kann außerdem den Schlüssel **`ACLAuthorizationPartitionID`** enthalten, der zur Identifizierung von **teamid, apple** und **cdhash** verwendet wird.<sup>[1]</sup>

- Wenn die **teamid** angegeben ist, muss die verwendete Anwendung dieselbe teamid besitzen, um auf den Wert des **Eintrags** **ohne** **Nachfrage** **zugreifen** zu können.
- Wenn **apple** angegeben ist, muss die App von **Apple** **signiert** sein.
- Wenn der **cdhash** angegeben ist, muss die **App** über den angegebenen **cdhash** verfügen.

### Erstellen eines Keychain-Eintrags

Wenn ein **neuer** **Eintrag** mit **`Keychain Access.app`** erstellt wird, gelten die folgenden Regeln:<sup>[1]</sup>

- Alle Apps können verschlüsseln.
- **Keine Apps** können exportieren/entschlüsseln (ohne den Benutzer zu fragen).
- Alle Apps können die Integritätsprüfung sehen.
- Keine Apps können ACLs ändern.
- Die **partitionID** wird auf **`apple`** gesetzt.

Wenn eine **Anwendung einen Eintrag im Keychain erstellt**, unterscheiden sich die Regeln geringfügig:<sup>[1]</sup>

- Alle Apps können verschlüsseln.
- Nur die **erstellende Anwendung** (oder andere ausdrücklich hinzugefügte Apps) kann exportieren/entschlüsseln (ohne den Benutzer zu fragen).
- Alle Apps können die Integritätsprüfung sehen.
- Keine Apps können die ACLs ändern.
- Die **partitionID** wird auf **`teamid:[teamID here]`** gesetzt.

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
> Die **Auflistung und das Dumping von Secrets aus der Keychain**, die **keinen Prompt erzeugen**, kann mit dem Tool [**LockSmith**](https://github.com/its-a-feature/LockSmith) durchgeführt werden.
>
> Weitere API-Endpunkte sind im Quellcode von [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) zu finden.

Liste und erhalte **Informationen** über jeden Keychain-Eintrag mit dem **Security Framework** oder überprüfe auch das Open-Source-CLI-Tool [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Einige API-Beispiele:<sup>[1]</sup>

- Die API **`SecItemCopyMatching`** liefert Informationen über jeden Eintrag, und bei ihrer Verwendung können einige Attribute gesetzt werden:
- **`kSecReturnData`**: Wenn true, wird versucht, die Daten zu entschlüsseln (auf false setzen, um mögliche Pop-ups zu vermeiden)
- **`kSecReturnRef`**: Gibt zusätzlich eine Referenz auf das Keychain-Element zurück (auf true setzen, falls du später feststellst, dass du es ohne Pop-up entschlüsseln kannst)
- **`kSecReturnAttributes`**: Liefert Metadaten über Einträge
- **`kSecMatchLimit`**: Anzahl der zurückzugebenden Ergebnisse
- **`kSecClass`**: Art des Keychain-Eintrags

Erhalte die **ACLs** jedes Eintrags:<sup>[1]</sup>

- Mit der API **`SecAccessCopyACLList`** kannst du die **ACL für das Keychain-Element** abrufen. Sie gibt eine Liste von ACLs zurück (wie `ACLAuhtorizationExportClear` und die zuvor erwähnten), wobei jede Liste Folgendes enthält:
- Beschreibung
- **Trusted Application List**. Dies kann Folgendes sein:
- Eine App: /Applications/Slack.app
- Ein Binary: /usr/libexec/airportd
- Eine Gruppe: group://AirPort

Exportiere die Daten:<sup>[1]</sup>

- Die API **`SecKeychainItemCopyContent`** ruft den Klartext ab
- Die API **`SecItemExport`** exportiert die Schlüssel und Zertifikate, möglicherweise müssen jedoch Passwörter gesetzt werden, um den Inhalt verschlüsselt zu exportieren

Dies sind die **Voraussetzungen**, um ein **Secret ohne Prompt exportieren** zu können:<sup>[1]</sup>

- Wenn **1+ vertrauenswürdige** Apps aufgelistet sind:
- Die entsprechenden **Autorisierungen** (**`Nil`** oder du musst **Teil** der erlaubten App-Liste in der Autorisierung für den Zugriff auf die vertraulichen Informationen sein)
- Die Codesignatur muss mit der **PartitionID** übereinstimmen
- Die Codesignatur muss der einer **vertrauenswürdigen App** entsprechen (oder du musst Mitglied der richtigen KeychainAccessGroup sein)
- Wenn **alle Anwendungen vertrauenswürdig** sind:
- Die entsprechenden **Autorisierungen**
- Die Codesignatur muss mit der **PartitionID** übereinstimmen
- Wenn keine **PartitionID** vorhanden ist, ist dies nicht erforderlich

> [!CAUTION]
> Wenn also **1 Anwendung aufgelistet** ist, musst du **Code in diese Anwendung injizieren**.
>
> Wenn **apple** in der **partitionID** angegeben ist, könntest du mit **`osascript`** darauf zugreifen. Das gilt also für alles, das allen Anwendungen mit apple in der partitionID vertraut. Auch **`Python`** könnte dafür verwendet werden.

### Zwei zusätzliche Attribute

- **Invisible**: Ein boolesches Flag, um den Eintrag in der **UI**-Keychain-App auszublenden<sup>[1]</sup>
- **General**: Dient zum Speichern von **Metadaten** (ist also NICHT VERSCHLÜSSELT)<sup>[1]</sup>
- Microsoft speicherte alle Refresh-Tokens für den Zugriff auf sensible Endpunkte im Klartext.<sup>[1]</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
