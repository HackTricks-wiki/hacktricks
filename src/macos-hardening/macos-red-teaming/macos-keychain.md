# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Wichtigste Keychains

- Der **User Keychain** (`~/Library/Keychains/login.keychain-db`), der zum Speichern **benutzerspezifischer Zugangsdaten** wie Anwendungspasswörtern, Internetpasswörtern, benutzergenerierten Zertifikaten, Netzwerkpasswörtern und benutzergenerierten öffentlichen/privaten Schlüsseln verwendet wird.
- Der **System Keychain** (`/Library/Keychains/System.keychain`), der **systemweite Zugangsdaten** wie WiFi-Passwörter, System-Root-Zertifikate, private Systemschlüssel und Passwörter von Systemanwendungen speichert.<sup>[[1]](#references)</sup>
- Es ist möglich, weitere Komponenten wie Zertifikate unter `/System/Library/Keychains/*` zu finden.
- In **iOS** gibt es nur einen **Keychain**, der sich unter `/private/var/Keychains/` befindet. Dieser Ordner enthält außerdem Datenbanken für den `TrustStore`, Zertifizierungsstellen (`caissuercache`) und OSCP-Einträge (`ocspache`).
- Apps werden im Keychain anhand ihrer Anwendungskennung auf ihren privaten Bereich beschränkt.

### Zugriff auf den Password Keychain

Diese Dateien verfügen zwar über keinen eigenen Schutz und können **heruntergeladen** werden, sind jedoch verschlüsselt und erfordern das **Klartextpasswort des Benutzers**, um entschlüsselt zu werden. Ein Tool wie [**Chainbreaker**](https://github.com/n0fate/chainbreaker) kann zur Entschlüsselung verwendet werden.<sup>[[1]](#references)</sup>

## Schutz der Keychain-Einträge

### ACLs

Jeder Eintrag im Keychain wird durch **Access Control Lists (ACLs)** geregelt, die festlegen, wer verschiedene Aktionen für den Keychain-Eintrag ausführen kann, einschließlich:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: Ermöglicht dem Inhaber, den Klartext des Geheimnisses abzurufen.
- **ACLAuhtorizationExportWrapped**: Ermöglicht dem Inhaber, den mit einem anderen angegebenen Passwort verschlüsselten Klartext abzurufen.
- **ACLAuhtorizationAny**: Ermöglicht dem Inhaber, jede Aktion auszuführen.

Die ACLs werden außerdem durch eine **Liste vertrauenswürdiger Anwendungen** ergänzt, die diese Aktionen ohne Nachfrage ausführen können. Dies kann Folgendes sein:<sup>[[1]](#references)</sup>

- **N`il`** (keine Autorisierung erforderlich, **jeder ist vertrauenswürdig**)
- Eine **leere** Liste (**niemand** ist vertrauenswürdig)
- Eine **Liste** bestimmter **Anwendungen**.

Der Eintrag kann außerdem den Schlüssel **`ACLAuthorizationPartitionID`** enthalten, der zur Identifizierung von **teamid, apple** und **cdhash** verwendet wird.<sup>[[1]](#references)</sup>

- Wenn **teamid** angegeben ist, muss die verwendete Anwendung dieselbe teamid besitzen, um auf den Wert des **Eintrags** **ohne** **Nachfrage** zuzugreifen.
- Wenn **apple** angegeben ist, muss die App von **Apple** **signiert** sein.
- Wenn **cdhash** angegeben ist, muss die **App** über den spezifischen **cdhash** verfügen.

### Erstellen eines Keychain-Eintrags

Wenn ein **neuer** **Eintrag** mit **`Keychain Access.app`** erstellt wird, gelten die folgenden Regeln:<sup>[[1]](#references)</sup>

- Alle Apps können verschlüsseln.
- **Keine Apps** können exportieren/entschlüsseln (ohne den Benutzer zu fragen).
- Alle Apps können die Integritätsprüfung sehen.
- Keine Apps können ACLs ändern.
- Die **partitionID** wird auf **`apple`** gesetzt.

Wenn eine **Anwendung einen Eintrag im Keychain erstellt**, gelten leicht abweichende Regeln:<sup>[[1]](#references)</sup>

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
> Die **keychain enumeration and dumping** von Secrets, die **keinen Prompt erzeugen**, kann mit dem Tool [**LockSmith**](https://github.com/its-a-feature/LockSmith) durchgeführt werden.
>
> Weitere API-Endpunkte sind im [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html)-Quellcode zu finden.

Liste jeden keychain-Eintrag mit dem **Security Framework** auf und rufe **Info** darüber ab. Alternativ kannst du auch das Open-Source-CLI-Tool [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** von Apple verwenden. Einige API-Beispiele:<sup>[[1]](#references)</sup>

- Die API **`SecItemCopyMatching`** liefert Informationen über jeden Eintrag. Bei ihrer Verwendung können einige Attribute festgelegt werden:
- **`kSecReturnData`**: Wenn true, wird versucht, die Daten zu entschlüsseln (auf false setzen, um potenzielle Pop-ups zu vermeiden)
- **`kSecReturnRef`**: Gibt auch eine Referenz auf das keychain-Element zurück (auf true setzen, falls du später feststellst, dass du es ohne Pop-up entschlüsseln kannst)
- **`kSecReturnAttributes`**: Gibt Metadaten über die Einträge zurück
- **`kSecMatchLimit`**: Gibt an, wie viele Ergebnisse zurückgegeben werden sollen
- **`kSecClass`**: Gibt an, um welche Art von keychain-Eintrag es sich handelt

Rufe die **ACLs** jedes Eintrags ab:<sup>[[1]](#references)</sup>

- Mit der API **`SecAccessCopyACLList`** kannst du die **ACL für das keychain-Element** abrufen. Sie gibt eine Liste von ACLs zurück (wie `ACLAuhtorizationExportClear` und die zuvor erwähnten anderen), wobei jede Liste Folgendes enthält:
- Beschreibung
- **Trusted Application List**. Diese kann Folgendes enthalten:
- Eine App: /Applications/Slack.app
- Eine Binary: /usr/libexec/airportd
- Eine Gruppe: group://AirPort

Exportiere die Daten:<sup>[[1]](#references)</sup>

- Die API **`SecKeychainItemCopyContent`** ruft den Klartext ab
- Die API **`SecItemExport`** exportiert die Schlüssel und Zertifikate, möglicherweise müssen jedoch Passwörter festgelegt werden, um den Inhalt verschlüsselt zu exportieren

Dies sind die **Voraussetzungen**, um ein **Secret ohne Prompt exportieren** zu können:<sup>[[1]](#references)</sup>

- Wenn **1+ vertrauenswürdige** Apps aufgelistet sind:
- Die entsprechenden **authorizations** werden benötigt (**`Nil`** oder du musst **Teil** der Liste der erlaubten Apps in der authorization für den Zugriff auf die Secret-Informationen sein)
- Die Code-Signatur muss mit der **PartitionID** übereinstimmen
- Die Code-Signatur muss mit der einer **trusted app** übereinstimmen (oder du musst Mitglied der richtigen KeychainAccessGroup sein)
- Wenn **alle Anwendungen vertrauenswürdig** sind:
- Die entsprechenden **authorizations** werden benötigt
- Die Code-Signatur muss mit der **PartitionID** übereinstimmen
- Wenn keine **PartitionID** vorhanden ist, ist dies nicht erforderlich

> [!CAUTION]
> Wenn daher **1 Anwendung aufgelistet** ist, musst du **Code in diese Anwendung injizieren**.
>
> Wenn **apple** in der **partitionID** angegeben ist, könntest du mit **`osascript`** darauf zugreifen. Das gilt für alles, was allen Anwendungen mit apple in der partitionID vertraut. Auch **`Python`** könnte dafür verwendet werden.

### Zwei zusätzliche Attribute

- **Invisible**: Dies ist ein Boolean-Flag, um den Eintrag in der **UI**-Keychain-App auszublenden<sup>[[1]](#references)</sup>
- **General**: Dient zum Speichern von **Metadaten** (daher ist es NICHT VERSCHLÜSSELT)<sup>[[1]](#references)</sup>
- Microsoft speicherte alle Refresh-Tokens für den Zugriff auf sensible Endpunkte im Klartext.<sup>[[1]](#references)</sup>

## Referenzen

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
