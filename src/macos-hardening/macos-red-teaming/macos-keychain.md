# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Wichtigste Keychains

- Die **User Keychain** (`~/Library/Keychains/login.keychain-db`), die zum Speichern **benutzerspezifischer Zugangsdaten** wie Anwendungs-, Internet-, Netzwerkpasswörtern, benutzergenerierten Zertifikaten sowie benutzergenerierten öffentlichen/privaten Schlüsseln verwendet wird.
- Die **System Keychain** (`/Library/Keychains/System.keychain`), die **systemweite Zugangsdaten** wie WiFi-Passwörter, System-Root-Zertifikate, private Systemschlüssel und Passwörter von Systemanwendungen speichert.<sup>[[1]](#references)</sup>
- Es ist möglich, weitere Komponenten wie Zertifikate in `/System/Library/Keychains/*` zu finden.
- In **iOS** gibt es nur eine **Keychain**, die sich in `/private/var/Keychains/` befindet. Dieser Ordner enthält auch Datenbanken für den `TrustStore`, Zertifizierungsstellen (`caissuercache`) und OSCP-Einträge (`ocspache`).
- Apps werden in der Keychain auf ihren privaten Bereich beschränkt, der auf ihrer Anwendungskennung basiert.

### Passwortzugriff auf die Keychain

Diese Dateien verfügen zwar über keinen inhärenten Schutz und können **heruntergeladen** werden, sind jedoch verschlüsselt und erfordern das **Klartextpasswort des Benutzers**, um entschlüsselt zu werden. Ein Tool wie [**Chainbreaker**](https://github.com/n0fate/chainbreaker) kann zur Entschlüsselung verwendet werden.<sup>[[1]](#references)</sup>

## Schutz der Keychain-Einträge

### ACLs

Jeder Eintrag in der Keychain wird durch **Access Control Lists (ACLs)** geregelt, die festlegen, wer verschiedene Aktionen am Keychain-Eintrag ausführen kann, einschließlich:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: Erlaubt dem Inhaber, den Klartext des Geheimnisses abzurufen.
- **ACLAuhtorizationExportWrapped**: Erlaubt dem Inhaber, den mit einem anderen angegebenen Passwort verschlüsselten Klartext abzurufen.
- **ACLAuhtorizationAny**: Erlaubt dem Inhaber, jede Aktion auszuführen.

Die ACLs werden außerdem von einer **Liste vertrauenswürdiger Anwendungen** begleitet, die diese Aktionen ohne Nachfrage ausführen können. Dies kann Folgendes sein:<sup>[[1]](#references)</sup>

- **N`il`** (keine Autorisierung erforderlich, **alle sind vertrauenswürdig**)
- Eine **leere** Liste (**niemand** ist vertrauenswürdig)
- **Liste** bestimmter **Anwendungen**.

Der Eintrag kann außerdem den Schlüssel **`ACLAuthorizationPartitionID`** enthalten, der zur Identifizierung von **teamid, apple** und **cdhash** verwendet wird.<sup>[[1]](#references)</sup>

- Wenn die **teamid** angegeben ist, muss die verwendete Anwendung dieselbe **teamid** haben, um auf den Wert des **Eintrags** **ohne** **Nachfrage** zugreifen zu können.
- Wenn **apple** angegeben ist, muss die App von **Apple** **signiert** sein.
- Wenn der **cdhash** angegeben ist, muss die **App** den spezifischen **cdhash** besitzen.

### Erstellen eines Keychain-Eintrags

Wenn ein **neuer** **Eintrag** mit **`Keychain Access.app`** erstellt wird, gelten die folgenden Regeln:<sup>[[1]](#references)</sup>

- Alle Apps können verschlüsseln.
- **Keine Apps** können exportieren/entschlüsseln (ohne den Benutzer zu fragen).
- Alle Apps können die Integritätsprüfung sehen.
- Keine Apps können ACLs ändern.
- Die **partitionID** wird auf **`apple`** gesetzt.

Wenn eine **Anwendung einen Eintrag in der Keychain erstellt**, unterscheiden sich die Regeln geringfügig:<sup>[[1]](#references)</sup>

- Alle Apps können verschlüsseln.
- Nur die **erstellende Anwendung** (oder andere ausdrücklich hinzugefügte Apps) kann exportieren/entschlüsseln (ohne den Benutzer zu fragen).
- Alle Apps können die Integritätsprüfung sehen.
- Keine Apps können die ACLs ändern.
- Die **partitionID** wird auf **`teamid:[teamID here]`** gesetzt.

## Zugriff auf die Keychain

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
> Weitere API-Endpunkte sind im Quellcode von [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) zu finden.

Liste jeden keychain-Eintrag auf und rufe **info** dazu über das **Security Framework** ab. Alternativ kannst du auch das Open-Source-CLI-Tool von Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** überprüfen. Einige API-Beispiele:<sup>[[1]](#references)</sup>

- Die API **`SecItemCopyMatching`** liefert Informationen zu jedem Eintrag. Bei ihrer Verwendung können einige Attribute festgelegt werden:
- **`kSecReturnData`**: Wenn true, wird versucht, die Daten zu entschlüsseln (auf false setzen, um mögliche Pop-ups zu vermeiden)
- **`kSecReturnRef`**: Ruft auch eine Referenz auf das keychain-Element ab (auf true setzen, falls du später feststellst, dass du es ohne Pop-up entschlüsseln kannst)
- **`kSecReturnAttributes`**: Ruft Metadaten zu den Einträgen ab
- **`kSecMatchLimit`**: Gibt an, wie viele Ergebnisse zurückgegeben werden sollen
- **`kSecClass`**: Gibt an, um welche Art von keychain-Eintrag es sich handelt

Rufe die **ACLs** jedes Eintrags ab:<sup>[[1]](#references)</sup>

- Mit der API **`SecAccessCopyACLList`** kannst du die **ACL für das keychain-Element** abrufen. Sie gibt eine Liste von ACLs zurück (wie `ACLAuhtorizationExportClear` und die zuvor erwähnten anderen), wobei jede Liste Folgendes enthält:
- Beschreibung
- **Trusted Application List**. Dies kann Folgendes sein:
- Eine App: /Applications/Slack.app
- Eine Binary: /usr/libexec/airportd
- Eine Gruppe: group://AirPort

Exportiere die Daten:<sup>[[1]](#references)</sup>

- Die API **`SecKeychainItemCopyContent`** ruft den Klartext ab
- Die API **`SecItemExport`** exportiert die Schlüssel und Zertifikate, möglicherweise müssen jedoch Passwörter festgelegt werden, um den Inhalt verschlüsselt zu exportieren

Dies sind die **Voraussetzungen**, um ein **Secret ohne Prompt exportieren** zu können:<sup>[[1]](#references)</sup>

- Wenn **1+ vertrauenswürdige** Apps aufgelistet sind:
- Die entsprechenden **authorizations** werden benötigt (**`Nil`** oder **Teil** der Liste erlaubter Apps in der authorization für den Zugriff auf die Secret-Informationen sein)
- Die Code-Signatur muss mit der **PartitionID** übereinstimmen
- Die Code-Signatur muss mit der einer **trusted app** übereinstimmen (oder Mitglied der richtigen KeychainAccessGroup sein)
- Wenn **alle Anwendungen trusted** sind:
- Die entsprechenden **authorizations** werden benötigt
- Die Code-Signatur muss mit der **PartitionID** übereinstimmen
- Wenn keine **PartitionID** vorhanden ist, ist dies nicht erforderlich

> [!CAUTION]
> Wenn also **1 Anwendung aufgelistet** ist, musst du **Code in diese Anwendung injizieren**.
>
> Wenn **apple** in der **partitionID** angegeben ist, kannst du mit **`osascript`** darauf zugreifen. Das gilt also für alles, was allen Anwendungen vertraut und apple in der partitionID enthält. Auch **`Python`** kann dafür verwendet werden.

### Zwei zusätzliche Attribute

- **Invisible**: Dies ist ein Boolean-Flag, um den Eintrag in der **UI** der Keychain-App auszublenden<sup>[[1]](#references)</sup>
- **General**: Dient zum Speichern von **Metadaten** (diese sind daher NICHT VERSCHLÜSSELT)<sup>[[1]](#references)</sup>
- Microsoft speicherte alle Refresh-Tokens im Klartext, um auf sensible Endpunkte zuzugreifen.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
