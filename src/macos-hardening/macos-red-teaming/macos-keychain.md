# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- Il **User Keychain** (`~/Library/Keychains/login.keychain-db`), che viene utilizzato per memorizzare **credenziali specifiche dell'utente** come password delle applicazioni, password di internet, certificati generati dall'utente, password di rete e chiavi pubbliche/private generate dall'utente.
- Il **System Keychain** (`/Library/Keychains/System.keychain`), che memorizza **credenziali a livello di sistema** come password WiFi, certificati root di sistema, chiavi private di sistema e password delle applicazioni di sistema.
- È possibile trovare altri componenti come certificati in `/System/Library/Keychains/*`
- In **iOS** c'è solo un **Keychain** situato in `/private/var/Keychains/`. Questa cartella contiene anche database per il `TrustStore`, autorità di certificazione (`caissuercache`) e voci OSCP (`ocspache`).
- Le app saranno limitate nel keychain solo alla loro area privata in base al loro identificatore di applicazione.

### Password Keychain Access

Questi file, pur non avendo protezione intrinseca e potendo essere **scaricati**, sono crittografati e richiedono la **password in chiaro dell'utente per essere decrittografati**. Uno strumento come [**Chainbreaker**](https://github.com/n0fate/chainbreaker) potrebbe essere utilizzato per la decrittografia.

## Keychain Entries Protections

### ACLs

Ogni voce nel keychain è governata da **Access Control Lists (ACLs)** che determinano chi può eseguire varie azioni sulla voce del keychain, inclusi:

- **ACLAuhtorizationExportClear**: Consente al titolare di ottenere il testo in chiaro del segreto.
- **ACLAuhtorizationExportWrapped**: Consente al titolare di ottenere il testo in chiaro crittografato con un'altra password fornita.
- **ACLAuhtorizationAny**: Consente al titolare di eseguire qualsiasi azione.

Le ACL sono ulteriormente accompagnate da un **elenco di applicazioni fidate** che possono eseguire queste azioni senza richiesta. Questo potrebbe essere:

- **N`il`** (nessuna autorizzazione richiesta, **tutti sono fidati**)
- Un **elenco vuoto** (**nessuno** è fidato)
- **Elenco** di **applicazioni** specifiche.

Inoltre, la voce potrebbe contenere la chiave **`ACLAuthorizationPartitionID`,** che viene utilizzata per identificare il **teamid, apple,** e **cdhash.**

- Se il **teamid** è specificato, allora per **accedere al valore** della voce **senza** un **prompt** l'applicazione utilizzata deve avere lo **stesso teamid**.
- Se l'**apple** è specificato, allora l'app deve essere **firmata** da **Apple**.
- Se il **cdhash** è indicato, allora l'**app** deve avere il **cdhash** specifico.

### Creating a Keychain Entry

Quando viene creata una **nuova** **voce** utilizzando **`Keychain Access.app`**, si applicano le seguenti regole:

- Tutte le app possono crittografare.
- **Nessuna app** può esportare/decrittografare (senza richiedere all'utente).
- Tutte le app possono vedere il controllo di integrità.
- Nessuna app può modificare le ACL.
- Il **partitionID** è impostato su **`apple`**.

Quando un'**applicazione crea una voce nel keychain**, le regole sono leggermente diverse:

- Tutte le app possono crittografare.
- Solo l'**applicazione che crea** (o altre app esplicitamente aggiunte) può esportare/decrittografare (senza richiedere all'utente).
- Tutte le app possono vedere il controllo di integrità.
- Nessuna app può modificare le ACL.
- Il **partitionID** è impostato su **`teamid:[teamID here]`**.

## Accessing the Keychain

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
> L'**enumerazione e il dumping** del keychain di segreti che **non genereranno un prompt** possono essere effettuati con lo strumento [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Altri endpoint API possono essere trovati nel codice sorgente di [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Elenca e ottieni **info** su ciascun elemento del keychain utilizzando il **Security Framework** oppure puoi anche controllare lo strumento cli open source di Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Alcuni esempi di API:

- L'API **`SecItemCopyMatching`** fornisce informazioni su ciascun elemento e ci sono alcuni attributi che puoi impostare quando la utilizzi:
- **`kSecReturnData`**: Se vero, tenterà di decrittografare i dati (imposta su falso per evitare potenziali pop-up)
- **`kSecReturnRef`**: Ottieni anche un riferimento all'elemento del keychain (imposta su vero nel caso in cui successivamente vedi che puoi decrittografare senza pop-up)
- **`kSecReturnAttributes`**: Ottieni metadati sugli elementi
- **`kSecMatchLimit`**: Quanti risultati restituire
- **`kSecClass`**: Che tipo di elemento del keychain

Ottieni **ACL** di ciascun elemento:

- Con l'API **`SecAccessCopyACLList`** puoi ottenere l'**ACL per l'elemento del keychain**, e restituirà un elenco di ACL (come `ACLAuhtorizationExportClear` e gli altri precedentemente menzionati) dove ciascun elenco ha:
- Descrizione
- **Elenco delle Applicazioni Affidabili**. Questo potrebbe essere:
- Un'app: /Applications/Slack.app
- Un binario: /usr/libexec/airportd
- Un gruppo: group://AirPort

Esporta i dati:

- L'API **`SecKeychainItemCopyContent`** ottiene il testo in chiaro
- L'API **`SecItemExport`** esporta le chiavi e i certificati ma potrebbe essere necessario impostare le password per esportare il contenuto crittografato

E questi sono i **requisiti** per poter **esportare un segreto senza un prompt**:

- Se ci sono **1+ app affidabili** elencate:
- Necessita delle appropriate **autorizzazioni** (**`Nil`**, o essere **parte** dell'elenco consentito di app nell'autorizzazione per accedere alle informazioni segrete)
- Necessita che la firma del codice corrisponda al **PartitionID**
- Necessita che la firma del codice corrisponda a quella di un **app affidabile** (o essere un membro del giusto KeychainAccessGroup)
- Se **tutte le applicazioni sono affidabili**:
- Necessita delle appropriate **autorizzazioni**
- Necessita che la firma del codice corrisponda al **PartitionID**
- Se **nessun PartitionID**, allora questo non è necessario

> [!CAUTION]
> Pertanto, se c'è **1 applicazione elencata**, è necessario **iniettare codice in quell'applicazione**.
>
> Se **apple** è indicato nel **partitionID**, potresti accedervi con **`osascript`** quindi qualsiasi cosa che stia fidandosi di tutte le applicazioni con apple nel partitionID. **`Python`** potrebbe essere utilizzato anche per questo.

### Due attributi aggiuntivi

- **Invisible**: È un flag booleano per **nascondere** l'elemento dall'app Keychain **UI**
- **General**: Serve a memorizzare **metadati** (quindi NON è CRITTOGRAFATO)
- Microsoft memorizzava in testo chiaro tutti i token di aggiornamento per accedere a endpoint sensibili.

## References

- [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
