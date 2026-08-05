# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Keychain principali

- Il **User Keychain** (`~/Library/Keychains/login.keychain-db`), utilizzato per memorizzare **credenziali specifiche dell'utente**, come password delle applicazioni, password Internet, certificati generati dall'utente, password di rete e chiavi pubbliche/private generate dall'utente.
- Il **System Keychain** (`/Library/Keychains/System.keychain`), che memorizza **credenziali a livello di sistema**, come password WiFi, certificati root di sistema, chiavi private di sistema e password delle applicazioni di sistema.<sup>[1]</sup>
- È possibile trovare altri componenti, come i certificati, in `/System/Library/Keychains/*`
- In **iOS** esiste un solo **Keychain**, situato in `/private/var/Keychains/`. Questa cartella contiene anche database per il `TrustStore`, le autorità di certificazione (`caissuercache`) e le entry OSCP (`ocspache`).
- Le app saranno limitate nel Keychain alla propria area privata in base al proprio identificatore applicativo.

### Accesso al Keychain tramite password

Questi file, sebbene non dispongano di una protezione intrinseca e possano essere **scaricati**, sono cifrati e richiedono la **password in chiaro dell'utente per essere decifrati**. Uno strumento come [**Chainbreaker**](https://github.com/n0fate/chainbreaker) può essere utilizzato per la decrittazione.<sup>[1]</sup>

## Protezioni delle entry del Keychain

### ACL

Ogni entry nel Keychain è regolata da **Access Control Lists (ACL)**, che determinano chi può eseguire varie azioni sull'entry del Keychain, tra cui:<sup>[1]</sup>

- **ACLAuhtorizationExportClear**: consente al titolare di ottenere il segreto in chiaro.
- **ACLAuhtorizationExportWrapped**: consente al titolare di ottenere il segreto in chiaro cifrato con un'altra password fornita.
- **ACLAuhtorizationAny**: consente al titolare di eseguire qualsiasi azione.

Le ACL sono inoltre accompagnate da una **lista di applicazioni attendibili** che possono eseguire queste azioni senza mostrare prompt. Può trattarsi di:<sup>[1]</sup>

- **N`il`** (non è richiesta alcuna autorizzazione, **tutti sono considerati attendibili**)
- Una lista **vuota** (**nessuno** è considerato attendibile)
- Una **lista** di **applicazioni** specifiche.

L'entry può inoltre contenere la chiave **`ACLAuthorizationPartitionID`,** utilizzata per identificare **teamid, apple** e **cdhash**.<sup>[1]</sup>

- Se è specificato il **teamid**, per **accedere al valore dell'entry** **senza** un **prompt**, l'applicazione utilizzata deve avere lo **stesso teamid**.
- Se è specificato **apple**, l'app deve essere **firmata** da **Apple**.
- Se è indicato il **cdhash**, l'**app** deve avere lo specifico **cdhash**.

### Creazione di una entry nel Keychain

Quando viene creata una **nuova** **entry** utilizzando **`Keychain Access.app`**, si applicano le seguenti regole:<sup>[1]</sup>

- Tutte le app possono cifrare.
- **Nessuna app** può esportare/decrittare (senza mostrare un prompt all'utente).
- Tutte le app possono visualizzare il controllo di integrità.
- Nessuna app può modificare le ACL.
- Il **partitionID** è impostato su **`apple`**.

Quando un'**applicazione crea una entry nel Keychain**, le regole sono leggermente diverse:<sup>[1]</sup>

- Tutte le app possono cifrare.
- Solo l'**applicazione creatrice** (o altre app aggiunte esplicitamente) può esportare/decrittare (senza mostrare un prompt all'utente).
- Tutte le app possono visualizzare il controllo di integrità.
- Nessuna app può modificare le ACL.
- Il **partitionID** è impostato su **`teamid:[teamID here]`**.

## Accesso al Keychain

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
> L'**enumerazione e il dumping del keychain** dei secret che **non generano un prompt** possono essere eseguiti con lo strumento [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Altri endpoint API possono essere trovati nel codice sorgente di [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Elenca e ottieni **info** su ogni voce del keychain usando il **Security Framework**, oppure puoi anche consultare lo strumento cli open source di Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Alcuni esempi di API:<sup>[1]</sup>

- L'API **`SecItemCopyMatching`** fornisce informazioni su ogni voce e, quando la usi, puoi impostare alcuni attributi:
- **`kSecReturnData`**: se è true, tenterà di decrittografare i dati (impostalo su false per evitare potenziali pop-up)
- **`kSecReturnRef`**: ottiene anche il riferimento all'elemento del keychain (impostalo su true nel caso in cui in seguito tu verifichi di poter decrittografare senza pop-up)
- **`kSecReturnAttributes`**: ottiene i metadati delle voci
- **`kSecMatchLimit`**: quanti risultati restituire
- **`kSecClass`**: quale tipo di voce del keychain

Ottieni le **ACL** di ogni voce:<sup>[1]</sup>

- Con l'API **`SecAccessCopyACLList`** puoi ottenere l'**ACL dell'elemento del keychain**, che restituirà un elenco di ACL (come `ACLAuhtorizationExportClear` e le altre menzionate in precedenza), in cui ogni elemento contiene:
- Descrizione
- **Trusted Application List**. Può contenere:
- Un'app: /Applications/Slack.app
- Un binary: /usr/libexec/airportd
- Un gruppo: group://AirPort

Esporta i dati:<sup>[1]</sup>

- L'API **`SecKeychainItemCopyContent`** ottiene il plaintext
- L'API **`SecItemExport`** esporta le chiavi e i certificati, ma potrebbe essere necessario impostare password per esportare il contenuto cifrato

Questi sono i **requisiti** per poter **esportare un secret senza un prompt**:<sup>[1]</sup>

- Se sono elencate **1+** app trusted:
- Sono necessarie le **autorizzazioni** appropriate (**`Nil`**, oppure devi essere **parte** dell'elenco di app autorizzate nell'autorizzazione ad accedere alle informazioni del secret)
- La code signature deve corrispondere al **PartitionID**
- La code signature deve corrispondere a quella di una **trusted app** (oppure devi essere membro del KeychainAccessGroup corretto)
- Se **tutte le applicazioni sono trusted**:
- Sono necessarie le **autorizzazioni** appropriate
- La code signature deve corrispondere al **PartitionID**
- Se non c'è un **PartitionID**, questo requisito non è necessario

> [!CAUTION]
> Pertanto, se è elencata **1 applicazione**, devi **iniettare codice in quell'applicazione**.
>
> Se nel **partitionID** è indicato **apple**, potresti accedervi con **`osascript`**, quindi qualsiasi elemento che considera trusted tutte le applicazioni con apple nel partitionID. Anche **`Python`** potrebbe essere usato a questo scopo.

### Due attributi aggiuntivi

- **Invisible**: è un flag booleano per **nascondere** la voce dall'app **UI** Keychain<sup>[1]</sup>
- **General**: serve per memorizzare **metadati** (quindi NON È CIFRATO)<sup>[1]</sup>
- Microsoft memorizzava in plain text tutti i refresh token per accedere a endpoint sensibili.<sup>[1]</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
