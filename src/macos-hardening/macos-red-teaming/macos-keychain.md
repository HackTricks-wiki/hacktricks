# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Keychain principali

- La **User Keychain** (`~/Library/Keychains/login.keychain-db`), utilizzata per archiviare **credenziali specifiche dell'utente**, come password delle applicazioni, password Internet, certificati generati dall'utente, password di rete e chiavi pubbliche/private generate dall'utente.
- La **System Keychain** (`/Library/Keychains/System.keychain`), che archivia **credenziali a livello di sistema**, come password WiFi, certificati radice di sistema, chiavi private di sistema e password delle applicazioni di sistema.<sup>[[1]](#references)</sup>
- È possibile trovare altri componenti, come i certificati, in `/System/Library/Keychains/*`
- In **iOS** esiste un'unica **Keychain**, situata in `/private/var/Keychains/`. Questa cartella contiene anche i database per il `TrustStore`, le autorità di certificazione (`caissuercache`) e le voci OSCP (`ocspache`).
- Le app avranno accesso limitato nella keychain esclusivamente alla propria area privata, in base al proprio identificatore dell'applicazione.

### Accesso alla Keychain tramite password

Sebbene questi file non dispongano di una protezione intrinseca e possano essere **scaricati**, sono crittografati e per la decrittografia richiedono la **password dell'utente in chiaro**. Per la decrittografia è possibile utilizzare uno strumento come [**Chainbreaker**](https://github.com/n0fate/chainbreaker).<sup>[[1]](#references)</sup>

## Protezioni delle voci della Keychain

### ACL

Ogni voce nella keychain è regolata da **Access Control Lists (ACL)**, che stabiliscono chi può eseguire varie azioni sulla voce della keychain, tra cui:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: consente al titolare di ottenere il testo in chiaro del segreto.
- **ACLAuhtorizationExportWrapped**: consente al titolare di ottenere il testo in chiaro crittografato con un'altra password fornita.
- **ACLAuhtorizationAny**: consente al titolare di eseguire qualsiasi azione.

Le ACL sono inoltre accompagnate da un **elenco di applicazioni attendibili** che possono eseguire queste azioni senza mostrare un prompt. Può trattarsi di:<sup>[[1]](#references)</sup>

- **N`il`** (nessuna autorizzazione richiesta, **tutti sono considerati attendibili**)
- Un elenco **vuoto** (**nessuno** è considerato attendibile)
- Un **elenco** di **applicazioni** specifiche.

La voce potrebbe inoltre contenere la chiave **`ACLAuthorizationPartitionID`,** utilizzata per identificare **teamid, apple** e **cdhash**.<sup>[[1]](#references)</sup>

- Se viene specificato il **teamid**, per **accedere** al valore della **voce** **senza** un **prompt**, l'applicazione utilizzata deve avere lo **stesso teamid**.
- Se viene specificato **apple**, l'app deve essere **firmata** da **Apple**.
- Se viene indicato il **cdhash**, l'**app** deve avere lo **specifico cdhash**.

### Creazione di una voce nella Keychain

Quando viene creata una **nuova** **voce** utilizzando **`Keychain Access.app`**, si applicano le seguenti regole:<sup>[[1]](#references)</sup>

- Tutte le app possono crittografare.
- **Nessuna app** può esportare/decrittografare (senza mostrare un prompt all'utente).
- Tutte le app possono visualizzare il controllo di integrità.
- Nessuna app può modificare le ACL.
- Il **partitionID** è impostato su **`apple`**.

Quando un'**applicazione crea una voce nella keychain**, le regole sono leggermente diverse:<sup>[[1]](#references)</sup>

- Tutte le app possono crittografare.
- Solo l'**applicazione che ha creato la voce** (o qualsiasi altra app aggiunta esplicitamente) può esportare/decrittografare (senza mostrare un prompt all'utente).
- Tutte le app possono visualizzare il controllo di integrità.
- Nessuna app può modificare le ACL.
- Il **partitionID** è impostato su **`teamid:[teamID here]`**.

## Accesso alla Keychain

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
> L'**enumerazione e il dumping delle** secret **del keychain che non generano un prompt** possono essere eseguiti con lo strumento [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Altri endpoint API possono essere trovati nel codice sorgente [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) di Apple.

Elenca e ottieni **info** su ogni voce del keychain utilizzando il **Security Framework**, oppure puoi anche consultare lo strumento cli open source di Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Alcuni esempi di API:<sup>[[1]](#references)</sup>

- L'API **`SecItemCopyMatching`** fornisce informazioni su ogni voce e ci sono alcuni attributi che puoi impostare quando la utilizzi:
- **`kSecReturnData`**: Se true, tenterà di decrittografare i dati (impostalo su false per evitare potenziali pop-up)
- **`kSecReturnRef`**: Ottiene anche un riferimento all'elemento del keychain (impostalo su true nel caso in cui successivamente tu possa verificare di riuscire a decrittografarlo senza pop-up)
- **`kSecReturnAttributes`**: Ottiene i metadata sulle voci
- **`kSecMatchLimit`**: Quanti risultati restituire
- **`kSecClass`**: Che tipo di voce del keychain

Ottieni gli **ACL** di ogni voce:<sup>[[1]](#references)</sup>

- Con l'API **`SecAccessCopyACLList`** puoi ottenere l'**ACL dell'elemento del keychain**; restituirà un elenco di ACL (come `ACLAuhtorizationExportClear` e le altre menzionate in precedenza), in cui ogni elenco contiene:
- Descrizione
- **Elenco delle applicazioni trusted**. Può trattarsi di:
- Un'app: /Applications/Slack.app
- Un binary: /usr/libexec/airportd
- Un gruppo: group://AirPort

Esporta i dati:<sup>[[1]](#references)</sup>

- L'API **`SecKeychainItemCopyContent`** ottiene il testo in chiaro
- L'API **`SecItemExport`** esporta le keys e i certificati, ma potrebbe essere necessario impostare password per esportare il contenuto cifrato

Questi sono i **requisiti** per poter **esportare una secret senza un prompt**:<sup>[[1]](#references)</sup>

- Se sono elencate **1 o più applicazioni trusted**:
- Sono necessarie le **authorizations** appropriate (**`Nil`**, oppure devi essere **parte** dell'elenco consentito di applicazioni nell'authorization per accedere alle informazioni della secret)
- La code signature deve corrispondere al **PartitionID**
- La code signature deve corrispondere a quella di una **trusted app** (oppure devi essere membro del KeychainAccessGroup corretto)
- Se **tutte le applicazioni sono trusted**:
- Sono necessarie le **authorizations** appropriate
- La code signature deve corrispondere al **PartitionID**
- Se non c'è **PartitionID**, questo requisito non è necessario

> [!CAUTION]
> Pertanto, se è elencata **1 applicazione**, devi **iniettare codice in quell'applicazione**.
>
> Se nel **partitionID** è indicato **apple**, puoi accedervi con **`osascript`**; quindi, qualsiasi elemento che consideri trusted tutte le applicazioni e che abbia apple nel partitionID può essere raggiunto in questo modo. A questo scopo può essere utilizzato anche **`Python`**.

### Due attributi aggiuntivi

- **Invisible**: È un flag booleano per **nascondere** la voce dall'app **UI** Keychain<sup>[[1]](#references)</sup>
- **General**: Serve per memorizzare **metadata** (quindi NON è ENCRYPTED)<sup>[[1]](#references)</sup>
- Microsoft memorizzava in testo in chiaro tutti i refresh tokens per accedere a endpoint sensibili.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
