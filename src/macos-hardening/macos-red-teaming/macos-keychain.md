# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- La **User Keychain** (`~/Library/Keychains/login.keychain-db`), utilizzata per archiviare **credenziali specifiche dell'utente**, come password delle applicazioni, password Internet, certificati generati dall'utente, password di rete e chiavi pubbliche/private generate dall'utente.
- La **System Keychain** (`/Library/Keychains/System.keychain`), che archivia **credenziali a livello di sistema**, come password WiFi, certificati root di sistema, chiavi private di sistema e password delle applicazioni di sistema.<sup>[[1]](#references)</sup>
- È possibile trovare altri componenti, come i certificati, in `/System/Library/Keychains/*`
- In **iOS** esiste una sola **Keychain**, situata in `/private/var/Keychains/`. Questa cartella contiene anche i database per il `TrustStore`, le autorità di certificazione (`caissuercache`) e le voci OSCP (`ocspache`).
- Le app avranno accesso limitato nella keychain esclusivamente alla propria area privata, in base al proprio identificatore dell'applicazione.

### Accesso alla Password Keychain

Questi file, sebbene non dispongano di una protezione intrinseca e possano essere **scaricati**, sono criptati e richiedono la **password in chiaro dell'utente per essere decriptati**. Per la decrittazione è possibile utilizzare uno strumento come [**Chainbreaker**](https://github.com/n0fate/chainbreaker).<sup>[[1]](#references)</sup>

## Protezioni delle Voci della Keychain

### ACL

Ogni voce nella keychain è regolata da **Access Control Lists (ACL)**, che stabiliscono chi può eseguire varie azioni sulla voce della keychain, tra cui:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: consente al titolare di ottenere il testo in chiaro del segreto.
- **ACLAuhtorizationExportWrapped**: consente al titolare di ottenere il testo in chiaro criptato con un'altra password fornita.
- **ACLAuhtorizationAny**: consente al titolare di eseguire qualsiasi azione.

Le ACL sono inoltre accompagnate da un **elenco di applicazioni trusted** che possono eseguire queste azioni senza mostrare un prompt. Può trattarsi di:<sup>[[1]](#references)</sup>

- **N`il`** (non è richiesta alcuna autorizzazione, **tutti sono trusted**)
- Un elenco **vuoto** (**nessuno** è trusted)
- Un **elenco** di **applicazioni** specifiche.

La voce può inoltre contenere la chiave **`ACLAuthorizationPartitionID`,** utilizzata per identificare **teamid, apple** e **cdhash.**<sup>[[1]](#references)</sup>

- Se è specificato il **teamid**, per **accedere al valore della voce** **senza** un **prompt**, l'applicazione utilizzata deve avere lo **stesso teamid**.
- Se è specificato **apple**, l'app deve essere **firmata** da **Apple**.
- Se è indicato il **cdhash**, l'**app** deve avere lo specifico **cdhash**.

### Creazione di una Voce della Keychain

Quando viene creata una **nuova** **voce** utilizzando **`Keychain Access.app`**, si applicano le seguenti regole:<sup>[[1]](#references)</sup>

- Tutte le app possono criptare.
- **Nessuna app** può esportare/decriptare (senza mostrare un prompt all'utente).
- Tutte le app possono visualizzare il controllo di integrità.
- Nessuna app può modificare le ACL.
- Il **partitionID** è impostato su **`apple`**.

Quando un'**applicazione crea una voce nella keychain**, le regole sono leggermente diverse:<sup>[[1]](#references)</sup>

- Tutte le app possono criptare.
- Solo l'**applicazione creatrice** (o qualsiasi altra app aggiunta esplicitamente) può esportare/decriptare (senza mostrare un prompt all'utente).
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
> L'**enumerazione e il dumping delle** secret del **keychain che non generano un prompt** possono essere eseguiti con lo strumento [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Altri endpoint API possono essere trovati nel codice sorgente [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) di Apple.

Elenca e ottieni **informazioni** su ogni voce del keychain usando il **Security Framework**, oppure puoi anche consultare lo strumento CLI open source di Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Alcuni esempi di API:<sup>[[1]](#references)</sup>

- L'API **`SecItemCopyMatching`** fornisce informazioni su ogni voce e ci sono alcuni attributi che puoi impostare quando la utilizzi:
- **`kSecReturnData`**: se impostato su true, tenterà di decrittografare i dati (impostalo su false per evitare potenziali pop-up)
- **`kSecReturnRef`**: ottiene anche un riferimento all'elemento del keychain (impostalo su true nel caso in cui in seguito tu scopra di poterlo decrittografare senza pop-up)
- **`kSecReturnAttributes`**: ottiene i metadati delle voci
- **`kSecMatchLimit`**: quanti risultati restituire
- **`kSecClass`**: il tipo di voce del keychain

Ottieni le **ACL** di ogni voce:<sup>[[1]](#references)</sup>

- Con l'API **`SecAccessCopyACLList`** puoi ottenere l'**ACL dell'elemento del keychain**, che restituirà un elenco di ACL (come `ACLAuhtorizationExportClear` e le altre menzionate in precedenza), in cui ogni elenco contiene:
- Descrizione
- **Elenco delle applicazioni attendibili**. Può trattarsi di:
- Un'app: /Applications/Slack.app
- Un binary: /usr/libexec/airportd
- Un gruppo: group://AirPort

Esporta i dati:<sup>[[1]](#references)</sup>

- L'API **`SecKeychainItemCopyContent`** ottiene il testo in chiaro
- L'API **`SecItemExport`** esporta le chiavi e i certificati, ma potrebbe essere necessario impostare password per esportare il contenuto cifrato

Questi sono i **requisiti** per poter **esportare una secret senza un prompt**:<sup>[[1]](#references)</sup>

- Se sono elencate **1 o più applicazioni attendibili**:
- Sono necessarie le **autorizzazioni** appropriate (**`Nil`**, oppure devi far **parte** dell'elenco consentito di applicazioni nell'autorizzazione per accedere alle informazioni secret)
- La firma del codice deve corrispondere al **PartitionID**
- La firma del codice deve corrispondere a quella di una **trusted app** (oppure devi essere membro del KeychainAccessGroup corretto)
- Se **tutte le applicazioni sono attendibili**:
- Sono necessarie le **autorizzazioni** appropriate
- La firma del codice deve corrispondere al **PartitionID**
- Se non è presente alcun **PartitionID**, questo requisito non è necessario

> [!CAUTION]
> Pertanto, se è **elencata 1 applicazione**, devi **iniettare codice in quell'applicazione**.
>
> Se nel **partitionID** è indicato **apple**, puoi accedervi con **`osascript`**, quindi questo vale per tutto ciò che considera attendibili tutte le applicazioni con apple nel partitionID. A questo scopo si può usare anche **`Python`**.

### Due attributi aggiuntivi

- **Invisible**: è un flag booleano per **nascondere** la voce dall'app Keychain nella **UI**<sup>[[1]](#references)</sup>
- **General**: serve a memorizzare **metadati** (quindi NON È CIFRATO)<sup>[[1]](#references)</sup>
- Microsoft memorizzava in testo in chiaro tutti i refresh token per accedere a endpoint sensibili.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
