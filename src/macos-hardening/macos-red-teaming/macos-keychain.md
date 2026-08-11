# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Portachiavi principali

- Il **User Keychain** (`~/Library/Keychains/login.keychain-db`), utilizzato per memorizzare **credenziali specifiche dell'utente**, come password delle applicazioni, password Internet, certificati generati dall'utente, password di rete e chiavi pubbliche/private generate dall'utente.
- Il **System Keychain** (`/Library/Keychains/System.keychain`), che memorizza **credenziali a livello di sistema**, come password WiFi, certificati root del sistema, chiavi private del sistema e password delle applicazioni di sistema.<sup>[[1]](#references)</sup>
- È possibile trovare altri componenti, come i certificati, in `/System/Library/Keychains/*`
- In **iOS** esiste un solo **Keychain**, situato in `/private/var/Keychains/`. Questa cartella contiene anche database per il `TrustStore`, le autorità di certificazione (`caissuercache`) e le voci OSCP (`ocspache`).
- Le app saranno limitate, nel keychain, alla propria area privata in base al proprio identificatore dell'applicazione.

### Accesso con password al Keychain

Questi file, sebbene non dispongano di una protezione intrinseca e possano essere **scaricati**, sono cifrati e richiedono la **password dell'utente in chiaro per essere decifrati**. Per la decrittazione è possibile utilizzare uno strumento come [**Chainbreaker**](https://github.com/n0fate/chainbreaker).<sup>[[1]](#references)</sup>

## Protezioni delle voci del Keychain

### ACL

Ogni voce nel keychain è regolata da **Access Control Lists (ACL)**, che stabiliscono chi può eseguire varie azioni sulla voce del keychain, tra cui:<sup>[[1]](#references)</sup>

- **ACLAuthorizationExportClear**: consente al titolare di ottenere il segreto in testo in chiaro.
- **ACLAuthorizationExportWrapped**: consente al titolare di ottenere il testo in chiaro cifrato con un'altra password fornita.
- **ACLAuthorizationAny**: consente al titolare di eseguire qualsiasi azione.

Le ACL sono inoltre accompagnate da un **elenco di applicazioni attendibili** che possono eseguire queste azioni senza mostrare richieste. Questo elenco può essere:<sup>[[1]](#references)</sup>

- **N`il`** (non è richiesta alcuna autorizzazione, **tutti sono attendibili**)
- Un elenco **vuoto** (**nessuno** è attendibile)
- Un **elenco** di **applicazioni** specifiche.

La voce potrebbe inoltre contenere la chiave **`ACLAuthorizationPartitionID`,** utilizzata per identificare **teamid, apple** e **cdhash**.<sup>[[1]](#references)</sup>

- Se viene specificato il **teamid**, l'applicazione deve avere lo **stesso teamid** per **accedere** al valore della voce **senza** una **richiesta**.
- Se viene specificato **apple**, l'app deve essere **firmata** da **Apple**.
- Se viene indicato il **cdhash**, l'**app** deve avere lo specifico **cdhash**.

### Creazione di una voce del Keychain

Quando viene creata una **nuova** **voce** utilizzando **`Keychain Access.app`**, si applicano le seguenti regole:<sup>[[1]](#references)</sup>

- Tutte le app possono cifrare.
- **Nessuna app** può esportare/decifrare (senza mostrare una richiesta all'utente).
- Tutte le app possono visualizzare il controllo di integrità.
- Nessuna app può modificare le ACL.
- Il **partitionID** è impostato su **`apple`**.

Quando un'**applicazione crea una voce nel keychain**, le regole sono leggermente diverse:<sup>[[1]](#references)</sup>

- Tutte le app possono cifrare.
- Solo l'**applicazione creatrice** (o qualsiasi altra app aggiunta esplicitamente) può esportare/decifrare (senza mostrare una richiesta all'utente).
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

# Change the specified entry's PartitionID value
security set-generic-password-partition-list -s "test service" -a "test account" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> L'**enumeration e il dumping** dei secret del **keychain** che **non generano un prompt** possono essere eseguiti con il tool [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Altri endpoint delle API sono disponibili nel codice sorgente [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Elenca e ottieni **info** su ogni elemento del keychain usando il **Security Framework**, oppure puoi anche consultare il tool CLI open source di Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Alcuni esempi di API:<sup>[[1]](#references)</sup>

- L'API **`SecItemCopyMatching`** fornisce informazioni su ogni elemento e consente di impostare alcuni attributi:
- **`kSecReturnData`**: se è true, tenterà di decrittografare i dati (impostalo su false per evitare potenziali pop-up)
- **`kSecReturnRef`**: ottiene anche un riferimento all'elemento del keychain (impostalo su true nel caso in cui in seguito si verifichi che è possibile decrittografarlo senza pop-up)
- **`kSecReturnAttributes`**: ottiene i metadati degli elementi
- **`kSecMatchLimit`**: quanti risultati restituire
- **`kSecClass`**: quale tipo di elemento del keychain

Ottieni le **ACL** di ogni elemento:<sup>[[1]](#references)</sup>

- Con l'API **`SecAccessCopyACLList`** puoi ottenere l'**ACL dell'elemento del keychain**. Restituisce un elenco di ACL (come `ACLAuthorizationExportClear` e le altre menzionate in precedenza), in cui ogni elemento contiene:
- Descrizione
- **Elenco delle applicazioni attendibili**. Può trattarsi di:
- Un'app: /Applications/Slack.app
- Un binary: /usr/libexec/airportd
- Un gruppo: group://AirPort

Esporta i dati:<sup>[[1]](#references)</sup>

- L'API **`SecKeychainItemCopyContent`** ottiene il plaintext
- L'API **`SecItemExport`** esporta le chiavi e i certificati, ma potrebbe essere necessario impostare password per esportare il contenuto cifrato

Questi sono i **requisiti** per poter **esportare un secret senza un prompt**:<sup>[[1]](#references)</sup>

- Se sono elencate **1 o più applicazioni attendibili**:
- Sono necessarie le **autorizzazioni** appropriate (**`Nil`**, oppure devi essere **parte** dell'elenco di app autorizzate nell'autorizzazione ad accedere alle informazioni secret)
- La code signature deve corrispondere al **PartitionID**
- La code signature deve corrispondere a quella di una **app attendibile** (oppure devi essere membro del KeychainAccessGroup corretto)
- Se **tutte le applicazioni sono attendibili**:
- Sono necessarie le **autorizzazioni** appropriate
- La code signature deve corrispondere al **PartitionID**
- Se non è presente un **PartitionID**, questo requisito non è necessario

> [!CAUTION]
> Pertanto, se è elencata **1 applicazione**, è necessario **iniettare codice in quell'applicazione**.
>
> Se nel **partitionID** è indicato **apple**, puoi accedervi con **`osascript`**, quindi questo vale per tutto ciò che considera attendibili tutte le applicazioni con apple nel partitionID. È possibile usare anche **`Python`**.

### Due attributi aggiuntivi

- **Invisible**: è un flag booleano per **nascondere** l'elemento dall'app **UI** Keychain<sup>[[1]](#references)</sup>
- **General**: serve per memorizzare **metadati** (quindi NON È CIFRATO)<sup>[[1]](#references)</sup>
- Microsoft memorizzava in testo in chiaro tutti i refresh token per accedere a endpoint sensibili.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
{{#include ../../banners/hacktricks-training.md}}
