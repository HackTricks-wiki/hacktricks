# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Keychain principali

- Il **Keychain utente** (`~/Library/Keychains/login.keychain-db`), usato per memorizzare **credenziali specifiche dell'utente** come password delle applicazioni, password Internet, certificati generati dall'utente, password di rete e chiavi pubbliche/private generate dall'utente.
- Il **Keychain di sistema** (`/Library/Keychains/System.keychain`), che memorizza **credenziali a livello di sistema** come password WiFi, certificati root di sistema, chiavi private di sistema e password delle applicazioni di sistema.<sup>[[1]](#references)</sup>
  - È possibile trovare altri componenti, come i certificati, in `/System/Library/Keychains/*`
- In **iOS** esiste un solo **Keychain**, situato in `/private/var/Keychains/`. Questa cartella contiene anche i database per `TrustStore`, le autorità di certificazione (`caissuercache`) e le voci OSCP (`ocspache`).
  - Le app possono accedere nel keychain solo alla propria area privata, in base all'identificatore dell'applicazione.

### Accesso al Keychain tramite password

Questi file, pur non avendo protezioni intrinseche e potendo essere **scaricati**, sono crittografati e richiedono la **password dell'utente in testo in chiaro per essere decrittati**. Per la decrittazione è possibile usare uno strumento come [**Chainbreaker**](https://github.com/n0fate/chainbreaker).<sup>[[1]](#references)</sup>

## Protezioni delle voci del Keychain

### ACL

Ogni voce del keychain è regolata da **liste di controllo degli accessi (ACL)**, che stabiliscono chi può eseguire diverse azioni sulla voce del keychain, tra cui:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: consente al titolare di ottenere il segreto in testo in chiaro.
- **`kSecACLAuthorizationExportWrapped`**: consente al titolare di ottenere il testo in chiaro crittografato con un'altra password fornita.
- **`kSecACLAuthorizationAny`**: consente al titolare di eseguire qualsiasi azione.

Le ACL sono inoltre accompagnate da un **elenco di applicazioni attendibili** che possono eseguire queste azioni senza mostrare una richiesta. L'elenco può essere:<sup>[[1]](#references)</sup>

- **N`il`** (non è richiesta alcuna autorizzazione, **tutti sono attendibili**)
- Un elenco **vuoto** (**nessuno** è attendibile)
- Un **elenco** di **applicazioni** specifiche.

La voce potrebbe inoltre contenere la chiave **`kSecACLAuthorizationPartitionID`,** usata per identificare **teamid, apple** e **cdhash**.<sup>[[1]](#references)[[2]](#references)</sup>

- Se è specificato **teamid**, l'applicazione deve avere lo **stesso teamid** per **accedere al valore della voce** senza una **richiesta**.
- Se è specificato **apple**, l'app deve essere **firmata** da **Apple**.
- Se è indicato **cdhash**, l'**app** deve avere lo specifico **cdhash**.

### Creazione di una voce nel Keychain

Quando si crea una **nuova** **voce** usando **`Keychain Access.app`**, si applicano le seguenti regole:<sup>[[1]](#references)</sup>

- Tutte le app possono crittografare.
- **Nessuna app** può esportare/decrittare (senza mostrare una richiesta all'utente).
- Tutte le app possono visualizzare il controllo di integrità.
- Nessuna app può modificare le ACL.
- Il **partitionID** è impostato su **`apple`**.

Quando un'**applicazione crea una voce nel keychain**, le regole sono leggermente diverse:<sup>[[1]](#references)</sup>

- Tutte le app possono crittografare.
- Solo l'**applicazione che l'ha creata** (o altre app aggiunte esplicitamente) può esportare/decrittare (senza mostrare una richiesta all'utente).
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
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` imposta la partition list dell'elemento, mentre `-k` fornisce la password corrente del Keychain necessaria per apportare la modifica; il flag che accetta la password è deprecato.<sup>[[4]](#references)</sup> Un aggiornamento riuscito non dimostra che una lettura successiva avverrà senza prompt: è stato osservato che un prototipo disabilitato continuava a generare una richiesta di conferma quando interrogava l'elemento tramite `Security.framework`. Un partition ID corrispondente è solo una parte dei controlli ACL e delle applicazioni attendibili descritti sopra, quindi verifica il percorso di lettura effettivo.<sup>[[3]](#references)</sup>

### API

> [!TIP]
> L'**enumerazione del Keychain e il dumping** dei segreti che **non generano un prompt** possono essere eseguiti con lo strumento [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Altri endpoint API si trovano nel codice sorgente di [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Elenca e recupera le **informazioni** su ogni voce del Keychain usando il **Security Framework**, oppure puoi consultare lo strumento CLI open source di Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Alcuni esempi di API:<sup>[[1]](#references)</sup>

- L'API **`SecItemCopyMatching`** restituisce informazioni su ogni voce e consente di impostare alcuni attributi:
  - **`kSecReturnData`**: se è true, tenterà di decifrare i dati (impostalo su false per evitare eventuali popup)
  - **`kSecReturnRef`**: recupera anche un riferimento all'elemento del Keychain (impostalo su true nel caso in cui in seguito risulti possibile decifrare senza popup)
  - **`kSecReturnAttributes`**: recupera i metadati delle voci
  - **`kSecMatchLimit`**: quanti risultati restituire
  - **`kSecClass`**: il tipo di voce del Keychain

Recupera le **ACL** di ogni voce:<sup>[[1]](#references)</sup>

- Con l'API **`SecAccessCopyACLList`** puoi recuperare l'**ACL dell'elemento del Keychain**. Restituisce un elenco di ACL (come `kSecACLAuthorizationExportClear` e le altre menzionate in precedenza), in cui ogni voce contiene:<sup>[[1]](#references)[[2]](#references)</sup>
  - Descrizione
  - **Elenco delle applicazioni attendibili**. Può essere:
    - Un'app: /Applications/Slack.app
    - Un binario: /usr/libexec/airportd
    - Un gruppo: group://AirPort

Esporta i dati:<sup>[[1]](#references)</sup>

- L'API **`SecKeychainItemCopyContent`** recupera il testo in chiaro
- L'API **`SecItemExport`** esporta le chiavi e i certificati, ma potrebbe essere necessario impostare password per esportare il contenuto cifrato

Questi sono i **requisiti** per poter **esportare un segreto senza un prompt**:<sup>[[1]](#references)</sup>

- Se è elencata almeno **1 app attendibile**:
  - Sono necessarie le **autorizzazioni** appropriate (**`Nil`** oppure l'app deve essere **inclusa** nell'elenco delle app autorizzate ad accedere alle informazioni segrete)
  - La firma del codice deve corrispondere al **PartitionID**
  - La firma del codice deve corrispondere a quella di un'**app attendibile** (oppure l'app deve appartenere al KeychainAccessGroup corretto)
- Se tutte le applicazioni sono attendibili:
  - Sono necessarie le **autorizzazioni** appropriate
  - La firma del codice deve corrispondere al **PartitionID**
    - Se non c'è un **PartitionID**, questo requisito non è necessario

> [!CAUTION]
> Pertanto, se è elencata **1 applicazione**, è necessario **iniettare codice in quell'applicazione**.
>
> Se **apple** è indicato nel **partitionID**, puoi accedervi con **`osascript`**: questo vale per qualsiasi elemento che si fidi di tutte le applicazioni con apple nel partitionID. È possibile usare anche **`Python`**.

### Due attributi aggiuntivi

- **Invisible**: è un flag booleano che **nasconde** la voce nell'app Keychain dell'**interfaccia utente**<sup>[[1]](#references)</sup>
- **General**: serve a memorizzare **metadati** (quindi NON È CIFRATO)<sup>[[1]](#references)</sup>
  - Microsoft memorizzava in testo in chiaro tutti i refresh token per accedere a endpoint sensibili.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [#OBTS v5.0: "Scassinare il Keychain di macOS" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - Una nuova versione del malware stealer MacSync per macOS prende di mira gli appassionati di criptovalute e gli sviluppatori](https://securelist.com/macsync-new-version/121383/)
- [4] [Mirror della pagina man di Apple security(1)](https://keith.github.io/xcode-man-pages/security.1.html)
