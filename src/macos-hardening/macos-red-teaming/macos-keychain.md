# Keychain di macOS

{{#include ../../banners/hacktricks-training.md}}

## Keychain principali

- Il **Keychain dell'utente** (`~/Library/Keychains/login.keychain-db`), usato per archiviare **credenziali specifiche dell'utente**, come password delle applicazioni, password Internet, certificati generati dall'utente, password di rete e chiavi pubbliche/private generate dall'utente.
- Il **Keychain di sistema** (`/Library/Keychains/System.keychain`), che archivia **credenziali a livello di sistema**, come password WiFi, certificati root di sistema, chiavi private di sistema e password delle applicazioni di sistema.<sup>[[1]](#references)</sup>
  - È possibile trovare altri componenti, come i certificati, in `/System/Library/Keychains/*`
- Il **keychain di protezione dei dati** per utente appare come **Elementi locali** o **iCloud** in Accesso Portachiavi. È separato da `login.keychain-db` e include elementi solo locali e sincronizzabili; `security` è principalmente uno strumento per keychain basati su file, quindi un risultato breve di `dump-keychain` non esclude la presenza di credenziali qui.<sup>[[5]](#references)</sup>
- In **iOS** esiste un solo **Keychain**, situato in `/private/var/Keychains/`. Questa cartella contiene anche database per `TrustStore`, autorità di certificazione (`caissuercache`) e voci OSCP (`ocspache`).
  - Le app sono limitate nel keychain alla propria area privata, in base all'identificatore dell'applicazione.

### Accesso alle password del Keychain

Un keychain **basato su file** copiato non è in chiaro. La decifratura offline degli elementi protetti richiede la password del keychain o materiale crittografico equivalente; [**Chainbreaker**](https://github.com/n0fate/chainbreaker) è progettato per questo formato.<sup>[[1]](#references)</sup> È diverso da una lettura in tempo reale in una sessione utente sbloccata, in cui i controlli di accesso degli elementi possono consentire la lettura o attivare una richiesta senza richiedere nuovamente la password di login. Il keychain di protezione dei dati usa un modello diverso di protezione e gruppi di accesso.<sup>[[5]](#references)</sup>

## Protezioni delle voci del Keychain

### ACL dei keychain basati su file

Le regole `SecAccess` ACL e dell'elenco delle partizioni riportate di seguito descrivono i keychain **basati su file**. Gli elementi del keychain di protezione dei dati usano invece gruppi di accesso basati sulla firma del codice e condizioni `SecAccessControl` facoltative; non dedurre la loro accessibilità da un dump ACL di un keychain basato su file.<sup>[[5]](#references)</sup>

Ogni voce di un keychain basato su file è regolata da **liste di controllo degli accessi (ACL)** che stabiliscono chi può eseguire diverse azioni sulla voce del keychain, tra cui:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: consente al titolare di ottenere il segreto in chiaro.
- **`kSecACLAuthorizationExportWrapped`**: consente al titolare di ottenere il testo in chiaro, cifrato con un'altra password fornita.
- **`kSecACLAuthorizationAny`**: consente al titolare di eseguire qualsiasi azione.

Le ACL sono inoltre accompagnate da un **elenco di applicazioni attendibili** che possono eseguire queste azioni senza mostrare richieste. L'elenco può essere:<sup>[[1]](#references)</sup>

- **N`il`** (non è richiesta alcuna autorizzazione, **tutti sono attendibili**)
- Un elenco **vuoto** (**nessuno** è attendibile)
- Un **elenco** di **applicazioni** specifiche.

La voce può inoltre contenere la chiave **`kSecACLAuthorizationPartitionID`,** usata per identificare **teamid, apple** e **cdhash**.<sup>[[1]](#references)[[2]](#references)</sup>

- Se è specificato **teamid**, l'applicazione deve avere lo **stesso teamid** per **accedere al valore** della voce **senza** una **richiesta**.
- Se è specificato **apple**, l'app deve essere **firmata** da **Apple**.
- Se è indicato **cdhash**, l'**app** deve avere il cdhash specificato.

### Creazione di una voce in un keychain basato su file

Quando si crea una **nuova** **voce** con **`Keychain Access.app`**, si applicano le regole seguenti:<sup>[[1]](#references)</sup>

- Tutte le app possono cifrare.
- **Nessuna app** può esportare/decifrare (senza chiedere conferma all'utente).
- Tutte le app possono vedere il controllo di integrità.
- Nessuna app può modificare le ACL.
- Il **partitionID** è impostato su **`apple`**.

Quando un'**applicazione crea una voce nel keychain**, le regole sono leggermente diverse:<sup>[[1]](#references)</sup>

- Tutte le app possono cifrare.
- Solo l'**applicazione creatrice** (o altre app aggiunte esplicitamente) può esportare/decifrare (senza chiedere conferma all'utente).
- Tutte le app possono vedere il controllo di integrità.
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

`-S` imposta l'elenco delle partizioni dell'elemento, mentre `-k` fornisce la password attuale del Keychain richiesta per apportare la modifica; il flag che accetta la password è deprecato.<sup>[[4]](#references)</sup> Un aggiornamento riuscito non dimostra che una lettura successiva avverrà senza prompt: un prototipo disabilitato osservato ha comunque attivato un prompt di conferma quando ha interrogato l'elemento tramite `Security.framework`. Un ID di partizione corrispondente è solo uno dei controlli ACL e delle applicazioni attendibili descritti sopra, quindi verifica il percorso di lettura effettivo.<sup>[[3]](#references)</sup>

### API

> [!TIP]
> L'**enumerazione del keychain e il dump** dei segreti che **non generano un prompt** possono essere eseguiti con lo strumento [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Altri endpoint API sono disponibili nel codice sorgente [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Elenca e ottieni **informazioni** su ciascuna voce del keychain usando **Security Framework**, oppure puoi anche consultare lo strumento CLI open source di Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Alcuni esempi di API:<sup>[[1]](#references)</sup>

- L'API **`SecItemCopyMatching`** fornisce informazioni su ciascuna voce e consente di impostare alcuni attributi:
  - **`kSecReturnData`**: se è true, tenterà di decrittografare i dati (impostalo su false per evitare potenziali popup)
  - **`kSecReturnRef`**: ottiene un riferimento a un oggetto chiave, certificato o identità; gli elementi password non hanno questa rappresentazione come oggetto. Usa `kSecReturnPersistentRef` per identificare una password in una query mirata successiva.<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`**: ottiene i metadati delle voci
  - **`kSecMatchLimit`**: quanti risultati restituire
  - **`kSecClass`**: il tipo di voce del keychain

Ottieni le **ACL** di ciascuna voce:<sup>[[1]](#references)</sup>

- Con l'API **`SecAccessCopyACLList`** puoi ottenere l'**ACL dell'elemento del keychain**. Restituisce un elenco di ACL (come `kSecACLAuthorizationExportClear` e le altre menzionate in precedenza), in cui ogni voce contiene:<sup>[[1]](#references)[[2]](#references)</sup>
  - Descrizione
  - **Elenco delle applicazioni attendibili**. Può essere:
    - Un'app: /Applications/Slack.app
    - Un binario: /usr/libexec/airportd
    - Un gruppo: group://AirPort

Esporta i dati:<sup>[[1]](#references)</sup>

- L'API **`SecKeychainItemCopyContent`** recupera il testo in chiaro
- L'API **`SecItemExport`** esporta le chiavi e i certificati, ma potrebbe essere necessario impostare delle password per esportare il contenuto crittografato

Questi sono i **requisiti** per poter **esportare un segreto senza un prompt**:<sup>[[1]](#references)</sup>

- Se è elencata almeno **1 app attendibile**:
  - Servono le **autorizzazioni** appropriate (**`Nil`**, oppure bisogna far **parte** dell'elenco di app autorizzate nell'autorizzazione ad accedere alle informazioni del segreto)
  - La firma del codice deve corrispondere a **PartitionID**
  - La firma del codice deve corrispondere a quella di una **app attendibile** (oppure bisogna appartenere al KeychainAccessGroup corretto)
- Se **tutte le applicazioni sono attendibili**:
  - Servono le **autorizzazioni** appropriate
  - La firma del codice deve corrispondere a **PartitionID**
    - Se **PartitionID è assente**, questo requisito non è necessario

> [!CAUTION]
> Pertanto, se è elencata **1 applicazione**, è necessario **iniettare codice in quell'applicazione**.
>
> Se **apple** è indicato in **partitionID**, puoi accedere con **`osascript`** a qualsiasi elemento che considera attendibili tutte le applicazioni e ha apple in partitionID. Puoi usare anche **`Python`**.

### Due attributi aggiuntivi

- **Invisible**: flag booleano per **nascondere** la voce nell'app Keychain dell'**interfaccia utente**<sup>[[1]](#references)</sup>
- **General**: serve a memorizzare **metadati** (quindi NON È CRITTOGRAFATO)<sup>[[1]](#references)</sup>
  - Microsoft memorizzava in testo semplice tutti i refresh token usati per accedere a endpoint sensibili.<sup>[[1]](#references)</sup>

### Keychain Data Protection: enumerare e poi interrogare un singolo elemento

Esegui `SecItemCopyMatching` da un'**app firmata nel contesto di login dell'utente target** con `kSecUseDataProtectionKeychain: true`; non dare per scontato che `security dump-keychain` o una query SecItem predefinita abbia cercato in questo archivio. Il chiamante vede solo i gruppi di accesso autorizzati.<sup>[[5]](#references)</sup>

Se il codice di test viene eseguito all'interno di un altro processo, l'accesso al suo keychain Data Protection dipende dagli entitlement dell'eseguibile host. Esamina gli entitlement effettivi della firma con `codesign -d --entitlements - /path/to/Target.app` e consulta [gli entitlement di code signing di macOS](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md) per controlli correlati.<sup>[[7]](#references)</sup>

Per prima cosa richiedi **solo gli attributi** per una classe di elementi. `kSecAttrSynchronizableAny` include sia le corrispondenze locali sia quelle sincronizzabili con iCloud; ometterlo esclude gli elementi sincronizzabili.<sup>[[8]](#references)</sup> `kSecUseAuthenticationUISkip` evita l'interfaccia di autenticazione durante l'enumerazione generale, ma esclude le corrispondenze protette.<sup>[[9]](#references)</sup> Se necessario, ripeti con `kSecClassInternetPassword`.

```swift
import Security
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
]
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
print(status)
if status == errSecSuccess, let items = result as? [[String: Any]] {
    for item in items { print(item) }
}
```

Per una lettura autorizzata di un segreto, crea una query **nuova** e circoscritta per l’elemento selezionato (ad esempio, classe, servizio e account), imposta `kSecReturnData: true` e `kSecMatchLimit: kSecMatchLimitOne` e aspettati un’autenticazione specifica per l’elemento o un errore. Non combinare `kSecReturnData` con `kSecMatchLimitAll` per gli elementi password.<sup>[[10]](#references)</sup> Un risultato `errSecItemNotFound` può anche indicare uno store errato, un filtro di sincronizzazione o la mancanza dell’entitlement per il gruppo di accesso, anziché l’assenza di una credenziale.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0: "Scassinare il portachiavi di macOS" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - Una nuova versione del malware stealer MacSync per macOS prende di mira gli appassionati di criptovalute e gli sviluppatori](https://securelist.com/macsync-new-version/121383/)
- [4] [Mirror della pagina man security(1) di Apple](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — API e implementazioni del portachiavi su Mac](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Apple Developer Forums — SecItem: fondamenti](https://developer.apple.com/forums/thread/724023)
- [7] [Apple Developer Forums — SecItem: errori comuni e best practice](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — Accesso agli elementi del portachiavi con Face ID o Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
