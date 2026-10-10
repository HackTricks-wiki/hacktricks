# Token di accesso

{{#include ../../banners/hacktricks-training.md}}

## Token di accesso

Ogni processo ha un **token di accesso primario** che definisce il proprio contesto di sicurezza. Un thread usa normalmente quel token, ma può avere temporaneamente anche un **token di impersonificazione**. I token contengono il SID dell'utente, i SID dei gruppi, i privilegi, le informazioni sull'integrità e un SID di accesso per la sessione di accesso. In genere, i processi ereditano un riferimento al token primario del processo padre; non ricevono una copia indipendente del suo contenuto.<sup>[[4]](#references)</sup>

Puoi visualizzare queste informazioni eseguendo `whoami /all`

```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

oppure usando _Process Explorer_ di Sysinternals (seleziona il processo e accedi alla scheda "Security"):

![Access Tokens - Access Tokens: oppure usando Process Explorer di Sysinternals (seleziona il processo e accedi alla scheda "Security")](<../../images/image (772).png>)

### Amministratore locale

Quando per un amministratore è attiva la **modalità Admin Approval Mode di UAC**, l'accesso interattivo crea un token di amministratore completo e un token filtrato. Per impostazione predefinita, Explorer e i normali processi figlio usano il token filtrato. Una richiesta di elevazione, come **Esegui come amministratore**, chiede a UAC di avviare il programma con il token completo. Il comportamento esatto varia per l'account Administrator predefinito e quando Admin Approval Mode è disabilitata.<sup>[[5]](#references)</sup>

Consulta la [**pagina dedicata a UAC**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) per le tecniche di bypass e i dettagli dei criteri.

In pratica, questo significa che una **shell di amministratore non elevata viene solitamente eseguita con un token filtrato**. Per questo `whoami /groups` mostra spesso **`BUILTIN\Administrators` come `Deny only`** finché il processo non viene elevato. Internamente, Windows conserva un **token elevato collegato** (`TokenLinkedToken`) e tiene traccia dello stato con campi come `TokenElevationType`.

### Impersonificazione dell'utente tramite credenziali

Se disponi di **credenziali valide di un altro utente**, puoi **creare** una **nuova sessione di accesso** con quelle credenziali:

```
runas /user:domain\username cmd.exe
```

L'**access token** contiene anche un **riferimento** alle sessioni di accesso all'interno di **LSASS**; è utile se il processo deve accedere ad alcune risorse di rete.\
Puoi avviare un processo che **utilizza credenziali diverse per accedere ai servizi di rete** usando:

```
runas /user:domain\username /netonly cmd.exe
```

Questo è utile se disponi di credenziali valide per accedere agli oggetti nella rete, ma non valide sull'host corrente, perché verranno utilizzate solo nella rete (sull'host corrente verranno usati i privilegi dell'utente attuale).

#### Dettagli di `runas /netonly`

`runas /netonly` (e gli helper C2 come `make_token`) crea un token **`LOGON32_LOGON_NEW_CREDENTIALS`**. È molto utile da comprendere durante il lateral movement perché:<sup>[[3]](#references)</sup>

- **Localmente**, il nuovo processo mantiene **la stessa identità locale**, gli stessi gruppi, lo stesso livello di integrità e, per la maggior parte, le stesse decisioni di accesso del token corrente.
- **In remoto**, l'autenticazione in uscita può usare le **credenziali fornite** per SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Di conseguenza, `whoami` può continuare a mostrare **l'utente locale originale**, mentre l'accesso alla rete avviene come **account alternativo**.

È un'ottima opzione quando le credenziali sono valide nel dominio o su un altro host, ma l'utente **non può o non dovrebbe accedere localmente** alla macchina corrente.

### Tipi di token

Sono disponibili due tipi di token:<sup>[[4]](#references)[[6]](#references)</sup>

- **Token primario**: rappresenta il contesto di sicurezza di un processo. Normalmente un processo figlio eredita il token primario del processo padre, mentre le API per la creazione di processi con un token esplicito impongono requisiti specifici relativi all'accesso al token e ai privilegi del chiamante.
- **Token di impersonificazione**: consente a un thread del server di usare temporaneamente il contesto di sicurezza di un client per i controlli di accesso. I suoi quattro livelli sono:
  - **Anonymous**: concede al server un accesso simile a quello di un utente non identificato.
  - **Identification**: consente al server di verificare l'identità del client senza usarla per accedere agli oggetti.
  - **Impersonation**: consente al server di operare con l'identità del client.
  - **Delegation**: consente al server di impersonare il client su sistemi remoti quando il meccanismo di autenticazione e la configurazione dell'account supportano la delega.

#### Valutare un token acquisito prima di usarlo

Non selezionare un token basandoti solo sul nome utente. Lo stesso account può avere diversi token con sessioni di accesso, SID di servizio, privilegi, livelli di integrità, restrizioni e credenziali di rete differenti.<sup>[[9]](#references)</sup> Interroga almeno **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** e **`TokenStatistics.AuthenticationId`** con `GetTokenInformation`.<sup>[[7]](#references)</sup>

Un token con restrizioni può contenere SID di sola negazione, privilegi rimossi e SID di restrizione. Se sono presenti SID di restrizione, Windows esegue un controllo di accesso con i SID abilitati e un altro con i SID di restrizione; **entrambi i controlli devono consentire l'accesso**. Pertanto, un SID utente interessante o un gruppo abilitato nell'output non dimostra, da solo, che il token possa accedere all'oggetto di destinazione.<sup>[[8]](#references)</sup>

Segui questo flusso decisionale per i requisiti documentati relativi ai token e alla creazione dei processi:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Un **token primario** richiede un handle con `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` prima di poter essere passato a `CreateProcessWithTokenW` o `CreateProcessAsUserW`.
2. Converti un **token di impersonificazione** con `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. I token di livello Identification possono esporre i dati dell'identità, ma non possono eseguire controlli di accesso come quel client.
3. `CreateProcessWithTokenW` richiede `SeImpersonatePrivilege` e avvia il processo figlio nella sessione del chiamante. `CreateProcessAsUserW` usa invece la sessione del token, ma normalmente richiede `SeIncreaseQuotaPrivilege` e può richiedere `SeAssignPrimaryTokenPrivilege`. Se sono disponibili credenziali ma mancano questi privilegi, `CreateProcessWithLogonW` è l'alternativa documentata.

#### Cercare gli handle dei token, non solo i proprietari dei processi

Aprire il token primario di ogni processo può non rilevare **token di impersonificazione conservati come handle ordinari** all'interno di servizi e processi broker. Un flusso di lavoro riutilizzabile per la tabella degli handle consiste nell'enumerare gli handle di sistema, filtrare gli oggetti token, aprire ogni proprietario con `PROCESS_DUP_HANDLE`, duplicare l'handle candidato nel processo corrente e poi interrogare i campi indicati sopra. Verifica che l'handle duplicato includa `TOKEN_QUERY` e `TOKEN_DUPLICATE`; individuare un handle di token non significa che possa essere duplicato in un token primario utilizzabile. I processi protetti e le DACL dei processi possono comunque impedire l'apertura dell'handle del processo proprietario.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` automatizza l'enumerazione dei token primari dei processi e degli handle di token conservati. `list_token` mantiene un candidato preferito per ogni nome utente, mentre `list_all_token` stampa tutti i candidati. Un PID limita l'enumerazione a un solo processo proprietario.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Per l’ispezione manuale e la verifica degli accessi, **TokenUniverse** può aprire token di processi/thread, cercare handle di token esistenti, ispezionare restrizioni e sessioni di logon, duplicare token e testare diversi metodi di creazione dei processi.<sup>[[13]](#references)</sup> Per la primitiva sottostante degli handle tra processi, vedi:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Impersonate Tokens

Usando il modulo _**incognito**_ di metasploit, se disponi di privilegi sufficienti puoi facilmente **elencare** e **impersonare** altri **token**. Questo può essere utile per eseguire **azioni come se fossi l'altro utente**. Con questa tecnica puoi anche **escalare i privilegi**.

Alcune note pratiche facili da dimenticare durante l'uso:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** richiede **`SeImpersonatePrivilege`** nel chiamante e il nuovo processo verrà eseguito nella **sessione del chiamante**.
- **`CreateProcessAsUserW`** è una possibile alternativa quando `CreateProcessWithTokenW` restituisce `1314`, ma solo se il chiamante soddisfa i requisiti di privilegi. È anche la scelta corretta quando il processo figlio deve essere eseguito nella **sessione a cui fa riferimento il token**.<sup>[[9]](#references)[[10]](#references)</sup>
- Se un token proviene da **`LogonUser(LOGON32_LOGON_NETWORK)`**, di solito è un **token di impersonation**; quindi, prima di provare ad avviare un processo con esso, devi usare **`DuplicateTokenEx(..., TokenPrimary, ...)`**.
- Non tutti i token di impersonation sono ugualmente utili: **`SecurityIdentification`** consente di ispezionare l'utente, ma **non di agire per suo conto**. Se una primitiva di coercion o un client pipe/RPC ti fornisce solo un token di livello identification, controlla **`TokenImpersonationLevel`** e passa a una primitiva che restituisca **`SecurityImpersonation`** o un livello superiore.

#### Furto di token senza toccare LSASS

Se disponi già di un contesto **service** o **SYSTEM** e un **utente privilegiato ha effettuato l'accesso**, rubare o duplicare il token di quell'utente è spesso più discreto che eseguire il dump di **LSASS**. In molte intrusioni reali questo è sufficiente per:<sup>[[2]](#references)</sup>

- eseguire azioni locali come quell'utente
- accedere a risorse remote come quell'utente
- eseguire operazioni AD senza prima estrarre credenziali riutilizzabili

Per esempi di **hijacking dei token di sessione/utente** da un contesto privilegiato, consulta [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Ricorda che API come **`WTSQueryUserToken`** sono destinate a **servizi altamente attendibili** e normalmente richiedono **`LocalSystem` + `SeTcbPrivilege`**; sono quindi utili soprattutto quando hai già il controllo di un contesto a livello di servizio. Per conoscere i metodi basati su privilegi specifici per ottenere prima **SYSTEM**, consulta le pagine seguenti.

### Privilegi dei token

Scopri quali **privilegi dei token possono essere abusati per escalare i privilegi:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Consulta [**tutti i possibili privilegi dei token e alcune definizioni in questa pagina esterna**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Comprendere e abusare degli Access Token — Parte II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusare dei token di Windows per compromettere Active Directory senza toccare LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Fare chiarezza sul comando "make_token" di Cobalt Strike](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Access Token - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Come funziona User Account Control - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Livelli di impersonation - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Enumerazione TOKEN_INFORMATION_CLASS - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Token con restrizioni - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Funzione CreateProcessWithTokenW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Funzione CreateProcessAsUserW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Funzione DuplicateHandle - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
