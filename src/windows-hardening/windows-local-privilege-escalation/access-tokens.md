# Token di accesso

{{#include ../../banners/hacktricks-training.md}}

## Token di accesso

Ogni **utente connesso** al sistema **dispone di un token di accesso contenente informazioni di sicurezza** per quella sessione di accesso. Il sistema crea un token di accesso quando l'utente effettua l'accesso. **Ogni processo eseguito** per conto dell'utente **dispone di una copia del token di accesso**. Il token identifica l'utente, i gruppi dell'utente e i privilegi dell'utente. Un token contiene anche un SID di accesso (Security Identifier) che identifica la sessione di accesso corrente.

È possibile visualizzare queste informazioni eseguendo `whoami /all`
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
o usando _Process Explorer_ di Sysinternals (seleziona il processo e accedi alla scheda "Security"):

![Access Tokens - Access Tokens: oppure usando Process Explorer di Sysinternals (seleziona il processo e accedi alla scheda "Security")](<../../images/image (772).png>)

### Amministratore locale

Quando un amministratore locale effettua l'accesso, vengono creati **due access token**: uno con diritti di amministratore e l'altro con diritti normali. **Per impostazione predefinita**, quando questo utente esegue un processo, viene utilizzato quello con **diritti** **normali** (non da amministratore). Quando questo utente tenta di **eseguire** qualcosa **come amministratore** (ad esempio, "Run as Administrator"), verrà utilizzato **UAC** per richiedere l'autorizzazione.\
Se vuoi [**saperne di più su UAC, leggi questa pagina**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

In pratica, ciò significa che una **shell di amministratore non elevata generalmente viene eseguita con un token filtrato**. Per questo motivo, `whoami /groups` mostra spesso **`BUILTIN\Administrators` come `Deny only`** finché il processo non viene elevato. Internamente, Windows mantiene un **token elevato collegato** (`TokenLinkedToken`) e tiene traccia dello stato tramite campi come `TokenElevationType`.

### Impersonazione dell'utente tramite credenziali

Se disponi di **credenziali valide di qualsiasi altro utente**, puoi **creare** una **nuova sessione di accesso** con tali credenziali:
```
runas /user:domain\username cmd.exe
```
L'**access token** contiene anche un **riferimento** alle sessioni di accesso all'interno di **LSASS**; questo è utile se il processo deve accedere ad alcuni oggetti della rete.\
Puoi avviare un processo che **utilizza credenziali diverse per accedere ai servizi di rete** usando:
```
runas /user:domain\username /netonly cmd.exe
```
Questo è utile se disponi di credenziali valide per accedere agli oggetti nella rete, ma tali credenziali non sono valide all'interno dell'host corrente, poiché verranno utilizzate solo nella rete (nell'host corrente verranno utilizzati i privilegi dell'utente attuale).

#### Dettagli di `runas /netonly`

`runas /netonly` (e helper C2 come `make_token`) crea un token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Questo è molto utile da comprendere durante il lateral movement perché:<sup>[[3]](#references)</sup>

- **Localmente**, il nuovo processo mantiene la **stessa identità locale**, gli stessi gruppi, lo stesso livello di integrità e la maggior parte delle stesse decisioni di accesso del token corrente.
- **Da remoto**, l'autenticazione in uscita può utilizzare le **credenziali fornite** per SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Di conseguenza, `whoami` può continuare a mostrare l'**utente locale originale**, mentre l'accesso alla rete avviene come **account alternativo**.

Questa è un'ottima opzione quando le credenziali sono valide nel dominio o in un altro host, ma l'utente **non può o non dovrebbe effettuare il logon localmente** sulla macchina corrente.

### Tipi di token

Sono disponibili due tipi di token:

- **Primary Token**: Funziona come rappresentazione delle credenziali di sicurezza di un processo. La creazione e l'associazione dei primary token ai processi sono azioni che richiedono privilegi elevati, sottolineando il principio della separazione dei privilegi. In genere, un servizio di autenticazione è responsabile della creazione del token, mentre un servizio di logon ne gestisce l'associazione alla shell del sistema operativo dell'utente. È importante notare che, al momento della creazione, i processi ereditano il primary token del processo padre.
- **Impersonation Token**: Permette a un'applicazione server di adottare temporaneamente l'identità del client per accedere a oggetti protetti. Questo meccanismo è suddiviso in quattro livelli operativi:
- **Anonymous**: Concede al server un accesso simile a quello di un utente non identificato.
- **Identification**: Consente al server di verificare l'identità del client senza utilizzarla per accedere agli oggetti.
- **Impersonation**: Permette al server di operare usando l'identità del client.
- **Delegation**: Simile a Impersonation, ma include la possibilità di estendere questa assunzione di identità ai sistemi remoti con cui il server interagisce, garantendo la conservazione delle credenziali.

#### Impersonate Tokens

Utilizzando il modulo _**incognito**_ di metasploit, se disponi di privilegi sufficienti puoi facilmente **elencare** e **impersonare** altri **token**. Questo può essere utile per eseguire **azioni come se fossi l'altro utente**. Potresti anche **escalare i privilegi** con questa tecnica.

Alcune note pratiche facili da dimenticare durante le operazioni:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** richiede **`SeImpersonatePrivilege`** nel chiamante e il nuovo processo verrà eseguito nella **sessione del chiamante**.
- **`CreateProcessAsUserW`** è il fallback abituale quando **`CreateProcessWithTokenW`** fallisce con `1314`, oppure quando devi avviare il processo nella **sessione referenziata dal token**.
- Se un token proviene da **`LogonUser(LOGON32_LOGON_NETWORK)`**, di solito è un **impersonation token**, quindi devi utilizzare **`DuplicateTokenEx(..., TokenPrimary, ...)`** prima di tentare di avviare un processo con esso.
- Non tutti gli impersonation token sono ugualmente utili: **`SecurityIdentification`** consente di ispezionare l'utente ma **non di agire a suo nome**. Se una coercion primitive o un client pipe/RPC ti fornisce solo un token a livello di identificazione, controlla **`TokenImpersonationLevel`** e passa a una primitive che restituisca **`SecurityImpersonation`** o superiore.

#### Token theft without touching LSASS

Se disponi già di un contesto **service** o **SYSTEM** e un **utente privilegiato ha effettuato il logon**, rubare o duplicare il token di quell'utente è spesso più discreto rispetto al dumping di **LSASS**. In molte intrusioni reali questo è sufficiente per:<sup>[[2]](#references)</sup>

- eseguire azioni locali come quell'utente
- accedere a risorse remote come quell'utente
- eseguire operazioni AD senza estrarre prima credenziali riutilizzabili

Per esempi di **session/user token hijacking** da un contesto privilegiato, consulta [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Ricorda che API come **`WTSQueryUserToken`** sono pensate per **servizi altamente affidabili** e normalmente richiedono **`LocalSystem` + `SeTcbPrivilege`**, quindi sono principalmente utili una volta ottenuto il controllo di un contesto a livello di servizio. Per metodi specifici dei privilegi con cui ottenere prima **SYSTEM**, consulta le pagine seguenti.

### Token Privileges

Scopri quali **privilegi dei token possono essere abusati per escalare i privilegi:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Dai un'occhiata a [**tutti i possibili privilegi dei token e ad alcune definizioni in questa pagina esterna**](https://github.com/gtworek/Priv2Admin).

## Riferimenti

- [1] [Understanding and Abusing Access Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Demystifying Cobalt Strike's "make_token" Command](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
