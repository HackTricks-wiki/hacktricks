# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Ogni **utente connesso** al sistema **possiede un token di accesso con informazioni di sicurezza** per quella sessione di accesso. Il sistema crea un token di accesso quando l'utente effettua il login. **Ogni processo eseguito** per conto dell'utente **ha una copia del token di accesso**. Il token identifica l'utente, i gruppi dell'utente e i privilegi dell'utente. Un token contiene anche un SID di accesso (Security Identifier) che identifica l'attuale sessione di accesso.

Puoi vedere queste informazioni eseguendo `whoami /all`
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
or usando _Process Explorer_ di Sysinternals (seleziona il processo e accedi alla scheda "Sicurezza"):

![](<../../images/image (772).png>)

### Amministratore locale

Quando un amministratore locale accede, **vengono creati due token di accesso**: uno con diritti di amministratore e l'altro con diritti normali. **Per impostazione predefinita**, quando questo utente esegue un processo, viene utilizzato quello con diritti **regolari** (non amministratore). Quando questo utente cerca di **eseguire** qualsiasi cosa **come amministratore** ("Esegui come amministratore" ad esempio), verrà utilizzato il **UAC** per chiedere il permesso.\
Se vuoi [**saperne di più sul UAC leggi questa pagina**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

### Impersonificazione delle credenziali utente

Se hai **credenziali valide di un altro utente**, puoi **creare** una **nuova sessione di accesso** con quelle credenziali:
```
runas /user:domain\username cmd.exe
```
Il **token di accesso** ha anche un **riferimento** delle sessioni di accesso all'interno del **LSASS**, questo è utile se il processo deve accedere ad alcuni oggetti della rete.\
Puoi avviare un processo che **utilizza credenziali diverse per accedere ai servizi di rete** utilizzando:
```
runas /user:domain\username /netonly cmd.exe
```
Questo è utile se hai credenziali utili per accedere a oggetti nella rete, ma quelle credenziali non sono valide all'interno dell'host attuale poiché saranno utilizzate solo nella rete (nell'host attuale verranno utilizzati i privilegi dell'utente corrente).

### Tipi di token

Ci sono due tipi di token disponibili:

- **Primary Token**: Serve come rappresentazione delle credenziali di sicurezza di un processo. La creazione e l'associazione di token primari con i processi sono azioni che richiedono privilegi elevati, sottolineando il principio della separazione dei privilegi. Tipicamente, un servizio di autenticazione è responsabile della creazione del token, mentre un servizio di accesso gestisce la sua associazione con la shell del sistema operativo dell'utente. Vale la pena notare che i processi ereditano il token primario del loro processo padre al momento della creazione.
- **Impersonation Token**: Consente a un'applicazione server di adottare temporaneamente l'identità del client per accedere a oggetti sicuri. Questo meccanismo è stratificato in quattro livelli di operazione:
- **Anonymous**: Concede accesso al server simile a quello di un utente non identificato.
- **Identification**: Consente al server di verificare l'identità del client senza utilizzarla per l'accesso agli oggetti.
- **Impersonation**: Abilita il server a operare sotto l'identità del client.
- **Delegation**: Simile a Impersonation ma include la possibilità di estendere questa assunzione di identità a sistemi remoti con cui il server interagisce, garantendo la preservazione delle credenziali.

#### Impersonate Tokens

Utilizzando il modulo _**incognito**_ di metasploit, se hai abbastanza privilegi, puoi facilmente **elencare** e **impersonare** altri **token**. Questo potrebbe essere utile per eseguire **azioni come se fossi l'altro utente**. Potresti anche **escalare i privilegi** con questa tecnica.

### Privilegi del Token

Scopri quali **privilegi del token possono essere abusati per escalare i privilegi:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Dai un'occhiata a [**tutti i possibili privilegi del token e alcune definizioni su questa pagina esterna**](https://github.com/gtworek/Priv2Admin).

## Riferimenti

Scopri di più sui token in questi tutorial: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) e [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

{{#include ../../banners/hacktricks-training.md}}
