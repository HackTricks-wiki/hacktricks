# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Ogni **utente connesso** al sistema **possiede un access token con informazioni di sicurezza** per quella sessione di logon. Il sistema crea un access token quando l'utente effettua il logon. **Ogni processo eseguito** per conto dell'utente **ha una copia dell'access token**. Il token identifica l'utente, i gruppi dell'utente e i privilegi dell'utente. Un token contiene anche un logon SID (Security Identifier) che identifica la sessione di logon corrente.

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
o usando _Process Explorer_ di Sysinternals (seleziona il processo e accedi alla scheda "Security"):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Amministratore locale

Quando un amministratore locale effettua il login, **vengono creati due access token**: uno con diritti admin e un altro con diritti normali. **Per impostazione predefinita**, quando questo utente esegue un processo viene usato quello con diritti **regolari** (non-amministratore). Quando questo utente cerca di **eseguire** qualcosa **come amministratore** ("Run as Administrator", per esempio) verrà usato il **UAC** per chiedere il permesso.\
Se vuoi [**saperne di più sul UAC, leggi questa pagina**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

In pratica, questo significa che una **shell admin non elevata di solito viene eseguita con un filtered token**. Per questo `whoami /groups` spesso mostra **`BUILTIN\Administrators` come `Deny only`** finché il processo non viene elevato. Internamente, Windows mantiene un **linked elevated token** (`TokenLinkedToken`) e traccia lo stato con campi come `TokenElevationType`.

### Impersonation delle credenziali dell'utente

Se hai **credenziali valide di qualsiasi altro utente**, puoi **creare** una **nuova sessione di logon** con quelle credenziali :
```
runas /user:domain\username cmd.exe
```
Il **access token** ha anche un **reference** delle sessioni di logon all’interno di **LSASS**, questo è utile se il processo deve accedere ad alcuni oggetti della rete.\
Puoi avviare un processo che **usa credenziali diverse per accedere ai servizi di rete** usando:
```
runas /user:domain\username /netonly cmd.exe
```
Questo è utile se hai credenziali valide per accedere a oggetti nella network ma quelle credenziali non sono valide all'interno dell'host corrente, poiché saranno usate solo nella network (nell'host corrente verranno usati i privilegi del tuo utente attuale).

#### Dettagli di `runas /netonly`

`runas /netonly` (e helper C2 come `make_token`) crea un token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Questo è molto utile da capire durante il lateral movement perché:

- **Localmente**, il nuovo processo mantiene la **stessa identità locale**, i gruppi, il livello di integrità e la maggior parte delle stesse decisioni di accesso del token corrente.
- **Remotamente**, l'autenticazione in uscita può usare le **credenziali fornite** per SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Quindi `whoami` può ancora mostrare l'**utente locale originale** mentre l'accesso alla network avviene come **l'account alternativo**.

Questa è un'ottima opzione quando le credenziali sono valide nel domain o in un altro host, ma l'utente **non può o non dovrebbe effettuare l'accesso localmente** alla macchina corrente.

### Tipi di token

Sono disponibili due tipi di token:

- **Primary Token**: Rappresenta le credenziali di sicurezza di un processo. La creazione e l'associazione dei primary token ai processi sono azioni che richiedono privilegi elevati, sottolineando il principio di separazione dei privilegi. In genere, un authentication service è responsabile della creazione del token, mentre un logon service gestisce la sua associazione con la shell del sistema operativo dell'utente. Vale la pena notare che i processi ereditano il primary token del processo padre alla creazione.
- **Impersonation Token**: Consente a un'applicazione server di adottare temporaneamente l'identità del client per accedere a oggetti protetti. Questo meccanismo è suddiviso in quattro livelli di operazione:
- **Anonymous**: Concede accesso al server simile a quello di un utente non identificato.
- **Identification**: Consente al server di verificare l'identità del client senza usarla per l'accesso agli oggetti.
- **Impersonation**: Consente al server di operare sotto l'identità del client.
- **Delegation**: Simile a Impersonation ma include la capacità di estendere questa assunzione di identità ai sistemi remoti con cui il server interagisce, garantendo la conservazione delle credenziali.

#### Impersonate Tokens

Usando il modulo _**incognito**_ di metasploit, se hai privilegi sufficienti puoi facilmente **elencare** e **impersonare** altri **token**. Questo può essere utile per eseguire **azioni come se fossi un altro utente**. Puoi anche **escalare privileges** con questa tecnica.

Alcune note pratiche facili da dimenticare durante l'operazione:

- **`CreateProcessWithTokenW`** richiede **`SeImpersonatePrivilege`** nel chiamante e il nuovo processo verrà eseguito nella **sessione del chiamante**.
- **`CreateProcessAsUserW`** è il fallback usuale quando `CreateProcessWithTokenW` fallisce con `1314`, oppure quando devi avviare nella **sessione referenziata dal token**.
- Se un token proviene da **`LogonUser(LOGON32_LOGON_NETWORK)`**, di solito è un **impersonation token**, quindi prima di provare ad avviare un processo con esso devi usare **`DuplicateTokenEx(..., TokenPrimary, ...)`**.
- Non tutti gli impersonation token sono ugualmente utili: **`SecurityIdentification`** ti consente di ispezionare l'utente ma **non di agire come lui**. Se un primitive di coercion o un client pipe/RPC ti fornisce solo un token a livello di identification, controlla **`TokenImpersonationLevel`** e passa a un primitive che restituisca **`SecurityImpersonation`** o superiore.

#### Token theft senza toccare LSASS

Se hai già un contesto **service** o **SYSTEM** e un **utente privilegiato è connesso**, rubare o duplicare il token di quell'utente è spesso più discreto del dump di **LSASS**. In molte intrusioni reali questo basta per:

- eseguire azioni locali come quell'utente
- accedere a risorse remote come quell'utente
- eseguire operazioni AD senza estrarre prima credenziali riutilizzabili

Per esempi di **session/user token hijacking** da un contesto privilegiato, consulta [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Ricorda che API come **`WTSQueryUserToken`** sono pensate per **servizi altamente affidabili** e normalmente richiedono **`LocalSystem` + `SeTcbPrivilege`**, quindi sono soprattutto utili quando hai già il controllo di un contesto a livello di service. Per modi specifici di ottenere prima **SYSTEM**, consulta le pagine qui sotto.

### Token Privileges

Impara quali **token privileges possono essere abusati per escalate privileges:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Dai un'occhiata a [**tutti i possibili token privileges e alcune definizioni in questa pagina esterna**](https://github.com/gtworek/Priv2Admin).

## References

- [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)
- [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
