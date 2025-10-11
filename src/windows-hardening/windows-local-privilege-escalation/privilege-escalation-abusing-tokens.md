# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

If you **don't know what are Windows Access Tokens** read this page before continuing:


{{#ref}}
access-tokens.md
{{#endref}}

**Potresti riuscire a escalare privilegi abusando dei token che già possiedi**

### SeImpersonatePrivilege

Questo privilegio, se assegnato a un processo, permette l'impersonificazione (ma non la creazione) di qualsiasi token, purché se ne possa ottenere un handle. Un token privilegiato può essere acquisito da un servizio Windows (DCOM) inducendolo a effettuare l'autenticazione NTLM verso un exploit, consentendo poi l'esecuzione di un processo con privilegi SYSTEM. Questa vulnerabilità può essere sfruttata con diversi tool, come [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (richiede che winrm sia disabilitato), [SweetPotato](https://github.com/CCob/SweetPotato) e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Molto simile a **SeImpersonatePrivilege**, usa lo **stesso metodo** per ottenere un token privilegiato.\
Questo privilegio permette poi di **assegnare un primary token** a un processo nuovo/sospeso. Con un token di impersonazione privilegiato si può derivare un primary token (DuplicateTokenEx).\
Con il token si può creare un **nuovo processo** con CreateProcessAsUser o creare un processo sospeso e **impostare il token** (in genere non è possibile modificare il primary token di un processo in esecuzione).

### SeTcbPrivilege

Se hai abilitato questo privilegio puoi usare **KERB_S4U_LOGON** per ottenere un **impersonation token** di qualsiasi altro utente senza conoscere le credenziali, **aggiungere un gruppo arbitrario** (es. admins) al token, impostare il **livello di integrità** del token a "**medium**" e assegnare questo token al **thread corrente** (SetThreadToken).

### SeBackupPrivilege

Questo privilegio causa al sistema di **concedere accesso in lettura completo** a qualsiasi file (limitato alle operazioni di lettura). Viene usato per **leggere gli hash delle password dell'amministratore locale** dal registro; successivamente strumenti come **psexec** o **wmiexec** possono essere usati con l'hash (tecnica Pass-the-Hash). Tuttavia, questa tecnica fallisce in due casi: quando l'account Local Administrator è disabilitato, o quando esiste una policy che rimuove i diritti amministrativi dagli Local Administrators che si connettono da remoto.\
Puoi **ab usare** questo privilegio con:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- seguendo **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Oppure come spiegato nella sezione **escalating privileges with Backup Operators** di:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Questo privilegio concede il permesso di **scrivere qualsiasi file di sistema**, indipendentemente dall'ACL del file. Apre numerose possibilità di escalation, inclusa la possibilità di **modificare servizi**, effettuare DLL Hijacking e impostare **debugger** tramite Image File Execution Options, tra varie altre tecniche.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege è un permesso potente, particolarmente utile quando un utente ha la capacità di impersonare token, ma utile anche in assenza di SeImpersonatePrivilege. Questa capacità si basa sulla possibilità di impersonare un token che rappresenti lo stesso utente e il cui livello di integrità non superi quello del processo corrente.

Punti chiave:

- Impersonificazione senza SeImpersonatePrivilege: è possibile sfruttare SeCreateTokenPrivilege per EoP impersonificando token in particolari condizioni.
- Condizioni per l'impersonificazione del token: l'impersonificazione ha successo se il token target appartiene allo stesso utente e ha un livello di integrità minore o uguale a quello del processo che tenta l'impersonificazione.
- Creazione e modifica di impersonation token: gli utenti possono creare un impersonation token e arricchirlo aggiungendo il SID di un gruppo privilegiato.

### SeLoadDriverPrivilege

Questo privilegio permette di **caricare e scaricare driver di dispositivo** creando una voce di registro con valori specifici per `ImagePath` e `Type`. Poiché l'accesso in scrittura diretto a `HKLM` è ristretto, bisogna utilizzare `HKCU`. Tuttavia, per rendere `HKCU` riconoscibile dal kernel per la configurazione del driver, deve essere seguita una specifica path.

Questa path è `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, dove `<RID>` è il Relative Identifier dell'utente corrente. All'interno di `HKCU` è necessario creare l'intero percorso e impostare due valori:

- `ImagePath`, che è il percorso del binario da eseguire
- `Type`, con valore `SERVICE_KERNEL_DRIVER` (`0x00000001`).

Passaggi da seguire:

1. Accedere a `HKCU` invece di `HKLM` a causa delle restrizioni in scrittura.
2. Creare il percorso `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dentro `HKCU`, dove `<RID>` rappresenta il Relative Identifier dell'utente corrente.
3. Impostare `ImagePath` al percorso di esecuzione del binario.
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
More ways to abuse this privilege in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Questo è simile a **SeRestorePrivilege**. La sua funzione principale permette a un processo di **assumere la proprietà di un oggetto**, aggirando il requisito per l'accesso discrezionale esplicito tramite la concessione dei diritti di accesso WRITE_OWNER. Il processo consiste innanzitutto nell'ottenere la proprietà della chiave del registro interessata per scopi di scrittura, quindi nel modificare la DACL per abilitare le operazioni di scrittura.
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

Questo privilegio consente di **eseguire il debug di altri processi**, incluso leggere e scrivere nella memoria. Con questo privilegio è possibile impiegare varie strategie di memory injection, in grado di eludere la maggior parte degli antivirus e delle soluzioni host intrusion prevention.

#### Dump memory

Puoi usare [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) dalla [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) per **catturare la memoria di un processo**. Nello specifico, ciò può riguardare il processo Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, che è responsabile dell'archiviazione delle credenziali utente una volta che un utente ha effettuato con successo l'accesso a un sistema.

Puoi poi caricare questo dump in mimikatz per ottenere le password:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Per ottenere una shell `NT SYSTEM` puoi usare:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Questo diritto (Perform volume maintenance tasks) permette di aprire raw volume device handles (ad es., \\.\C:) per I/O diretto su disco che bypassa gli ACL NTFS. Con esso puoi copiare i byte di qualsiasi file sul volume leggendo i blocchi sottostanti, abilitando la lettura arbitraria di file contenenti materiale sensibile (ad es., chiavi private della macchina in %ProgramData%\Microsoft\Crypto\, hive del registro, SAM/NTDS via VSS). È particolarmente impattante sui server CA, dove esfiltrare la chiave privata della CA consente di forgiare un Golden Certificate per impersonare qualsiasi principal.

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Verifica privilegi
```
whoami /priv
```
I **tokens che appaiono come Disabled** possono essere abilitati; in realtà puoi abusare sia dei token _Enabled_ sia di quelli _Disabled_.

### Abilitare tutti i tokens

Se hai tokens Disabled, puoi usare lo script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) per abilitare tutti i tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
O lo **script** incorporato in questo [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabella

Riepilogo completo dei privilegi dei token su [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), il sommario sotto elenca solo i modi diretti per sfruttare il privilegio per ottenere una sessione admin o leggere file sensibili.

| Privilege                  | Impatto     | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Leggere file sensibili con `robocopy /b`                                                                                                                                                                                                                                                                                                          | <p>- Può essere più interessante se riesci a leggere %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (e robocopy) non è utile quando si tratta di file aperti.<br><br>- Robocopy richiede sia SeBackup che SeRestore per funzionare con il parametro /b.</p>                                                            |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Creare un token arbitrario incluso i diritti di admin locale con `NtCreateToken`.                                                                                                                                                                                                                                                                  |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicare il token di `lsass.exe`.                                                                                                                                                                                                                                                                                                                 | Script disponibile su [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Caricare un driver kernel buggy come <code>szkg64.sys</code><br>2. Sfruttare la vulnerabilità del driver<br><br>Alternatively, the privilege may be used to unload security-related drivers with <code>ftlMC</code> builtin command. i.e.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. La vulnerabilità di <code>szkg64</code> è elencata come <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Il <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> è stato creato da <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Avviare PowerShell/ISE con il privilegio SeRestore presente.<br>2. Abilitare il privilegio con <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.<br>3. Rinominare utilman.exe in utilman.old<br>4. Rinominare cmd.exe in utilman.exe<br>5. Bloccare la console e premere Win+U</p> | <p>L'attacco può essere rilevato da alcuni software AV.</p><p>Metodo alternativo si basa sulla sostituzione dei binari di servizio memorizzati in "Program Files" usando lo stesso privilegio</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rinominare cmd.exe in utilman.exe<br>4. Bloccare la console e premere Win+U</p>                                                                                                                                       | <p>L'attacco può essere rilevato da alcuni software AV.</p><p>Metodo alternativo si basa sulla sostituzione dei binari di servizio memorizzati in "Program Files" usando lo stesso privilegio.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipolare i token per includere i diritti di admin locale. Potrebbe richiedere SeImpersonate.</p><p>Da verificare.</p>                                                                                                                                                                                                                         |                                                                                                                                                                                                                                                                                                                                |

## Riferimenti

- Dai un'occhiata a questa tabella che definisce i token di Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Dai un'occhiata a [**questo paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) su privesc con i token.
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
