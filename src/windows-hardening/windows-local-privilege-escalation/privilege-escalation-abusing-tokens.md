# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Se **non sai cosa sono i Windows Access Tokens** leggi questa pagina prima di continuare:


{{#ref}}
access-tokens.md
{{#endref}}

**Potresti riuscire a scalare privilegi abusando dei token che già possiedi**

### SeImpersonatePrivilege

Questo privilegio, se assegnato a un processo, permette l'impersonificazione (ma non la creazione) di qualsiasi token, purché si possa ottenere una handle su di esso. Un token privilegiato può essere acquisito da un servizio Windows (DCOM) inducendolo a effettuare l'autenticazione NTLM verso un exploit, permettendo poi l'esecuzione di un processo con privilegi SYSTEM. Questa vulnerabilità può essere sfruttata con vari strumenti, come [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (che richiede winrm disabilitato), [SweetPotato](https://github.com/CCob/SweetPotato) e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

È molto simile a **SeImpersonatePrivilege**, usa lo **stesso metodo** per ottenere un token privilegiato.\
Poi, questo privilegio permette **di assegnare un primary token** a un processo nuovo/sospeso. Con il token di impersonificazione privilegiato puoi derivare un primary token (DuplicateTokenEx).\
Con il token, puoi creare un **nuovo processo** con 'CreateProcessAsUser' o creare un processo sospeso e **impostare il token** (in generale, non è possibile modificare il primary token di un processo in esecuzione).

### SeTcbPrivilege

Se hai abilitato questo privilegio puoi usare **KERB_S4U_LOGON** per ottenere un **impersonation token** per qualsiasi altro utente senza conoscere le credenziali, **aggiungere un gruppo arbitrario** (admins) al token, impostare il **livello di integrità** del token a "**medium**", e assegnare questo token al **thread corrente** (SetThreadToken).

### SeBackupPrivilege

Questo privilegio causa il sistema a **concedere pieno accesso in lettura** a qualsiasi file (limitato alle operazioni di lettura). Viene utilizzato per **leggere gli hash delle password degli account Administrator locali** dal registro, dopodiché strumenti come "**psexec**" o "**wmiexec**" possono essere usati con l'hash (tecnica Pass-the-Hash). Tuttavia, questa tecnica fallisce in due casi: quando l'account Local Administrator è disabilitato, o quando è in vigore una policy che rimuove i diritti amministrativi agli Local Administrators che si connettono da remoto.\
Puoi **abusare di questo privilegio** con:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- seguendo **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Oppure come spiegato nella sezione **escalating privileges with Backup Operators** di:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Questo privilegio fornisce il permesso di **scrittura su qualsiasi file di sistema**, indipendentemente dalla Access Control List (ACL) del file. Apre numerose possibilità per l'escalation, inclusa la capacità di **modificare servizi**, eseguire DLL Hijacking e impostare **debugger** tramite Image File Execution Options, oltre ad altre tecniche.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege è un permesso potente, particolarmente utile quando un utente possiede la capacità di impersonare token, ma efficace anche in assenza di SeImpersonatePrivilege. Questa possibilità dipende dalla capacità di impersonare un token che rappresenti lo stesso utente e il cui livello di integrità non superi quello del processo corrente.

**Punti chiave:**

- **Impersonazione senza SeImpersonatePrivilege:** È possibile sfruttare SeCreateTokenPrivilege per EoP impersonando token in condizioni specifiche.
- **Condizioni per l'impersonazione di token:** L'impersonazione avrà successo se il token target appartiene allo stesso utente e ha un livello di integrità minore o uguale a quello del processo che tenta l'impersonazione.
- **Creazione e modifica di impersonation token:** Gli utenti possono creare un impersonation token e potenziarlo aggiungendo il SID di un gruppo privilegiato (Security Identifier).

### SeLoadDriverPrivilege

Questo privilegio permette di **caricare e scaricare driver di dispositivo** creando una voce di registro con valori specifici per `ImagePath` e `Type`. Poiché l'accesso in scrittura diretto a `HKLM` (HKEY_LOCAL_MACHINE) è limitato, deve essere utilizzato `HKCU` (HKEY_CURRENT_USER). Tuttavia, per rendere `HKCU` riconoscibile dal kernel per la configurazione del driver, è necessario seguire un percorso specifico.

Questo percorso è `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, dove `<RID>` è il Relative Identifier dell'utente corrente. All'interno di `HKCU` deve essere creato tutto questo percorso, e vanno impostati due valori:

- `ImagePath`, che è il percorso del binario da eseguire
- `Type`, con valore `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Accedere a `HKCU` invece di `HKLM` a causa dell'accesso in scrittura limitato.
2. Creare il percorso `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` all'interno di `HKCU`, dove `<RID>` rappresenta il Relative Identifier dell'utente corrente.
3. Impostare `ImagePath` sul percorso di esecuzione del binario.
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
Altri modi per abusare di questo privilegio in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Questo è simile a **SeRestorePrivilege**. La sua funzione principale permette a un processo di **assumere la proprietà di un oggetto**, aggirando la necessità di un accesso discrezionale esplicito mediante l'assegnazione del diritto WRITE_OWNER. Il processo consiste prima nell'ottenere la proprietà della chiave di registro destinata per poter scrivere, quindi nel modificare la DACL per abilitare le operazioni di scrittura.
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

Questo privilegio permette di eseguire il debug di altri processi, incluso leggere e scrivere nella memoria. Con questo privilegio possono essere impiegate varie strategie di memory injection, in grado di eludere la maggior parte degli antivirus e delle soluzioni di host intrusion prevention.

#### Dump della memoria

Puoi usare [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) dalla [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) per **catturare la memoria di un processo**. In particolare, questo può essere applicato al processo **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, che è responsabile della memorizzazione delle credenziali utente una volta che un utente ha effettuato con successo l'accesso a un sistema.

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

Questo diritto (Perform volume maintenance tasks) permette di aprire raw volume device handles (ad es., \\.\C:) per I/O diretto su disco che bypassa gli NTFS ACLs. Con esso puoi copiare i byte di qualsiasi file sul volume leggendo i blocchi sottostanti, consentendo la lettura arbitraria di file contenenti materiale sensibile (ad es., chiavi private della macchina in %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS). È particolarmente impattante sui server CA, dove l'esfiltrazione della chiave privata della CA permette di forgiare un Golden Certificate per impersonare qualsiasi entità.

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Verificare i privilegi
```
whoami /priv
```
I **tokens che appaiono come Disabled** possono essere abilitati; in realtà puoi abusare sia dei token _Enabled_ che _Disabled_.

### Abilitare tutti i token

Se hai token disabilitati, puoi usare lo script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) per abilitare tutti i token:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Oppure lo **script** incorporato in questo [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabella

Cheatsheet completo dei privilegi dei token su [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), il riepilogo seguente elenca solo i modi diretti per sfruttare il privilegio per ottenere una sessione admin o leggere file sensibili.

| Privilegio                 | Impatto     | Strumento               | Percorso di esecuzione                                                                                                                                                                                                                                                                                                                              | Osservazioni                                                                                                                                                                                                                                                                                                                    |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`SeAssignPrimaryToken`** | _**Admin**_ | strumento di terze parti| _"Consentirebbe a un utente di impersonare token e ottenere privesc su nt system utilizzando strumenti come potato.exe, rottenpotato.exe e juicypotato.exe"_                                                                                                                                                                                         | Grazie a [Aurélien Chalot](https://twitter.com/Defte_) per l'aggiornamento. Cercherò di riformularlo in modo più 'ricettario' a breve.                                                                                                                                                                                                 |
| **`SeBackup`**             | **Threat**  | _**Comandi integrati**_ | Leggere file sensibili con `robocopy /b`                                                                                                                                                                                                                                                                                                           | <p>- Può essere più interessante se si riesce a leggere %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (e robocopy) non è utile quando si tratta di file aperti.<br><br>- Robocopy richiede sia SeBackup che SeRestore per funzionare con il parametro /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | strumento di terze parti| Creare token arbitrari inclusi diritti locali admin con `NtCreateToken`.                                                                                                                                                                                                                                                                           |                                                                                                                                                                                                                                                                                                                                  |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicare il token di `lsass.exe`.                                                                                                                                                                                                                                                                                                                 | Script da trovare su [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                              |
| **`SeLoadDriver`**         | _**Admin**_ | strumento di terze parti| <p>1. Caricare un kernel driver vulnerabile come <code>szkg64.sys</code><br>2. Sfruttare la vulnerabilità del driver<br><br>In alternativa, il privilegio può essere usato per scaricare driver legati alla sicurezza con il comando builtin <code>fltMC</code>, es.: <code>fltMC sysmondrv</code></p>                                            | <p>1. La vulnerabilità di <code>szkg64</code> è elencata come <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Il <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">codice exploit</a> è stato creato da <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Avviare PowerShell/ISE con il privilegio SeRestore abilitato.<br>2. Abilitare il privilegio con <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.<br>3. Rinominare utilman.exe in utilman.old<br>4. Rinominare cmd.exe in utilman.exe<br>5. Bloccare la console e premere Win+U</p> | <p>L'attacco può essere rilevato da alcuni software AV.</p><p>Il metodo alternativo si basa sulla sostituzione dei binari dei servizi memorizzati in "Program Files" usando lo stesso privilegio</p>                                                                                                                         |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Comandi integrati**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rinominare cmd.exe in utilman.exe<br>4. Bloccare la console e premere Win+U</p>                                                                                                                                     | <p>L'attacco può essere rilevato da alcuni software AV.</p><p>Il metodo alternativo si basa sulla sostituzione dei binari dei servizi memorizzati in "Program Files" usando lo stesso privilegio.</p>                                                                                                                             |
| **`SeTcb`**                | _**Admin**_ | strumento di terze parti| <p>Manipolare i token per includere i diritti locali admin. Può richiedere SeImpersonate.</p><p>Da verificare.</p>                                                                                                                                                                                                                                  |                                                                                                                                                                                                                                                                                                                                  |

## Riferimenti

- Dai un'occhiata a questa tabella che definisce i token di Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Dai un'occhiata a [**questo paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) sul privesc con i token.
- Microsoft – Eseguire attività di manutenzione del volume (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
