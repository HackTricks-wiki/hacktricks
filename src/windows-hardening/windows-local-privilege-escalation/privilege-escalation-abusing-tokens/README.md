# Abusing Tokens

{{#include ../../../banners/hacktricks-training.md}}

## Tokens

Se **non sai cosa sono i Windows Access Tokens**, leggi questa pagina prima di continuare:

{{#ref}}
../access-tokens.md
{{#endref}}

**Forse potresti essere in grado di elevare i privilegi abusando dei token che già possiedi**

### SeImpersonatePrivilege

Questo è un privilegio detenuto da qualsiasi processo che consente l'impersonificazione (ma non la creazione) di qualsiasi token, a condizione che si possa ottenere un handle. Un token privilegiato può essere acquisito da un servizio Windows (DCOM) inducendolo a eseguire l'autenticazione NTLM contro un exploit, abilitando successivamente l'esecuzione di un processo con privilegi SYSTEM. Questa vulnerabilità può essere sfruttata utilizzando vari strumenti, come [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (che richiede che winrm sia disabilitato), [SweetPotato](https://github.com/CCob/SweetPotato), [EfsPotato](https://github.com/zcgonvh/EfsPotato), [DCOMPotato](https://github.com/zcgonvh/DCOMPotato) e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{{#ref}}
../roguepotato-and-printspoofer.md
{{#endref}}

{{#ref}}
../juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

È molto simile a **SeImpersonatePrivilege**, utilizzerà il **stesso metodo** per ottenere un token privilegiato.\
Questo privilegio consente **di assegnare un token primario** a un nuovo processo/sospeso. Con il token di impersonificazione privilegiato puoi derivare un token primario (DuplicateTokenEx).\
Con il token, puoi creare un **nuovo processo** con 'CreateProcessAsUser' o creare un processo sospeso e **impostare il token** (in generale, non puoi modificare il token primario di un processo in esecuzione).

### SeTcbPrivilege

Se hai abilitato questo token puoi utilizzare **KERB_S4U_LOGON** per ottenere un **token di impersonificazione** per qualsiasi altro utente senza conoscere le credenziali, **aggiungere un gruppo arbitrario** (amministratori) al token, impostare il **livello di integrità** del token su "**medio**" e assegnare questo token al **thread corrente** (SetThreadToken).

### SeBackupPrivilege

Il sistema è indotto a **concedere a tutti l'accesso in lettura** a qualsiasi file (limitato alle operazioni di lettura) da questo privilegio. Viene utilizzato per **leggere gli hash delle password degli account Administrator locali** dal registro, dopo di che, strumenti come "**psexec**" o "**wmiexec**" possono essere utilizzati con l'hash (tecnica Pass-the-Hash). Tuttavia, questa tecnica fallisce in due condizioni: quando l'account Local Administrator è disabilitato, o quando è in atto una politica che rimuove i diritti amministrativi dagli amministratori locali che si connettono da remoto.\
Puoi **abuse questo privilegio** con:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- seguendo **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- O come spiegato nella sezione **elevare i privilegi con Backup Operators** di:

{{#ref}}
../../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Il permesso per **l'accesso in scrittura** a qualsiasi file di sistema, indipendentemente dalla Access Control List (ACL) del file, è fornito da questo privilegio. Apre numerose possibilità di elevazione, inclusa la capacità di **modificare i servizi**, eseguire DLL Hijacking e impostare **debugger** tramite Image File Execution Options tra varie altre tecniche.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege è un permesso potente, particolarmente utile quando un utente possiede la capacità di impersonare token, ma anche in assenza di SeImpersonatePrivilege. Questa capacità si basa sulla possibilità di impersonare un token che rappresenta lo stesso utente e il cui livello di integrità non supera quello del processo corrente.

**Punti Chiave:**

- **Impersonificazione senza SeImpersonatePrivilege:** È possibile sfruttare SeCreateTokenPrivilege per EoP impersonando token in condizioni specifiche.
- **Condizioni per l'Impersonificazione del Token:** L'impersonificazione riuscita richiede che il token target appartenga allo stesso utente e abbia un livello di integrità che è minore o uguale al livello di integrità del processo che tenta l'impersonificazione.
- **Creazione e Modifica di Token di Impersonificazione:** Gli utenti possono creare un token di impersonificazione e migliorarlo aggiungendo un SID (Security Identifier) di un gruppo privilegiato.

### SeLoadDriverPrivilege

Questo privilegio consente di **caricare e scaricare driver di dispositivo** con la creazione di una voce di registro con valori specifici per `ImagePath` e `Type`. Poiché l'accesso in scrittura diretto a `HKLM` (HKEY_LOCAL_MACHINE) è ristretto, è necessario utilizzare `HKCU` (HKEY_CURRENT_USER). Tuttavia, per rendere `HKCU` riconoscibile dal kernel per la configurazione del driver, deve essere seguita una specifica strada.

Questo percorso è `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, dove `<RID>` è l'Identificatore Relativo dell'utente corrente. All'interno di `HKCU`, deve essere creato l'intero percorso e devono essere impostati due valori:

- `ImagePath`, che è il percorso del binario da eseguire
- `Type`, con un valore di `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Passi da Seguire:**

1. Accedi a `HKCU` invece di `HKLM` a causa dell'accesso in scrittura ristretto.
2. Crea il percorso `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` all'interno di `HKCU`, dove `<RID>` rappresenta l'Identificatore Relativo dell'utente corrente.
3. Imposta `ImagePath` sul percorso di esecuzione del binario.
4. Assegna `Type` come `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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

Questo è simile a **SeRestorePrivilege**. La sua funzione principale consente a un processo di **assumere la proprietà di un oggetto**, eludendo il requisito di accesso discrezionale esplicito attraverso la fornitura di diritti di accesso WRITE_OWNER. Il processo prevede prima di assicurarsi la proprietà della chiave di registro prevista per scopi di scrittura, quindi di modificare il DACL per abilitare le operazioni di scrittura.
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

Questo privilegio consente di **debuggare altri processi**, inclusa la lettura e scrittura nella memoria. Possono essere impiegate varie strategie per l'iniezione di memoria, capaci di eludere la maggior parte delle soluzioni antivirus e di prevenzione delle intrusioni host, con questo privilegio.

#### Dump della memoria

Puoi utilizzare [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) dalla [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) per **catturare la memoria di un processo**. In particolare, questo può applicarsi al processo **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**, che è responsabile della memorizzazione delle credenziali utente una volta che un utente ha effettuato l'accesso con successo a un sistema.

Puoi quindi caricare questo dump in mimikatz per ottenere le password:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Se vuoi ottenere una shell `NT SYSTEM` puoi usare:

- \***\*[**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)\*\***
- \***\*[**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)\*\***
- \***\*[**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)\*\***
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Il `SeManageVolumePrivilege` è un diritto utente di Windows che consente agli utenti di gestire i volumi disco, inclusa la creazione e la cancellazione degli stessi. Sebbene sia destinato agli amministratori, se concesso a utenti non amministratori, può essere sfruttato per l'escalation dei privilegi.

È possibile sfruttare questo privilegio per manipolare i volumi, portando a un accesso completo ai volumi. Il [SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit) può essere utilizzato per dare accesso completo a tutti gli utenti per C:\

Inoltre, il processo descritto in [questo articolo di Medium](https://medium.com/@raphaeltzy13/exploiting-semanagevolumeprivilege-with-dll-hijacking-windows-privilege-escalation-1a4f28372d37) illustra l'uso del DLL hijacking in combinazione con il `SeManageVolumePrivilege` per escalare i privilegi. Posizionando un payload DLL `C:\Windows\System32\wbem\tzres.dll` e chiamando `systeminfo`, la dll viene eseguita.

## Controlla i privilegi
```
whoami /priv
```
I **token che appaiono come Disabilitati** possono essere abilitati, puoi effettivamente abusare dei token _Abilitati_ e _Disabilitati_.

### Abilita tutti i token

Se hai token disabilitati, puoi usare lo script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) per abilitare tutti i token:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or lo **script** incorporato in questo [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabella

Scheda completa dei privilegi del token su [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), il riepilogo qui sotto elencherà solo i modi diretti per sfruttare il privilegio per ottenere una sessione admin o leggere file sensibili.

| Privilegio                 | Impatto     | Strumento               | Percorso di esecuzione                                                                                                                                                                                                                                                                                                                                     | Osservazioni                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Strumento di terze parti | _"Consentirebbe a un utente di impersonare token e privesc al sistema nt utilizzando strumenti come potato.exe, rottenpotato.exe e juicypotato.exe"_                                                                                                                                                                                                      | Grazie [Aurélien Chalot](https://twitter.com/Defte_) per l'aggiornamento. Proverò a riformularlo in qualcosa di più simile a una ricetta presto.                                                                                                                                                                                         |
| **`SeBackup`**             | **Minaccia** | _**Comandi integrati**_ | Leggi file sensibili con `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Potrebbe essere più interessante se puoi leggere %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (e robocopy) non è utile quando si tratta di file aperti.<br><br>- Robocopy richiede sia SeBackup che SeRestore per funzionare con il parametro /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Strumento di terze parti | Crea token arbitrari inclusi i diritti di amministratore locale con `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplica il token `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Script da trovare su [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Strumento di terze parti | <p>1. Carica un driver del kernel difettoso come <code>szkg64.sys</code><br>2. Sfrutta la vulnerabilità del driver<br><br>In alternativa, il privilegio può essere utilizzato per scaricare driver relativi alla sicurezza con il comando integrato <code>ftlMC</code>. i.e.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. La vulnerabilità <code>szkg64</code> è elencata come <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Il <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">codice di sfruttamento</a> è stato creato da <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Avvia PowerShell/ISE con il privilegio SeRestore presente.<br>2. Abilita il privilegio con <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rinomina utilman.exe in utilman.old<br>4. Rinomina cmd.exe in utilman.exe<br>5. Blocca la console e premi Win+U</p> | <p>L'attacco potrebbe essere rilevato da alcuni software antivirus.</p><p>Il metodo alternativo si basa sulla sostituzione dei file binari di servizio memorizzati in "Program Files" utilizzando lo stesso privilegio</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Comandi integrati**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rinomina cmd.exe in utilman.exe<br>4. Blocca la console e premi Win+U</p>                                                                                                                                       | <p>L'attacco potrebbe essere rilevato da alcuni software antivirus.</p><p>Il metodo alternativo si basa sulla sostituzione dei file binari di servizio memorizzati in "Program Files" utilizzando lo stesso privilegio.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Strumento di terze parti | <p>Manipola i token per avere diritti di amministratore locale inclusi. Potrebbe richiedere SeImpersonate.</p><p>Da verificare.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Riferimento

- Dai un'occhiata a questa tabella che definisce i token di Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Dai un'occhiata a [**questo documento**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) riguardo privesc con i token.

{{#include ../../../banners/hacktricks-training.md}}
