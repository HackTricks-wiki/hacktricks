# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## 概要 <a href="#3f17" id="3f17"></a>

**この technique に関する[すべての情報については、原文の記事を確認してください](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。**<sup>[[1]](#references)</sup>

**要約**: ユーザーまたはコンピューターの **msDS-KeyCredentialLink** property に書き込みできる場合、その object の **NT hash** を取得できます。<sup>[[1]](#references)</sup>

この記事では、**public-private key authentication credentials** を設定し、対象の NTLM hash を含む一意の **Service Ticket** を取得する方法が説明されています。このプロセスでは、Privilege Attribute Certificate (PAC) 内の暗号化された NTLM_SUPPLEMENTAL_CREDENTIAL が使用されますが、これは復号できます。<sup>[[1]](#references)</sup>

### 必要条件

この technique を適用するには、以下の条件を満たす必要があります。<sup>[[1]](#references)</sup>

- 少なくとも 1 台の Windows Server 2016 Domain Controller が必要です。
- Domain Controller に server authentication digital certificate がインストールされている必要があります。
- Active Directory が Windows Server 2016 Functional Level である必要があります。
- 対象 object の msDS-KeyCredentialLink attribute を変更するための delegated rights を持つ account が必要です。

## Abuse

computer objects に対する Key Trust の Abuse には、Ticket Granting Ticket (TGT) と NTLM hash の取得以外の手順も含まれます。選択肢は次のとおりです。<sup>[[1]](#references)</sup>

1. 対象 host 上で privileged users として振る舞うために、**RC4 silver ticket** を作成する。
2. **privileged users** を impersonate するために TGT を **S4U2Self** とともに使用する。この場合、service name に service class を追加するために Service Ticket の変更が必要です。

Key Trust abuse の大きな利点は、攻撃者が生成した private key のみに限定されることです。これにより、脆弱性のある可能性がある account への delegation を回避でき、削除が困難な computer account の作成も必要ありません。<sup>[[1]](#references)</sup>

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

DSInternals をベースとしており、この attack に C# interface を提供します。Whisker とその Python counterpart である **pyWhisker** を使用すると、`msDS-KeyCredentialLink` attribute を操作して Active Directory accounts を制御できます。これらの tools は、対象 object の key credentials に対する追加、一覧表示、削除、クリアなど、さまざまな操作をサポートしています。

**Whisker** の functions は次のとおりです。

- **Add**: key pair を生成し、key credential を追加します。
- **List**: すべての key credential entries を表示します。
- **Remove**:指定した key credential を削除します。
- **Clear**: すべての key credentials を消去します。これにより、正規の WHfB の使用が妨げられる可能性があります。
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Whiskerの機能を**UNIXベースのシステム**に拡張し、ImpacketとPyDSInternalsを活用して、KeyCredentialsの一覧表示、追加、削除、およびJSON形式でのインポートとエクスポートを含む包括的なexploit機能を提供します。
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray は、**広範なユーザーグループがドメインオブジェクトに対して持つ可能性のある GenericWrite/GenericAll 権限を悪用し**、ShadowCredentials を広範囲に適用することを目的としています。ドメインへのログイン、ドメインの機能レベルの確認、ドメインオブジェクトの列挙、TGT の取得と NT hash の暴露を目的とした KeyCredentials の追加を試みます。Cleanup オプションと再帰的な悪用手法により、実用性がさらに高められています。

## 参考文献

- [1] [Shadow Credentials: Key Trust Account Mapping を悪用した Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - msDS-KeyCredentialLink を操作して AD アカウントを乗っ取るための Tool](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - ドメイン全体に Shadow Credentials を spray するための Tool](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Shadow Credentials tool の Python version](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
