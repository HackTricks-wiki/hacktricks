# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## 概要 <a href="#3f17" id="3f17"></a>

**[この technique に関するすべての情報は、元の記事を確認してください](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。**<sup>[[1]](#references)</sup>

要約すると、ユーザーまたはコンピューターの **`msDS-KeyCredentialLink`** を制御できると、攻撃者は key credential を追加し、PKINIT でそのオブジェクトとして認証し、KDC とアカウントが必要なフローをサポートしている場合は、得られた ticket を `S4U2Self`/user-to-user とともに使用して、そのオブジェクトの NT hash を復元できます。<sup>[[1]](#references)</sup>

この記事では、対象の NTLM hash を含む一意の **Service Ticket** を取得するために、**public-private key authentication credentials** を設定する方法が説明されています。このプロセスでは、Privilege Attribute Certificate (PAC) 内の暗号化された NTLM_SUPPLEMENTAL_CREDENTIAL が使用されます。これは復号できます。<sup>[[1]](#references)</sup>

### 要件

この technique を適用するには、以下の条件を満たす必要があります。<sup>[[1]](#references)</sup>

- 少なくとも1台の Windows Server 2016 Domain Controller が必要です。
- Domain Controller に server authentication digital certificate がインストールされている必要があります。
- directory schema に `msDS-KeyCredentialLink` が含まれている必要があります。調査で説明されている実用上の platform 要件は、Windows Server 2016 以降の DC と、KDC 上の PKINIT-capable certificate です。exploitability が domain functional-level label だけで決まると仮定せず、domain の schema/DC mix を確認してください。
- 対象オブジェクトの msDS-KeyCredentialLink attribute を変更する delegated rights を持つアカウントが必要です。

## Abuse

computer objects に対する Key Trust の abuse には、Ticket Granting Ticket (TGT) と NTLM hash の取得以外の手順も含まれます。選択肢には以下があります。<sup>[[1]](#references)</sup>

1. 対象ホスト上で privileged users として振る舞うための **RC4 silver ticket** を作成する。
2. TGT を `S4U2Self` とともに使用して **privileged users** の impersonation を行う。このためには、service name に service class を追加するよう Service Ticket を変更する必要があります。

Key Trust abuse の大きな利点は、攻撃者が生成した private key に限定されることです。これにより、潜在的に脆弱なアカウントへの delegation を回避でき、削除が困難になる可能性のある computer account の作成も必要ありません。<sup>[[1]](#references)</sup>

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker は C# から DSInternals を使用して `msDS-KeyCredentialLink` を操作します。Whisker とその Python counterpart である **pyWhisker** は、key credentials の追加、一覧表示、削除、消去をサポートします。<sup>[[2]](#references)[[4]](#references)</sup>

**Whisker** の機能には以下があります。

- **Add**: key pair を生成し、key credential を追加します。
- **List**: すべての key credential entries を表示します。
- **Remove**: 指定した key credential を削除します。
- **Clear**: すべての key credentials を消去します。これにより、正規の WHfB usage が妨げられる可能性があります。
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhiskerは、ImpacketとPyDSInternalsを使用して**UNIX-like systems**にワークフローを導入し、list/add/removeおよびJSONのimport/export操作に対応します。<sup>[[4]](#references)</sup>
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray は、オペレーターが `GenericWrite`/`GenericAll` などの権限を持つドメインオブジェクトを列挙し、広範囲に key credentials の追加を試みます。また、クリーンアップ/再帰モードも備えています。広範囲への spraying は環境に影響を与え、目立つため、明示的なターゲットを使用し、正確に削除できるよう追加した各 DeviceID を保持してください。<sup>[[3]](#references)</sup>

## References

- [1] [Shadow Credentials: アカウント乗っ取りのための Key Trust Account Mapping の悪用](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - msDS-KeyCredentialLink を操作して AD アカウントを乗っ取るツール](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - ドメイン全体に Shadow Credentials を spraying するツール](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Shadow Credentials ツールの Python 版](https://github.com/ShutdownRepo/pywhisker)
{{#include ../../../banners/hacktricks-training.md}}
