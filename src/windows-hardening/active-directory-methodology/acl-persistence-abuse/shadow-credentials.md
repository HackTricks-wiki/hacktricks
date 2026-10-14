# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## 概要 <a href="#3f17" id="3f17"></a>

**この手法に関する[すべての情報](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)は、元の記事を確認してください。**<sup>[[1]](#references)</sup>

要約すると、ユーザーまたはコンピューターの **`msDS-KeyCredentialLink`** を制御できると、攻撃者はキー資格情報を追加し、PKINIT でそのオブジェクトとして認証できます。さらに、KDC とアカウントが必要なフローに対応していれば、取得したチケットを `S4U2Self`/user-to-user と組み合わせて、オブジェクトの NT hash を復元できます。<sup>[[1]](#references)</sup>

この記事では、**公開鍵・秘密鍵による認証資格情報**を設定し、ターゲットの NTLM hash を含む固有の **Service Ticket** を取得する方法が解説されています。このプロセスでは、Privilege Attribute Certificate (PAC) 内の暗号化された NTLM_SUPPLEMENTAL_CREDENTIAL を復号できます。<sup>[[1]](#references)</sup>

### 必要条件

この手法を適用するには、次の条件を満たす必要があります。<sup>[[1]](#references)</sup>

- Windows Server 2016 以降の Domain Controller が少なくとも 1 台必要です。
- Domain Controller にサーバー認証用のデジタル証明書がインストールされている必要があります。
- ディレクトリ スキーマに `msDS-KeyCredentialLink` が含まれている必要があります。調査で示されている実用上のプラットフォーム要件は、Windows Server 2016 以降の DC と、KDC 上の PKINIT 対応証明書です。ドメイン機能レベルの表記だけで悪用可能性を判断せず、ドメインのスキーマと DC の構成を確認してください。
- ターゲット オブジェクトの msDS-KeyCredentialLink 属性を変更する委任権限を持つアカウントが必要です。

## 悪用

コンピューター オブジェクトに対する Key Trust の悪用には、Ticket Granting Ticket (TGT) と NTLM hash の取得以上の手順が含まれます。次の方法があります。<sup>[[1]](#references)</sup>

1. 対象ホストで特権ユーザーとして振る舞うための **RC4 silver ticket** を作成する。
2. TGT を **S4U2Self** で使用して **特権ユーザー**になりすます。この場合、サービス名にサービス クラスを追加するため、Service Ticket の変更が必要です。

Key Trust の悪用には、攻撃者が生成した秘密鍵だけで完結し、脆弱な可能性のあるアカウントへの委任を避けられるという大きな利点があります。また、削除が困難な場合があるコンピューター アカウントを作成する必要もありません。<sup>[[1]](#references)</sup>

## ツール

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker は DSInternals を使用して、C# から `msDS-KeyCredentialLink` を操作します。Whisker とその Python 版 **pyWhisker** は、キー資格情報の追加、一覧表示、削除、全消去に対応しています。<sup>[[2]](#references)[[4]](#references)</sup>

**Whisker** の機能:

- **Add**: キーペアを生成し、キー資格情報を追加します。
- **List**: すべてのキー資格情報エントリを表示します。
- **Remove**: 指定したキー資格情報を削除します。
- **Clear**: すべてのキー資格情報を消去します。正規の WHfB の利用に支障をきたす可能性があります。

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhiskerは、ImpacketとPyDSInternalsを使用して**UNIX系システム**でもワークフローを実行でき、一覧表示/追加/削除やJSONのインポート/エクスポート操作に対応しています。<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSprayは、オペレーターが`GenericWrite`/`GenericAll`などの権限を持つドメインオブジェクトを列挙し、広範囲にkey credentialsの追加を試みます。また、クリーンアップモードや再帰モードも備えています。広範囲にsprayすると、サービスに支障をきたし、目立つおそれがあります。明示的にターゲットを指定し、正確に削除できるよう、追加した各DeviceIDを記録してください。<sup>[[3]](#references)</sup>

直接LDAPがフィルタリングされている場合、ADWS経由でkey-credential writeを実行できます。[SOAPy ADWS workflow](../adws-enumeration.md#shadow-credentials-over-adws)を参照してください。<sup>[[5]](#references)</sup>



## References

- [1] [Shadow Credentials: アカウント乗っ取りを目的としたKey Trust Account Mappingの悪用](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - msDS-KeyCredentialLinkを操作してADアカウントを乗っ取るツール](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - ドメイン全体にShadow Credentialsをsprayするツール](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Shadow CredentialsツールのPython版](https://github.com/ShutdownRepo/pywhisker)
- [5] [SOAPy Wiki – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../../banners/hacktricks-training.md}}
