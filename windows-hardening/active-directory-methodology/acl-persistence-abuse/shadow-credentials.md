# シャドウクレデンシャル

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFT](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[Telegramグループ](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有するために、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

## イントロ <a href="#3f17" id="3f17"></a>

**このテクニックに関するすべての情報については、[元の投稿を確認してください](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。**

**要約**: ユーザー/コンピューターの**msDS-KeyCredentialLink**プロパティに書き込むことができれば、そのオブジェクトの**NTハッシュ**を取得できます。

この投稿では、**公開-秘密鍵認証クレデンシャル**を設定して、ターゲットのNTLMハッシュを含む一意の**サービスチケット**を取得する方法が概説されています。このプロセスには、PAC内の暗号化されたNTLM_SUPPLEMENTAL_CREDENTIALが含まれており、これを復号化できます。

### 必要条件

このテクニックを適用するには、特定の条件を満たす必要があります：
- 少なくとも1つのWindows Server 2016ドメインコントローラーが必要です。
- ドメインコントローラーにはサーバー認証デジタル証明書がインストールされている必要があります。
- Active DirectoryはWindows Server 2016機能レベルである必要があります。
- ターゲットオブジェクトの**msDS-KeyCredentialLink**属性を変更する権限を持つアカウントが必要です。

## 悪用

コンピューターオブジェクトのKey Trustの悪用には、TGT（Ticket Granting Ticket）とNTLMハッシュを取得する手順に加えて、次のオプションが含まれます：
1. 特権ユーザーとして振る舞う**RC4シルバーチケット**を作成します。
2. **S4U2Self**を使用してTGTを使用し、**特権ユーザー**を偽装します。この場合、サービスチケットにサービス名にサービスクラスを追加する必要があります。

Key Trustの悪用の重要な利点は、攻撃者が生成したプライベートキーに制限されていることであり、潜在的に脆弱なアカウントに委任されることなく、コンピューターアカウントを作成する必要がないため、削除が難しい場合があることです。

## ツール

### [**Whisker**](https://github.com/eladshamir/Whisker)

この攻撃に対するC#インターフェースを提供するDSInternalsに基づいています。**Whisker**およびそのPythonバージョンである**pyWhisker**は、`msDS-KeyCredentialLink`属性を操作してActive Directoryアカウントを制御することを可能にします。これらのツールは、ターゲットオブジェクトからキークレデンシャルを追加、リスト、削除、クリアするなどのさまざまな操作をサポートしています。

**Whisker**の機能には次のものがあります：
- **Add**: キーペアを生成してキークレデンシャルを追加します。
- **List**: すべてのキークレデンシャルエントリを表示します。
- **Remove**: 指定されたキークレデンシャルを削除します。
- **Clear**: すべてのキークレデンシャルを消去し、合法的なWHfBの使用を妨げる可能性があります。
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

それはImpacketとPyDSInternalsを活用して、**UNIXベースのシステム**にWhiskerの機能を拡張し、リスト、追加、削除KeyCredentials、およびそれらをJSON形式でインポートおよびエクスポートする包括的な攻撃能力を提供します。
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSprayは、広範なユーザーグループがドメインオブジェクトに対して持っているGenericWrite/GenericAll権限を悪用して、ShadowCredentialsを広く適用することを目的としています。これには、ドメインにログインし、ドメインの機能レベルを確認し、ドメインオブジェクトを列挙し、TGT取得およびNTハッシュの明らかにするためにKeyCredentialsを追加しようとする作業が含まれます。クリーンアップオプションと再帰的な悪用戦術がその有用性を高めています。


## 参考文献

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学びましょう</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>!</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセス**したいですか？または、HackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションを見つけます
* [**公式PEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れます
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングトリックを共有するために、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
