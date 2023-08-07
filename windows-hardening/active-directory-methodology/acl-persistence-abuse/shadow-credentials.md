# シャドウクレデンシャル

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

## イントロ <a href="#3f17" id="3f17"></a>

このテクニックの[**すべての情報については、元の投稿を確認してください**](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。

要約すると、ユーザー/コンピュータの**msDS-KeyCredentialLink**プロパティに書き込むことができれば、そのオブジェクトの**NTハッシュ**を取得できます。

これは、オブジェクトの**公開-秘密鍵認証資格情報**を設定し、それらを使用して**特別なサービスチケット**を取得できるためです。このサービスチケットには、暗号化されたNTLM\_SUPPLEMENTAL\_CREDENTIALエンティティ内にそのNTLMハッシュが含まれています。

### 必要条件 <a href="#2de4" id="2de4"></a>

このテクニックには以下が必要です：

* 少なくとも1つのWindows Server 2016ドメインコントローラー。
* ドメインコントローラーにインストールされたサーバー認証用のデジタル証明書。
* Active DirectoryでのWindows Server 2016機能レベル。
* ターゲットオブジェクトのmsDS-KeyCredentialLink属性に書き込むための委任された権限を持つアカウントを侵害する。

## 悪用

コンピュータオブジェクトのKey Trustの悪用には、TGTとアカウントのNTLMハッシュを取得した後、追加の手順が必要です。一般的には、次の2つのオプションがあります。

1. **RC4シルバーチケット**を偽造して、対応するホストに特権ユーザーとしてなりすます。
2. TGTを使用して**S4U2Self**を呼び出し、対応するホストに特権ユーザーとしてなりすます。このオプションでは、取得したサービスチケットを変更してサービス名にサービスクラスを含める必要があります。

Key Trustの悪用は、他のアカウントへのアクセスを委任しないため、侵害される可能性のある別のアカウントへのアクセスを制限します。また、特権エスカレーションが達成されるまでクリーンアップが困難なコンピュータアカウントを作成する必要もありません。

Whisker

この記事と一緒に、 " [Whisker](https://github.com/eladshamir/Whisker) "というツールをリリースします。Whiskerは、MichaelのDSInternalsのコードをベースにした、この攻撃を実行するためのC#ラッパーを提供します。WhiskerはLDAPを使用してターゲットオブジェクトを更新し、DSInternalsはLDAPとDirectory Replication Service（DRS）リモートプロトコルを使用してオブジェクトを更新することができます。

[Whisker](https://github.com/eladshamir/Whisker)には、次の4つの機能があります：

* Add — この機能は、公開-秘密鍵ペアを生成し、ユーザーが新しいデバイスからWHfBに登録したかのように、ターゲットオブジェクトに新しいキー資格情報を追加します。
* List — この機能は、ターゲットオブジェクトのmsDS-KeyCredentialLink属性のすべてのエントリをリストします。
* Remove — この機能は、DeviceID GUIDで指定されたターゲットオブジェクトからキー資格情報を削除します。
* Clear — この機能は、ターゲットオブジェクトのmsDS-KeyCredentialLink属性からすべての値を削除します。ターゲットオブジェクトが正当にWHfBを使用している場合、これにより破損します。

## [Whisker](https://github.com/eladshamir/Whisker) <a href="#7e2e" id="7e2e"></a>

Whiskerは、ターゲットアカウントの`msDS-KeyCredentialLink`属性を操作することで、Active Directoryのユーザーアカウントとコンピュータアカウントを乗っ取るためのC#ツールです。これにより、ターゲットアカウントに「シャドウクレデンシャル」が追加されます。

[**Whisker**](https://github.com/eladshamir/Whisker)には、次の4つの機能があります：

* **Add** — この機能は、公開-秘密鍵ペアを生成し、ユーザーが新しいデバイスからWHfBに登録したかのように、ターゲットオブジェクトに新しいキー資格情報を追加します。
* **List** — この機能は、ターゲットオブジェクトのmsDS-KeyCredentialLink属性のすべてのエントリをリストします。
* **Remove** — この機能は、DeviceID GUIDで指定されたターゲットオブジェクトからキー資格情報を削除します。
* **Clear** — この機能は、ターゲットオブジェクトのmsDS-KeyCredentialLink属性からすべての値を削除します。ターゲットオブジェクトが正当にWHfBを使用している場合、これにより破損します。

### Add

ターゲットオブジェクトの**`msDS-KeyCredentialLink`**属性に新しい値を追加します
## [pywhisker](https://github.com/ShutdownRepo/pywhisker) <a href="#7e2e" id="7e2e"></a>

pyWhiskerは、Elad Shamirによって作成され、C＃で書かれたオリジナルのWhiskerのPython版です。このツールは、ターゲットのユーザー/コンピュータのmsDS-KeyCredentialLink属性を操作して、そのオブジェクトを完全に制御することができます。

これは、ImpacketとMichael GrafnetterのDSInternalsのPython版であるPyDSInternalsに基づいています。

このツールは、Dirk-janのPKINITtoolsとともに、UNIXベースのシステムでの完全なプリミティブな攻撃を可能にします。

pyWhiskerは、ターゲットのmsDs-KeyCredentialLink属性に対してさまざまなアクションを実行するために使用できます。

- *list*: 現在のKeyCredentialsのIDと作成時刻を一覧表示します。
- *info*: KeyCredential構造に含まれるすべての情報を表示します。
- *add*: msDs-KeyCredentialLinkに新しいKeyCredentialを追加します。
- *remove*: msDs-KeyCredentialLinkからKeyCredentialを削除します。
- *clear*: msDs-KeyCredentialLinkからすべてのKeyCredentialを削除します。
- *export*: msDs-KeyCredentialLinkからすべてのKeyCredentialをJSON形式でエクスポートします。
- *import*: JSONファイルからKeyCredentialを使用してmsDs-KeyCredentialLinkを上書きします。

pyWhiskerは、次の認証をサポートしています：
- (NTLM) クリアテキストパスワード
- (NTLM) パス・ザ・ハッシュ
- (Kerberos) クリアテキストパスワード
- (Kerberos) パス・ザ・キー/オーバーパス・ザ・ハッシュ
- (Kerberos) パス・ザ・キャッシュ（パス・ザ・チケットの一種）

![](https://github.com/ShutdownRepo/pywhisker/blob/main/.assets/add_pfx.png)

{% hint style="info" %}
[**Readme**](https://github.com/ShutdownRepo/pywhisker)でさらにオプションを確認してください。
{% endhint %}

## [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

いくつかの場合、グループ「Everyone」/「Authenticated Users」/「Domain Users」または他の**広範なグループ**には、ドメイン内のほとんどのユーザーがドメイン内の他のオブジェクトに対して**GenericWrite**/**GenericAll** DACLsを持っています。[**ShadowSpray**](https://github.com/Dec0ne/ShadowSpray/)は、それらすべてに対して**ShadowCredentials**を乱用しようとします。

以下のような手順で行われます：

1. 供給された資格情報でドメインに**ログイン**します（または現在のセッションを使用します）。
2. **ドメインの機能レベルが2016**であることを確認します（Shadow Credentials攻撃は機能しません）。
3. LDAPからドメイン内のすべてのオブジェクト（ユーザーとコンピューター）の**リストを収集**します。
4. リスト内の**各オブジェクト**に対して、以下の操作を行います：
   1. オブジェクトの`msDS-KeyCredentialLink`属性に**KeyCredential**を追加しようとします。
   2. 上記が**成功した場合**、追加されたKeyCredentialを使用して**PKINIT**を使用して**TGT**を要求します。
   3. 上記が**成功した場合**、**UnPACTheHash**攻撃を実行してユーザー/コンピューターの**NTハッシュ**を明らかにします。
   4. **`--RestoreShadowCred`**が指定された場合：追加されたKeyCredentialを削除します（後片付け...）。
   5. **`--Recursive`**が指定された場合：所有している各ユーザー/コンピューターアカウントを使用して**同じプロセス**を実行します。

## 参考文献

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**最新バージョンのPEASSやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけて、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを発見してください。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、[hacktricksのリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudのリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
