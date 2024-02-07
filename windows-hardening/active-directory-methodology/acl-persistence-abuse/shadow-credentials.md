# シャドウクレデンシャル

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで企業を宣伝**したいですか？または、**PEASSの最新バージョンを入手したり、HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを入手しましょう。
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手しましょう。
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## イントロ <a href="#3f17" id="3f17"></a>

このテクニックに関するすべての情報については、[**元の投稿**](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)をチェックしてください。

**要約**: ユーザー/コンピューターの**msDS-KeyCredentialLink**プロパティに書き込むことができれば、そのオブジェクトの**NTハッシュ**を取得できます。

これは、オブジェクトのために**公開-秘密鍵認証資格情報**を設定し、それらを使用して**NTLMハッシュを含む特別なサービスチケット**を取得し、暗号化されたNTLM\_SUPPLEMENTAL\_CREDENTIALエンティティ内の特権属性証明書（PAC）にそのハッシュが含まれているためです。

### 必要条件 <a href="#2de4" id="2de4"></a>

このテクニックには以下が必要です：

* 少なくとも1つのWindows Server 2016 ドメインコントローラー。
* ドメインコントローラーにインストールされたサーバー認証用のデジタル証明書。
* Active Directory内のWindows Server 2016機能レベル。
* 対象オブジェクトの**msDS-KeyCredentialLink**属性に書き込む権限を持つアカウントを侵害する。

## 濫用

コンピューターオブジェクトのKey Trustを濫用するには、TGTとアカウントのNTLMハッシュを取得した後、追加の手順が必要です。一般的に、次の2つのオプションがあります：

1. 特権ユーザーを模倣するために**RC4シルバーチケット**を偽造する。
2. TGTを使用して**S4U2Self**を呼び出し、対応するホストに**特権ユーザー**を模倣する。このオプションでは、取得したサービスチケットにサービス名にサービスクラスを含める必要があります。

Key Trustの濫用には、他のアカウントにアクセス権限を委任する必要がないため、**攻撃者によって生成された秘密鍵に制限されています**。さらに、特権昇格が達成されるまでクリーンアップが難しいかもしれないコンピューターアカウントを作成する必要がありません。

Whisker

この投稿と同時に、" [Whisker](https://github.com/eladshamir/Whisker) "というツールをリリースします。Michael's DSInternalsのコードをベースにしたWhiskerは、この攻撃を実行するためのC#ラッパーを提供します。WhiskerはLDAPを使用して対象オブジェクトを更新し、DSInternalsはLDAPとDirectory Replication Service（DRS）リモートプロトコルを使用してオブジェクトを更新することができます。

[Whisker](https://github.com/eladshamir/Whisker)には次の4つの機能があります：

* Add — この機能は、公開-秘密鍵ペアを生成し、ユーザーが新しいデバイスからWHfBに登録したかのように、対象オブジェクトに新しいキークレデンシャルを追加します。
* List — この機能は、対象オブジェクトのmsDS-KeyCredentialLink属性のすべてのエントリをリストします。
* Remove — この機能は、DeviceID GUIDで指定された対象オブジェクトからキークレデンシャルを削除します。
* Clear — この機能は、対象オブジェクトのmsDS-KeyCredentialLink属性からすべての値を削除します。対象オブジェクトが正当にWHfBを使用している場合、これにより破損します。

## [Whisker](https://github.com/eladshamir/Whisker) <a href="#7e2e" id="7e2e"></a>

Whiskerは、Active Directoryユーザーやコンピューターアカウントを乗っ取るために、彼らの`msDS-KeyCredentialLink`属性を操作して「シャドウクレデンシャル」を対象アカウントに追加するためのC#ツールです。

[**Whisker**](https://github.com/eladshamir/Whisker)には次の4つの機能があります：

* **Add** — この機能は、公開-秘密鍵ペアを生成し、対象オブジェクトに新しいキークレデンシャルを追加します。ユーザーが新しいデバイスからWHfBに登録したかのように。
* **List** — この機能は、対象オブジェクトのmsDS-KeyCredentialLink属性のすべてのエントリをリストします。
* **Remove** — この機能は、DeviceID GUIDで指定された対象オブジェクトからキークレデンシャルを削除します。
* **Clear** — この機能は、対象オブジェクトのmsDS-KeyCredentialLink属性からすべての値を削除します。対象オブジェクトが正当にWHfBを使用している場合、これにより破損します。

### Add

対象オブジェクトの**`msDS-KeyCredentialLink`**属性に新しい値を追加します：

* `/target:<samAccountName>`: 必須。対象名を設定します。コンピューターオブジェクトは'$'で終わる必要があります。
* `/domain:<FQDN>`: オプション。対象の完全修飾ドメイン名（FQDN）を設定します。指定しない場合、現在のユーザーのFQDNを解決しようとします。
* `/dc:<IP/HOSTNAME>`: オプション。対象のドメインコントローラー（DC）を設定します。指定しない場合、プライマリドメインコントローラー（PDC）を対象にしようとします。
* `/path:<PATH>`: オプション。認証用に生成された自己署名証明書を保存するパスを設定します。指定しない場合、証明書はBase64ブロブとして表示されます。
* `/password:<PASWORD>`: オプション。保存された自己署名証明書のパスワードを設定します。指定しない場合、ランダムなパスワードが生成されます。

例: **`Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1`**

{% hint style="info" %}
[**Readme**](https://github.com/eladshamir/Whisker)でさらにオプションを確認してください。
{% endhint %}

## [pywhisker](https://github.com/ShutdownRepo/pywhisker) <a href="#7e2e" id="7e2e"></a>

pyWhiskerは、C#で書かれた元のWhiskerのPython版です。このツールを使用すると、対象ユーザー/コンピューターの`msDS-KeyCredentialLink`属性を操作して、そのオブジェクトに完全な制御を取得できます。

Impacketと、Michael GrafnetterのDSInternalsのPython版であるPyDSInternalsに基づいています。
このツールは、Dirk-janのPKINITtoolsとともに、UNIXベースのシステムでの完全な原始的な悪用を可能にします。

pyWhiskerは、対象の**msDs-KeyCredentialLink**属性でさまざまなアクションを実行できます。

- *list*: 現在のKeyCredentials IDと作成時刻をリストします
- *info*: KeyCredential構造に含まれるすべての情報を表示します
- *add*: msDs-KeyCredentialLinkに新しいKeyCredentialを追加します
- *remove*: msDs-KeyCredentialLinkからKeyCredentialを削除します
- *clear*: msDs-KeyCredentialLinkからすべてのKeyCredentialsを削除します
- *export*: msDs-KeyCredentialLinkからすべてのKeyCredentialsをJSON形式でエクスポートします
- *import*: JSONファイルからKeyCredentialsを使用してmsDs-KeyCredentialLinkを上書きします

pyWhiskerは次の認証をサポートしています：
- (NTLM) クリアテキストパスワード
- (NTLM) パスザハッシュ
- (Kerberos) クリアテキストパスワード
- (Kerberos) パスザキー / ハッシュを超える
- (Kerberos) キャッシュを渡す（Pass-the-ticketのタイプ）

![](https://github.com/ShutdownRepo/pywhisker/blob/main/.assets/add_pfx.png)

{% hint style="info" %}
[**Readme**](https://github.com/ShutdownRepo/pywhisker)でさらにオプションを確認してください。
{% endhint %}

## [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

いくつかのケースでは、グループ「Everyone」/「Authenticated Users」/「Domain Users」または他の**広範なグループ**が、ドメイン内の他のオブジェクトに対して**GenericWrite**/**GenericAll** DACLsを持っていることがあります。[**ShadowSpray**](https://github.com/Dec0ne/ShadowSpray/)は、それらすべてに対して**ShadowCredentials**を濫用しようとします。

手順は次のようになります：

1. 供給された資格情報でドメインに**ログイン**します（または現在のセッションを使用します）。
2. **ドメイン機能レベルが2016**であることを確認します（そうでない場合、Shadow Credentials攻撃は機能しません）。
3. LDAPからドメイン内のすべてのオブジェクト（ユーザーおよびコンピューター）の**リストを収集**します。
4. リスト内の**各オブジェクト**に対して、次の手順を実行します：
1. オブジェクトの`msDS-KeyCredentialLink`属性に**KeyCredentialを追加**しようとします。
2. 上記が**成功した場合**、追加されたKeyCredentialを使用してTGTを要求するために**PKINIT**を使用します。
3. 上記が**成功した場合**、**UnPACTheHash**攻撃を実行してユーザー/コンピューターの**NTハッシュ**を明らかにします。
4. **`--RestoreShadowCred`**が指定されている場合：追加されたKeyCredentialを削除します（自己クリーンアップ...）
5. **`--Recursive`**が指定されている場合：**所有権を取得した各ユーザー/コンピューターアカウント**を使用して**同じプロセス**を実行します。

## 参考文献

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
