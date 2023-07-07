# macOS Keychain

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有する**ために、[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

## メインのキーチェーン

* **ユーザーキーチェーン** (`~/Library/Keychains/login.keycahin-db`) は、アプリケーションのパスワード、インターネットのパスワード、ユーザーが生成した証明書、ネットワークのパスワード、ユーザーが生成した公開/秘密鍵など、**ユーザー固有の資格情報**を保存するために使用されます。
* **システムキーチェーン** (`/Library/Keychains/System.keychain`) は、WiFiのパスワード、システムのルート証明書、システムの秘密鍵、システムのアプリケーションパスワードなど、**システム全体の資格情報**を保存します。

### パスワードキーチェーンへのアクセス

これらのファイルは、**固有の保護はありません**が、暗号化されており、**ユーザーの平文パスワードを復号化するために必要**です。[**Chainbreaker**](https://github.com/n0fate/chainbreaker)のようなツールを使用して復号化することができます。

## キーチェーンエントリの保護

### ACLs

キーチェーンの各エントリは、**アクセス制御リスト（ACLs）**によって管理され、キーチェーンエントリで実行できるさまざまなアクションを指示します。これには以下が含まれます：

* **ACLAuhtorizationExportClear**：保持者が秘密のクリアテキストを取得できるようにします。
* **ACLAuhtorizationExportWrapped**：保持者が別の提供されたパスワードで暗号化されたクリアテキストを取得できるようにします。
* **ACLAuhtorizationAny**：保持者が任意のアクションを実行できるようにします。

ACLにはさらに、これらのアクションをプロンプトなしで実行できる**信頼されたアプリケーションのリスト**が付属しています。これには以下が含まれます：

* **N`il`**（認証は必要ありません、**誰もが信頼されています**）
* **空の**リスト（**誰も信頼されていません**）
* 特定の**アプリケーション**の**リスト**。

また、エントリには**`ACLAuthorizationPartitionID`**というキーが含まれている場合があります。これは**teamid、apple、cdhash**を識別するために使用されます。

* **teamid**が指定されている場合、エントリの値に**プロンプトなしでアクセス**するためには、使用されるアプリケーションに**同じteamid**が必要です。
* **apple**が指定されている場合、アプリは**Appleによって署名**されている必要があります。
* **cdhash**が指定されている場合、**アプリ**は特定の**cdhash**を持っている必要があります。

### キーチェーンエントリの作成

**`Keychain Access.app`**を使用して**新しいエントリ**を作成する場合、次のルールが適用されます：

* すべてのアプリが暗号化できます。
* **アプリは**エクスポート/復号化できません（ユーザーにプロンプトを表示せずに）。
* すべてのアプリが整合性チェックを表示できます。
* すべてのアプリがACLを変更できません。
* **partitionID**は**`apple`**に設定されます。

**アプリケーションがキーチェーンにエントリを作成する**場合、ルールは若干異なります：

* すべてのアプリが暗号化できます。
* エントリのエクスポート/復号化（ユーザーにプロンプトを表示せずに）は、**作成したアプリケーション**（または明示的に追加された他のアプリ）のみができます。
* すべてのアプリが整合性チェックを表示できます。
* すべてのアプリがACLを変更できません。
* **partitionID**は**`teamid:[ここにteamIDを入力]`**に設定されます。

## キーチェーンへのアクセス

### `security`
```bash
# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S
```
### APIs

{% hint style="success" %}
**キーチェーンの列挙とシークレットのダンプ**は、[**LockSmith**](https://github.com/its-a-feature/LockSmith)というツールを使用して、**プロンプトを生成しない**で行うことができます。
{% endhint %}

各キーチェーンエントリについてのリストと**情報**を取得します：

* API **`SecItemCopyMatching`** は各エントリに関する情報を提供し、使用する際に設定できるいくつかの属性があります：
* **`kSecReturnData`**：trueの場合、データを復号化しようとします（ポップアップを回避するためにfalseに設定します）
* **`kSecReturnRef`**：キーチェーンアイテムへの参照も取得します（ポップアップなしで復号化できることがわかった場合にtrueに設定します）
* **`kSecReturnAttributes`**：エントリに関するメタデータを取得します
* **`kSecMatchLimit`**：返す結果の数
* **`kSecClass`**：どの種類のキーチェーンエントリか

各エントリの**ACL**を取得します：

* API **`SecAccessCopyACLList`** を使用すると、キーチェーンアイテムの**ACL**を取得できます。これにより、ACLのリスト（`ACLAuhtorizationExportClear`など、以前に言及したもの）が返されます。各リストには以下が含まれます：
* 説明
* **信頼されたアプリケーションリスト**。これは次のようなものです：
* アプリ：/Applications/Slack.app
* バイナリ：/usr/libexec/airportd
* グループ：group://AirPort

データをエクスポートします：

* API **`SecKeychainItemCopyContent`** は平文を取得します
* API **`SecItemExport`** はキーと証明書をエクスポートしますが、コンテンツを暗号化してエクスポートするにはパスワードを設定する必要があるかもしれません

そして、**プロンプトなしでシークレットをエクスポート**するための**要件**は次のとおりです：

* **1つ以上の信頼された**アプリがリストされている場合：
* 適切な**認証**が必要です（**`Nil`**、またはシークレット情報へのアクセスを許可するアプリの許可リストの一部であること）
* コード署名が**PartitionID**と一致する必要があります
* コード署名が**信頼されたアプリ**のものと一致する必要があります（または適切なKeychainAccessGroupのメンバーである必要があります）
* **すべてのアプリケーションが信頼されている**場合：
* 適切な**認証**が必要です
* コード署名が**PartitionID**と一致する必要があります
* **PartitionID**がない場合、これは必要ありません

{% hint style="danger" %}
したがって、**1つのアプリケーションがリストされている**場合、そのアプリケーションに**コードをインジェクトする**必要があります。

**PartitionID**に**apple**が指定されている場合、**`osascript`**を使用してアクセスできます。つまり、PartitionIDにappleを含むすべてのアプリケーションを信頼しているものにアクセスできます。これには**`Python`**も使用できます。
{% endhint %}

### 2つの追加属性

* **Invisible**：UIキーチェーンアプリからエントリを**非表示**にするためのブールフラグです
* **General**：**メタデータ**を保存するためのものです（つまり、**暗号化されていません**）
* Microsoftは、機密なエンドポイントにアクセスするためのすべてのリフレッシュトークンを平文で保存していました。

## 参考文献

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
