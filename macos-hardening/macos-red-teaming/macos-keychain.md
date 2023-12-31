# macOS Keychain

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>

## 主要なKeychains

* **ユーザーKeychain** (`~/Library/Keychains/login.keycahin-db`)は、アプリケーションのパスワード、インターネットのパスワード、ユーザーが生成した証明書、ネットワークのパスワード、ユーザーが生成した公開/秘密キーなどの**ユーザー固有の資格情報**を保存するために使用されます。
* **システムKeychain** (`/Library/Keychains/System.keychain`)は、WiFiのパスワード、システムルート証明書、システム秘密キー、システムアプリケーションのパスワードなどの**システム全体の資格情報**を保存します。

### パスワードKeychainアクセス

これらのファイルは、本来の保護はありませんが、**ダウンロード**可能であり、暗号化されており、**ユーザーのプレーンテキストパスワードが必要です**。[**Chainbreaker**](https://github.com/n0fate/chainbreaker)のようなツールを使用して復号化することができます。

## Keychainエントリの保護

### ACLs

Keychainの各エントリは**アクセス制御リスト（ACLs）**によって管理され、Keychainエントリに対してさまざまなアクションを実行できる人を決定します。これには以下が含まれます:

* **ACLAuhtorizationExportClear**: 秘密のクリアテキストを取得することを許可します。
* **ACLAuhtorizationExportWrapped**: 別の提供されたパスワードで暗号化されたクリアテキストを取得することを許可します。
* **ACLAuhtorizationAny**: 任意のアクションを実行することを許可します。

ACLは、これらのアクションをプロンプトなしで実行できる**信頼できるアプリケーションのリスト**によってさらに補完されます。これには以下が含まれる可能性があります:

* &#x20;**N`il`** (認証不要、**全員が信頼されています**)
* **空の**リスト (**誰も**信頼されていません)
* 特定の**アプリケーション**の**リスト**。

また、エントリには**`ACLAuthorizationPartitionID`,** というキーが含まれている場合があり、これは**teamid, apple,** および**cdhash**を識別するために使用されます。

* **teamid**が指定されている場合、**プロンプトなしで**エントリ値に**アクセスする**ためには、使用されるアプリケーションは**同じteamid**を持っている必要があります。
* **apple**が指定されている場合、アプリは**Apple**によって**署名**されている必要があります。
* **cdhash**が指定されている場合、**アプリ**は特定の**cdhash**を持っている必要があります。

### Keychainエントリの作成

**`Keychain Access.app`**を使用して**新しい** **エントリ**が作成される場合、以下のルールが適用されます:

* すべてのアプリは暗号化できます。
* **アプリは**エクスポート/復号化できません（ユーザーにプロンプトなしで）。
* すべてのアプリは整合性チェックを見ることができます。
* アプリはACLを変更できません。
* **partitionID**は**`apple`**に設定されます。

**アプリケーションがkeychainにエントリを作成する**場合、ルールは少し異なります:

* すべてのアプリは暗号化できます。
* **作成アプリケーション**（または明示的に追加された他のアプリ）のみがエクスポート/復号化できます（ユーザーにプロンプトなしで）。
* すべてのアプリは整合性チェックを見ることができます。
* アプリはACLを変更できません。
* **partitionID**は**`teamid:[teamID here]`**に設定されます。

## Keychainへのアクセス

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
キーチェーンの列挙とプロンプトを生成しない秘密の**ダンプ**は、ツール[**LockSmith**](https://github.com/its-a-feature/LockSmith)を使用して行うことができます。
{% endhint %}

各キーチェーンエントリについての**情報**をリストし、取得します：

* API **`SecItemCopyMatching`** は各エントリについての情報を提供し、使用時に設定できるいくつかの属性があります：
* **`kSecReturnData`**: trueの場合、データの復号化を試みます（ポップアップを避けるためにfalseに設定）
* **`kSecReturnRef`**: キーチェーンアイテムへの参照も取得します（後でポップアップなしで復号化できるとわかった場合にtrueに設定）
* **`kSecReturnAttributes`**: エントリについてのメタデータを取得
* **`kSecMatchLimit`**: 返す結果の数
* **`kSecClass`**: キーチェーンエントリの種類

各エントリの**ACL**を取得します：

* API **`SecAccessCopyACLList`** を使用すると、**キーチェーンアイテムのACL**を取得でき、それぞれのリストには（`ACLAuhtorizationExportClear`や前述の他のもののような）ACLのリストが返されます。各リストには以下が含まれます：
* 説明
* **信頼されたアプリケーションリスト**。これには以下が含まれる可能性があります：
* アプリ：/Applications/Slack.app
* バイナリ：/usr/libexec/airportd
* グループ：group://AirPort

データをエクスポートします：

* API **`SecKeychainItemCopyContent`** はプレーンテキストを取得します
* API **`SecItemExport`** はキーと証明書をエクスポートしますが、内容を暗号化してエクスポートするためにパスワードを設定する必要があるかもしれません

そして、プロンプトなしで秘密を**エクスポート**するために必要な**要件**は以下の通りです：

* **1つ以上の信頼された**アプリがリストされている場合：
* 適切な**認証**が必要です（**`Nil`**、または秘密情報へのアクセスを許可するアプリのリストの一部である必要があります）
* コード署名が**PartitionID**と一致する必要があります
* コード署名が**信頼されたアプリ**の1つと一致する必要があります（または適切なKeychainAccessGroupのメンバーである必要があります）
* **すべてのアプリケーションが信頼されている**場合：
* 適切な**認証**が必要です
* コード署名が**PartitionID**と一致する必要があります
* **PartitionIDがない**場合、これは必要ありません

{% hint style="danger" %}
したがって、**1つのアプリケーションがリストされている**場合、そのアプリケーションにコードを**注入する**必要があります。

**apple**が**partitionID**に示されている場合、**`osascript`** を使用してアクセスできます。つまり、partitionIDにappleが含まれているすべてのアプリケーションを信頼しています。**`Python`** もこれに使用できます。
{% endhint %}

### 追加の2つの属性

* **Invisible**: UIキーチェーンアプリからエントリを**隠す**ためのブールフラグです
* **General**: **メタデータ**を保存するためのものです（従って、暗号化されていません）
* Microsoftは、機密エンドポイントへのアクセスに必要なすべてのリフレッシュトークンをプレーンテキストで保存していました。

## 参考文献

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><strong>AWSのハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTコレクション**](https://opensea.io/collection/the-peass-family)です。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>
