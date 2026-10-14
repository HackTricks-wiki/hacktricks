# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- **User Keychain**（`~/Library/Keychains/login.keychain-db`）は、アプリケーションのパスワード、インターネットパスワード、ユーザーが生成した証明書、ネットワークパスワード、ユーザーが生成した公開鍵／秘密鍵など、**ユーザー固有の認証情報**の保存に使用されます。
- **System Keychain**（`/Library/Keychains/System.keychain`）は、WiFiパスワード、システムルート証明書、システム秘密鍵、システムアプリケーションのパスワードなど、**システム全体で使われる認証情報**を保存します。<sup>[[1]](#references)</sup>
  - `/System/Library/Keychains/*` に証明書など、ほかのコンポーネントが見つかることもあります。
- **iOS** には、`/private/var/Keychains/` にある **Keychain** が1つだけ存在します。このフォルダーには、`TrustStore`、証明機関（`caissuercache`）、OSCPエントリー（`ocspache`）のデータベースも含まれます。
  - アプリがKeychainでアクセスできるのは、アプリケーション識別子に基づく自身のプライベート領域に限られます。

### Password Keychain Access

これらのファイルには本質的な保護機能がなく、**ダウンロード可能**ですが、暗号化されており、復号には**ユーザーの平文パスワードが必要**です。[**Chainbreaker**](https://github.com/n0fate/chainbreaker) などのツールを復号に使用できます。<sup>[[1]](#references)</sup>

## Keychain Entries Protections

### ACLs

Keychainの各エントリーは **Access Control Lists (ACLs)** によって制御され、エントリーに対して実行できる操作を指定します。<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: 保有者がシークレットの平文を取得できます。
- **`kSecACLAuthorizationExportWrapped`**: 保有者が、別途指定されたパスワードで暗号化されたシークレットの平文を取得できます。
- **`kSecACLAuthorizationAny`**: 保有者があらゆる操作を実行できます。

ACLには、確認を求めずにこれらの操作を実行できる、信頼されたアプリケーションの**リスト**も含まれます。これは次のいずれかです。<sup>[[1]](#references)</sup>

- **N`il`**（認証不要、**すべてが信頼される**）
- **空の**リスト（**何も**信頼されない）
- 特定の**アプリケーションのリスト**

エントリーには、**teamid、apple、**および **cdhash** を特定するために使われる **`kSecACLAuthorizationPartitionID`** キーが含まれる場合もあります。<sup>[[1]](#references)[[2]](#references)</sup>

- **teamid** が指定されている場合、確認を求めずにエントリーの値に**アクセスするには**、アプリケーションが同じ **teamid** を持つ必要があります。
- **apple** が指定されている場合、アプリは **Apple** によって**署名**されている必要があります。
- **cdhash** が指定されている場合、アプリは特定の **cdhash** を持つ必要があります。

### Creating a Keychain Entry

**`Keychain Access.app`** を使って**新しい**エントリーを作成すると、次のルールが適用されます。<sup>[[1]](#references)</sup>

- すべてのアプリが暗号化できます。
- **確認なしでは、どのアプリも**エクスポート／復号できません。
- すべてのアプリが整合性チェックを確認できます。
- どのアプリもACLを変更できません。
- **partitionID** は **`apple`** に設定されます。

**アプリケーションがKeychainにエントリーを作成する場合**、ルールは少し異なります。<sup>[[1]](#references)</sup>

- すべてのアプリが暗号化できます。
- **作成したアプリケーション**（または明示的に追加されたほかのアプリ）のみ、確認なしでエクスポート／復号できます。
- すべてのアプリが整合性チェックを確認できます。
- どのアプリもACLを変更できません。
- **partitionID** は **`teamid:[teamID here]`** に設定されます。

## Accessing the Keychain

### `security`

```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entry's PartitionID value
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` は項目の partition list を設定し、`-k` はその変更に必要な現在の Keychain password を指定します。この password を受け取るフラグは非推奨です。<sup>[[4]](#references)</sup> 更新に成功しても、後で読み取る際にプロンプトが表示されないとは限りません。実際に、無効化されたプロトタイプであっても、`Security.framework` を介して項目を照会すると確認プロンプトが表示された事例が確認されています。partition ID が一致することは、前述の ACL と trusted-application のチェックの一部にすぎないため、実際の読み取り経路を確認してください。<sup>[[3]](#references)</sup>

### API

> [!TIP]
> **プロンプトを生成しない**秘密情報の**Keychain 列挙とダンプ**は、ツール [**LockSmith**](https://github.com/its-a-feature/LockSmith) で実行できます。
>
> その他の API エンドポイントは、[**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) のソースコードで確認できます。

**Security Framework** を使って各 Keychain エントリを一覧表示し、**情報**を取得できます。または、Apple のオープンソース CLI ツール [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** を確認することもできます。API の例をいくつか紹介します。<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** は各エントリの情報を返します。使用時に設定できる属性は次のとおりです。
  - **`kSecReturnData`**: true の場合、データの復号を試みます（ポップアップの可能性を避けるには false に設定）
  - **`kSecReturnRef`**: Keychain 項目への参照も取得します（後でポップアップなしで復号できるとわかった場合に備え、true に設定）
  - **`kSecReturnAttributes`**: エントリのメタデータを取得
  - **`kSecMatchLimit`**: 返す結果の数
  - **`kSecClass`**: Keychain エントリの種類

各エントリの **ACL** を取得します。<sup>[[1]](#references)</sup>

- API **`SecAccessCopyACLList`** を使うと、**Keychain 項目の ACL** を取得できます。ACL のリスト（`kSecACLAuthorizationExportClear` や前述のその他の ACL など）が返され、各エントリには次の情報があります。<sup>[[1]](#references)[[2]](#references)</sup>
  - 説明
  - **Trusted Application List**。次のような項目が含まれます。
    - アプリ: /Applications/Slack.app
    - バイナリ: /usr/libexec/airportd
    - グループ: group://AirPort

データをエクスポートします。<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** は平文を取得します
- API **`SecItemExport`** は鍵と証明書をエクスポートしますが、コンテンツを暗号化してエクスポートするには password の設定が必要な場合があります

また、プロンプトなしで秘密情報を**エクスポート**するために必要な**条件**は次のとおりです。<sup>[[1]](#references)</sup>

- **1 つ以上の trusted app** がリストされている場合:
  - 適切な **authorizations** が必要です（**`Nil`** を指定するか、秘密情報にアクセスするための authorization で許可されているアプリのリストに**含まれている**こと）
  - コード署名が **PartitionID** と一致する必要があります
  - コード署名が **trusted app** のいずれかのものと一致する必要があります（または適切な KeychainAccessGroup のメンバーであること）
- **すべてのアプリケーションが trusted** の場合:
  - 適切な **authorizations** が必要です
  - コード署名が **PartitionID** と一致する必要があります
    - **PartitionID がない場合**、この条件は不要です

> [!CAUTION]
> したがって、**アプリケーションが 1 つリストされている**場合、その**アプリケーションにコードを inject** する必要があります。
>
> **partitionID** に **apple** が指定されている場合、**`osascript`** を使ってアクセスできます。つまり、partitionID に apple が含まれ、すべてのアプリケーションを trust する項目が対象です。この用途には **`Python`** も使えます。

### 追加の属性 2 つ

- **Invisible**: Keychain の **UI** アプリでエントリを**非表示**にする boolean フラグです<sup>[[1]](#references)</sup>
- **General**: **メタデータ**を保存するための属性です（つまり、**暗号化されません**）<sup>[[1]](#references)</sup>
  - Microsoft は、機密性の高いエンドポイントにアクセスするための refresh token をすべて平文で保存していました。<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [#OBTS v5.0: 「macOS Keychain の Lock Picking」 - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - 暗号資産愛好家と開発者を標的とする MacSync macOS stealer の新バージョン](https://securelist.com/macsync-new-version/121383/)
- [4] [Apple security(1) man page ミラー](https://keith.github.io/xcode-man-pages/security.1.html)
