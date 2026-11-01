# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## 主な Keychain

- **User Keychain**（`~/Library/Keychains/login.keychain-db`）は、アプリケーションのパスワード、インターネットパスワード、ユーザーが生成した証明書、ネットワークパスワード、ユーザーが生成した公開鍵／秘密鍵など、**ユーザー固有の認証情報**を保存するために使われます。
- **System Keychain**（`/Library/Keychains/System.keychain`）は、WiFiパスワード、システムルート証明書、システム秘密鍵、システムアプリケーションのパスワードなど、**システム全体の認証情報**を保存します。<sup>[[1]](#references)</sup>
  - `/System/Library/Keychains/*` に証明書など、ほかのコンポーネントが見つかる場合もあります。
- ユーザーごとの **data protection keychain** は、Keychain Access では **Local Items** または **iCloud** として表示されます。これは `login.keychain-db` とは別で、ローカルのみの項目と同期可能な項目の両方を含みます。`security` は主にファイルベースの keychain を扱うツールであるため、`dump-keychain` の結果が短くても、ここに認証情報がないとは限りません。<sup>[[5]](#references)</sup>
- **iOS** には `/private/var/Keychains/` にある **Keychain** が1つだけ存在します。このフォルダーには、`TrustStore`、証明機関（`caissuercache`）、および OSCP エントリー（`ocspache`）のデータベースも含まれています。
  - アプリが keychain 内でアクセスできるのは、アプリケーション識別子に基づく自身のプライベート領域に限られます。

### パスワード Keychain へのアクセス

コピーした**ファイルベース**の keychain は平文ではありません。保護された項目をオフラインで復号するには、keychain のパスワード、またはそれに相当する鍵素材が必要です。[**Chainbreaker**](https://github.com/n0fate/chainbreaker) はこの形式を対象としています。<sup>[[1]](#references)</sup> これは、ロック解除済みのユーザーセッションでのライブ読み取りとは異なります。ライブ読み取りでは、項目のアクセス制御によって、再度ログインパスワードを求められずに読み取りが許可されたり、プロンプトが表示されたりすることがあります。data protection keychain では、異なる保護モデルとアクセスグループモデルが使われます。<sup>[[5]](#references)</sup>

## Keychain エントリーの保護

### ファイルベース keychain の ACL

以下の `SecAccess` ACL と partition-list のルールは、**ファイルベース**の keychain について説明しています。一方、data protection keychain の項目では、コード署名アクセスグループと、任意の `SecAccessControl` 条件が使われます。ファイルベースの ACL ダンプから、そちらのアクセス可能性を推測しないでください。<sup>[[5]](#references)</sup>

ファイルベース keychain の各エントリーは **Access Control Lists（ACL）** によって管理され、keychain エントリーに対して実行できる操作の権限を定めています。<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: 保有者がシークレットの平文を取得できるようにします。
- **`kSecACLAuthorizationExportWrapped`**: 保有者が、別途指定したパスワードで暗号化された平文を取得できるようにします。
- **`kSecACLAuthorizationAny`**: 保有者が任意の操作を実行できるようにします。

ACL には、プロンプトなしでこれらの操作を実行できる**信頼されたアプリケーションのリスト**も付随します。これは次のいずれかです。<sup>[[1]](#references)</sup>

- **N`il`**（認証不要、**全員が信頼される**）
- **空の**リスト（**誰も**信頼されない）
- 特定の**アプリケーション**の**リスト**

また、エントリーには **`kSecACLAuthorizationPartitionID`** キーが含まれる場合があり、これは **teamid、apple、**および **cdhash** の識別に使われます。<sup>[[1]](#references)[[2]](#references)</sup>

- **teamid** が指定されている場合、プロンプトなしでエントリーの値に**アクセスする**には、アプリケーションが**同じ teamid** を持っている必要があります。
- **apple** が指定されている場合、アプリは **Apple によって署名**されている必要があります。
- **cdhash** が指定されている場合、アプリは指定された **cdhash** を持っている必要があります。

### ファイルベース keychain エントリーの作成

**`Keychain Access.app`** を使って**新しい**エントリーを作成すると、次のルールが適用されます。<sup>[[1]](#references)</sup>

- すべてのアプリが暗号化できます。
- ユーザーへのプロンプトなしでは、**どのアプリも**エクスポート／復号できません。
- すべてのアプリが整合性チェックを確認できます。
- どのアプリも ACL を変更できません。
- **partitionID** は **`apple`** に設定されます。

**アプリケーションが keychain にエントリーを作成する**場合、ルールは若干異なります。<sup>[[1]](#references)</sup>

- すべてのアプリが暗号化できます。
- ユーザーへのプロンプトなしでエクスポート／復号できるのは、**作成したアプリケーション**（または明示的に追加されたほかのアプリ）のみです。
- すべてのアプリが整合性チェックを確認できます。
- どのアプリも ACL を変更できません。
- **partitionID** は **`teamid:[teamID here]`** に設定されます。

## Keychain へのアクセス

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

`-S` は項目の partition list を設定し、`-k` はその変更に必要な現在の Keychain パスワードを指定します。このパスワード指定フラグは非推奨です。<sup>[[4]](#references)</sup> 更新に成功しても、後続の読み取り時に確認プロンプトが表示されないとは限りません。観測された無効化済みのプロトタイプの1つでは、`Security.framework` 経由で項目を照会した際に確認プロンプトが表示されました。一致する partition ID は、前述の ACL と信頼済みアプリケーションのチェックの一部にすぎないため、実際の読み取り経路を検証してください。<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> **プロンプトを表示せずに**シークレットを**列挙・ダンプ**するには、ツール [**LockSmith**](https://github.com/its-a-feature/LockSmith) を使用できます。
>
> その他の API エンドポイントは、[**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) ソースコードで確認できます。

**Security Framework** を使って各 Keychain エントリを一覧表示し、**情報**を取得できます。または、Apple のオープンソース CLI ツール [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** も確認できます。API の例:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** は各エントリの情報を返します。使用時に設定できる属性は次のとおりです。
  - **`kSecReturnData`**: true の場合、データの復号を試みます（ポップアップの可能性を避けるには false に設定）
  - **`kSecReturnRef`**: キー、証明書、または ID のオブジェクト参照を取得します。パスワード項目にはこのオブジェクト表現がありません。後で対象を絞って照会するためにパスワードを識別するには、`kSecReturnPersistentRef` を使用します。<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`**: エントリのメタデータを取得
  - **`kSecMatchLimit`**: 返す結果の数
  - **`kSecClass`**: Keychain エントリの種類

各エントリの **ACL** を取得します。<sup>[[1]](#references)</sup>

- API **`SecAccessCopyACLList`** を使うと、**Keychain 項目の ACL** を取得できます。これは ACL のリスト（`kSecACLAuthorizationExportClear` など、前述のもの）を返し、各エントリには次の情報が含まれます。<sup>[[1]](#references)[[2]](#references)</sup>
  - 説明
  - **信頼済みアプリケーションのリスト**。次のような項目が含まれます。
    - アプリ: /Applications/Slack.app
    - バイナリ: /usr/libexec/airportd
    - グループ: group://AirPort

データをエクスポートします。<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** は平文を取得します
- API **`SecItemExport`** はキーと証明書をエクスポートしますが、内容を暗号化してエクスポートするにはパスワードの設定が必要な場合があります

以下は、**プロンプトなしでシークレットをエクスポートする**ための**要件**です。<sup>[[1]](#references)</sup>

- 信頼済みアプリが **1つ以上**登録されている場合:
  - 適切な**認可**が必要（**`Nil`**、またはシークレット情報へのアクセスを認可するアプリの許可リストに含まれていること）
  - コード署名が **PartitionID** と一致すること
  - コード署名が**信頼済みアプリ**のいずれかと一致すること（または適切な KeychainAccessGroup のメンバーであること）
- **すべてのアプリケーションが信頼済み**の場合:
  - 適切な**認可**が必要
  - コード署名が **PartitionID** と一致すること
    - **PartitionID がない**場合は不要

> [!CAUTION]
> したがって、**アプリケーションが1つ登録されている**場合、その**アプリケーションにコードをインジェクト**する必要があります。
>
> **partitionID** に **apple** が指定されていれば、**`osascript`** でアクセスできます。つまり、partitionID に apple を含むすべてのアプリケーションを信頼している場合に利用できます。**`Python`** も使用できます。

### 追加の属性2つ

- **Invisible**: Keychain アプリの **UI** でエントリを**非表示**にするブール値フラグです<sup>[[1]](#references)</sup>
- **General**: **メタデータ**を格納します（つまり、**暗号化されません**）<sup>[[1]](#references)</sup>
  - Microsoft は、機密エンドポイントへのアクセスに使用するすべての refresh token を平文で保存していました。<sup>[[1]](#references)</sup>

### データ保護 Keychain: 列挙してから1項目を照会する

対象ユーザーのログインコンテキストで、**署名済みアプリ**から `SecItemCopyMatching` を `kSecUseDataProtectionKeychain: true` とともに実行してください。`security dump-keychain` やデフォルトの SecItem クエリがこのストアを検索したと想定しないでください。呼び出し元から見えるのは、認可されたアクセスグループのみです。<sup>[[5]](#references)</sup>

テストコードが別のプロセス内で実行される場合、データ保護 Keychain へのアクセスは、そのホスト実行ファイルの entitlements に従います。`codesign -d --entitlements - /path/to/Target.app` で実際の署名済み entitlements を確認し、関連するチェックについては [macOS code-signing entitlements](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md) を参照してください。<sup>[[7]](#references)</sup>

まず、1つの項目クラスについて**属性のみ**を要求してください。`kSecAttrSynchronizableAny` を指定すると、ローカル項目と iCloud 同期対象の項目の両方が一致します。省略すると、同期対象の項目は除外されます。<sup>[[8]](#references)</sup> `kSecUseAuthenticationUISkip` は、保護された一致項目をスキップする代わりに、広範な列挙中の認証 UI を回避します。<sup>[[9]](#references)</sup> 必要に応じて `kSecClassInternetPassword` でも繰り返してください。

```swift
import Security
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
]
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
print(status)
if status == errSecSuccess, let items = result as? [[String: Any]] {
    for item in items { print(item) }
}
```

許可されたシークレット読み取りでは、選択したアイテム用に**新しい**絞り込んだクエリ（たとえば、クラス、サービス、アカウント）を作成し、`kSecReturnData: true` と `kSecMatchLimit: kSecMatchLimitOne` を設定して、アイテム固有の認証またはエラーを想定してください。パスワードアイテムでは、`kSecReturnData` と `kSecMatchLimitAll` を組み合わせないでください。<sup>[[10]](#references)</sup> `errSecItemNotFound` の結果は、認証情報が存在しないのではなく、ストアの誤り、同期フィルター、またはアクセスグループのエンタイトルメント不足を示している場合もあります。<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0: 「macOS KeychainのLock Picking」 - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - 暗号資産愛好家と開発者を標的とするMacSync macOS stealerの新バージョン](https://securelist.com/macsync-new-version/121383/)
- [4] [Apple security(1) manページのミラー](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — Macのkeychain APIと実装について](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Apple Developer Forums — SecItem: 基礎](https://developer.apple.com/forums/thread/724023)
- [7] [Apple Developer Forums — SecItem: 落とし穴とベストプラクティス](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — Face IDまたはTouch IDを使ったKeychainアイテムへのアクセス](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
