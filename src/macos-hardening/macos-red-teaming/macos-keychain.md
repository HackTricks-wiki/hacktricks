# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- **User Keychain**（`~/Library/Keychains/login.keychain-db`）は、アプリケーションパスワード、インターネットパスワード、ユーザーが生成した証明書、ネットワークパスワード、ユーザーが生成した公開鍵および秘密鍵などの**ユーザー固有の認証情報**を保存するために使用されます。
- **System Keychain**（`/Library/Keychains/System.keychain`）は、WiFiパスワード、システムルート証明書、システム秘密鍵、システムアプリケーションパスワードなどの**システム全体の認証情報**を保存します。<sup>[[1]](#references)</sup>
- `/System/Library/Keychains/*` には、証明書などの他のコンポーネントも存在する可能性があります。
- **iOS**には、`/private/var/Keychains/` に配置された**Keychain**が1つだけ存在します。このフォルダーには、`TrustStore`、証明書認証局（`caissuercache`）、OSCPエントリ（`ocspache`）のデータベースも含まれています。
- アプリは、アプリケーション識別子に基づき、Keychain内の自身のプライベート領域にのみアクセスできます。

### Password Keychain Access

これらのファイルには本質的な保護がなく、**download**できますが、暗号化されており、**復号にはユーザーの平文パスワードが必要**です。[**Chainbreaker**](https://github.com/n0fate/chainbreaker)のようなtoolを復号に使用できます。<sup>[[1]](#references)</sup>

## Keychain Entries Protections

### ACLs

Keychain内の各エントリは**Access Control Lists（ACLs）**によって管理され、Keychainエントリに対して誰がどのような操作を実行できるかを決定します。<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: 保持者がsecretの平文を取得できるようにします。
- **ACLAuhtorizationExportWrapped**: 保持者が、別途指定されたパスワードで暗号化されたsecretの平文を取得できるようにします。
- **ACLAuhtorizationAny**: 保持者が任意の操作を実行できるようにします。

ACLsには、promptなしでこれらの操作を実行できる**trusted applicationsのリスト**も付随します。これは次のいずれかです。<sup>[[1]](#references)</sup>

- **N`il`**（認証は不要で、**everyone is trusted**）
- **空の**リスト（**nobody is trusted**）
- 特定の**applications**の**List**

また、エントリには **`ACLAuthorizationPartitionID`** キーが含まれる場合があり、これは **teamid、apple、**および**cdhash**を識別するために使用されます。<sup>[[1]](#references)</sup>

- **teamid**が指定されている場合、**prompt**なしで**エントリ**の値に**access**するには、使用するアプリケーションが**同じteamid**を持っている必要があります。
- **apple**が指定されている場合、アプリは**Apple**によって**signed**されている必要があります。
- **cdhash**が指定されている場合、**app**は特定の**cdhash**を持っている必要があります。

### Creating a Keychain Entry

**`Keychain Access.app`**を使用して**new** **entry**を作成すると、次のルールが適用されます。<sup>[[1]](#references)</sup>

- すべてのアプリが暗号化できます。
- **ユーザーにpromptを表示せずに**export/decryptできる**appはありません**。
- すべてのアプリがintegrity checkを確認できます。
- ACLsを変更できるアプリはありません。
- **partitionID**は **`apple`** に設定されます。

**applicationがKeychainにentryを作成する場合**、ルールは少し異なります。<sup>[[1]](#references)</sup>

- すべてのアプリが暗号化できます。
- **creating application**（または明示的に追加された他のアプリ）のみが、**ユーザーにpromptを表示せずに**export/decryptできます。
- すべてのアプリがintegrity checkを確認できます。
- ACLsを変更できるアプリはありません。
- **partitionID**は **`teamid:[teamID here]`** に設定されます。

## Accessing the Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> **promptを生成しない** **keychain enumeration and dumping** は、[**LockSmith**](https://github.com/its-a-feature/LockSmith) ツールで実行できます。
>
> その他のAPI endpointは、[**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) のsource codeにあります。

**Security Framework**を使用して各keychain entryの**info**を一覧表示および取得できます。また、Appleのopen source cli toolである[**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**も**確認できます。APIの例:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** は各entryのinfoを提供し、使用時に設定できるattributeがいくつかあります:
- **`kSecReturnData`**: trueの場合、dataのdecryptを試みます（潜在的なポップアップを避けるにはfalseに設定）
- **`kSecReturnRef`**: keychain itemへのreferenceも取得します（後でポップアップなしにdecryptできると判断した場合はtrueに設定）
- **`kSecReturnAttributes`**: entryに関するmetadataを取得
- **`kSecMatchLimit`**: 返す結果の数
- **`kSecClass`**: keychain entryの種類

各entryの**ACLs**を取得:<sup>[[1]](#references)</sup>

- API **`SecAccessCopyACLList`**を使用すると、**keychain itemのACL**を取得できます。これはACLのリスト（`ACLAuhtorizationExportClear`や前述のその他のACLなど）を返し、各リストには以下が含まれます:
- Description
- **Trusted Application List**。以下のようなものがあります:
- An app: /Applications/Slack.app
- A binary: /usr/libexec/airportd
- A group: group://AirPort

dataをexport:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** はplaintextを取得します
- API **`SecItemExport`** はkeysとcertificatesをexportしますが、contentをencryptedでexportするにはpasswordの設定が必要になる場合があります

そして、**promptなしでsecretをexport**できるようにするための**要件**は以下のとおりです:<sup>[[1]](#references)</sup>

- **1つ以上のtrusted** appがlistedされている場合:
- 適切な **authorizations** が必要（**`Nil`**、またはsecret infoへのaccess authorizationで許可されたappのリストの**一部**であること）
- code signatureが**PartitionID**と一致する必要がある
- code signatureが1つの**trusted app**のものと一致する必要がある（または適切なKeychainAccessGroupのmemberであること）
- **すべてのapplicationがtrusted**の場合:
- 適切な **authorizations** が必要
- code signatureが**PartitionID**と一致する必要がある
- **PartitionID**がない場合、これは不要

> [!CAUTION]
> したがって、**1つのapplicationがlistedされている**場合、そのapplicationに**codeをinject**する必要があります。
>
> **apple**が**partitionID**に指定されている場合、**`osascript`**でaccessできます。つまり、partitionIDにappleが含まれている場合、すべてのapplicationをtrustしているものが対象です。**`Python`**も使用できます。

### 2つの追加attribute

- **Invisible**: **UI** Keychain appでentryを**hide**するためのboolean flagです<sup>[[1]](#references)</sup>
- **General**: **metadata**を保存するためのものです（つまり、**ENCRYPTEDではありません**）<sup>[[1]](#references)</sup>
- Microsoftは、sensitive endpointへのaccessに使用するすべてのrefresh tokenをplain textで保存していました。<sup>[[1]](#references)</sup>

## 参考資料

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
