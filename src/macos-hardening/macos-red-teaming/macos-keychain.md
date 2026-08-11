# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- **User Keychain**（`~/Library/Keychains/login.keychain-db`）は、アプリケーションパスワード、インターネットパスワード、ユーザーが生成した証明書、ネットワークパスワード、ユーザーが生成した公開鍵・秘密鍵などの**ユーザー固有の認証情報**を保存するために使用されます。
- **System Keychain**（`/Library/Keychains/System.keychain`）は、WiFiパスワード、システムルート証明書、システム秘密鍵、システムアプリケーションパスワードなどの**システム全体の認証情報**を保存します。<sup>[[1]](#references)</sup>
- `/System/Library/Keychains/*` には証明書などのコンポーネントが存在する場合があります。
- **iOS**には、`/private/var/Keychains/` にある**Keychain**が1つだけ存在します。このフォルダには、`TrustStore`、証明書認証局（`caissuercache`）、OSCPエントリ（`ocspache`）用のデータベースも含まれています。
- アプリは、アプリケーション識別子に基づき、Keychain内の自身のプライベート領域のみにアクセスが制限されます。

### Password Keychain Access

これらのファイルには固有の保護機能がなく、**ダウンロード**できますが、暗号化されており、**復号にはユーザーの平文パスワードが必要**です。復号には[**Chainbreaker**](https://github.com/n0fate/chainbreaker)などのtoolを使用できます。<sup>[[1]](#references)</sup>

## Keychain Entries Protections

### ACLs

Keychain内の各エントリは**Access Control Lists (ACLs)**によって管理されます。ACLsは、Keychainエントリに対して誰が各種アクションを実行できるかを指定します。<sup>[[1]](#references)</sup>

- **ACLAuthorizationExportClear**: 保持者がsecretの平文を取得できるようにします。
- **ACLAuthorizationExportWrapped**: 保持者が、指定された別のパスワードで暗号化されたsecretの平文を取得できるようにします。
- **ACLAuthorizationAny**: 保持者が任意のアクションを実行できるようにします。

ACLsには、promptなしでこれらのアクションを実行できる**trusted applicationsのリスト**も付随します。これは次のいずれかです。<sup>[[1]](#references)</sup>

- **N`il`**（authorization不要、**全員がtrusted**）
- **空の**リスト（**誰も**trustedではない）
- 特定の**applications**の**List**

また、エントリには**`ACLAuthorizationPartitionID`**キーが含まれる場合があり、これは**teamid、apple、**および**cdhash**の識別に使用されます。<sup>[[1]](#references)</sup>

- **teamid**が指定されている場合、**prompt**なしでエントリの**valueにアクセス**するには、applicationが**同じteamid**を持っている必要があります。
- **apple**が指定されている場合、appは**Apple**によって**署名**されている必要があります。
- **cdhash**が指定されている場合、**app**は指定された**cdhash**を持っている必要があります。

### Creating a Keychain Entry

**`Keychain Access.app`**を使用して**新しい****entry**を作成すると、次のルールが適用されます。<sup>[[1]](#references)</sup>

- すべてのappが暗号化できます。
- ユーザーにpromptを表示しない限り、**どのapp**もexport/decryptできません。
- すべてのappがintegrity checkを確認できます。
- どのappもACLsを変更できません。
- **partitionID**は**`apple`**に設定されます。

**applicationがKeychainにentryを作成する場合**、ルールは少し異なります。<sup>[[1]](#references)</sup>

- すべてのappが暗号化できます。
- **作成元のapplication**（または明示的に追加されたその他のapp）のみが、ユーザーにpromptを表示せずにexport/decryptできます。
- すべてのappがintegrity checkを確認できます。
- どのappもACLsを変更できません。
- **partitionID**は**`teamid:[teamID here]`**に設定されます。

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
security set-generic-password-partition-list -s "test service" -a "test account" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> **promptを生成しない**secretの**keychain enumeration and dumping**は、[**LockSmith**](https://github.com/its-a-feature/LockSmith)ツールで実行できます。
>
> その他のAPI endpointは、[**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html)のsource codeにあります。

**Security Framework**を使用して各keychain entryの**info**を一覧表示・取得できます。また、Appleのopen source cli toolである[**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**も確認できます。**APIの例:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`**は各entryの情報を返し、使用時に設定できる属性があります。
- **`kSecReturnData`**: trueの場合、dataのdecryptを試みます（潜在的なpop-upを避けるにはfalseに設定します）
- **`kSecReturnRef`**: keychain itemへのreferenceも取得します（後でpop-upなしにdecryptできることがわかった場合に備えてtrueに設定します）
- **`kSecReturnAttributes`**: entryに関するmetadataを取得します
- **`kSecMatchLimit`**: 返す結果の数
- **`kSecClass`**: keychain entryの種類

各entryの**ACL**を取得します:<sup>[[1]](#references)</sup>

- API **`SecAccessCopyACLList`**を使用すると、**keychain itemのACL**を取得できます。これはACLのlist（`ACLAuthorizationExportClear`や前述のその他のものなど）を返し、各entryには以下が含まれます。
- Description
- **Trusted Application List**。以下のようなものがあります。
- アプリ: /Applications/Slack.app
- binary: /usr/libexec/airportd
- group: group://AirPort

dataをexportします:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`**はplaintextを取得します
- API **`SecItemExport`**はkeysとcertificatesをexportしますが、contentをencryptedでexportするにはpasswordの設定が必要になる場合があります

また、**promptなしでsecretをexport**するには、以下の**requirements**があります:<sup>[[1]](#references)</sup>

- **1つ以上のtrusted** appがlistされている場合:
- 適切な**authorizations**が必要（**`Nil`**、またはsecret infoへのaccess authorizationで許可されたappのlistに**含まれている**こと）
- code signatureが**PartitionID**と一致する必要があります
- code signatureが**trusted app**のいずれかと一致する必要があります（または適切なKeychainAccessGroupのmemberである必要があります）
- **すべてのapplicationがtrusted**の場合:
- 適切な**authorizations**が必要です
- code signatureが**PartitionID**と一致する必要があります
- **PartitionIDがない**場合、これは必要ありません

> [!CAUTION]
> したがって、**1つのapplicationがlistされている**場合、そのapplicationに**codeをinject**する必要があります。
>
> **partitionID**に**apple**が示されている場合、**`osascript`**でaccessできます。つまり、partitionIDにappleが含まれるすべてのapplicationをtrustしているものが対象です。これには**`Python`**も使用できます。

### 2つの追加属性

- **Invisible**: **UI** Keychain appからentryを**hide**するためのboolean flagです<sup>[[1]](#references)</sup>
- **General**: **metadata**を保存するためのものです（そのため、**ENCRYPTEDではありません**）<sup>[[1]](#references)</sup>
- Microsoftは、sensitive endpointにaccessするためのすべてのrefresh tokenをplain textで保存していました。<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
{{#include ../../banners/hacktricks-training.md}}
