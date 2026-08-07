# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- **User Keychain**（`~/Library/Keychains/login.keychain-db`）は、アプリケーションパスワード、インターネットパスワード、ユーザーが生成した証明書、ネットワークパスワード、ユーザーが生成した公開鍵および秘密鍵などの**ユーザー固有の認証情報**を保存するために使用されます。
- **System Keychain**（`/Library/Keychains/System.keychain`）は、WiFiパスワード、システムルート証明書、システム秘密鍵、システムアプリケーションパスワードなどの**システム全体の認証情報**を保存します。<sup>[[1]](#references)</sup>
- `/System/Library/Keychains/*` には、証明書などの他のコンポーネントも存在する場合があります。
- **iOS** には、`/private/var/Keychains/` にある **Keychain** が1つだけ存在します。このフォルダーには、`TrustStore`、証明書認証局（`caissuercache`）、OSCPエントリ（`ocspache`）のデータベースも含まれています。
- アプリは、アプリケーション識別子に基づき、Keychain内の自分専用の領域のみにアクセスを制限されます。

### Password Keychain Access

これらのファイルには固有の保護機能がなく**download**できますが、暗号化されており、復号するには**ユーザーの平文パスワード**が必要です。[**Chainbreaker**](https://github.com/n0fate/chainbreaker) のようなツールを復号に使用できます。<sup>[[1]](#references)</sup>

## Keychain Entries Protections

### ACLs

Keychain内の各エントリは**Access Control Lists（ACLs）**によって管理されます。ACLsは、Keychainエントリに対して誰がさまざまなアクションを実行できるかを規定します。<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: 保持者がsecretのclear textを取得できるようにします。
- **ACLAuhtorizationExportWrapped**: 保持者が、別途指定されたパスワードで暗号化されたclear textを取得できるようにします。
- **ACLAuhtorizationAny**: 保持者が任意のアクションを実行できるようにします。

ACLsには、promptなしでこれらのアクションを実行できる**trusted applicationsのリスト**も付随します。これは次のいずれかです。<sup>[[1]](#references)</sup>

- **N`il`**（authorization不要、**everyone is trusted**）
- **空の**リスト（**nobody** is trusted）
- 特定の**applications**の**List**

また、エントリには **`ACLAuthorizationPartitionID`** キーが含まれる場合があり、これは **teamid、apple、**および **cdhash** を識別するために使用されます。<sup>[[1]](#references)</sup>

- **teamid** が指定されている場合、**prompt**なしで**entry**の値に**access**するには、使用するアプリケーションが**同じteamid**を持っている必要があります。
- **apple** が指定されている場合、アプリは**Apple**によって**signed**されている必要があります。
- **cdhash** が指定されている場合、**app**は特定の**cdhash**を持っている必要があります。

### Creating a Keychain Entry

**`Keychain Access.app`**を使用して**new** **entry**を作成すると、次のルールが適用されます。<sup>[[1]](#references)</sup>

- すべてのアプリがencryptできます。
- **No apps** can export/decrypt（ユーザーにpromptしない場合）。
- すべてのアプリがintegrity checkを確認できます。
- ACLsを変更できるアプリはありません。
- **partitionID**は**`apple`**に設定されます。

**applicationがKeychainにentryを作成する場合**、ルールは若干異なります。<sup>[[1]](#references)</sup>

- すべてのアプリがencryptできます。
- **creating application**（または明示的に追加された他のアプリ）のみが、ユーザーにpromptせずにexport/decryptできます。
- すべてのアプリがintegrity checkを確認できます。
- ACLsを変更できるアプリはありません。
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

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> **promptを生成しない** **keychain enumeration and dumping** は、[**LockSmith**](https://github.com/its-a-feature/LockSmith) ツールで実行できます。
>
> その他の API endpoint は、[**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) の source code にあります。

**Security Framework** を使用して各 keychain entry の **info** を一覧表示・取得できます。または、Apple の open source cli tool である [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** も確認できます。API の例:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** は各 entry の info を取得し、使用時に設定できる attributes があります。
- **`kSecReturnData`**: true の場合、data の decrypt を試みます（潜在的な pop-up を避けるには false に設定）
- **`kSecReturnRef`**: keychain item への reference も取得します（後で pop-up なしで decrypt できると分かった場合に備え、true に設定）
- **`kSecReturnAttributes`**: entry に関する metadata を取得
- **`kSecMatchLimit`**: 返す結果の数
- **`kSecClass`**: keychain entry の種類

各 entry の **ACL** を取得します:<sup>[[1]](#references)</sup>

- API **`SecAccessCopyACLList`** を使用すると、**keychain item の ACL** を取得できます。この API は ACL のリスト（`ACLAuhtorizationExportClear` や、前述したその他の ACL など）を返し、各リストには次の情報が含まれます。
- Description
- **Trusted Application List**。次のようなものがあります。
- アプリ: /Applications/Slack.app
- binary: /usr/libexec/airportd
- group: group://AirPort

data を export します:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** は plaintext を取得します。
- API **`SecItemExport`** は keys と certificates を export しますが、content を encrypted で export するには password の設定が必要になる場合があります。

また、**prompt なしで secret を export** できるようにするための **requirements** は次のとおりです:<sup>[[1]](#references)</sup>

- **1 つ以上の trusted app** がリストされている場合:
- 適切な **authorizations** が必要（**`Nil`**、または secret info への access authorization において許可された app のリストの **一部** であること）
- code signature が **PartitionID** と一致する必要がある
- code signature が **trusted app** のいずれかと一致する必要がある（または適切な KeychainAccessGroup の member である必要がある）
- **すべての applications が trusted** の場合:
- 適切な **authorizations** が必要
- code signature が **PartitionID** と一致する必要がある
- **PartitionID がない**場合、これは必要ありません

> [!CAUTION]
> したがって、**1 つの application がリストされている**場合、その application に **code を inject** する必要があります。
>
> **apple** が **partitionID** に指定されている場合、**`osascript`** を使用して access できます。つまり、partitionID に apple が含まれ、すべての applications を trust しているものが対象です。これには **`Python`** も使用できます。

### Two additional attributes

- **Invisible**: **UI** の Keychain app から entry を**非表示にする** boolean flag です<sup>[[1]](#references)</sup>
- **General**: **metadata** を保存するためのものです（そのため、**ENCRYPTED ではありません**）<sup>[[1]](#references)</sup>
- Microsoft は、sensitive endpoint に access するための refresh tokens をすべて plain text で保存していました。<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
