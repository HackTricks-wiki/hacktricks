# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## 主要な Keychain

- **User Keychain**（`~/Library/Keychains/login.keychain-db`）は、アプリケーションパスワード、インターネットパスワード、ユーザーが生成した証明書、ネットワークパスワード、ユーザーが生成した公開鍵/秘密鍵などの**ユーザー固有の認証情報**を保存するために使用されます。
- **System Keychain**（`/Library/Keychains/System.keychain`）は、WiFiパスワード、システムルート証明書、システム秘密鍵、システムアプリケーションパスワードなどの**システム全体の認証情報**を保存します。<sup>[1]</sup>
- `/System/Library/Keychains/*` には、証明書などの他のコンポーネントも存在する可能性があります。
- **iOS**には `/private/var/Keychains/` に1つの **Keychain** しかありません。このフォルダーには、`TrustStore`、認証局の証明書（`caissuercache`）、OSCPエントリ（`ocspache`）のデータベースも含まれています。
- アプリは、アプリケーション識別子に基づき、Keychain内の自身のプライベート領域のみにアクセスを制限されます。

### Password Keychain Access

これらのファイルには本質的な保護がないため**download**できますが、暗号化されており、復号するには**ユーザーの平文パスワード**が必要です。復号には[**Chainbreaker**](https://github.com/n0fate/chainbreaker)のようなツールを使用できます。<sup>[1]</sup>

## Keychain Entries Protections

### ACLs

Keychain内の各エントリは **Access Control Lists (ACLs)** によって管理されます。ACLsは、Keychainエントリに対して誰がさまざまな操作を実行できるかを指定します。<sup>[1]</sup>

- **ACLAuhtorizationExportClear**: 保有者がsecretの平文を取得できるようにします。
- **ACLAuhtorizationExportWrapped**: 保有者が、指定された別のパスワードで暗号化されたsecretの平文を取得できるようにします。
- **ACLAuhtorizationAny**: 保有者が任意の操作を実行できるようにします。

ACLsには、promptなしでこれらの操作を実行できる **trusted applications** の**list**も付随します。これは次のいずれかです。<sup>[1]</sup>

- **N`il`**（authorization不要、**everyone is trusted**）
- **empty** list（**nobody** is trusted）
- 特定の**applications**の**List**

また、エントリには **`ACLAuthorizationPartitionID`** keyが含まれる場合があり、これは **teamid、apple、**および **cdhash**の識別に使用されます。<sup>[1]</sup>

- **teamid**が指定されている場合、**prompt**なしで**entry**のvalueに**access**するには、使用するアプリケーションが**同じteamid**を持っている必要があります。
- **apple**が指定されている場合、アプリは**Apple**によって**signed**されている必要があります。
- **cdhash**が指定されている場合、**app**は指定された**cdhash**を持っている必要があります。

### Creating a Keychain Entry

**`Keychain Access.app`**を使用して**new** **entry**を作成すると、次のルールが適用されます。<sup>[1]</sup>

- すべてのappsが暗号化できます。
- **No apps** can export/decrypt（ユーザーにpromptを表示しない場合）。
- すべてのappsがintegrity checkを確認できます。
- No apps can change ACLs。
- **partitionID**は **`apple`** に設定されます。

**applicationがKeychain内にentryを作成する場合**、ルールは少し異なります。<sup>[1]</sup>

- すべてのappsが暗号化できます。
- **creating application**（または明示的に追加された他のapps）のみが、ユーザーにpromptを表示せずにexport/decryptできます。
- すべてのappsがintegrity checkを確認できます。
- No apps can change the ACLs。
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
> その他の API endpoint は、[**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) の source code にあります。

**Security Framework** を使用して各 keychain entry の **info** を一覧表示および取得できます。また、Apple の open source cli tool である [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** も確認できます。API の例:<sup>[1]</sup>

- API **`SecItemCopyMatching`** は各 entry の info を提供し、使用時に設定できる attributes があります。
- **`kSecReturnData`**: true の場合、data の decrypt を試みます（潜在的な pop-up を避けるには false に設定します）
- **`kSecReturnRef`**: keychain item への reference も取得します（後で pop-up なしで decrypt できることが分かった場合に備え、true に設定します）
- **`kSecReturnAttributes`**: entry に関する metadata を取得します
- **`kSecMatchLimit`**: 返す結果の数
- **`kSecClass`**: keychain entry の種類

各 entry の **ACLs** を取得します:<sup>[1]</sup>

- API **`SecAccessCopyACLList`** を使用すると、**keychain item の ACL** を取得できます。また、ACL の list（`ACLAuhtorizationExportClear` や前述のその他のもの）が返されます。各 list には以下が含まれます。
- Description
- **Trusted Application List**。以下のいずれかになります。
- An app: /Applications/Slack.app
- A binary: /usr/libexec/airportd
- A group: group://AirPort

data を Export します:<sup>[1]</sup>

- API **`SecKeychainItemCopyContent`** は plaintext を取得します
- API **`SecItemExport`** は keys と certificates を export しますが、content を encrypted で export するには passwords の設定が必要になる場合があります

以下は、**prompt なしで secret を export** できるようにするための **requirements** です:<sup>[1]</sup>

- **1 つ以上の trusted** app が listed の場合:
- 適切な **authorizations** が必要です（**`Nil`**、または secret info への access authorization で許可された app の list の **part** であること）
- code signature が **PartitionID** と一致する必要があります
- code signature が **trusted app** のいずれかと一致する必要があります（または適切な KeychainAccessGroup の member である必要があります）
- **all applications trusted** の場合:
- 適切な **authorizations** が必要です
- code signature が **PartitionID** と一致する必要があります
- **PartitionID** がない場合、これは不要です

> [!CAUTION]
> したがって、**1 application が listed** の場合、その application に **code を inject** する必要があります。
>
> **apple** が **partitionID** に指定されている場合、**`osascript`** で access できます。つまり、partitionID に apple が含まれ、すべての applications を trust しているものが対象です。**`Python`** も使用できます。

### 2 つの追加 attributes

- **Invisible**: entry を **UI** Keychain app から **hide** するための boolean flag です<sup>[1]</sup>
- **General**: **metadata** を保存するためのものです（そのため **ENCRYPTED ではありません**）<sup>[1]</sup>
- Microsoft は、sensitive endpoint に access するためのすべての refresh tokens を plain text で保存していました。<sup>[1]</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
