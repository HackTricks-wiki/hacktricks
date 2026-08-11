# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- **User Keychain**（`~/Library/Keychains/login.keychain-db`），用于存储**用户特定的凭据**，例如应用程序密码、互联网密码、用户生成的证书、网络密码以及用户生成的公钥/私钥。
- **System Keychain**（`/Library/Keychains/System.keychain`），用于存储**系统范围的凭据**，例如 WiFi 密码、系统根证书、系统私钥以及系统应用程序密码。<sup>[[1]](#references)</sup>
- 还可以在 `/System/Library/Keychains/*` 中找到证书等其他组件。
- 在 **iOS** 中，只有一个位于 `/private/var/Keychains/` 的 **Keychain**。此文件夹还包含 `TrustStore`、证书颁发机构（`caissuercache`）以及 OSCP 条目（`ocspache`）的数据库。
- 根据应用程序标识符，应用程序在 Keychain 中将仅被限制访问其私有区域。

### Password Keychain Access

这些文件虽然没有内在保护并且可以被**下载**，但经过加密，需要使用**用户的明文密码进行解密**。可以使用 [**Chainbreaker**](https://github.com/n0fate/chainbreaker) 等工具进行解密。<sup>[[1]](#references)</sup>

## Keychain Entries Protections

### ACLs

Keychain 中的每个条目都受 **Access Control Lists (ACLs)** 管理，这些列表规定了谁可以对 Keychain 条目执行各种操作，包括：<sup>[[1]](#references)</sup>

- **ACLAuthorizationExportClear**：允许持有者获取秘密的明文。
- **ACLAuthorizationExportWrapped**：允许持有者获取使用另一个所提供密码加密的秘密明文。
- **ACLAuthorizationAny**：允许持有者执行任何操作。

ACL 还附带一个**受信任应用程序列表**，这些应用程序可以在不显示提示的情况下执行这些操作。该列表可能是：<sup>[[1]](#references)</sup>

- **N`il`**（无需授权，**所有人都受信任**）
- 空列表（**没有人**受信任）
- 特定**应用程序**的**列表**。

此外，该条目还可能包含密钥 **`ACLAuthorizationPartitionID`**，用于识别 **teamid、apple** 和 **cdhash**。<sup>[[1]](#references)</sup>

- 如果指定了 **teamid**，应用程序必须具有**相同的 teamid**，才能在不显示**提示**的情况下**访问条目**值。
- 如果指定了 **apple**，则应用程序需要由 **Apple** 签名。
- 如果指定了 **cdhash**，则**应用程序**必须具有指定的 **cdhash**。

### Creating a Keychain Entry

使用 **`Keychain Access.app`** 创建**新****条目**时，适用以下规则：<sup>[[1]](#references)</sup>

- 所有应用程序都可以加密。
- **任何应用程序**都不能导出/解密（不会向用户显示提示）。
- 所有应用程序都可以查看完整性检查。
- 没有应用程序可以更改 ACL。
- **partitionID** 被设置为 **`apple`**。

当**应用程序在 Keychain 中创建条目**时，规则略有不同：<sup>[[1]](#references)</sup>

- 所有应用程序都可以加密。
- 只有**创建该条目的应用程序**（或其他被明确添加的应用程序）可以导出/解密（不会向用户显示提示）。
- 所有应用程序都可以查看完整性检查。
- 没有应用程序可以更改 ACL。
- **partitionID** 被设置为 **`teamid:[teamID here]`**。

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
> 使用工具 [**LockSmith**](https://github.com/its-a-feature/LockSmith) 可以枚举和 dump **不会生成 prompt** 的 secret，包括 **keychain enumeration and dumping**。
>
> 其他 API endpoints 可以在 [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) 源代码中找到。

使用 **Security Framework** 列出并获取每个 keychain 条目的 **info**，也可以查看 Apple 的开源 cli 工具 [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**。** 以下是一些 API 示例：<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** 可以获取每个条目的 info，使用时可以设置一些属性：
- **`kSecReturnData`**：如果为 true，它会尝试解密 data（设置为 false 以避免潜在的弹窗）
- **`kSecReturnRef`**：同时获取对 keychain item 的 reference（如果之后发现可以在不弹窗的情况下解密，则设置为 true）
- **`kSecReturnAttributes`**：获取条目的 metadata
- **`kSecMatchLimit`**：返回多少个结果
- **`kSecClass`**：keychain entry 的类型

获取每个条目的 **ACLs**：<sup>[[1]](#references)</sup>

- 使用 API **`SecAccessCopyACLList`** 可以获取 **keychain item 的 ACL**。它会返回一个 ACL 列表（例如 `ACLAuthorizationExportClear` 以及前面提到的其他 ACL），其中每个条目包含：
- Description
- **Trusted Application List**。它可能是：
- 一个 app：/Applications/Slack.app
- 一个 binary：/usr/libexec/airportd
- 一个 group：group://AirPort

导出 data：<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** 获取 plaintext
- API **`SecItemExport`** 导出 keys 和 certificates，但可能需要设置 passwords，才能以 encrypted 形式导出 content

以下是能够在不产生 prompt 的情况下 **export a secret** 所需的条件：<sup>[[1]](#references)</sup>

- 如果列出了 **1+ trusted** apps：
- 需要适当的 **authorizations**（**`Nil`**，或者在授权访问 secret info 的允许 app 列表中）
- code signature 必须匹配 **PartitionID**
- code signature 必须匹配某个 **trusted app** 的 code signature（或成为正确 KeychainAccessGroup 的成员）
- 如果 **all applications trusted**：
- 需要适当的 **authorizations**
- code signature 必须匹配 **PartitionID**
- 如果没有 **PartitionID**，则不需要此条件

> [!CAUTION]
> 因此，如果列出了 **1 application**，就需要向该 application **inject code**。
>
> 如果 **apple** 出现在 **partitionID** 中，则可以使用 **`osascript`** 访问它，因此任何在 partitionID 中包含 apple 且信任所有 applications 的条目都可以这样访问。也可以使用 **`Python`**。

### 两个额外属性

- **Invisible**：这是一个 boolean flag，用于在 **UI** Keychain app 中 **hide** 该条目<sup>[[1]](#references)</sup>
- **General**：用于存储 **metadata**（因此它**未加密**）<sup>[[1]](#references)</sup>
- Microsoft 曾以 plaintext 存储所有用于访问 sensitive endpoint 的 refresh tokens。<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
{{#include ../../banners/hacktricks-training.md}}
