# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## 主要 Keychain

- **用户 Keychain**（`~/Library/Keychains/login.keychain-db`），用于存储**用户特定的凭据**，例如应用程序密码、互联网密码、用户生成的证书、网络密码以及用户生成的公钥/私钥。
- **系统 Keychain**（`/Library/Keychains/System.keychain`），用于存储**系统范围的凭据**，例如 WiFi 密码、系统根证书、系统私钥以及系统应用程序密码。<sup>[[1]](#references)</sup>
- 还可以在 `/System/Library/Keychains/*` 中找到证书等其他组件。
- 在 **iOS** 中，只有一个位于 `/private/var/Keychains/` 的 **Keychain**。该文件夹还包含 `TrustStore`、证书颁发机构（`caissuercache`）以及 OSCP 条目（`ocspache`）的数据库。
- 根据应用程序标识符，应用程序在 Keychain 中仅被限制访问其私有区域。

### 密码 Keychain 访问

这些文件本身没有固有的保护机制，虽然可以被**下载**，但它们经过加密，必须使用**用户的明文密码进行解密**。可以使用 [**Chainbreaker**](https://github.com/n0fate/chainbreaker) 等工具进行解密。<sup>[[1]](#references)</sup>

## Keychain 条目保护

### ACL

Keychain 中的每个条目都由**访问控制列表（ACL）**管理，用于规定谁可以对 Keychain 条目执行各种操作，包括：<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**：允许持有者获取 secret 的明文。
- **ACLAuhtorizationExportWrapped**：允许持有者获取使用另一个所提供密码加密的 secret 明文。
- **ACLAuhtorizationAny**：允许持有者执行任何操作。

ACL 还附带一个**受信任应用程序列表**，这些应用程序可以在不发出提示的情况下执行相关操作。该列表可能是：<sup>[[1]](#references)</sup>

- **N`il`**（不需要授权，**所有人都受信任**）
- **空**列表（**没有人**受信任）
- 特定**应用程序**的**列表**。

此外，该条目可能包含 **`ACLAuthorizationPartitionID`** 密钥，用于识别 **teamid、apple** 和 **cdhash**。<sup>[[1]](#references)</sup>

- 如果指定了 **teamid**，则要在没有**提示**的情况下**访问条目**值，所使用的应用程序必须具有**相同的 teamid**。
- 如果指定了 **apple**，则应用程序必须由 **Apple** **签名**。
- 如果指定了 **cdhash**，则**应用程序**必须具有指定的 **cdhash**。

### 创建 Keychain 条目

使用 **`Keychain Access.app`** 创建**新** **条目**时，适用以下规则：<sup>[[1]](#references)</sup>

- 所有应用程序都可以加密。
- **没有应用程序**可以导出/解密（不会向用户发出提示）。
- 所有应用程序都可以查看完整性检查。
- 没有应用程序可以修改 ACL。
- **partitionID** 被设置为 **`apple`**。

当**应用程序在 Keychain 中创建条目**时，规则略有不同：<sup>[[1]](#references)</sup>

- 所有应用程序都可以加密。
- 只有**创建该条目的应用程序**（或其他被显式添加的应用程序）可以导出/解密（不会向用户发出提示）。
- 所有应用程序都可以查看完整性检查。
- 没有应用程序可以修改 ACL。
- **partitionID** 被设置为 **`teamid:[teamID here]`**。

## 访问 Keychain

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
> 使用工具 [**LockSmith**](https://github.com/its-a-feature/LockSmith) 可以枚举和 dump **不会生成 prompt** 的 **keychain secrets**
>
> 其他 API endpoints 可在 [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) 源代码中找到。

使用 **Security Framework** 列出并获取每个 keychain entry 的 **信息**，也可以查看 Apple 的开源 CLI 工具 [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**。** 以下是一些 API 示例：<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** 可获取每个 entry 的信息，使用时可以设置一些 attributes：
- **`kSecReturnData`**：如果为 true，将尝试解密数据（设为 false 以避免潜在的 pop-up）
- **`kSecReturnRef`**：同时获取 keychain item 的 reference（如果之后发现可以在不弹出 pop-up 的情况下解密，则设为 true）
- **`kSecReturnAttributes`**：获取 entry 的 metadata
- **`kSecMatchLimit`**：返回多少个结果
- **`kSecClass`**：keychain entry 的类型

获取每个 entry 的 **ACLs**：<sup>[[1]](#references)</sup>

- 使用 API **`SecAccessCopyACLList`** 可以获取 **keychain item 的 ACL**，它会返回 ACL 列表（例如 `ACLAuhtorizationExportClear` 以及之前提到的其他 ACL），其中每个列表包含：
- Description
- **Trusted Application List**。可能是：
- 一个 app：/Applications/Slack.app
- 一个 binary：/usr/libexec/airportd
- 一个 group：group://AirPort

导出数据：<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** 获取 plaintext
- API **`SecItemExport`** 导出 keys 和 certificates，但可能需要设置 passwords，以加密方式导出内容

以下是能够**在不弹出 prompt 的情况下导出 secret** 的要求：<sup>[[1]](#references)</sup>

- 如果列出了 **1+ trusted** apps：
- 需要适当的 **authorizations**（**`Nil`**，或在 authorization 中允许访问 secret 信息的 app 列表中）
- 需要 code signature 与 **PartitionID** 匹配
- 需要 code signature 与某个 **trusted app** 的匹配（或成为正确 KeychainAccessGroup 的成员）
- 如果 **all applications trusted**：
- 需要适当的 **authorizations**
- 需要 code signature 与 **PartitionID** 匹配
- 如果没有 **PartitionID**，则不需要此项

> [!CAUTION]
> 因此，如果列出了 **1 application**，就需要向该 application **inject code**。
>
> 如果 **partitionID** 中指示了 **apple**，则可以使用 **`osascript`** 访问它，因此任何在 partitionID 中包含 apple 且信任所有 applications 的 entry 都可以这样访问。也可以使用 **`Python`**。

### Two additional attributes

- **Invisible**：用于**隐藏** entry，使其不显示在 **UI** Keychain app 中的 boolean flag<sup>[[1]](#references)</sup>
- **General**：用于存储 **metadata**（因此**未加密**）<sup>[[1]](#references)</sup>
- Microsoft 曾以明文存储所有用于访问 sensitive endpoint 的 refresh tokens。<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
