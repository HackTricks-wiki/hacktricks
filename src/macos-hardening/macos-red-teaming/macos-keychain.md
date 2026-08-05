# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## 主要 Keychain

- **User Keychain**（`~/Library/Keychains/login.keychain-db`），用于存储**用户特定的凭据**，例如应用程序密码、Internet 密码、用户生成的证书、网络密码，以及用户生成的公钥/私钥。
- **System Keychain**（`/Library/Keychains/System.keychain`），用于存储**系统范围的凭据**，例如 WiFi 密码、系统根证书、系统私钥以及系统应用程序密码。<sup>[[1]](#references)</sup>
- 还可以在 `/System/Library/Keychains/*` 中找到证书等其他组件。
- 在 **iOS** 中只有一个 **Keychain**，位于 `/private/var/Keychains/`。此文件夹还包含 `TrustStore`、证书颁发机构（`caissuercache`）以及 OSCP 条目（`ocspache`）的数据库。
- Apps 在 Keychain 中只能访问基于其应用程序标识符分配的私有区域。

### Password Keychain Access

这些文件本身没有保护机制，虽然可以被**下载**，但它们经过加密，需要**用户的明文密码才能解密**。可以使用 [**Chainbreaker**](https://github.com/n0fate/chainbreaker) 等工具进行解密。<sup>[[1]](#references)</sup>

## Keychain 条目保护

### ACLs

Keychain 中的每个条目都受 **Access Control Lists (ACLs)** 管理，这些 ACL 规定了哪些主体可以对 Keychain 条目执行各种操作，包括：<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**：允许持有者获取 secret 的明文。
- **ACLAuhtorizationExportWrapped**：允许持有者获取使用另一个提供的密码加密后的 secret 明文。
- **ACLAuhtorizationAny**：允许持有者执行任意操作。

ACLs 还附带一个**受信任应用程序列表**，这些应用程序可以在不触发提示的情况下执行相应操作。该列表可能是：<sup>[[1]](#references)</sup>

- **N`il`**（不需要授权，**所有人都受信任**）
- 空列表（**没有人**受信任）
- 特定**应用程序**的**列表**。

此外，该条目可能包含 **`ACLAuthorizationPartitionID`** 密钥，用于识别 **teamid、apple** 和 **cdhash**。<sup>[[1]](#references)</sup>

- 如果指定了 **teamid**，则要在没有 **prompt** 的情况下**访问条目**值，所使用的应用程序必须具有**相同的 teamid**。
- 如果指定了 **apple**，则该 app 必须由 **Apple** 签名。
- 如果指定了 **cdhash**，则 **app** 必须具有指定的 **cdhash**。

### 创建 Keychain 条目

使用 **`Keychain Access.app`** 创建**新** **条目**时，适用以下规则：<sup>[[1]](#references)</sup>

- 所有 apps 都可以加密。
- **任何 app** 都不能导出/解密（除非向用户发出提示）。
- 所有 apps 都可以查看完整性检查。
- 任何 app 都不能更改 ACLs。
- **partitionID** 设置为 **`apple`**。

当**应用程序在 Keychain 中创建条目**时，规则略有不同：<sup>[[1]](#references)</sup>

- 所有 apps 都可以加密。
- 只有**创建该条目的应用程序**（或其他被明确添加的 apps）可以导出/解密（无需向用户发出提示）。
- 所有 apps 都可以查看完整性检查。
- 任何 app 都不能更改 ACLs。
- **partitionID** 设置为 **`teamid:[teamID here]`**。

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
> 使用工具 [**LockSmith**](https://github.com/its-a-feature/LockSmith) 可以对**不会生成提示**的 **keychain enumeration and dumping** secrets 执行操作。
>
> 其他 API endpoints 可以在 [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) source code 中找到。

使用 **Security Framework** 列出并获取每个 keychain entry 的 **info**，也可以查看 Apple 的 open source cli tool [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**。** 一些 API 示例：<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** 可以获取每个 entry 的 info，使用它时可以设置一些 attributes：
- **`kSecReturnData`**：如果为 true，它会尝试 decrypt data（设置为 false 以避免潜在的弹窗）
- **`kSecReturnRef`**：同时获取 keychain item 的 reference（如果之后发现可以在不弹窗的情况下 decrypt，则设置为 true）
- **`kSecReturnAttributes`**：获取 entry 的 metadata
- **`kSecMatchLimit`**：返回多少个结果
- **`kSecClass`**：keychain entry 的类型

获取每个 entry 的 **ACLs**：<sup>[[1]](#references)</sup>

- 使用 API **`SecAccessCopyACLList`** 可以获取 **keychain item 的 ACL**，它会返回一个 ACL 列表（例如 `ACLAuhtorizationExportClear` 以及之前提到的其他 ACL），其中每个列表包含：
- Description
- **Trusted Application List**。它可以是：
- 一个 app：/Applications/Slack.app
- 一个 binary：/usr/libexec/airportd
- 一个 group：group://AirPort

Export data：<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** 获取 plaintext
- API **`SecItemExport`** exports keys 和 certificates，但可能需要设置 passwords 才能以 encrypted 形式 export content

以下是能够**在不弹窗的情况下 export secret** 的要求：<sup>[[1]](#references)</sup>

- 如果列出了 **1+ trusted** apps：
- 需要适当的 **authorizations**（**`Nil`**，或在 authorization 中允许访问该 secret info 的 apps 列表中）
- code signature 必须匹配 **PartitionID**
- code signature 必须匹配某个 **trusted app** 的 code signature（或属于正确的 KeychainAccessGroup）
- 如果 **all applications trusted**：
- 需要适当的 **authorizations**
- code signature 必须匹配 **PartitionID**
- 如果没有 **PartitionID**，则不需要此项

> [!CAUTION]
> 因此，如果列出了 **1 application**，你需要在该 application 中 **inject code**。
>
> 如果 **partitionID** 中标示了 **apple**，你可以使用 **`osascript`** 访问它，因此任何在 partitionID 中包含 apple 且信任所有 applications 的对象都可以被访问。**`Python`** 也可以用于此目的。

### Two additional attributes

- **Invisible**：这是一个用于将 entry 从 **UI** Keychain app 中隐藏的 boolean flag<sup>[[1]](#references)</sup>
- **General**：用于存储 **metadata**（因此它**未加密**）<sup>[[1]](#references)</sup>
- Microsoft 曾以 plain text 存储所有用于访问 sensitive endpoint 的 refresh tokens。<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
