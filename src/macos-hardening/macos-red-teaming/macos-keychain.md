# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## 主要 Keychain

- **用户 Keychain**（`~/Library/Keychains/login.keychain-db`），用于存储**用户专属凭据**，例如应用程序密码、互联网密码、用户生成的证书、网络密码，以及用户生成的公钥/私钥。
- **系统 Keychain**（`/Library/Keychains/System.keychain`），用于存储**系统范围的凭据**，例如 WiFi 密码、系统根证书、系统私钥和系统应用程序密码。<sup>[[1]](#references)</sup>
  - 还可以在 `/System/Library/Keychains/*` 中找到证书等其他组件。
- 每位用户的**数据保护 Keychain**在 Keychain Access 中显示为 **Local Items** 或 **iCloud**。它独立于 `login.keychain-db`，同时包含仅限本地和可同步项目；`security` 主要用于基于文件的 Keychain，因此 `dump-keychain` 的结果较少，并不能排除这里存有凭据。<sup>[[5]](#references)</sup>
- **iOS** 中只有一个 **Keychain**，位于 `/private/var/Keychains/`。此文件夹还包含 `TrustStore`、证书颁发机构（`caissuercache`）和 OSCP 条目（`ocspache`）的数据库。
  - 应用只能根据其应用标识符访问 Keychain 中属于自己的私有区域。

### 密码 Keychain 访问

复制的**基于文件的** Keychain 并非明文。离线解密其中受保护的项目需要 Keychain 密码或等效的密钥材料；[**Chainbreaker**](https://github.com/n0fate/chainbreaker) 可处理这种格式。<sup>[[1]](#references)</sup> 这与在已解锁的用户会话中实时读取不同：此时项目访问控制可能允许读取，或触发提示，而无需再次输入登录密码。数据保护 Keychain 使用不同的保护机制和访问组模型。<sup>[[5]](#references)</sup>

## Keychain 条目的保护机制

### 基于文件的 Keychain ACL

以下 `SecAccess` ACL 和分区列表规则描述的是**基于文件的** Keychain。数据保护 Keychain 项目使用代码签名访问组以及可选的 `SecAccessControl` 条件；不要根据基于文件的 ACL dump 推断它们的可访问性。<sup>[[5]](#references)</sup>

基于文件的 Keychain 中的每个条目都受**访问控制列表（ACL）**管理，用于规定谁可以对该 Keychain 条目执行各种操作，包括：<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**：允许持有者获取机密的明文。
- **`kSecACLAuthorizationExportWrapped`**：允许持有者获取使用另一个提供的密码加密后的明文。
- **`kSecACLAuthorizationAny`**：允许持有者执行任何操作。

ACL 还配有一份**受信任应用程序列表**，其中的应用程序可以无需提示即可执行这些操作。该列表可以是：<sup>[[1]](#references)</sup>

- **N`il`**（无需授权，**所有人均受信任**）
- **空**列表（**无人**受信任）
- 特定**应用程序**的**列表**。

此外，条目可能包含 **`kSecACLAuthorizationPartitionID`** 键，用于识别 **teamid、apple** 和 **cdhash**。<sup>[[1]](#references)[[2]](#references)</sup>

- 如果指定了 **teamid**，应用程序必须具有**相同的 teamid**，才能**无需提示**地**访问条目**值。
- 如果指定了 **apple**，应用程序必须由 **Apple** **签名**。
- 如果指定了 **cdhash**，则**应用程序**必须具有指定的 **cdhash**。

### 创建基于文件的 Keychain 条目

使用 **`Keychain Access.app`** 创建**新** **条目**时，适用以下规则：<sup>[[1]](#references)</sup>

- 所有应用都可以加密。
- **没有应用**可以导出/解密（除非提示用户）。
- 所有应用都可以查看完整性检查。
- 没有应用可以更改 ACL。
- **partitionID** 被设置为 **`apple`**。

**应用程序在 Keychain 中创建条目**时，规则略有不同：<sup>[[1]](#references)</sup>

- 所有应用都可以加密。
- 只有**创建该条目的应用程序**（或明确添加的其他应用程序）可以导出/解密（无需提示用户）。
- 所有应用都可以查看完整性检查。
- 没有应用可以更改 ACL。
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

# Change the specified entry's PartitionID value
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` 用于设置条目的 partition list，而 `-k` 用于提供进行该更改所需的当前 Keychain 密码；用于接收密码的 flag 已弃用。<sup>[[4]](#references)</sup> 更新成功并不能证明之后读取时不会弹出提示：有观察记录显示，一个已禁用的原型在通过 `Security.framework` 查询条目时仍触发了确认提示。匹配的 partition ID 只是上述 ACL 和 trusted-application 检查的一部分，因此请验证实际读取路径。<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> 可以使用工具 [**LockSmith**](https://github.com/its-a-feature/LockSmith) **枚举并导出不会触发提示的** secrets。
>
> 其他 API endpoints 可在 [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) 源代码中找到。

使用 **Security Framework** 列出并获取每个 Keychain 条目的 **info**，也可以查看 Apple 的开源 CLI 工具 [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**。** 一些 API 示例：<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** 可获取每个条目的 info，使用时可以设置一些属性：
  - **`kSecReturnData`**：如果为 true，则会尝试解密数据（设为 false 可避免可能出现的弹窗）
  - **`kSecReturnRef`**：获取 key、certificate 或 identity 的对象引用；password 条目没有这种对象表示形式。使用 `kSecReturnPersistentRef` 可标识 password，以便之后进行有针对性的查询。<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`**：获取条目的 metadata
  - **`kSecMatchLimit`**：要返回的结果数量
  - **`kSecClass`**：Keychain 条目的类型

获取每个条目的 **ACL**：<sup>[[1]](#references)</sup>

- 使用 API **`SecAccessCopyACLList`** 可以获取 **Keychain 条目的 ACL**。它会返回一个 ACL 列表（例如 `kSecACLAuthorizationExportClear` 及前面提到的其他项），其中每个条目包含：<sup>[[1]](#references)[[2]](#references)</sup>
  - Description
  - **Trusted Application List**。其中可以包括：
    - 一个 app：/Applications/Slack.app
    - 一个 binary：/usr/libexec/airportd
    - 一个 group：group://AirPort

导出数据：<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** 可获取明文
- API **`SecItemExport`** 可导出 keys 和 certificates，但可能需要设置密码，以加密形式导出内容

以下是**无需提示即可导出 secret** 的**要求**：<sup>[[1]](#references)</sup>

- 如果列出了 1 个或多个 **trusted** apps：
  - 需要相应的 **authorizations**（**`Nil`**，或者属于授权中允许访问 secret info 的 apps 列表）
  - 代码签名必须与 **PartitionID** 匹配
  - 代码签名必须与某个 **trusted app** 的签名匹配（或者属于正确的 KeychainAccessGroup）
- 如果 **所有 applications 都是 trusted**：
  - 需要相应的 **authorizations**
  - 代码签名必须与 **PartitionID** 匹配
    - 如果没有 **PartitionID**，则不需要此项

> [!CAUTION]
> 因此，如果**列出了 1 个 application**，就需要**向该 application 注入代码**。
>
> 如果 **partitionID** 中指定了 **apple**，则可以通过 **`osascript`** 访问。因此，任何在 partitionID 中包含 apple 且信任所有 applications 的条目都可以通过这种方式访问。也可以使用 **`Python`**。

### 两个额外属性

- **Invisible**：用于将条目从 **UI** Keychain app 中**隐藏**的布尔 flag<sup>[[1]](#references)</sup>
- **General**：用于存储 **metadata**（因此它**未加密**）<sup>[[1]](#references)</sup>
  - Microsoft 曾以明文形式存储用于访问敏感 endpoint 的所有 refresh tokens。<sup>[[1]](#references)</sup>

### Data protection keychain：先枚举，再查询单个条目

从**目标用户的登录上下文中运行的已签名 app** 调用 `SecItemCopyMatching`，并设置 `kSecUseDataProtectionKeychain: true`；不要假设 `security dump-keychain` 或默认的 SecItem 查询会搜索此存储。调用方只能看到其获授权的 access groups。<sup>[[5]](#references)</sup>

如果测试代码在另一个进程中运行，其 data protection keychain 访问权限取决于该宿主 executable 的 entitlements。使用 `codesign -d --entitlements - /path/to/Target.app` 检查实际签名的 entitlements，并参阅 [macOS code-signing entitlements](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md) 了解相关检查。<sup>[[7]](#references)</sup>

首先针对一种条目类别，仅请求 **attributes**。`kSecAttrSynchronizableAny` 同时包含本地匹配项和 iCloud-synchronizable 匹配项；省略它则会排除 synchronizable 条目。<sup>[[8]](#references)</sup> `kSecUseAuthenticationUISkip` 可避免在广泛枚举时显示认证 UI，但代价是跳过受保护的匹配项。<sup>[[9]](#references)</sup> 如有需要，请对 `kSecClassInternetPassword` 重复此操作。

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

对于经过授权的机密读取，请针对选定项目构建一个**新的**、范围明确的查询（例如，指定 class、service 和 account），设置 `kSecReturnData: true` 和 `kSecMatchLimit: kSecMatchLimitOne`，并预期会触发针对该项目的身份验证或返回错误。对于 password 项目，**不要**将 `kSecReturnData` 与 `kSecMatchLimitAll` 组合使用。<sup>[[10]](#references)</sup> `errSecItemNotFound` 也可能是由于选错存储区、同步筛选条件不正确或缺少 access-group entitlement，而非凭据不存在。<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0：「破解 macOS Keychain」- Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - MacSync macOS stealer 新版本针对加密货币爱好者和开发者](https://securelist.com/macsync-new-version/121383/)
- [4] [Apple security(1) man page 镜像](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — 关于 Mac keychain API 和实现](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Apple Developer Forums — SecItem：基础知识](https://developer.apple.com/forums/thread/724023)
- [7] [Apple Developer Forums — SecItem：陷阱与最佳实践](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — 使用 Face ID 或 Touch ID 访问 Keychain 项目](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
