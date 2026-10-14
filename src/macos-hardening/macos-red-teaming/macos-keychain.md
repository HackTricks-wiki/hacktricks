# macOS 钥匙串

{{#include ../../banners/hacktricks-training.md}}

## 主要钥匙串

- **用户钥匙串**（`~/Library/Keychains/login.keychain-db`），用于存储**用户专属凭据**，例如应用程序密码、互联网密码、用户生成的证书、网络密码，以及用户生成的公钥/私钥。
- **系统钥匙串**（`/Library/Keychains/System.keychain`），用于存储**系统范围的凭据**，例如 WiFi 密码、系统根证书、系统私钥和系统应用程序密码。<sup>[[1]](#references)</sup>
  - 也可以在 `/System/Library/Keychains/*` 中找到其他组件，例如证书。
- **iOS** 中只有一个 **Keychain**，位于 `/private/var/Keychains/`。此文件夹还包含 `TrustStore`、证书颁发机构（`caissuercache`）和 OSCP 条目（`ocspache`）的数据库。
  - 应用只能访问钥匙串中属于其应用标识符的私有区域。

### 密码保护的钥匙串访问

这些文件本身没有保护机制，因此可以被**下载**，但它们经过加密，需要**用户的明文密码才能解密**。可以使用 [**Chainbreaker**](https://github.com/n0fate/chainbreaker) 之类的工具进行解密。<sup>[[1]](#references)</sup>

## 钥匙串条目的保护机制

### ACL

钥匙串中的每个条目都由**访问控制列表（ACL）**管理，用于规定谁可以对该条目执行各种操作，包括：<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**：允许持有者获取机密的明文。
- **`kSecACLAuthorizationExportWrapped`**：允许持有者使用另一个提供的密码加密机密明文后获取。
- **`kSecACLAuthorizationAny`**：允许持有者执行任何操作。

ACL 还附带一份**受信任应用程序列表**，这些应用程序可以无需提示而执行相关操作。该列表可以是：<sup>[[1]](#references)</sup>

- **N`il`**（无需授权，**所有人都受信任**）
- **空**列表（**无人**受信任）
- 特定**应用程序**的列表。

此外，条目可能包含键 **`kSecACLAuthorizationPartitionID`**，用于标识 **teamid、apple** 和 **cdhash**。<sup>[[1]](#references)[[2]](#references)</sup>

- 如果指定了 **teamid**，应用程序必须具有**相同的 teamid**，才能**无需提示**地**访问条目**值。
- 如果指定了 **apple**，应用必须由 **Apple** **签名**。
- 如果指定了 **cdhash**，则**应用**必须具有指定的 **cdhash**。

### 创建钥匙串条目

使用 **`Keychain Access.app`** 创建**新**条目时，适用以下规则：<sup>[[1]](#references)</sup>

- 所有应用都可以加密。
- **任何应用**都不能导出/解密（除非提示用户）。
- 所有应用都可以查看完整性检查。
- 任何应用都不能更改 ACL。
- **partitionID** 设置为 **`apple`**。

**应用程序在钥匙串中创建条目时**，规则略有不同：<sup>[[1]](#references)</sup>

- 所有应用都可以加密。
- 只有**创建该条目的应用程序**（或明确添加的其他应用）可以导出/解密（除非提示用户）。
- 所有应用都可以查看完整性检查。
- 任何应用都不能更改 ACL。
- **partitionID** 设置为 **`teamid:[teamID here]`**。

## 访问钥匙串

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

`-S` 设置条目的 partition list，而 `-k` 提供进行此更改所需的当前 Keychain 密码；用于输入密码的标志已弃用。<sup>[[4]](#references)</sup> 更新成功并不能证明之后读取时不会弹出提示：一个被观察到的、已禁用的原型在通过 `Security.framework` 查询该条目时，仍触发了确认提示。匹配的 partition ID 只是上述 ACL 和受信任应用检查的一部分，因此请验证实际的读取路径。<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> 使用工具 [**LockSmith**](https://github.com/its-a-feature/LockSmith) 可以对不会触发提示的密钥进行 **keychain 枚举和转储**。
>
> 其他 API 端点可在 [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) 源代码中找到。

使用 **Security Framework** 列出并获取每个 keychain 条目的**信息**，也可以查看 Apple 的开源命令行工具 [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**。** 一些 API 示例：<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** 可提供每个条目的信息，使用时可以设置一些属性：
  - **`kSecReturnData`**：若为 true，则会尝试解密数据（设为 false 可避免可能出现的弹窗）
  - **`kSecReturnRef`**：同时获取 keychain 条目的引用（若之后发现可以在不弹窗的情况下解密，则设为 true）
  - **`kSecReturnAttributes`**：获取条目的元数据
  - **`kSecMatchLimit`**：返回结果的数量
  - **`kSecClass`**：keychain 条目的类型

获取每个条目的 **ACL**：<sup>[[1]](#references)</sup>

- 使用 API **`SecAccessCopyACLList`** 可以获取 **keychain 条目的 ACL**。它会返回 ACL 列表（例如 `kSecACLAuthorizationExportClear` 及前面提到的其他项），其中每个条目包含：<sup>[[1]](#references)[[2]](#references)</sup>
  - 描述
  - **受信任应用列表**。其中可能包含：
    - 一个应用：/Applications/Slack.app
    - 一个二进制文件：/usr/libexec/airportd
    - 一个组：group://AirPort

导出数据：<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** 获取明文
- API **`SecItemExport`** 导出密钥和证书，但可能需要设置密码才能以加密形式导出内容

以下是**无提示导出机密**所需的条件：<sup>[[1]](#references)</sup>

- 如果列出了一个或多个受信任应用：
  - 需要具备相应的**授权**（**`Nil`**，或属于授权中允许访问机密信息的应用列表）
  - 代码签名必须匹配 **PartitionID**
  - 代码签名必须与某个**受信任应用**匹配（或属于正确的 KeychainAccessGroup）
- 如果所有应用都受信任：
  - 需要具备相应的**授权**
  - 代码签名必须匹配 **PartitionID**
    - 如果**没有 PartitionID**，则无需满足此条件

> [!CAUTION]
> 因此，如果列出了**一个应用**，就需要**向该应用注入代码**。
>
> 如果 **partitionID** 中标注了 **apple**，就可以通过 **`osascript`** 访问；因此，任何信任所有应用且 partitionID 中包含 apple 的条目都可以这样访问。也可以使用 **`Python`**。

### 两个额外属性

- **Invisible**：用于在 Keychain **UI** 应用中**隐藏**该条目的布尔标志<sup>[[1]](#references)</sup>
- **General**：用于存储**元数据**（因此**不会加密**）<sup>[[1]](#references)</sup>
  - Microsoft 曾将用于访问敏感端点的所有 refresh token 以明文形式存储。<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [#OBTS v5.0：「撬开 macOS Keychain」- Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - 新版本 MacSync macOS 窃取程序瞄准加密货币爱好者和开发者](https://securelist.com/macsync-new-version/121383/)
- [4] [Apple security(1) 手册页镜像](https://keith.github.io/xcode-man-pages/security.1.html)
