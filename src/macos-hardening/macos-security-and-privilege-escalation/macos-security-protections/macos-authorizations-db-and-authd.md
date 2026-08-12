# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## Authorization Database

Security framework 的 Authorization Services 允许 privileged helpers 和其他组件评估命名的 authorization rights。在当前的 macOS 版本中，其中许多规则会持久化存储在 `/var/db/auth.db` 中，并由 `authd` 进行评估；此文件及其 SQLite schema 属于实现细节，可能会在不同版本之间发生变化。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

系统默认值历来取自 `/System/Library/Security/authorization.plist`，而 installers 或 privileged services 可能会添加命名的 rights。请优先使用受支持的 `security authorizationdb read|write|remove` interface，而不是直接编辑数据库。<sup>[[3]](#references)</sup>

在所记录的 build 中观察到的 `rules` table 包含以下 columns。请将其视为 forensic map，而不是稳定的 public schema：

- **id**：每条 rule 的唯一标识符，自动递增，并作为 primary key。
- **name**：用于在 authorization system 中识别和引用 rule 的唯一名称。
- **type**：指定 rule 的类型，仅限于值 1 或 2，用于定义其 authorization logic。
- **class**：将 rule 归类到特定 class 中，并确保其为正整数。
- 常见的 rule classes 包括 `allow`、`deny`、`user`、`rule` 和 `evaluate-mechanisms`。Mechanisms 可以是 built-ins，也可以是位于 `/System/Library/CoreServices/SecurityAgentPlugins/` 或 `/Library/Security/SecurityAgentPlugins/` 下的 Security Agent plug-ins。<sup>[[2]](#references)</sup>
- **group**：表示与 rule 关联的 user group，用于基于 group 的 authorization。
- **kofn**：表示 “k-of-n” 参数，用于确定总数中必须满足多少个 subrules。
- **timeout**：定义 rule 授予的 authorization 在过期前持续的秒数。
- **flags**：包含用于修改 rule 行为和特征的各种 flags。
- **tries**：限制允许的 authorization attempts 次数，以增强 security。
- **version**：跟踪 rule 的版本，用于版本控制和更新。
- **created**：记录 rule 创建时的 timestamp，以便进行 auditing。
- **modified**：存储对 rule 进行最后一次修改时的 timestamp。
- **hash**：保存 rule 的 hash value，以确保其 integrity 并检测 tampering。
- **identifier**：提供唯一的 string identifier，例如 UUID，以便外部引用 rule。
- **requirement**：包含定义 rule 特定 authorization requirements 和 mechanisms 的 serialized data。
- **comment**：提供关于 rule 的人类可读 description 或 comment，以便文档记录和理解。

### Example
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
以下解码后的规则展示了文档所述 macOS 版本中的 `authenticate-admin-nonshared`：<sup>[[1]](#references)</sup>
```json
{
"allow-root": "false",
"authenticate-user": "true",
"class": "user",
"comment": "Authenticate as an administrator.",
"group": "admin",
"session-owner": "false",
"shared": "false",
"timeout": "30",
"tries": "10000",
"version": "1"
}
```
## Authd

`authd` 是用于评估 Authorization Services 请求的 XPC 服务。在当前的 macOS 构建版本中，可以在 `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc` 检查其 bundle；该路径属于实现细节，可能因版本而异。较旧版本会写入 `/var/log/authd.log`；当前版本主要使用统一日志系统，可通过带有 `authd` 进程谓词的 `log show`/`log stream` 进行查询。<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

`security` 工具提供了多种 Authorization Services 操作。一个历史示例会使用 `AuthorizationExecuteWithPrivileges` 和 `security execute-with-privileges /bin/ls`。Apple 已在 macOS 10.7 中弃用该 API；现代的特权 helper 应使用由 launchd 管理的 helper，并通过 XPC authorization 实现。<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

在仍支持该功能的版本中，此操作会使用 `/usr/libexec/security_authtrampoline`，并在以 root 身份运行命令前显示 authorization prompt：

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - macOS Authorization Right 概述](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Apple Authorization Services 编程指南（存档）](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [`security(1)` macOS 手册页](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Daemons and Services 编程指南：创建 launchd jobs](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Apple 开源 Security 项目 - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)
{{#include ../../../banners/hacktricks-training.md}}
