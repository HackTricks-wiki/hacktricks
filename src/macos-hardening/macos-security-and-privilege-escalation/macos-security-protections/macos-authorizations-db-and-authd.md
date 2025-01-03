# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **授权数据库**

位于 `/var/db/auth.db` 的数据库用于存储执行敏感操作的权限。这些操作完全在 **用户空间** 中执行，通常由 **XPC 服务** 使用，这些服务需要检查 **调用客户端是否被授权** 执行某些操作，通过检查该数据库。

最初，该数据库是从 `/System/Library/Security/authorization.plist` 的内容创建的。然后，一些服务可能会添加或修改该数据库以添加其他权限。

规则存储在数据库中的 `rules` 表内，包含以下列：

- **id**: 每条规则的唯一标识符，自动递增，作为主键。
- **name**: 规则的唯一名称，用于在授权系统中识别和引用它。
- **type**: 指定规则的类型，仅限于值 1 或 2，以定义其授权逻辑。
- **class**: 将规则分类为特定类别，确保它是正整数。
- "allow" 表示允许，"deny" 表示拒绝，"user" 如果组属性指示一个允许访问的组，"rule" 表示在数组中需要满足的规则，"evaluate-mechanisms" 后跟一个 `mechanisms` 数组，这些机制可以是内置的或是 `/System/Library/CoreServices/SecurityAgentPlugins/` 或 /Library/Security//SecurityAgentPlugins 中的一个包的名称。
- **group**: 指示与规则相关联的用户组，用于基于组的授权。
- **kofn**: 表示 "k-of-n" 参数，确定必须满足的子规则数量。
- **timeout**: 定义规则授予的授权在多少秒后过期。
- **flags**: 包含各种标志，以修改规则的行为和特征。
- **tries**: 限制允许的授权尝试次数，以增强安全性。
- **version**: 跟踪规则的版本，以便进行版本控制和更新。
- **created**: 记录规则创建时的时间戳，以便审计。
- **modified**: 存储对规则进行的最后修改的时间戳。
- **hash**: 保存规则的哈希值，以确保其完整性并检测篡改。
- **identifier**: 提供唯一的字符串标识符，例如 UUID，以供外部引用规则。
- **requirement**: 包含序列化数据，定义规则的特定授权要求和机制。
- **comment**: 提供关于规则的可读描述或注释，以便于文档和清晰性。

### 示例
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
此外，在 [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) 可以查看 `authenticate-admin-nonshared` 的含义：
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

它是一个守护进程，将接收请求以授权客户端执行敏感操作。它作为一个在 `XPCServices/` 文件夹中定义的 XPC 服务工作，并将日志写入 `/var/log/authd.log`。

此外，使用安全工具可以测试许多 `Security.framework` API。例如，运行 `AuthorizationExecuteWithPrivileges`：`security execute-with-privileges /bin/ls`

这将以 root 身份分叉并执行 `/usr/libexec/security_authtrampoline /bin/ls`，这将提示请求权限以 root 身份执行 ls：

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

{{#include ../../../banners/hacktricks-training.md}}
