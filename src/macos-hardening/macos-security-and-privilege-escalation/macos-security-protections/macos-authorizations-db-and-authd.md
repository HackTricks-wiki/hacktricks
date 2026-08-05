# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Authorizations DB**

位于 `/var/db/auth.db` 的数据库用于存储执行敏感操作所需的权限。这些操作完全在**用户态**中执行，通常由需要检查**调用客户端是否有权**执行特定操作的 **XPC services** 使用，检查依据就是该数据库。

该数据库最初根据 `/System/Library/Security/authorization.plist` 的内容创建。随后，某些 services 可能会添加或修改该数据库，以加入其他权限。

规则存储在数据库内的 `rules` 表中，并包含以下列：

- **id**：每条规则的唯一标识符，自动递增，并作为主键。
- **name**：规则的唯一名称，用于在授权系统中识别和引用该规则。
- **type**：指定规则的类型，仅限于值 1 或 2，用于定义其授权逻辑。
- **class**：将规则归类到特定类别中，并确保其为正整数。
- "allow" 表示允许，"deny" 表示拒绝，"user" 表示 `group` 属性指定了一个组，该组的成员可获得访问权限，"rule" 表示数组中存在必须满足的规则，"evaluate-mechanisms" 后跟一个 `mechanisms` 数组，其中的元素可以是 builtins，也可以是 `/System/Library/CoreServices/SecurityAgentPlugins/` 或 `/Library/Security//SecurityAgentPlugins` 中 bundle 的名称。
- **group**：表示与该规则关联的用户组，用于基于组的授权。
- **kofn**：表示 "k-of-n" 参数，用于确定总数为 n 的子规则中必须满足多少条。
- **timeout**：定义该规则授予的授权在多少秒后过期。
- **flags**：包含用于修改规则行为和特征的各种标志。
- **tries**：限制允许的授权尝试次数，以增强安全性。
- **version**：跟踪规则的版本，用于版本控制和更新。
- **created**：记录规则创建时的时间戳，用于审计。
- **modified**：存储对规则进行最后一次修改时的时间戳。
- **hash**：保存规则的哈希值，用于确保其完整性并检测篡改。
- **identifier**：提供唯一的字符串标识符（例如 UUID），用于从外部引用该规则。
- **requirement**：包含定义规则具体授权要求和 mechanisms 的序列化数据。
- **comment**：提供关于该规则的可读描述或注释，用于文档记录和提高可读性。

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
此外，在 [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) 中，可以查看 `authenticate-admin-nonshared` 的含义：<sup>[[1]](#references)</sup>
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

这是一个用于接收授权客户端执行敏感操作请求的 daemon。它作为定义在 `XPCServices/` 文件夹中的 XPC service 运行，并将日志写入 `/var/log/authd.log`。

此外，使用 security tool 可以测试许多 `Security.framework` APIs。例如，运行 `AuthorizationExecuteWithPrivileges`：`security execute-with-privileges /bin/ls`

该命令会以 root 身份 fork 并执行 `/usr/libexec/security_authtrampoline /bin/ls`，随后弹出权限请求提示，以 root 身份执行 ls：

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Overview of the macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
