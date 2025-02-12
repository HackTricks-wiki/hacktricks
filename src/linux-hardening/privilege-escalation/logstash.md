{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash is used to **gather, transform, and dispatch logs** through a system known as **pipelines**. These pipelines are made up of **input**, **filter**, and **output** stages. An interesting aspect arises when Logstash operates on a compromised machine.

### Pipeline Configuration

Pipelines are configured in the file **/etc/logstash/pipelines.yml**, which lists the locations of the pipeline configurations:

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

This file reveals where the **.conf** files, containing pipeline configurations, are located. When employing an **Elasticsearch output module**, it's common for **pipelines** to include **Elasticsearch credentials**, which often possess extensive privileges due to Logstash's need to write data to Elasticsearch. Wildcards in configuration paths allow Logstash to execute all matching pipelines in the designated directory.

### Privilege Escalation via Writable Pipelines

To attempt privilege escalation, first identify the user under which the Logstash service is running, typically the **logstash** user. Ensure you meet **one** of these criteria:

- Possess **write access** to a pipeline **.conf** file **or**
- The **/etc/logstash/pipelines.yml** file uses a wildcard, and you can write to the target folder

Additionally, **one** of these conditions must be fulfilled:

- Capability to restart the Logstash service **or**
- The **/etc/logstash/logstash.yml** file has **config.reload.automatic: true** set

Given a wildcard in the configuration, creating a file that matches this wildcard allows for command execution. For instance:

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

Here, **interval** determines the execution frequency in seconds. In the given example, the **whoami** command runs every 120 seconds, with its output directed to **/tmp/output.log**.

With **config.reload.automatic: true** in **/etc/logstash/logstash.yml**, Logstash will automatically detect and apply new or modified pipeline configurations without needing a restart. If there's no wildcard, modifications can still be made to existing configurations, but caution is advised to avoid disruptions.

## References

{{#include ../../banners/hacktricks-training.md}}

