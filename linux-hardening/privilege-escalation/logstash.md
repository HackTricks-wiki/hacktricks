

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


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

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


