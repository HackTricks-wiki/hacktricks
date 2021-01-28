# Logstash

## Basic Information

Logstash  is used for collecting, transforming and outputting logs. This is realized by using **pipelines**, which contain input, filter and output modules. The service gets interesting when having compromised a machine which is running Logstash as a service.

### Pipelines

The pipeline configuration file **/etc/logstash/pipelines.yml** specifies the locations of active pipelines:

```bash
# This file is where you define your pipelines. You can define multiple.
# For more information on multiple pipelines, see the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
  path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
  path.config: "/usr/share/logstash/pipeline/1*.conf"
  pipeline.workers: 6
```

In here you can find the paths to the **.conf** files, which contain the configured pipelines. If the **Elasticsearch output module** is used, **pipelines** are likely to **contain** valid **credentials** for an Elasticsearch instance. Those credentials have often more privileges, since Logstash has to write data to Elasticsearch. If wildcards are used, Logstash tries to run all pipelines located in that folder matching the wildcard.

### Privesc with writable pipelines

Before trying to elevate your own privileges you should check which user is running the logstash service, since this will be the user, you will be owning afterwards. Per default the logstash service runs with the privileges of the **logstash** user.

Check whether you have **one** of the required rights:

* You have **write permissions** on a pipeline **.conf** file **or**
* **/etc/logstash/pipelines.yml** contains a wildcard and you are allowed to write into the specified folder

Further **one** of the requirements must be met:

* You are able to restart the logstash service **or**
* **/etc/logstash/logstash.yml** contains the entry **config.reload.automatic: true**

If a wildcard is specified, try to create a file matching that wildcard. Following content can be written into the file to execute commands:

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

The **interval** specifies the time in seconds. In this example the **whoami** command is executed every 120 seconds. The output of the command is saved into **/tmp/output.log**.

If **/etc/logstash/logstash.yml** contains the entry **config.reload.automatic: true** you only have to wait until the command gets executed, since Logstash will automatically recognize new pipeline configuration files or any changes in existing pipeline configurations. Otherwise trigger a restart of the logstash service.

If no wildcard is used, you can apply those changes to an existing pipeline configuration. **Make sure you do not break things!**

## References

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)

