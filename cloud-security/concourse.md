# Concourse

## Introduction

Concourse is a pipeline-based continuous thing-doer.

### Installation for testing

This docker-compose file simplifies the installation to do some tests with concourse:

```bash
wget https://raw.githubusercontent.com/starkandwayne/concourse-tutorial/master/docker-compose.yml
docker-compose up -d
```

You can download the command line `fly` for your OS from the web in `127.0.0.1:8080`

### Create Pipeline

A pipeline is made of a list of [Jobs](https://concourse-ci.org/jobs.html) which contains an ordered list of [Steps](https://concourse-ci.org/steps.html).

### Steps

Several different type of steps can be used:

* the [`task` step](https://concourse-ci.org/task-step.html) runs a [task](https://concourse-ci.org/tasks.html)
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
- name: hello-world-job
  plan:
  - task: hello-world-task
    config:
      # Tells Concourse which type of worker this task should run on
      platform: linux
      image_resource:
        type: registry-image
        source:
          repository: busybox # images are pulled from docker hub by default
      # The command Concourse will run inside the container
      # echo "Hello world!"
      run:
        path: echo
        args: ["Hello world!"]
```

```bash
fly -t tutorial set-pipeline -p hello-world -c hello-world.yml
# pipelines are paused when first created
fly -t tutorial unpause-pipeline -p hello-world
# trigger the job and watch it run to completion
fly -t tutorial trigger-job --job hello-world/hello-world-job --watch
```

### Bash script with output/input pipeline

```yaml
jobs:
- name: hello-world-job
  plan:
  - task: hello-world-task
    config:
      platform: linux
      image_resource:
        type: registry-image
        source:
          repository: busybox
      outputs:
      - name: the-artifact
      run:
        # This is a neat way of embedding a script into a task
        path: sh
        args:
        - -cx
        - |
          ls -l .
          echo "hello from another step!" > the-artifact/message
  # Add a second task that reads the contents of the-artifact/message
  - task: read-the-artifact
    config:
      platform: linux
      image_resource:
        type: registry-image
        source:
          repository: busybox
      # To recieve "the-artifact", specify it as an input
      inputs:
      - name: the-artifact
      run:
        path: sh
        args:
        - -cx
        - |
          ls -l .
          cat the-artifact/message
```

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

## Vars & Credential Manager

In the YAML configs you can configure values using the syntax `((`_`source-name`_`:`_`secret-path`_`.`_`secret-field`_`))`.\
The **source-name is optional**, and if omitted, he [cluster-wide credential manager](https://concourse-ci.org/vars.html#cluster-wide-credential-manager) will be used, or the value may be provided [statically](https://concourse-ci.org/vars.html#static-vars).\
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
  * `fly --target example login --team-name my-team --concourse-url https://ci.example.com [`--insecure`] [--client-cert=./path --client-key=./path]`
* Get configured **targets**:
  * `fly targets`
* Get if the configured **target connection** is still **valid**:
  * `fly -t <target> status`
* Get **role** of the user against the indicated target:
  * `fly -t <target> userinfo`

### Pipelines

* **List** pipelines:
  * `fly pipelines`
* **Get** pipeline yaml (**sensitive information** might be found in the definition):
  * `fly get-pipeline -p <pipeline-name>`

