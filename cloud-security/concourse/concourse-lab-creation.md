<details> <summary><strong>Support HackTricks and get benefits!</strong></summary> Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)! Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family) Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.** **Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.** </details>
# Concourse Lab Creation

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
# After the installation you will find the indications to connect to it in the console

# If you need to delete it
helm delete concourse-release
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

* **the** [**`task` step**](https://concourse-ci.org/task-step.html) **runs a** [**task**](https://concourse-ci.org/tasks.html)
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

Check **127.0.0.1:8080** to see the pipeline flow.

### Bash script with output/input pipeline

It's possible to **save the results of one task in a file** and indicate that it's an output and then indicate the input of the next task as the output of the previous task. What concourse does is to **mount the directory of the previous task in the new task where you can access the files created by the previous task**.

### Triggers

You don't need to trigger the jobs manually every-time you need to run them, you can also program  them to be run every-time:

* Some time passes: [Time resource](https://github.com/concourse/time-resource/)
* On new commits to the main branch: [Git resource](https://github.com/concourse/git-resource)
* New PR's: [Github-PR resource](https://github.com/telia-oss/github-pr-resource)
* Fetch or push the latest image of your app: [Registry-image resource](https://github.com/concourse/registry-image-resource/)

Check a YAML pipeline example that triggers on new commits to master in [https://concourse-ci.org/tutorial-resources.html](https://concourse-ci.org/tutorial-resources.html)
<details> <summary><strong>Support HackTricks and get benefits!</strong></summary> Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)! Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family) Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.** **Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.** </details>
