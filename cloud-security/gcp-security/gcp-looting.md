# GCP - Other Services Enumeration

## Stackdriver logging

[Stackdriver](https://cloud.google.com/stackdriver/) is Google's general-purpose infrastructure logging suite which might be capturing sensitive information like syslog-like capabilities that report individual commands run inside Compute Instances, HTTP requests sent to load balancers or App Engine applications, network packet metadata for VPC communications, and more.

The service account for a Compute Instance **only needs WRIT**E access to enable logging on instance actions, **but** an administrator may **mistakenly** **grant** the service account both **READ** and WRITE access. If this is the case, you can explore logs for sensitive data.

[gcloud logging](https://cloud.google.com/sdk/gcloud/reference/logging/) provides tools to get this done. First, you'll want to see what types of logs are available in your current project.

```bash
# List logs
gcloud logging logs list
NAME
projects/REDACTED/logs/OSConfigAgent
projects/REDACTED/logs/cloudaudit.googleapis.com%2Factivity
projects/REDACTED/logs/cloudaudit.googleapis.com%2Fsystem_event
projects/REDACTED/logs/bash.history
projects/REDACTED/logs/compute.googleapis.com
projects/REDACTED/logs/compute.googleapis.com%2Factivity_log

# Read logs
gcloud logging read [FOLDER]

# Write logs
# An attacker writing logs may confuse the Blue Team
gcloud logging write [FOLDER] [MESSAGE]
```

## AI platform configurations <a href="reviewing-ai-platform-configurations" id="reviewing-ai-platform-configurations"></a>

Google [AI Platform](https://cloud.google.com/ai-platform/) is another "serverless" offering for machine learning projects.

There are a few areas here you can look for interesting information - models and jobs. Try the following commands.

```
$ gcloud ai-platform models list --format=json
$ gcloud ai-platform jobs list --format=json
```

## Cloud pub/sub <a href="reviewing-cloud-pubsub" id="reviewing-cloud-pubsub"></a>

Google [Cloud Pub/Sub](https://cloud.google.com/pubsub/) is a service that allows independent applications to **send messages** back and forth. Basically, there are **topics** where applications may **subscribe** to send and receive **messages** (which are composed by the message content and some metadata).

```bash
# Get a list of topics in the project
gcloud pubsub topics list

# Get a list of subscriptions across all topics
gcloud pubsub subscriptions list --format=json

# This will retrive a non ACKed message (and won't ACK it)
gcloud pubsub subscriptions pull [SUBSCRIPTION NAME]
```

However, you may have better results [asking for a larger set of data](https://cloud.google.com/pubsub/docs/replay-overview), including older messages. This has some prerequisites and could impact applications, so make sure you really know what you're doing.

## Cloud Git repositories <a href="reviewing-cloud-git-repositories" id="reviewing-cloud-git-repositories"></a>

Google's [Cloud Source Repositories](https://cloud.google.com/source-repositories/) are Git designed to be private storage for source code. You might **find useful secrets here**, or use the **source to discover vulnerabilities** in other applications.

You can explore the available repositories with the following commands:

```bash
# enumerate what's available
gcloud source repos list

# clone a repo locally
gcloud source repos clone [REPO NAME]
```

## Cloud Filestore Instances

Google [Cloud Filestore](https://cloud.google.com/filestore/) is NAS for Compute Instances and Kubernetes Engine instances. You can think of this like any other **shared document repository -** a potential source of sensitive info.

If you find a filestore available in the project, you can **mount it** from within your compromised Compute Instance. Use the following command to see if any exist.

```
gcloud filestore instances list --format=json
```

## Containers

```bash
gcloud container images list
gcloud container subnets list
gcloud container clusters list
gcloud container clusters get-credentials [NAME]

# Run a container locally
docker run --rm -ti gcr.io/<project-name>/secret:v1 sh
```

## Kubernetes

First, you can check to see if any Kubernetes clusters exist in your project.

```
gcloud container clusters list
```

If you do have a cluster, you can have `gcloud` automatically configure your `~/.kube/config` file. This file is used to authenticate you when you use [kubectl](https://kubernetes.io/docs/reference/kubectl/overview/), the native CLI for interacting with K8s clusters. Try this command.

```
gcloud container clusters get-credentials [CLUSTER NAME] --region [REGION]
```

Then, take a look at the `~/.kube/config` file to see the generated credentials. This file will be used to automatically refresh access tokens based on the same identity that your active `gcloud` session is using. This of course requires the correct permissions in place.

Once this is set up, you can try the following command to get the cluster configuration.

```
kubectl cluster-info
```

You can read more about `gcloud` for containers [here](https://cloud.google.com/sdk/gcloud/reference/container/).

This is a simple script to enumerate kubernetes in GCP: [https://gitlab.com/gitlab-com/gl-security/security-operations/gl-redteam/gcp\_k8s\_enum](https://gitlab.com/gitlab-com/gl-security/security-operations/gl-redteam/gcp\_k8s\_enum)&#x20;

## References

* [https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/#reviewing-stackdriver-logging](https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/#reviewing-stackdriver-logging)
