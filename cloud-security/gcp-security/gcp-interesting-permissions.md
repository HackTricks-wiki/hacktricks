# GCP - Interesting Permissions

These techniques were copied from [https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/) and [https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/](https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/#gcp-privesc-scanner)

## deploymentmanager

### deploymentmanager.deployments.create

This single permission lets you **launch new deployments** of resources into GCP a**s the **_**\<project number>@cloudservices.gserviceaccount.com**_** Service Account**, which, by default, is granted the Editor role on the project.

![](<../../.gitbook/assets/image (626).png>)

In the following example [this script](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/deploymentmanager.deployments.create.py) is used to deploy a compute instance, but any resource listed in `gcloud deployment-manager types list`_ _could be actually deployed:

## IAM

### iam.roles.update

You can use this permission to **update the “includedPermissons” on your role**, so you can get any permission you want.

![](<../../.gitbook/assets/image (627) (1).png>)

```
gcloud iam roldes update <rol name> --project <project> --add-permissions <permission>
```

You can find a script to abuse this privilege [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.roles.update.py).

### iam.serviceAccounts.getAccessToken

This permission allows to **request an access token that belongs to a Service Account**, so it's possible to request an access token of a Service Account with more privileges than ours.

The following screenshot shows an example of it, where the “iamcredentials” API is targeted to generate a new token. You can even specify the associated scopes for the token.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image11-1000x208.png)

The exploit script for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.serviceAccounts.getAccessToken.py).

### iam.serviceAccountKeys.create

This permission allows us to do something similar to the previous method, but instead of an access token, we are **creating a user-managed key for a Service Account**, which will allow us to access GCP as that Service Account. The screenshot below shows us using the gcloud CLI to create a new Service Account key. Afterwards, we would just use this key to authenticate with the API.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image3-1000x98.png)

```
gcloud iam service-accounts keys create --iam-account <name>
```

The exploit script for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.serviceAccountKeys.create.py).

### iam.serviceAccounts.implicitDelegation

If you have the _iam.serviceAccounts.implicitDelegation_ permission on another Service Account that has the _iam.serviceAccounts.getAccessToken_ permission on a third Service Account, then you can use implicitDelegation to create a token for that third Service Account. Here is a diagram to help explain.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image2-500x493.png)

The following screenshot shows a Service Account (Service Account A) making a request to the “iamcredentials” API to generate an access token for the “test-project” Service Account (Service Account C). The “scc-user” Service Account (Service Account B) is specified in the POST body as a “delegate”, meaning you are using your implicitDelegation permission on “scc-user” (Service Account B) to create an access token for “test-project” (Service Account C). Next, a request is made to the “tokeninfo” endpoint to verify the validity of the received token.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image10-1000x417.png)

The exploit script for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.serviceAccounts.implicitDelegation.py).

### iam.serviceAccounts.signBlob

The _iam.serviceAccounts.signBlob_ permission “allows signing of arbitrary payloads” in GCP. This means we can **create a signed blob that requests an access token from the Service Account **we are targeting.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image4-1000x168.png)

The exploit scripts for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.serviceAccounts.signBlob-accessToken.py) and [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.serviceAccounts.signBlob-gcsSignedUrl.py).

### iam.serviceAccounts.signJwt

Similar to how the previous method worked by signing arbitrary payloads, this method works by signing well-formed JSON web tokens (JWTs). The script for this method will sign a well-formed JWT and **request a new access token belonging to the Service Account with it**.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image5-1000x78.png)

The exploit script for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.serviceAccounts.signJWT.py).

### iam.serviceAccounts.actAs

This means that as part of creating certain resources, you must “actAs” the Service Account for the call to complete successfully. For example, when starting a new Compute Engine instance with an attached Service Account, you need _iam.serviceAccounts.actAs_ on that Service Account. This is because without that permission, users could escalate permissions with fewer permissions to start with.

**There are multiple individual methods that use **_**iam.serviceAccounts.actAs**_**, so depending on your own permissions, you may only be able to exploit one (or more) of these methods below**. These methods are slightly different in that they **require multiple permissions to exploit, rather than a single permission** like all of the previous methods.

## cloudbuild

### cloudbuild.builds.create

You can find the exploit script [here on our GitHub](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/cloudbuild.builds.create.py). This script accepts GCP credentials and an HTTP(S) URL, and will exfiltrate the access token belonging to the Cloud Build Service Account to the URL supplied. If you don’t supply that URL, you must specify the IP and port of the current server and an HTTP server will automatically be launched to listen for the token to be received. Remember, you need the “cloudbuild.builds.create” permission for it to work.

To use the script, just run it with the compromised GCP credentials you gained access to and set up an HTTP(S) listener on a public-facing server (or use the built-in server on the current host). The token will be sent to that server in the body of a POST request.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/cloudbuild.builds.create.png)

Now that we have the token, we can begin making API calls as the Cloud Build Service account and hopefully find something juicy with these extra permissions!

For a more indepth explanation visit [https://rhinosecuritylabs.com/gcp/iam-privilege-escalation-gcp-cloudbuild/](https://rhinosecuritylabs.com/gcp/iam-privilege-escalation-gcp-cloudbuild/)

## cloudfunctions

### cloudfunctions.functions.create (iam.serviceAccounts.actAs)

For this method, we will be **creating a new Cloud Function with an associated Service Account** that we want to gain access to. Because Cloud Function invocations have **access to the metadata** API, we can request a token directly from it, just like on a Compute Engine instance.

The **required permissions** for this method are as follows:

* _cloudfunctions.functions.call _**OR**_ cloudfunctions.functions.setIamPolicy_
* _cloudfunctions.functions.create_
* _cloudfunctions.functions.sourceCodeSet_
* _iam.serviceAccounts.actAs_

The script for this method uses a premade Cloud Function that is included on GitHub, meaning you will need to upload the associated .zip file and make it public on Cloud Storage (see the exploit script for more information). Once the function is created and uploaded, you can either invoke the function directly or modify the IAM policy to allow you to invoke the function. The response will include the access token belonging to the Service Account assigned to that Cloud Function.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image12-750x618.png)

The script creates the function and waits for it to deploy, then it runs it and gets returned the access token.

The exploit scripts for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/cloudfunctions.functions.create-call.py) and [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/cloudfunctions.functions.create-setIamPolicy.py) and the prebuilt .zip file can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/tree/master/ExploitScripts/CloudFunctions).

### cloudfunctions.functions.update (iam.serviceAccounts.actAs)

Similar to _cloudfunctions.functions.create_, this method **updates (overwrites) an existing function instead of creating a new one**. The API used to update the function also allows you to **swap the Service Account if you have another one you want to get the token for**. The script will update the target function with the malicious code, then wait for it to deploy, then finally invoke it to be returned the Service Account access token.

The following **permissions are required** for this method:

* _cloudfunctions.functions.sourceCodeSet_
* _cloudfunctions.functions.update_
* _iam.serviceAccounts.actAs_

The exploit script for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/cloudfunctions.functions.update.py).

## compute

### compute.instances.create (iam.serviceAccounts.actAs)

This method **creates a new Compute Engine instance with a specified Service Account**, then **sends the token** belonging to that Service Account to an **external server.**

The following **permissions are required** for this method:

* _compute.disks.create_
* _compute.instances.create_
* _compute.instances.setMetadata_
* _compute.instances.setServiceAccount_
* _compute.subnetworks.use_
* _compute.subnetworks.useExternalIp_
* _iam.serviceAccounts.actAs_

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image9-750x594.png)

The exploit script for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/compute.instances.create.py).

## run

### run.services.create (iam.serviceAccounts.actAs)

Similar to the _cloudfunctions.functions.create_ method, this method creates a **new Cloud Run Service **that, when invoked, **returns the Service Account’s** access token by accessing the metadata API of the server it is running on. A Cloud Run service will be deployed and a request can be performed to it to get the token.

The following **permissions are required** for this method:

* _run.services.create_
* _iam.serviceaccounts.actAs_
* _run.services.setIamPolicy _**OR**_ run.routes.invoke_

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image8-1000x503.png)

This method uses an included Docker image that must be built and hosted to exploit correctly. The image is designed to tell Cloud Run to respond with the Service Account’s access token when an HTTP request is made.

The exploit script for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/run.services.create.py) and the Docker image can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/tree/master/ExploitScripts/CloudRunDockerImage).

## Cloudscheduler

### cloudscheduler.jobs.create (iam.serviceAccounts.actAs)

Cloud Scheduler allows you to set up cron jobs targeting arbitrary HTTP endpoints. **If that endpoint is a \*.googleapis.com endpoint**, then you can also tell Scheduler that you want it to authenticate the request **as a specific Service Account**, which is exactly what we want.

Because we control all aspects of the HTTP request being made from Cloud Scheduler, we can set it up to hit another Google API endpoint. For example, if we wanted to create a new job that will use a specific Service Account to create a new Storage bucket on our behalf, we could run the following command:

```
gcloud scheduler jobs create http test –schedule=’* * * * *’ –uri=’https://storage.googleapis.com/storage/v1/b?project=<PROJECT-ID>’ –message-body “{‘name’:’new-bucket-name’}” –oauth-service-account-email 111111111111-compute@developer.gserviceaccount.com –headers Content-Type=application/json
```

This command would schedule an HTTP POST request for every minute that authenticates as _111111111111-compute@developer.gserviceaccount.com_. The request will hit the Cloud Storage API endpoint and will create a new bucket with the name “new-bucket-name”.

The following permissions are required for this method:

* _cloudscheduler.jobs.create_
* _cloudscheduler.locations.list_
* _iam.serviceAccounts.actAs_

To escalate our privileges with this method, we just need to **craft the HTTP request of the API we want to hit as the Service Account we pass in**. Instead of a script, you can just use the gcloud command above.

A similar method may be possible with Cloud Tasks, but we were not able to do it in our testing.

## orgpolicy

### orgpolicy.policy.set

This method does **not necessarily grant you more IAM permissions**, but it may **disable some barriers **that are preventing certain actions. For example, there is an Organization Policy constraint named _appengine.disableCodeDownload_ that prevents App Engine source code from being downloaded by users of the project. If this was enabled, you would not be able to download that source code, but you could use _orgpolicy.policy.set_ to disable the constraint and then continue with the source code download.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image5-1.png)

The screenshot above shows that the _appengine.disableCodeDownload_ constraint is enforced, which means it is preventing us from downloading the source code. Using _orgpolicy.policy.set_, we can disable that enforcement and then continue on to download the source code.

The exploit script for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/orgpolicy.policy.set.py).

## serviceusage

### serviceusage.apiKeys.create

There is another method of authenticating with GCP APIs known as API keys. By default, they are created with no restrictions, which means they have access to the entire GCP project they were created in. We can capitalize on that fact by creating a new API key that may have more privileges than our own user. There is no official API for this, so a custom HTTP request needs to be sent to _https://apikeys.clients6.google.com/_ (or _https://apikeys.googleapis.com/_). This was discovered by monitoring the HTTP requests and responses while browsing the GCP web console. For documentation on the restrictions associated with API keys, visit [this link](https://cloud.google.com/docs/authentication/api-keys).

The following screenshot shows how you would create an API key in the web console.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image6-1.png)

With the undocumented API that was discovered, we can also create API keys through the API itself.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image3-1.png)

The screenshot above shows a POST request being sent to retrieve a new API key for the project.

The exploit script for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/serviceusage.apiKeys.create.py).

### serviceusage.apiKeys.list

Another undocumented API was found for listing API keys that have already been created (this can also be done in the web console). Because you can still see the API key’s value after its creation, we can pull all the API keys in the project.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image4-1.png)

The screenshot above shows that the request is exactly the same as before, it just is a GET request instead of a POST request. This only shows a single key, but if there were additional keys in the project, those would be listed too.

The exploit script for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/serviceusage.apiKeys.list.py).

## storage

### storage.hmacKeys.create

There is a feature of Cloud Storage, “interoperability”, that provides a way for Cloud Storage to interact with storage offerings from other cloud providers, like AWS S3. As part of that, there are HMAC keys that can be created for both Service Accounts and regular users. We can **escalate Cloud Storage permissions by creating an HMAC key for a higher-privileged Service Account**.&#x20;

HMAC keys belonging to your user cannot be accessed through the API and must be accessed through the web console, but what’s nice is that both the access key and secret key are available at any point. This means we could take an existing pair and store them for backup access to the account. HMAC keys belonging to Service Accounts **can** be accessed through the API, but after creation, you are not able to see the access key and secret again.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image2-1.png)

The exploit script for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/storage.hmacKeys.create.py).

## \*.setIamPolicy

If you owns a user that has the **`setIamPolicy`** permission in a resource you can **escalate privileges in that resource **because you will be able to change the IAM policy of that resource and give you more privileges over it.

A few that are worth looking into for privilege escalation are listed here:

* _resourcemanager.organizations.setIamPolicy_
  * Attach IAM roles to your user at the Organization level.
* _resourcemanager.folders.setIamPolicy_
  * Attach IAM roles to your user at the Folder level.
* _resourcemanager.projects.setIamPolicy_
  * Attach IAM roles to your user at the Project level.
* _iam.serviceAccounts.setIamPolicy_
  * Attach IAM roles to your user at the Service Account level.
* _cloudfunctions.functions.setIamPolicy_
  * Modify the policy of a Cloud Function to allow yourself to invoke it.

There are tens of resources types with this kind of permission, you can find all of them in [https://cloud.google.com/iam/docs/permissions-reference](https://cloud.google.com/iam/docs/permissions-reference) searching for setIamPolicy.

An **example** of privilege escalation abusing .setIamPolicy (in this case in a bucket) can be found here:

{% content-ref url="gcp-buckets-brute-force-and-privilege-escalation.md" %}
[gcp-buckets-brute-force-and-privilege-escalation.md](gcp-buckets-brute-force-and-privilege-escalation.md)
{% endcontent-ref %}
