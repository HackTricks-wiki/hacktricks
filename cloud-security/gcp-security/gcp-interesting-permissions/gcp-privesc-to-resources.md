# GCP - Privesc to Resources

## cloudfunctions

### cloudfunctions.functions.create,iam.serviceAccounts.actAs

For this method, we will be **creating a new Cloud Function with an associated Service Account** that we want to gain access to. Because Cloud Function invocations have **access to the metadata** API, we can request a token directly from it, just like on a Compute Engine instance.

The **required permissions** for this method are as follows:

* _cloudfunctions.functions.call_ **OR** _cloudfunctions.functions.setIamPolicy_
* _cloudfunctions.functions.create_
* _cloudfunctions.functions.sourceCodeSet_
* _iam.serviceAccounts.actAs_

The script for this method uses a premade Cloud Function that is included on GitHub, meaning you will need to upload the associated .zip file and make it public on Cloud Storage (see the exploit script for more information). Once the function is created and uploaded, you can either invoke the function directly or modify the IAM policy to allow you to invoke the function. The response will include the access token belonging to the Service Account assigned to that Cloud Function.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image12-750x618.png)

The script creates the function and waits for it to deploy, then it runs it and gets returned the access token.

The exploit scripts for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/cloudfunctions.functions.create-call.py) and [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/cloudfunctions.functions.create-setIamPolicy.py) and the prebuilt .zip file can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/tree/master/ExploitScripts/CloudFunctions).

### cloudfunctions.functions.update,iam.serviceAccounts.actAs

Similar to _cloudfunctions.functions.create_, this method **updates (overwrites) an existing function instead of creating a new one**. The API used to update the function also allows you to **swap the Service Account if you have another one you want to get the token for**. The script will update the target function with the malicious code, then wait for it to deploy, then finally invoke it to be returned the Service Account access token.

The following **permissions are required** for this method:

* _cloudfunctions.functions.sourceCodeSet_
* _cloudfunctions.functions.update_
* _iam.serviceAccounts.actAs_

The exploit script for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/cloudfunctions.functions.update.py).

## compute

### compute.instances.create,iam.serviceAccounts.actAs

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

### run.services.create,iam.serviceAccounts.actAs

Similar to the _cloudfunctions.functions.create_ method, this method creates a **new Cloud Run Service** that, when invoked, **returns the Service Account’s** access token by accessing the metadata API of the server it is running on. A Cloud Run service will be deployed and a request can be performed to it to get the token.

The following **permissions are required** for this method:

* _run.services.create_
* _iam.serviceaccounts.actAs_
* _run.services.setIamPolicy_ **OR** _run.routes.invoke_

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image8-1000x503.png)

This method uses an included Docker image that must be built and hosted to exploit correctly. The image is designed to tell Cloud Run to respond with the Service Account’s access token when an HTTP request is made.

The exploit script for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/run.services.create.py) and the Docker image can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/tree/master/ExploitScripts/CloudRunDockerImage).

## Cloudscheduler

### cloudscheduler.jobs.create,iam.serviceAccounts.actAs

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

This method does **not necessarily grant you more IAM permissions**, but it may **disable some barriers** that are preventing certain actions. For example, there is an Organization Policy constraint named _appengine.disableCodeDownload_ that prevents App Engine source code from being downloaded by users of the project. If this was enabled, you would not be able to download that source code, but you could use _orgpolicy.policy.set_ to disable the constraint and then continue with the source code download.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image5-1.png)

The screenshot above shows that the _appengine.disableCodeDownload_ constraint is enforced, which means it is preventing us from downloading the source code. Using _orgpolicy.policy.set_, we can disable that enforcement and then continue on to download the source code.

The exploit script for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/orgpolicy.policy.set.py).

## serviceusage

The following permissions are useful to create and steal API keys, not this from the docs: _An API key is a simple encrypted string that **identifies an application without any principal**. They are useful for accessing **public data anonymously**, and are used to **associate** API requests with your project for quota and **billing**._

Therefore, with an API key you can make that company pay for your use of the API, but you won't be able to escalate privileges.

### serviceusage.apiKeys.create

There is another method of authenticating with GCP APIs known as API keys. By default, they are created with no restrictions, which means they have access to the entire GCP project they were created in. We can capitalize on that fact by creating a new API key that may have more privileges than our own user. There is no official API for this, so a custom HTTP request needs to be sent to _https://apikeys.clients6.google.com/_ (or _https://apikeys.googleapis.com/_). This was discovered by monitoring the HTTP requests and responses while browsing the GCP web console. For documentation on the restrictions associated with API keys, visit [this link](https://cloud.google.com/docs/authentication/api-keys).

The following screenshot shows how you would create an API key in the web console.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image6-1.png)

With the undocumented API that was discovered, we can also create API keys through the API itself.

The screenshot above shows a POST request being sent to retrieve a new API key for the project.

The exploit script for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/serviceusage.apiKeys.create.py).

### serviceusage.apiKeys.list

Another undocumented API was found for listing API keys that have already been created (this can also be done in the web console). Because you can still see the API key’s value after its creation, we can pull all the API keys in the project.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image4-1.png)

The screenshot above shows that the request is exactly the same as before, it just is a GET request instead of a POST request. This only shows a single key, but if there were additional keys in the project, those would be listed too.

The exploit script for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/serviceusage.apiKeys.list.py).

## apikeys

The following permissions are useful to create and steal API keys, not this from the docs: _An API key is a simple encrypted string that **identifies an application without any principal**. They are useful for accessing **public data anonymously**, and are used to **associate** API requests with your project for quota and **billing**._

Therefore, with an API key you can make that company pay for your use of the API, but you won't be able to escalate privileges.

### apikeys.keys.create <a href="#apikeys.keys.create" id="apikeys.keys.create"></a>

This permission allows to **create an API key**:

```bash
gcloud alpha services api-keys create
Operation [operations/akmf.p7-[...]9] complete. Result: {
    "@type":"type.googleapis.com/google.api.apikeys.v2.Key",
    "createTime":"2022-01-26T12:23:06.281029Z",
    "etag":"W/\"HOhA[...]==\"",
    "keyString":"AIzaSy[...]oU",
    "name":"projects/5[...]6/locations/global/keys/f707[...]e8",
    "uid":"f707[...]e8",
    "updateTime":"2022-01-26T12:23:06.378442Z"
}
```

You can find a script to automate the [**creation, exploit and cleaning of a vuln environment here**](https://github.com/carlospolop/gcp\_privesc\_scripts/blob/main/tests/b-apikeys.keys.create.sh).

### apikeys.keys.getKeyString,apikeys.keys.list <a href="#apikeys.keys.getkeystringapikeys.keys.list" id="apikeys.keys.getkeystringapikeys.keys.list"></a>

These permissions allows **list and get all the apiKeys and get the Key**:

```bash
gcloud alpha services api-keys create
for  key  in  $(gcloud --impersonate-service-account="${SERVICE_ACCOUNT_ID}@${PROJECT_ID}.iam.gserviceaccount.com" alpha services api-keys list --uri); do
	gcloud --impersonate-service-account="${SERVICE_ACCOUNT_ID}@${PROJECT_ID}.iam.gserviceaccount.com" alpha services api-keys get-key-string "$key"
done
```

You can find a script to automate the [**creation, exploit and cleaning of a vuln environment here**](https://github.com/carlospolop/gcp\_privesc\_scripts/blob/main/tests/c-apikeys.keys.getKeyString.sh).

### apikeys.keys.regenerate,apikeys.keys.list <a href="#serviceusage.apikeys.regenerateapikeys.keys.list" id="serviceusage.apikeys.regenerateapikeys.keys.list"></a>

These permissions will (potentially) allow you to **list and regenerate all the apiKeys getting the new Key**.\
It’s not possible to use this from `gcloud` but you probably can use it via the API. Once it’s supported, the exploitation will be similar to the previous one (I guess).

### apikeys.keys.lookup <a href="#apikeys.keys.lookup" id="apikeys.keys.lookup"></a>

This is extremely useful to check to **which GCP project an API key that you have found belongs to**:

```bash
gcloud alpha services api-keys lookup AIzaSyD[...]uE8Y
name: projects/5[...]6/locations/global/keys/28d[...]e0e
parent: projects/5[...]6/locations/global
```

In this scenario it could also be interesting to run the tool [https://github.com/ozguralp/gmapsapiscanner](https://github.com/ozguralp/gmapsapiscanner) and check what you can access with the API key

## storage

### storage.hmacKeys.create

There is a feature of Cloud Storage, “interoperability”, that provides a way for Cloud Storage to interact with storage offerings from other cloud providers, like AWS S3. As part of that, there are HMAC keys that can be created for both Service Accounts and regular users. We can **escalate Cloud Storage permissions by creating an HMAC key for a higher-privileged Service Account**.&#x20;

HMAC keys belonging to your user cannot be accessed through the API and must be accessed through the web console, but what’s nice is that both the access key and secret key are available at any point. This means we could take an existing pair and store them for backup access to the account. HMAC keys belonging to Service Accounts **can** be accessed through the API, but after creation, you are not able to see the access key and secret again.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image2-1.png)

The exploit script for this method can be found [here](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/storage.hmacKeys.create.py).

## secretmanager

### secretmanager.secrets.get

This give you access to read the secrets from the secret manager.

### secretmanager.secrets.setIamPolicy

This give you access to give you access to read the secrets from the secret manager.

## \*.setIamPolicy

If you owns a user that has the **`setIamPolicy`** permission in a resource you can **escalate privileges in that resource** because you will be able to change the IAM policy of that resource and give you more privileges over it.

* _cloudfunctions.functions.setIamPolicy_
  * Modify the policy of a Cloud Function to allow yourself to invoke it.

There are tens of resources types with this kind of permission, you can find all of them in [https://cloud.google.com/iam/docs/permissions-reference](https://cloud.google.com/iam/docs/permissions-reference) searching for setIamPolicy.

An **example** of privilege escalation abusing .setIamPolicy (in this case in a bucket) can be found here:

{% content-ref url="../gcp-buckets-brute-force-and-privilege-escalation.md" %}
[gcp-buckets-brute-force-and-privilege-escalation.md](../gcp-buckets-brute-force-and-privilege-escalation.md)
{% endcontent-ref %}

## Generic Interesting Permissions

### \*.create, \*.update

These permissions can be very useful to try to escalate privileges in resources by **creating a new one or updating a new one**. These can of permissions are specially useful if you also has the permission **iam.serviceAccounts.actAs** over a Service Account and the resource you have .create/.update over can attach a service account.

### \*ServiceAccount\*

This permission will usually let you **access or modify a Service Account in some resource** (e.g.: compute.instances.setServiceAccount). This **could lead to a privilege escalation** vector, but it will depend on each case.

## References

* [https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/)
* [https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/](https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/#gcp-privesc-scanner)
