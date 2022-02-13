# GCP - Privesc to other Principals

{% hint style="info" %}
GCP has **hundreds of permissions**. This is just a list containing the **known** ones that could allow you to escalate to other principals.\
If you know about any other permissions not mentioned here, **please send a PR to add it** or let me know and I will add it.
{% endhint %}

## IAM

### iam.roles.update (iam.roles.get)

If you have the mentioned permissions you will be able to update a role assigned to you and give you extra permissions to other resources like:

```bash
gcloud iam roldes update <rol name> --project <project> --add-permissions <permission>
```

You can find a script to automate the [**creation, exploit and cleaning of a vuln environment here**](gcp-privesc-to-other-principals.md#deploymentmanager) and a python script to abuse this privilege [**here**](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.roles.update.py). For more information check the [**original research**](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/).

### iam.serviceAccounts.getAccessToken (iam.serviceAccounts.get)

This permission allows to **request an access token that belongs to a Service Account**, so it's possible to request an access token of a Service Account with more privileges than ours.

You can find a script to automate the [**creation, exploit and cleaning of a vuln environment here**](https://github.com/carlospolop/gcp\_privesc\_scripts/blob/main/tests/4-iam.serviceAccounts.getAccessToken.sh) and a python script to abuse this privilege [**here**](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.serviceAccounts.getAccessToken.py). For more information check the [**original research**](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/).

### iam.serviceAccountKeys.create

This permission allows us to do something similar to the previous method, but instead of an access token, we are **creating a user-managed key for a Service Account**, which will allow us to access GCP as that Service Account.

```bash
gcloud iam service-accounts keys create --iam-account <name>
```

You can find a script to automate the [**creation, exploit and cleaning of a vuln environment here**](https://github.com/carlospolop/gcp\_privesc\_scripts/blob/main/tests/3-iam.serviceAccountKeys.create.sh) and a python script to abuse this privilege [**here**](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.serviceAccountKeys.create.py). For more information check the [**original research**](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/).

Note that **iam.serviceAccountKeys.update won't work to modify the key** of a SA because to do that the permissions iam.serviceAccountKeys.create is also needed.

### iam.serviceAccounts.implicitDelegation

If you have the _**iam.serviceAccounts.implicitDelegation**_\*\* permission on a Service Account\*\* that has the _**iam.serviceAccounts.getAccessToken**_\*\* permission on a third Service Account\*\*, then you can use implicitDelegation to **create a token for that third Service Account**. Here is a diagram to help explain.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image2-500x493.png)

You can find a script to automate the [**creation, exploit and cleaning of a vuln environment here**](https://github.com/carlospolop/gcp\_privesc\_scripts/blob/main/tests/5-iam.serviceAccounts.implicitDelegation.sh) and a python script to abuse this privilege [**here**](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.serviceAccounts.implicitDelegation.py). For more information check the [**original research**](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/).

Note that according to the [**documentation**](https://cloud.google.com/iam/docs/understanding-service-accounts), the delegation only works to generate a token using the [**generateAccessToken()**](https://cloud.google.com/iam/credentials/reference/rest/v1/projects.serviceAccounts/generateAccessToken) method.

### iam.serviceAccounts.signBlob

The _iam.serviceAccounts.signBlob_ permission “allows signing of arbitrary payloads” in GCP. This means we can **create an unsigined JWT of the SA and then send it as a blob to get the JWT signed** by the SA we are targeting. For more information [**read this**](https://medium.com/google-cloud/using-serviceaccountactor-iam-role-for-account-impersonation-on-google-cloud-platform-a9e7118480ed).

You can find a script to automate the [**creation, exploit and cleaning of a vuln environment here**](https://github.com/carlospolop/gcp\_privesc\_scripts/blob/main/tests/6-iam.serviceAccounts.signBlob.sh) and a python script to abuse this privilege [**here**](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.serviceAccounts.signBlob-accessToken.py) and [**here**](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.serviceAccounts.signBlob-gcsSignedUrl.py). For more information check the [**original research**](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/).

### iam.serviceAccounts.signJwt

Similar to how the previous method worked by signing arbitrary payloads, this method works by signing well-formed JSON web tokens (JWTs). The difference with the previous method is that **instead of making google sign a blob containing a JWT, we use the signJWT method that already expects a JWT**. This makes it easier to use but you can only sign JWT instead of any bytes.

You can find a script to automate the [**creation, exploit and cleaning of a vuln environment here**](https://github.com/carlospolop/gcp\_privesc\_scripts/blob/main/tests/7-iam.serviceAccounts.signJWT.sh) and a python script to abuse this privilege [**here**](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.serviceAccounts.signJWT.py). For more information check the [**original research**](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/).

### iam.serviceAccounts.setIamPolicy <a href="#iam.serviceaccounts.setiampolicy" id="iam.serviceaccounts.setiampolicy"></a>

This permission allows to **add IAM policies to service accounts**. You can abuse it to **grant yourself** the permissions you need to impersonate the service account. In the following example we are granting ourselves the “roles/iam.serviceAccountTokenCreator” role over the interesting SA:

```bash
gcloud iam service-accounts add-iam-policy-binding "${VICTIM_SA}@${PROJECT_ID}.iam.gserviceaccount.com" \
	--member="user:username@domain.com" \
	--role="roles/iam.serviceAccountTokenCreator"
```

You can find a script to automate the [**creation, exploit and cleaning of a vuln environment here**](https://github.com/carlospolop/gcp\_privesc\_scripts/blob/main/tests/d-iam.serviceAccounts.setIamPolicy.sh)**.**

### iam.serviceAccounts.actAs

This means that as part of creating certain resources, you must “actAs” the Service Account for the call to complete successfully. For example, when starting a new Compute Engine instance with an attached Service Account, you need _iam.serviceAccounts.actAs_ on that Service Account. This is because without that permission, users could escalate permissions with fewer permissions to start with.

**There are multiple individual methods that use \_iam.serviceAccounts.actAs**\_**, so depending on your own permissions, you may only be able to exploit one (or more) of these methods below**. These methods are slightly different in that they **require multiple permissions to exploit, rather than a single permission** like all of the previous methods.

### iam.serviceAccounts.getOpenIdToken

This permission can be used to generate an OpenID JWT. These are used to assert identity and do not necessarily carry any implicit authorization against a resource.

According to this [**interesting post**](https://medium.com/google-cloud/authenticating-using-google-openid-connect-tokens-e7675051213b), it's necessary to indicate the audience (service where you want to use the token to authenticate to) and you will receive a JWT signed by google indicating the service account and the audience of the JWT.

You can generate an OpenIDToken (if you have the access) with:

```bash
# First activate the SA with iam.serviceAccounts.getOpenIdToken over the other SA
gcloud auth activate-service-account --key-file=/path/to/svc_account.json
# Then, generate token
gcloud auth print-identity-token "${ATTACK_SA}@${PROJECT_ID}.iam.gserviceaccount.com" --audiences=https://example.com
```

Then you can just use it to access the service with:

```bash
curl -v -H "Authorization: Bearer id_token" https://some-cloud-run-uc.a.run.app
```

Some services that support authentication via this kind of tokens are:

* [Google Cloud Run](https://cloud.google.com/run/)
* [Google Cloud Functions](https://cloud.google.com/functions/docs/)
* [Google Identity Aware Proxy](https://cloud.google.com/iap/docs/authentication-howto)
* [Google Cloud Endpoints](https://cloud.google.com/endpoints/docs/openapi/authenticating-users-google-id) (if using Google OIDC)

You can find an example on how to create and OpenID token behalf a service account [**here**](https://github.com/carlospolop-forks/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.serviceAccounts.getOpenIdToken.py).

## resourcemanager

### resourcemanager.organizations.setIamPolicy

Like in the exploitation of [**iam.serviceAccounts.setIamPolicy**](gcp-privesc-to-other-principals.md#iam.serviceaccounts.setiampolicy), this permission allows you to **modify** your **permissions** against **any resource** at **organization** level. So, you can follow the same exploitation example.

### resourcemanager.folders.setIamPolicy

Like in the exploitation of [**iam.serviceAccounts.setIamPolicy**](gcp-privesc-to-other-principals.md#iam.serviceaccounts.setiampolicy), this permission allows you to **modify** your **permissions** against **any resource** at **folder** level. So, you can follow the same exploitation example.

### resourcemanager.projects.setIamPolicy

Like in the exploitation of [**iam.serviceAccounts.setIamPolicy**](gcp-privesc-to-other-principals.md#iam.serviceaccounts.setiampolicy), this permission allows you to **modify** your **permissions** against **any resource** at **project** level. So, you can follow the same exploitation example.

## deploymentmanager

### deploymentmanager.deployments.create

This single permission lets you **launch new deployments** of resources into GCP with arbitrary service accounts. You could for example launch a compute instance with a SA to escalate to it.

You could actually **launch any resource** listed in `gcloud deployment-manager types list`

In the [**original research**](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/) following[ **script**](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/deploymentmanager.deployments.create.py) is used to deploy a compute instance, however that script won't work. Check a script to automate the [**creation, exploit and cleaning of a vuln environment here**](https://github.com/carlospolop/gcp\_privesc\_scripts/blob/main/tests/1-deploymentmanager.deployments.create.sh)**.**

### deploymentmanager.deployments.**update**

This is like the previous abuse but instead of creating a new deployment, you modifies one already existing (so be careful)

Check a script to automate the [**creation, exploit and cleaning of a vuln environment here**](https://github.com/carlospolop/gcp\_privesc\_scripts/blob/main/tests/e-deploymentmanager.deployments.update.sh)**.**

### deploymentmanager.deployments.**setIamPolicy**

This is like the previous abuse but instead of directly creating a new deployment, you first give you that access and then abuses the permission as explained in the previos _deploymentmanager.deployments.create_ section.

## cloudbuild

### cloudbuild.builds.create

With this permission you can **submit a cloud build**. The cloudbuild machine will have in it’s filesystem by **default a token of the powerful cloudbuild Service Account**: `<PROJECT_NUMBER>@cloudbuild.gserviceaccount.com` . However, you can **indicate any service account inside the project** in the cloudbuild configuration.\
Therefore, you can just make the machine exfiltrate to your server the token or **get a reverse shell inside of it and get yourself the token** (the file containing the token might change).

You can find the original exploit script [**here on GitHub**](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/cloudbuild.builds.create.py) (but the location it's taking the token from didn't work for me). Therefore, check a script to automate the [**creation, exploit and cleaning of a vuln environment here**](https://github.com/carlospolop/gcp\_privesc\_scripts/blob/main/tests/f-cloudbuild.builds.create.sh) and a python script to get a reverse shell inside of the cloudbuild machine and [**steal it here**](https://github.com/carlospolop/gcp\_privesc\_scripts/blob/main/tests/f-cloudbuild.builds.create.py) (in the code you can find how to specify other service accounts)**.**

For a more in-depth explanation visit [https://rhinosecuritylabs.com/gcp/iam-privilege-escalation-gcp-cloudbuild/](https://rhinosecuritylabs.com/gcp/iam-privilege-escalation-gcp-cloudbuild/)

### cloudbuild.builds.update

**Potentially** with this permission you will be able to **update a cloud build and just steal the service account token** like it was performed with the previous permission (but unfortunately at the time of this writing I couldn't find any way to call that API).

## container

### container.clusters.get

This permission allows to **gather credentials for the Kubernetes cluster** using something like:

```bash
gcloud container clusters get-credentials <cluster_name> --zone <zone>
```

Without extra permissions, the credentials are pretty basic as you can **just list some resource**, but hey are useful to find miss-configurations in the environment.

{% hint style="info" %}
Note that **kubernetes clusters might be configured to be private**, that will disallow that access to the Kube-API server from the Internet.
{% endhint %}

### container.clusters.getCredentials

Apparently this permission might be useful to gather auth credentials (basic auth method isn't supported anymore by GKE if you use the latest GKE versions).

### container.roles.escalate/container.clusterRoles.escalate

**Kubernetes** by default **prevents** principals from being able to **create** or **update** **Roles** and **ClusterRoles** with **more permissions** that the ones the principal has. However, a **GCP** principal with that permissions will be **able to create/update Roles/ClusterRoles with more permissions** that ones he held, effectively bypassing the Kubernetes protection against this behaviour.

**container.roles.create** and/or **container.roles.update** are also **necessary** to perform those privilege escalation actions.

### container.roles.bind/container.clusterRoles.bind

**Kubernetes** by default **prevents** principals from being able to **create** or **update** **RoleBindings** and **ClusterRoleBindings** to give **more permissions** that the ones the principal has. However, a **GCP** principal with that permissions will be **able to create/update RolesBindings/ClusterRolesBindings with more permissions** that ones he has, effectively bypassing the Kubernetes protection against this behaviour.

**container.roleBindings.create** and/or **container.roleBindings.update** are also **necessary** to perform those privilege escalation actions.

### container.cronJobs.create, container.cronJobs.update container.daemonSets.create, container.daemonSets.update container.deployments.create, container.deployments.update container.jobs.create, container.jobs.update container.pods.create, container.pods.update container.replicaSets.create, container.replicaSets.update container.replicationControllers.create, container.replicationControllers.update container.scheduledJobs.create, container.scheduledJobs.update container.statefulSets.create, container.statefulSets.update

All these permissions are going to allow you to **create or update a resource** where you can **define** a **pod**. Defining a pod you can **specify the SA** that is going to be **attached** and the **image** that is going to be **run**, therefore you can run an image that is going to **exfiltrate the token of the SA to your server** allowing you to escalate to any service account.\
For more information check:

{% content-ref url="../../../pentesting/pentesting-kubernetes/hardening-roles-clusterroles/" %}
[hardening-roles-clusterroles](../../../pentesting/pentesting-kubernetes/hardening-roles-clusterroles/)
{% endcontent-ref %}

As we are in a GCP environment, you will also be able to **get the nodepool GCP SA** from the **metadata** service and **escalate privileges in GC**P (by default the compute SA is used).

### container.secrets.get, container.secrets.list

As [**explained in this page**](../../../pentesting/pentesting-kubernetes/hardening-roles-clusterroles/#listing-secrets), with these permissions you can **read** the **tokens** of all the **SAs of kubernetes**, so you can escalate to them.

### container.pods.exec

With this permission you will be able to **exec into pods**, which gives you **access** to all the **Kubernetes SAs running in pods** to escalate privileges within K8s, but also you will be able to **steal** the **GCP Service Account** of the **NodePool**, **escalating privileges in GCP**.

### container.pods.portForward

As [**explained in this page**](../../../pentesting/pentesting-kubernetes/hardening-roles-clusterroles/#port-forward), with these permissions you can **access local services** running in **pods** that might allow you to **escalate privileges in Kubernetes** (and in **GCP** if somehow you manage to talk to the metadata service)**.**

### container.serviceAccounts.createToken

Because of the **name** of the **permission**, it **looks like that it will allow you to generate tokens of the K8s Service Accounts**, so you will be able to **privesc to any SA** inside Kubernetes. However, I couldn't find any API endpoint to use it, so let me know if you find it.

### container.mutatingWebhookConfigurations.create, container.mutatingWebhookConfigurations.update

These permissions might allow you to escalate privileges in Kubernetes, but more probably, you could abuse them to **persist in the cluster**.\
For more information [**follow this link**](../../../pentesting/pentesting-kubernetes/hardening-roles-clusterroles/#malicious-admission-controller).

## References

* [https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/)
* [https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/](https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/#gcp-privesc-scanner)
