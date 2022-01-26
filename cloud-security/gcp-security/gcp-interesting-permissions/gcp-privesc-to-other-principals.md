# GCP - Privesc to other Principals

## IAM

### iam.roles.update (iam.roles.get)

If you have the mentioned permissions you will be able to update a role assigned to you and give you extra permissions to other resources like:

```bash
gcloud iam roldes update <rol name> --project <project> --add-permissions <permission>
```

You can find a script to automate the [**creation, exploit and cleaning of a vuln environment here**](gcp-privesc-to-other-principals.md#deploymentmanager) and a python script to abuse this privilege [**here**](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.roles.update.py). For more information check the [**original research**](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/).

### iam.serviceAccounts.getAccessToken  (iam.serviceAccounts.get)

This permission allows to **request an access token that belongs to a Service Account**, so it's possible to request an access token of a Service Account with more privileges than ours.

You can find a script to automate the [**creation, exploit and cleaning of a vuln environment here**](https://github.com/carlospolop/gcp\_privesc\_scripts/blob/main/tests/4-iam.serviceAccounts.getAccessToken.sh) and a python script to abuse this privilege [**here**](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.serviceAccounts.getAccessToken.py). For more information check the [**original research**](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/).

### iam.serviceAccountKeys.create

This permission allows us to do something similar to the previous method, but instead of an access token, we are **creating a user-managed key for a Service Account**, which will allow us to access GCP as that Service Account.

```bash
gcloud iam service-accounts keys create --iam-account <name>
```

You can find a script to automate the [**creation, exploit and cleaning of a vuln environment here**](https://github.com/carlospolop/gcp\_privesc\_scripts/blob/main/tests/3-iam.serviceAccountKeys.create.sh) and a python script to abuse this privilege [**here**](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.serviceAccountKeys.create.py). For more information check the [**original research**](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/).

### iam.serviceAccounts.implicitDelegation

If you have the _**iam.serviceAccounts.implicitDelegation**_** permission on a Service Account** that has the _**iam.serviceAccounts.getAccessToken**_** permission on a third Service Account**, then you can use implicitDelegation to **create a token for that third Service Account**. Here is a diagram to help explain.

![](https://rhinosecuritylabs.com/wp-content/uploads/2020/04/image2-500x493.png)

You can find a script to automate the [**creation, exploit and cleaning of a vuln environment here**](https://github.com/carlospolop/gcp\_privesc\_scripts/blob/main/tests/5-iam.serviceAccounts.implicitDelegation.sh) and a python script to abuse this privilege [**here**](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/iam.serviceAccounts.implicitDelegation.py). For more information check the [**original research**](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/).

### iam.serviceAccounts.signBlob

The _iam.serviceAccounts.signBlob_ permission “allows signing of arbitrary payloads” in GCP. This means we can **create an unsigined JWT of the SA and then send it as a blob to get the JWT signed** by the SA **** we are targeting. For more information [**read this**](https://medium.com/google-cloud/using-serviceaccountactor-iam-role-for-account-impersonation-on-google-cloud-platform-a9e7118480ed).

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

You can find a script to automate the [**creation, exploit and cleaning of a vuln environment here**](https://github.com/carlospolop/gcp\_privesc\_scripts/blob/main/tests/d-iam.serviceAccounts.setIamPolicy.sh).

### iam.serviceAccounts.actAs

This means that as part of creating certain resources, you must “actAs” the Service Account for the call to complete successfully. For example, when starting a new Compute Engine instance with an attached Service Account, you need _iam.serviceAccounts.actAs_ on that Service Account. This is because without that permission, users could escalate permissions with fewer permissions to start with.

**There are multiple individual methods that use **_**iam.serviceAccounts.actAs**_**, so depending on your own permissions, you may only be able to exploit one (or more) of these methods below**. These methods are slightly different in that they **require multiple permissions to exploit, rather than a single permission** like all of the previous methods.

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

