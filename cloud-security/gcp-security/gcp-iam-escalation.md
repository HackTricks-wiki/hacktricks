# GCP - IAM Escalation

## **iam.serviceAccountTokenCreator**

The predefined role called **`iam.serviceAccountTokenCreator`** allow to **impersonate other accounts** that can have more permissions and/or a less restrictive scope.

Using this role you could impersonate the default service account if it still exists in the project as it has the primitive role of Project Editor. You should also search for a service account with the primitive role of Owner.

`gcloud` has a `--impersonate-service-account` [flag](https://cloud.google.com/sdk/gcloud/reference/#--impersonate-service-account) which can be used with any command to execute in the context of that account.

To give this a shot, you can try the following:

```bash
# View available service accounts
gcloud iam service-accounts list

# Impersonate the account
gcloud compute instances list \
    --impersonate-service-account xxx@developer.gserviceaccount.com
```
