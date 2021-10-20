# GCP - Buckets Brute-Force & Privilege Escalation

As other clouds, GCP also offers Buckets to its users. These buckets might be  (to list the content, read, write...).

The following tools can be used to generate variations of the name given and search for miss-configured buckets with that names:

* [https://github.com/RhinoSecurityLabs/GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute)
* [https://github.com/initstring/cloud\_enum](https://github.com/initstring/cloud\_enum)

## Privilege Escalation

If the bucket policy allowed either “allUsers” or “allAuthenticatedUsers” to **write to their bucket policy **(the **storage.buckets.setIamPolicy** permission)**, **then anyone can modify the bucket policy and grant himself full access.

### Check Permissions

There are 2 ways to check the permissions over a bucket. The first one is to ask for them by making a request to `https://www.googleapis.com/storage/v1/b/BUCKET_NAME/iam` or running `gsutil iam get gs://BUCKET_NAME`.

However, if your user (potentially belonging to allUsers or allAuthenticatedUsers") doesn't have permissions to read the iam policy of the bucket (storage.buckets.getIamPolicy), that won't work.

The other option which will always work is to use the testPermissions endpoint of the bucket to figure out if you have the specified permission, for example accessing: `https://www.googleapis.com/storage/v1/b/BUCKET_NAME/iam/testPermissions?permissions=storage.buckets.delete&permissions=storage.buckets.get&permissions=storage.buckets.getIamPolicy&permissions=storage.buckets.setIamPolicy&permissions=storage.buckets.update&permissions=storage.objects.create&permissions=storage.objects.delete&permissions=storage.objects.get&permissions=storage.objects.list&permissions=storage.objects.update`

### Escalating

With the “gsutil” Google Storage CLI program, we can run the following command to grant “allAuthenticatedUsers” access to the “Storage Admin” role, thus **escalating the privileges we were granted** to the bucket:

```
gsutil iam ch group:allAuthenticatedUsers:admin gs://BUCKET_NAME
```

One of the main attractions to escalating from a LegacyBucketOwner to Storage Admin is the ability to use the “storage.buckets.delete” privilege. In theory, you could **delete the bucket after escalating your privileges, then you could create the bucket in your own account to steal the name**.

## References

* [https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/](https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/)
