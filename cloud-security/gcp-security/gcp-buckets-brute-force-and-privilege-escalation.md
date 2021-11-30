# GCP - Buckets: Public Assets Brute-Force & Discovery, & Buckets Privilege Escalation

## Public Assets Discovery

One way to discover public cloud resources that belongs to a company is to scrape their webs looking for them. Tools like [**CloudScraper**](https://github.com/jordanpotti/CloudScraper) will scrape the web an search for **links to public cloud resources** (in this case this tools searches `['amazonaws.com', 'digitaloceanspaces.com', 'windows.net', 'storage.googleapis.com', 'aliyuncs.com']`)

Note that other cloud resources could be searched for and that some times these resources are hidden behind **subdomains that are pointing them via CNAME registry**.

## Public Resources Brute-Force

### Buckets, Firebase, Apps & Cloud Functions

* [https://github.com/initstring/cloud\_enum](https://github.com/initstring/cloud\_enum): This tool in GCP brute-force Buckets, Firebase Realtime Databases, Google App Engine sites, and Cloud Functions
* [https://github.com/0xsha/CloudBrute](https://github.com/0xsha/CloudBrute): This tool in GCP brute-force Buckets and Apps.

### Buckets

As other clouds, GCP also offers Buckets to its users. These buckets might be  (to list the content, read, write...).

![](<../../.gitbook/assets/image (628) (1) (1).png>)

The following tools can be used to generate variations of the name given and search for miss-configured buckets with that names:

* [https://github.com/RhinoSecurityLabs/GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute)

## Privilege Escalation

If the bucket policy allowed either “allUsers” or “allAuthenticatedUsers” to **write to their bucket policy** (the **storage.buckets.setIamPolicy** permission)**,** then anyone can modify the bucket policy and grant himself full access.

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
