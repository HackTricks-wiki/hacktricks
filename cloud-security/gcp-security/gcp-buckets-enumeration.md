# GCP - Buckets Enumeration

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

### Search Open Buckets

With the following script [gathered from here](https://gitlab.com/gitlab-com/gl-security/security-operations/gl-redteam/gcp\_misc/-/blob/master/find\_open\_buckets.sh) you can find all the open buckets:

```bash
#!/bin/bash

#############################
# Run this tool to find buckets that are open to the public anywhere
# in your GCP organization.
#
# Enjoy!
#############################

for proj in $(gcloud projects list --format="get(projectId)"); do
    echo "[*] scraping project $proj"
    for bucket in $(gsutil ls -p $proj); do
        echo "    $bucket"
        ACL="$(gsutil iam get $bucket)"

        all_users="$(echo $ACL | grep allUsers)"
        all_auth="$(echo $ACL | grep allAuthenticatedUsers)"

        if [ -z "$all_users" ]
        then
              :
        else
              echo "[!] Open to all users: $bucket"
        fi

        if [ -z "$all_auth" ]
        then
              :
        else
              echo "[!] Open to all authenticated users: $bucket"
        fi
    done

```
