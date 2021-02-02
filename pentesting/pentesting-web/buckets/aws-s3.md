# AWS-S3

## Amazon S3 Buckets

A bucket is typically considered “public” if any user can list the contents of the bucket, and “private” if the bucket's contents can only be listed or written by certain S3 users. This is important to understand and emphasize. _**A public bucket will list all of its files and directories to an any user that asks.**_

It should be emphasized that a public bucket is not a risk created by Amazon but rather a misconfiguration caused by the owner of the bucket. And although a file might be listed in a bucket it does not necessarily mean that it can be downloaded. Buckets and objects have their own access control lists \(ACLs\).  Amazon provides information on managing access controls for buckets [here](http://docs.aws.amazon.com/AmazonS3/latest/dev/UsingAuthAccess.html). Furthermore, Amazon helps their users by publishing a best practices document on [public access considerations around S3 buckets](http://aws.amazon.com/articles/5050). The default configuration of an S3 bucket is private.

**Learn about AWS-S3 misconfiguration here:** [ **http://flaws.cloud**](%20http://flaws.cloud) **and** [**http://flaws2.cloud/**](http://flaws2.cloud/) **\(Most of the information here has been take from those resources\)**

#### **Regions**

* US Standard = http://s3.amazonaws.com
* Ireland = http://s3-eu-west-1.amazonaws.com
* Northern California = http://s3-us-west-1.amazonaws.com
* Singapore = http://s3-ap-southeast-1.amazonaws.com
* Tokyo = http://s3-ap-northeast-1.amazonaws.com

## AWS Configuration

Prerequisites, at least you need awscli

```text
sudo apt install awscli
```

You can get your credential here [https://console.aws.amazon.com/iam/home?\#/security\_credential](https://console.aws.amazon.com/iam/home?#/security_credential) but you need an aws account, free tier account : [https://aws.amazon.com/s/dm/optimization/server-side-test/free-tier/free\_np/](https://aws.amazon.com/s/dm/optimization/server-side-test/free-tier/free_np/)

```text
aws configure --profile <PROFILE_NAME>
AWSAccessKeyId=[ENTER HERE YOUR KEY]
AWSSecretKey=[ENTER HERE YOUR KEY]
```

Alternatively you can use environment variables instead of creating a profile.

```text
export AWS_ACCESS_KEY_ID=ASIAZ[...]PODP56
export AWS_SECRET_ACCESS_KEY=fPk/Gya[...]4/j5bSuhDQ
export AWS_SESSION_TOKEN=FQoGZXIvYXdzE[...]8aOK4QU=
```

## Finding AWS Buckets used by the target

Different methods to find when a webpage is using AWS to storage some resources:

* Using wappalyzer browser plugin
* Using BURP \(spidering the web\) or by manually navigating through the page all resources loaded will be save in the History.
* Check for resources in domains like:

  ```text
  http://s3.amazonaws.com/[bucket_name]/
  http://[bucket_name].s3.amazonaws.com/
  ```

Notice that a domain could be hiding some of this URLs for example `resources.domain.com --> bucket.s3.amazonaws.com`

You can get the region of a bucket with a dig and nslookup:

```text
$ dig flaws.cloud
;; ANSWER SECTION:
flaws.cloud.    5    IN    A    52.218.192.11

$ nslookup 52.218.192.11
Non-authoritative answer:
11.192.218.52.in-addr.arpa name = s3-website-us-west-2.amazonaws.com.
```

Check that the resolved domain have the word "website".  
You can access the static website going to: `flaws.cloud.s3-website-us-west-2.amazonaws.com`   
or you can access the bucket visiting:  `flaws.cloud.s3-us-west-2.amazonaws.com`

If you tries to access a bucket but in the domain name you specifies another region \(for example the bucket is in `bucket.s3.amazonaws.com` but you try to access `bucket.s3-website-us-west-2.amazonaws.com` you will be redirected to the correct location.

## Enumerating the bucket

To test the openness of the bucket a user can just enter the URL in their web browser. A private bucket will respond with "Access Denied". A public bucket will list the first 1,000 objects that have been stored.

Open to everyone:

![](../../../.gitbook/assets/image%20%2880%29.png)

Private:

![](../../../.gitbook/assets/image%20%2836%29.png)

You can also check this with the `aws` tool: 

```bash
#Use --no-sign-request for check Everyones permissions
#Use --profile <PROFILE_NAME> to indicate the AWS profile(keys) that youwant to use: Check for "Any Authenticated AWS User" permissions
#--recursive if you want list recursivelyls 
#Opcionally you can select the region if you now it
aws s3 ls  s3://flaws.cloud/ [--no-sign-request] [--profile <PROFILE_NAME>] [ --recursive] [--region us-west-2]
```

If the bucket doesn't have a domain name, when trying to enumerate it, **only put the bucket name** and not the hole AWSs3 domain. Example: `s3://<BUCKETNAME>`

## Enumerating a AWS User

If you find some private AWS keys, you can create a profile using those:

```text
aws configure --profile flawscloud
```

Notice that if you find a users credentials in the meta-data folder, you will need to add the _aws\_session\_token_ to the profile.

### Get buckets

And the check to which buckets this profile is related to \(may or may not have access to them\):

```text
aws s3 ls --profile flawscloud
```

![](../../../.gitbook/assets/image%20%2815%29.png)

### User Information

Check the **UserId, Account number** and **UserName** doing:

```text
aws --profile flawscloud sts get-caller-identity
```

![](../../../.gitbook/assets/image%20%28180%29.png)

```text
aws iam get-user --profile level6
```

![](../../../.gitbook/assets/image%20%28168%29.png)

### Get User Policies

```text
aws iam list-attached-user-policies --profile <Profile> --user-name <UserName>
```

![](../../../.gitbook/assets/image%20%28194%29.png)

To get information about a policy you first need the DefaultVersionId:

```text
aws iam get-policy --profile <PROFILE> --policy-arn <POLICY_ARN> #Example: arn:aws:iam::975426262029:policy/list_apigateways
```

![](../../../.gitbook/assets/image%20%28170%29.png)

Now, you can see the policy:

```text
aws iam get-policy-version --profile level6 --policy-arn arn:aws:iam::975426262029:policy/list_apigateways --version-id v4
```

![](../../../.gitbook/assets/image%20%28334%29.png)

This means that you can access `GET arn:aws:apigateway:us-west-2::/restapis/*`

Now it's time to find out possible lambda functions to execute:

```text
aws --region us-west-2 --profile level6 lambda list-functions
```

![](../../../.gitbook/assets/image%20%2871%29.png)

A lambda function called "Level6" is available. Lets find out how to call it:

```bash
aws --region us-west-2 --profile level6 lambda get-policy --function-name Level6
```

![](../../../.gitbook/assets/image%20%28185%29.png)

Now, that you know the name and the ID you can get the Name:

```bash
aws --profile level6 --region us-west-2 apigateway get-stages --rest-api-id "s33ppypa75"
```

![](../../../.gitbook/assets/image%20%2824%29.png)

And finally call the function accessing \(notice that the ID, Name and functoin-name appears in the URL\): [https://s33ppypa75.execute-api.us-west-2.amazonaws.com/Prod/level6](https://s33ppypa75.execute-api.us-west-2.amazonaws.com/Prod/level6)

### User privileges enumeration and privilege escalation

Try the tool: [pacu](https://github.com/RhinoSecurityLabs/pacu)

### Find and Download Elastic Container Registry

```bash
## Find
aws ecr list-images --repository-name <ECR_name> --registry-id <UserID> --region <region> --profile <profile_name>
## Download
aws ecr get-login
docker pull <UserID>.dkr.ecr.us-east-1.amazonaws.com/<ECRName>:latest
docker inspect sha256:079aee8a89950717cdccd15b8f17c80e9bc4421a855fcdc120e1c534e4c102e0
```

### Get Snapshots

Notice that ****AWS allows you to make snapshots of EC2's and databases \(RDS\). The main purpose for that is to make backups, but people sometimes use snapshots to get access back to their own EC2's when they forget the passwords.

Look for snapshots this user has access to \(note the **SnapshotId**\):

```bash
#This timeyou need to specify the region
aws  ec2 describe-snapshots --profile flawscloud --owner-id 975426262029 --region us-west-2
```

![](../../../.gitbook/assets/image%20%284%29.png)

If you run that command without specifying the --owner-id you can see how many publicly available EC2 snapshots are.

## Mounting an EC2 snapshot

Create a copy of the backup:

```bash
aws ec2 create-volume --profile YOUR_ACCOUNT --availability-zone us-west-2a --region us-west-2  --snapshot-id  snap-0b49342abd1bdcb89
```

**Mount it in a EC2 VM under your control** \(it has to be in the same region as the copy of the backup\):

**step 1:** Head over to EC2 –&gt; Volumes and create a new volume of your preferred size and type.

**Step 2:** Select the created volume, right click and select the “attach volume” option.

**Step 3:** Select the instance from the instance text box as shown below.[![attach ebs volume](https://devopscube.com/wp-content/uploads/2016/08/ebs-volume.jpg)](https://devopscube.com/wp-content/uploads/2016/08/ebs-volume.jpg)

**Step 4:** Now, login to your ec2 instance and list the available disks using the following command.

```text
lsblk
```

The above command will list the disk you attached to your instance.

**Step5:**

![](../../../.gitbook/assets/image%20%28304%29.png)

## SSRF attacks through AWS

If you want to read about how can you exploit meta-data in AWS [you should read this page](../../../pentesting-web/ssrf-server-side-request-forgery.md#abusing-ssrf-in-aws-environment)



## Tools to scan the configuration of buckets **or to discover buckets**

{% embed url="https://github.com/sa7mon/S3Scanner" %}

{% embed url="https://github.com/kromtech/s3-inspector" %}

{% embed url="https://github.com/jordanpotti/AWSBucketDump" %}

{% embed url="https://github.com/hehnope/slurp" %}

{% embed url="https://github.com/fellchase/flumberboozle" %}

{% embed url="https://github.com/smaranchand/bucky" %}

{% embed url="https://github.com/tomdev/teh\_s3\_bucketeers" %}

\*\*\*\*

## **List of Open Buckets**

{% embed url="https://buckets.grayhatwarfare.com/" %}

\*\*\*\*

