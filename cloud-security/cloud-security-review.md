# Cloud Security Review

**Check for nice cloud hacking tricks in** [**https://hackingthe.cloud/aws/general-knowledge/connection-tracking/**](https://hackingthe.cloud/aws/general-knowledge/connection-tracking/)

## Generic tools

There are several tools that can be used to test different cloud environments. The installation steps and links are going to be indicated in this section.

### [ScoutSuite](https://github.com/nccgroup/ScoutSuite)

AWS, Azure, GCP, Alibaba Cloud, Oracle Cloud Infrastructure

```text
pip3 install scoutsuite
```

### [cs-suite](https://github.com/SecurityFTW/cs-suite)

AWS, GCP, Azure, DigitalOcean

```text
git clone https://github.com/SecurityFTW/cs-suite.git && cd cs-suite/
pip install virtualenv
virtualenv -p python2.7 venv
source venv/bin/activate
pip install -r requirements.txt
python cs.py --help
```

### Nessus

Nessus has an _**Audit Cloud Infrastructure**_ scan supporting: AWS, Azure, Office 365, Rackspace, Salesforce. Some extra configurations in **Azure** are needed to obtain a **Client Id**.

### Common Sense

Take a look to the **network access rules** and detect if the services are correctly protected:

* ssh available from everywhere?
* Unencrypted services running \(telnet, http, ...\)?
* Unprotected admin consoles?
* In general, check that all services are correctly protected depending on their needs

## Azure

Access the portal here: [http://portal.azure.com/](http://portal.azure.com/)  
To start the tests you should have access with a user with **Reader permissions over the subscription** and **Global Reader role in AzureAD**. If even in that case you are **not able to access the content of the Storage accounts** you can fix it with the **role Storage Account Contributor**.

It is recommended to **install azure-cli** in a **linux** and **windows** virtual machines \(to be able to run powershell and python scripts\): [https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest)  
Then, run `az login` to login. Note the **account information** and **token** will be **saved** inside _&lt;HOME&gt;/.azure_ \(in both Windows and Linux\).

Remember that if the **Security Centre Standard Pricing Tier** is being used and **not** the **free** tier, you can **generate** a **CIS compliance scan report** from the azure portal. Go to _Policy & Compliance-&gt; Regulatory Compliance_ \(or try to access [https://portal.azure.com/\#blade/Microsoft\_Azure\_Security/SecurityMenuBlade/22](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/22)\).  
\_\_If the company is not paying for a Standard account you may need to review the **CIS Microsoft Azure Foundations Benchmark** by "hand" \(you can get some help using the following tools\). Download it from [**here**](https://www.newnettechnologies.com/cis-benchmark.html?keyword=&gclid=Cj0KCQjwyPbzBRDsARIsAFh15JYSireQtX57C6XF8cfZU3JVjswtaLFJndC3Hv45YraKpLVDgLqEY6IaAhsZEALw_wcB#microsoft-azure).

### Run scanners

Run the scanners to look for **vulnerabilities** and **compare** the security measures implemented with **CIS**.

```bash
pip install scout
scout azure --cli --report-dir <output_dir>

#Fix azureaudit.py before launching cs.py
#Adding "j_res = {}" on line 1074
python cs.py -env azure

#Azucar is an Azure security scanner for PowerShell (https://github.com/nccgroup/azucar)
#Run it from its folder
.\Azucar.ps1 -AuthMode Interactive -ForceAuth -ExportTo EXCEL

#Azure-CIS-Scanner,CIS scanner for Azure (https://github.com/kbroughton/azure_cis_scanner)
pip3 install azure-cis-scanner #Install
azscan #Run, login before with `az login`
```

### Attack Graph

[**Stormspotter** ](https://github.com/Azure/Stormspotter)creates an “attack graph” of the resources in an Azure subscription. It enables red teams and pentesters to visualize the attack surface and pivot opportunities within a tenant, and supercharges your defenders to quickly orient and prioritize incident response work.

### More checks

* Check for a **high number of Global Admin** \(between 2-4 are recommended\). Access it on: [https://portal.azure.com/\#blade/Microsoft\_AAD\_IAM/ActiveDirectoryMenuBlade/Overview](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview)
* Global admins should have MFA activated. Go to Users and click on Multi-Factor Authentication button.

![](../.gitbook/assets/image%20%28281%29.png)

* Dedicated admin account shouldn't have mailboxes \(they can only have mailboxes if they have Office 365\).
* Local AD shouldn't be sync with Azure AD if not needed\([https://portal.azure.com/\#blade/Microsoft\_AAD\_IAM/ActiveDirectoryMenuBlade/AzureADConnect](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/AzureADConnect)\). And if synced Password Hash Sync should be enabled for reliability. In this case it's disabled:

![](../.gitbook/assets/image%20%2852%29.png)

* **Global Administrators** shouldn't be synced from a local AD. Check if Global Administrators emails uses the domain **onmicrosoft.com**. If not, check the source of the user, the source should be Azure Active Directory, if it comes from Windows Server AD, then report it.

![](../.gitbook/assets/image%20%2889%29.png)

* **Standard tier** is recommended instead of free tier \(see the tier being used in _Pricing & Settings_ or in [https://portal.azure.com/\#blade/Microsoft\_Azure\_Security/SecurityMenuBlade/24](https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/24)\)
* **Periodic SQL servers scans**: 

  _Select the SQL server_ --&gt; _Make sure that 'Advanced data security' is set to 'On'_ --&gt; _Under 'Vulnerability assessment settings', set 'Periodic recurring scans' to 'On', and configure a storage account for storing vulnerability assessment scan results_ --&gt; _Click Save_

* **Lack of App Services restrictions**: Look for "App Services" in Azure \([https://portal.azure.com/\#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Web%2Fsites](https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Web%2Fsites)\) and check if anyone is being used. In that case check go through each App checking for "Access Restrictions" and there aren't rules, report it. The access to the app service should be restricted according to the needs.

## Office365

You need **Global Admin** or at least **Global Admin Reader** \(but note that Global Admin Reader is a little bit limited\). However, those limitations appear in some PS modules and can be bypassed accessing the features via the web application.

## AWS

Get objects in graph: [https://github.com/FSecureLABS/awspx](https://github.com/FSecureLABS/awspx)

## GPC

If you find a **SSRF** in an application running in [**GPC checkout this information**](../pentesting-web/ssrf-server-side-request-forgery.md#6440)**.**  
If a **SQL database** \(like MySQL\) is used in a GPC machine, users may misconfigure it and open it to the Internet. Try to connect. \([**MySQL**](../pentesting/pentesting-mysql.md), [**PostgreSQL**](../pentesting/pentesting-postgresql.md)\)  
**Google Cloud Storage publicly exposed**: Sometimes a bucket can be miss-configured and left accessible by everyone. If miss-configured, accessing via HTTP you will find a list of the files stored there:

![](../.gitbook/assets/image%20%28616%29.png)

```bash
# Use leaked service account
gcloud auth activate-service-account --key-file=service-key.json

# List images
gcloud container images list

## Download and run locally an image
docker run  --rm  -ti  gcr.io/<project-name>/secret:v1 sh
```

**Service accounts**

Virtual machine instances are usually assigned a service account. Every GCP project has a [default service account](https://cloud.google.com/compute/docs/access/service-accounts#default_service_account), and this will be assigned to new Compute Instances unless otherwise specified. Administrators can choose to use either a custom account or no account at all. This service account can be used by any user or application on the machine to communicate with the Google APIs. You can run the following command to see what accounts are available to you:

```text
gcloud auth list
```

Default service accounts will look like one of the following:

```text
PROJECT_NUMBER-compute@developer.gserviceaccount.com
PROJECT_ID@appspot.gserviceaccount.com
```

More savvy administrators will have configured a custom service account to use with the instance. This allows them to be more granular with permissions.

A custom service account will look like this:

```text
SERVICE_ACCOUNT_NAME@PROJECT_NAME.iam.gserviceaccount.com
```

If `gcloud auth list` returns multiple accounts available, something interesting is going on. You should generally see only the service account. If there is more than one, you can cycle through each using `gcloud config set account [ACCOUNT]` while trying the various tasks in this blog.

**Access scopes**

The service account on a GCP Compute Instance will use OAuth to communicate with the Google Cloud APIs. When [access scopes](https://cloud.google.com/compute/docs/access/service-accounts#accesscopesiam) are used, the OAuth token that is generated for the instance will have a [scope](https://oauth.net/2/scope/) limitation included. This defines what API endpoints it can authenticate to. It does NOT define the actual permissions.

When using a custom service account, Google [recommends](https://cloud.google.com/compute/docs/access/service-accounts#service_account_permissions) that access scopes are not used and to rely totally on IAM. The web management portal actually enforces this, but access scopes can still be applied to instances using custom service accounts programatically.

There are three options when setting an access scope on a VM instance:

* Allow default access
* All full access to all cloud APIs
* Set access for each API

You can see what scopes are assigned by querying the metadata URL. Here is an example from a VM with "default" access assigned:

```text
$ curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes \
    -H 'Metadata-Flavor:Google'

https://www.googleapis.com/auth/devstorage.read_only
https://www.googleapis.com/auth/logging.write
https://www.googleapis.com/auth/monitoring.write
https://www.googleapis.com/auth/servicecontrol
https://www.googleapis.com/auth/service.management.readonly
https://www.googleapis.com/auth/trace.append
```

The most interesting thing in the default scope is `devstorage.read_only`. This grants read access to all storage buckets in the project. This can be devastating, which of course is great for us as an attacker.

Here is what you'll see from an instance with no scope limitations:

```text
$ curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes -H 'Metadata-Flavor:Google'
https://www.googleapis.com/auth/cloud-platform
```

This `cloud-platform` scope is what we are really hoping for, as it will allow us to authenticate to any API function and leverage the full power of our assigned IAM permissions. It is also Google's recommendation as it forces administrators to choose only necessary permissions, and not to rely on access scopes as a barrier to an API endpoint.

It is possible to encounter some conflicts when using both IAM and access scopes. For example, your service account may have the IAM role of `compute.instanceAdmin` but the instance you've breached has been crippled with the scope limitation of `https://www.googleapis.com/auth/compute.readonly`. This would prevent you from making any changes using the OAuth token that's automatically assigned to your instance.

