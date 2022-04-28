# Cloud Security Review

**Check for nice cloud hacking tricks in** [**https://hackingthe.cloud**](https://hackingthe.cloud)

## Generic tools

There are several tools that can be used to test different cloud environments. The installation steps and links are going to be indicated in this section.

### [ScoutSuite](https://github.com/nccgroup/ScoutSuite)

AWS, Azure, GCP, Alibaba Cloud, Oracle Cloud Infrastructure

```
pip3 install scoutsuite
```

### [cs-suite](https://github.com/SecurityFTW/cs-suite)

AWS, GCP, Azure, DigitalOcean

```
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
* Unencrypted services running (telnet, http, ...)?
* Unprotected admin consoles?
* In general, check that all services are correctly protected depending on their needs

## Azure

Access the portal here: [http://portal.azure.com/](http://portal.azure.com)\
To start the tests you should have access with a user with **Reader permissions over the subscription** and **Global Reader role in AzureAD**. If even in that case you are **not able to access the content of the Storage accounts** you can fix it with the **role Storage Account Contributor**.

It is recommended to **install azure-cli** in a **linux** and **windows** virtual machines (to be able to run powershell and python scripts): [https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest)\
Then, run `az login` to login. Note the **account information** and **token** will be **saved** inside _\<HOME>/.azure_ (in both Windows and Linux).

Remember that if the **Security Centre Standard Pricing Tier** is being used and **not** the **free** tier, you can **generate** a **CIS compliance scan report** from the azure portal. Go to _Policy & Compliance-> Regulatory Compliance_ (or try to access [https://portal.azure.com/#blade/Microsoft\_Azure\_Security/SecurityMenuBlade/22](https://portal.azure.com/#blade/Microsoft\_Azure\_Security/SecurityMenuBlade/22)).\
\_\_If the company is not paying for a Standard account you may need to review the **CIS Microsoft Azure Foundations Benchmark** by "hand" (you can get some help using the following tools). Download it from [**here**](https://www.newnettechnologies.com/cis-benchmark.html?keyword=\&gclid=Cj0KCQjwyPbzBRDsARIsAFh15JYSireQtX57C6XF8cfZU3JVjswtaLFJndC3Hv45YraKpLVDgLqEY6IaAhsZEALw\_wcB#microsoft-azure).

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

* Check for a **high number of Global Admin** (between 2-4 are recommended). Access it on: [https://portal.azure.com/#blade/Microsoft\_AAD\_IAM/ActiveDirectoryMenuBlade/Overview](https://portal.azure.com/#blade/Microsoft\_AAD\_IAM/ActiveDirectoryMenuBlade/Overview)
* Global admins should have MFA activated. Go to Users and click on Multi-Factor Authentication button.

![](<../.gitbook/assets/image (293).png>)

* Dedicated admin account shouldn't have mailboxes (they can only have mailboxes if they have Office 365).
* Local AD shouldn't be sync with Azure AD if not needed([https://portal.azure.com/#blade/Microsoft\_AAD\_IAM/ActiveDirectoryMenuBlade/AzureADConnect](https://portal.azure.com/#blade/Microsoft\_AAD\_IAM/ActiveDirectoryMenuBlade/AzureADConnect)). And if synced Password Hash Sync should be enabled for reliability. In this case it's disabled:

![](<../.gitbook/assets/image (294).png>)

* **Global Administrators** shouldn't be synced from a local AD. Check if Global Administrators emails uses the domain **onmicrosoft.com**. If not, check the source of the user, the source should be Azure Active Directory, if it comes from Windows Server AD, then report it.

![](<../.gitbook/assets/image (295).png>)

* **Standard tier** is recommended instead of free tier (see the tier being used in _Pricing & Settings_ or in [https://portal.azure.com/#blade/Microsoft\_Azure\_Security/SecurityMenuBlade/24](https://portal.azure.com/#blade/Microsoft\_Azure\_Security/SecurityMenuBlade/24))
*   **Periodic SQL servers scans**:

    _Select the SQL server_ --> _Make sure that 'Advanced data security' is set to 'On'_ --> _Under 'Vulnerability assessment settings', set 'Periodic recurring scans' to 'On', and configure a storage account for storing vulnerability assessment scan results_ --> _Click Save_
* **Lack of App Services restrictions**: Look for "App Services" in Azure ([https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Web%2Fsites](https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Web%2Fsites)) and check if anyone is being used. In that case check go through each App checking for "Access Restrictions" and there aren't rules, report it. The access to the app service should be restricted according to the needs.

## Office365

You need **Global Admin** or at least **Global Admin Reader** (but note that Global Admin Reader is a little bit limited). However, those limitations appear in some PS modules and can be bypassed accessing the features via the web application.

## AWS

Get objects in graph: [https://github.com/FSecureLABS/awspx](https://github.com/FSecureLABS/awspx)

## GPC

{% content-ref url="gcp-security/" %}
[gcp-security](gcp-security/)
{% endcontent-ref %}
