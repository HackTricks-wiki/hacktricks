# BloodHound & Other AD Enum Tools

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) is from Sysinternal Suite:

> An advanced Active Directory (AD) viewer and editor. You can use AD Explorer to navigate an AD database easily, define favourite locations, view object properties, and attributes without opening dialog boxes, edit permissions, view an object's schema, and execute sophisticated searches that you can save and re-execute.

### Snapshots

AD Explorer can create snapshots of an AD so you can check it offline.\
It can be used to discover vulns offline, or to compare different states of the AD DB across the time.

You will be requires the username, password, and direction to connect (any AD user is required).

To take a snapshot of AD, go to `File` --> `Create Snapshot` and enter a name for the snapshot.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) is a tool which extracts and combines various artefacts out of an AD environment. The information can be presented in a **specially formatted** Microsoft Excel **report** that includes summary views with metrics to facilitate analysis and provide a holistic picture of the current state of the target AD environment.

```bash
# Run it
.\ADRecon.ps1
```

## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound is a single page Javascript web application, built on top of [Linkurious](http://linkurio.us/), compiled with [Electron](http://electron.atom.io/), with a [Neo4j](https://neo4j.com/) database fed by a C# data collector.

BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory or Azure environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory or Azure environment.

So, [Bloodhound ](https://github.com/BloodHoundAD/BloodHound)is an amazing tool which can enumerate a domain automatically, save all the information, find possible privilege escalation paths and show all the information using graphs.

Booldhound is composed of 2 main parts: **ingestors** and the **visualisation application**.

The **ingestors** are used to **enumerate the domain and extract all the information** in a format that the visualisation application will understand.

The **visualisation application uses neo4j** to show how all the information is related and to show different ways to escalate privileges in the domain.

### Installation
After the creation of BloodHound CE, the entire project was updated for ease of use with Docker. The easiest way to get started is to use its pre-configured Docker Compose configuration.

1. Install Docker Compose. This should be included with the [Docker Desktop](https://www.docker.com/products/docker-desktop/) installation.
2. Run:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Locate the randomly generated password in the terminal output of Docker Compose.
4. In a browser, navigate to http://localhost:8080/ui/login. Login with a username of admin and the randomly generated password from the logs.

After this you will need to change the randomly generated password and you will have the new interface ready, from which you can directly download the ingestors.

### SharpHound

They have several options but if you want to run SharpHound from a PC joined to the domain, using your current user and extract all the information you can do:

```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```

> You can read more about **CollectionMethod** and loop session [here](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

If you wish to execute SharpHound using different credentials you can create a CMD netonly session and run SharpHound from there:

```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```

[**Learn more about Bloodhound in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)


## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) is a tool to find **vulnerabilities** in Active Directory associated **Group Policy**. \
You need to **run group3r** from a host inside the domain using **any domain user**.

```bash
group3r.exe -f <filepath-name.log> 
# -s sends results to stdin
# -f send results to file
```

## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **evaluates the security posture of an AD environment** and provides a nice **report** with graphs.

To run it, can execute the binary `PingCastle.exe` and it will start an **interactive session** presenting a menu of options. The default option to use is **`healthcheck`** which will establish a baseline **overview** of the **domain**, and find **misconfigurations** and **vulnerabilities**.&#x20;

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
