# BloodHound

## What is BloodHound

> BloodHound is a single page Javascript web application, built on top of [Linkurious](http://linkurio.us/), compiled with [Electron](http://electron.atom.io/), with a [Neo4j](https://neo4j.com/)database fed by a PowerShell ingestor.
>
> BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment.
>
> BloodHound is developed by [@\_wald0](https://www.twitter.com/_wald0), [@CptJesus](https://twitter.com/CptJesus), and [@harmj0y](https://twitter.com/harmj0y).
>
> From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

So, [Bloodhound ](https://github.com/BloodHoundAD/BloodHound)is an amazing tool which can enumerate a domain automatically, save all the information, find possible privilege escalation paths and show all the information using graphs.

Booldhound is composed of 2 main parts: The **ingestors** and the **visualisation application**.  
The **ingestors** are called SharpHound and are the applications \(PS1 and C\# exe\) used to **enumerate the domain and extract all the information** in a format that the visualisation application will understand.  
The **visualisation application uses neo4j** to show how all the information is related and to show different ways to escalate privileges in the domain.

## Installation

You can download the [Ingestors from the github](https://github.com/BloodHoundAD/BloodHound/tree/master/Ingestors).

To install the visualisation application you will need to install **neo4j** and the **bloodhound application**.  
The easiest way to do this is just doing:

```text
apt-get install bloodhound
```

But, at the time of this writing, this wont install the latest bloodhound, so you may need to **download a pre-compiled bloodhound latest version** from: [https://github.com/BloodHoundAD/BloodHound/releases](https://github.com/BloodHoundAD/BloodHound/releases) or [compile it from the source](https://github.com/BloodHoundAD/BloodHound/wiki/Building-BloodHound-from-source).  
You can **download the community version of neo4j** from [here](https://neo4j.com/download-center/#community).

**If** you **download** by your own **bloodhound from releases** and n**eo4j from the web** page \(instead of using `apt-get`\) you will need to **decompress** the downloaded **files** to access the executables.

## Visualisation app Execution

After downloading/installing the required applications, lets start them.  
First of all you need to **start the neo4j database**:

```bash
./bin/neo4j start
#or
service neo4j start
```

The first time that you start this database you will need to access [http://localhost:7474/browser/](http://localhost:7474/browser/). You will be asked default credentials \(neo4j:neo4j\) and you will be **required to change the password**, so change it and don't forget it.

Now, start the **bloodhound application**:

```bash
./BloodHound-linux-x64
#or
bloodhound
```

You will be prompted for the database credentials: **neo4j:&lt;Your new password&gt;**

  
  
****And bloodhound will be ready to ingest data.

![](../../.gitbook/assets/image%20%28246%29.png)

## Ingestors

### Windows

You can download the [Ingestors from the github](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors).  
They have several options but if you want to run SharpHound from a PC joined to the domain, using your current user and extract all the information you can do:

```text
./SharpHound.exe --CollectionMethod All
Invoke-BloodHound -CollectionMethod All
```

If you wish to execute SharpHound using different credentials you can create a CMD netonly session and run SharpHound from there:

```text
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```

You could also use other parameters like: **DomainController**, **Domain**, **LdapUsername**, **LdapPassword...**

\*\*\*\*[**Learn more about Bloodhound in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)\*\*\*\*

### **Python**

If you have domain credentials you can run a **python bloodhound ingestor from any platform** so you don't need to depend on Windows.  
Download it from [https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py) or doing `pip3 install bloodhound`

```bash
bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all
```

