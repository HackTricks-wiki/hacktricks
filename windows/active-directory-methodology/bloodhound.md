# BloodHound

## What is BloodHound

> BloodHound is a single page Javascript web application, built on top of [Linkurious](http://linkurio.us), compiled with [Electron](http://electron.atom.io), with a [Neo4j](https://neo4j.com)database fed by a PowerShell ingestor.
>
> BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment.
>
> BloodHound is developed by [@\_wald0](https://www.twitter.com/\_wald0), [@CptJesus](https://twitter.com/CptJesus), and [@harmj0y](https://twitter.com/harmj0y).
>
> From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

So, [Bloodhound ](https://github.com/BloodHoundAD/BloodHound)is an amazing tool which can enumerate a domain automatically, save all the information, find possible privilege escalation paths and show all the information using graphs.

Booldhound is composed of 2 main parts: **ingestors** and the **visualisation application**.

The **ingestors** are used to **enumerate the domain and extract all the information** in a format that the visualisation application will understand.

The **visualisation application uses neo4j** to show how all the information is related and to show different ways to escalate privileges in the domain.

## Installation

1. Bloodhound 

To install the visualisation application you will need to install **neo4j** and the **bloodhound application**.\
The easiest way to do this is just doing:

```
apt-get install bloodhound
```
You can **download the community version of neo4j** from [here](https://neo4j.com/download-center/#community).

2. Ingestors

You can download the Ingestors from:
- https://github.com/BloodHoundAD/SharpHound/releases
- https://github.com/BloodHoundAD/BloodHound/releases
- https://github.com/fox-it/BloodHound.py

3. Learn the path from the graph

Bloodhound come with various queries to highlight sensitive compromission path. 
It it possible to add custom queries to enhance the search and correlation between objects and more!

This repo has a nice collections of queries: https://github.com/CompassSecurity/BloodHoundQueries

<u>Installation process</u>:
```sh
$ curl -o "~/.config/bloodhound/customqueries.json" "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/customqueries.json"
```

## Visualisation app Execution

After downloading/installing the required applications, lets start them.\
First of all you need to **start the neo4j database**:

```bash
./bin/neo4j start
#or
service neo4j start
```

The first time that you start this database you will need to access [http://localhost:7474/browser/](http://localhost:7474/browser/). You will be asked default credentials (neo4j:neo4j) and you will be **required to change the password**, so change it and don't forget it.

Now, start the **bloodhound application**:

```bash
./BloodHound-linux-x64
#or
bloodhound
```

You will be prompted for the database credentials: **neo4j:\<Your new password>**

And bloodhound will be ready to ingest data.

![](<../../.gitbook/assets/image (171).png>)

## Ingestors

### Windows

They have several options but if you want to run SharpHound from a PC joined to the domain, using your current user and extract all the information you can do:

```
./SharpHound.exe --CollectionMethod All
Invoke-BloodHound -CollectionMethod All
```

> You can read more about **CollectionMethod** and loop session [here](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html)

If you wish to execute SharpHound using different credentials you can create a CMD netonly session and run SharpHound from there:

```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```

****[**Learn more about Bloodhound in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)****

### **Python**

If you have domain credentials you can run a **python bloodhound ingestor from any platform** so you don't need to depend on Windows.\
Download it from [https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py) or doing `pip3 install bloodhound`

```bash
bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all
```
