# Active Directory Methodology

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

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
  * A more detailed guide on how to enumerate a SMB server can be found here:

{% content-ref url="../../network-services-pentesting/pentesting-smb.md" %}
[pentesting-smb.md](../../network-services-pentesting/pentesting-smb.md)
{% endcontent-ref %}

* **Enumerate Ldap**
  * `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  * A more detailed guide on how to enumerate LDAP can be found here (pay **special attention to the anonymous access**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Poison the network**
  * Gather credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  * Access host by [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  * Gather credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
  * Extract usernames/names from internal documents, social media, services (mainly web) inside the domain environments and also from the publicly available.
  * If you find the complete names of company workers, you could try different AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). The most common conventions are: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
  * Tools:
    * [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    * [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

* **Anonymous SMB/LDAP enum:** Check the [**pentesting SMB**](../../network-services-pentesting/pentesting-smb.md) and [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) pages.
* **Kerbrute enum**: When an **invalid username is requested** the server will respond using the **Kerberos error** code _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, allowing us to determine that the username was invalid. **Valid usernames** will illicit either the **TGT in a AS-REP** response or the error _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, indicating that the user is required to perform pre-authentication.

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```

* **OWA (Outlook Web Access) Server**

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

{% hint style="warning" %}
You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).

However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.
{% endhint %}

### Knowing one or several usernames

Ok, so you know you have already a valid username but no passwords... Then try:

* [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT\_REQ\_PREAUTH_ you can **request a AS\_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
* [**Password Spraying**](password-spraying.md): Let's try the most **common passwords** with each of the discovered users, maybe some user is using a bad password (keep in mind the password policy!).
  * Note that you can also **spray OWA servers** to try to get access to the users mail servers.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NS Poisoning

You might be able to **obtain** some challenge **hashes** to crack **poisoning** some protocols of the **network**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTML [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* to get access to the AD env.

### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTML authentication against you** so you can **steal** the **NTLM challenge** to crack it:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Enumerating Active Directory WITH credentials/session

For this phase you need to have **compromised the credentials or a session of a valid domain account.** If you have some valid credentials or a shell as a domain user, **you should remember that the options given before are still options to compromise other users**.

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Enumeration

Having compromised an account is a **big step to start compromising the whole domain**, because you are going to be able to start the **Active Directory Enumeration:**

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

* You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
* You can also use [**powershell for recon**](../basic-powershell-for-pentesters/) which will be stealthier
* You ca also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
* Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
  * **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* \*\*\*\*[**DNS records of the AD**](ad-dns-records.md) \*\*\*\* as they might contain interesting information.
* A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
* You can also search in the LDAP database with **ldapsearch** to look for credentials in fields _userPassword_ & _unixUserPassword_, or even for _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
* If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
* You could also try automated tools as:
  * [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  * [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Extracting all domain users**

    It's very easy to obtain all the domain usernames from Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). In Linux, you can use: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

The goal of Kerberoasting is to harvest **TGS tickets for services that run on behalf of domain user accounts**. Part of these TGS tickets are **encrypted wit keys derived from user passwords**. As a consequence, their credentials could be **cracked offline**.\
More about this in:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

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

### **Looks for Creds in Computer Shares**

Now that you have some basic credentials you should check if you can **find** any **interesting files being shared inside the AD**. You could do that manually but it's a very boring repetitive task (and more if you find hundreds of docs you need to check).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb.md#domain-shared-folders-search)

### Steal NTLM Creds

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTML authentication against you** so you can **steal** the **NTLM challenge** to crack it:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **compromise the domain controller**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Hopefully you have managed to **compromise some local admin** account using [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/).\
Then, its time to dump all the hashes in memory and locally.\
[**Read this page about different ways to obtain the hashes.**](broken-reference)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
You need to use some **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.\
[**Read this page for more information.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

This attack is similar to Pass the Key, but instead of using hashes to request a ticket, the **ticket itself is stolen** and used to authenticate as its owner.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Credentials Reuse

If you have the **hash** or **password** of a **local administrato**r you should try to **login locally** to other **PCs** with it.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

{% hint style="warning" %}
Note that this is quite **noisy** and **LAPS** would **mitigate** it.
{% endhint %}

### MSSQL Abuse & Trusted Links

If a user has privileges to **access MSSQL instances**, he could be able to use it to **execute commands** in the MSSQL host (if running as SA), **steal** the NetNTLM **hash** or even perform a **relay** **attack**.\
Also, if a MSSQL instance is trusted (database link) by a different MSSQL instance. If the user has privileges over the trusted database, he is going to be able to **use the trust relationship to execute queries also in the other instance**. These trusts can be chained and at some point the user might be able to find a misconfigured database where he can execute commands.\
**The links between databases work even across forest trusts.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Unconstrained Delegation

If you find any Computer object with the attribute [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) and you have domain privileges in the computer, you will be able to dump TGTs from memory of every users that logins onto the computer.\
So, if a **Domain Admin logins onto the computer**, you will be able to dump his TGT and impersonate him using [Pass the Ticket](pass-the-ticket.md).\
Thanks to constrained delegation you could even **automatically compromise a Print Server** (hopefully it will be a DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Constrained Delegation

If a user or computer is allowed for "Constrained Delegation" it will be able to **impersonate any user to access some services in a computer**.\
Then, if you **compromise the hash** of this user/computer you will be able to **impersonate any user** (even domain admins) to access some services.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Resourced-based Constrain Delegation

It's possible to gain code execution with **elevated privileges on a remote computer if you have WRITE privilege** on that computer's AD object.

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### ACLs Abuse

The compromised user could have some **interesting privileges over some domain objects** that could let you **move** laterally/**escalate** privileges.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Printer Spooler service abuse

If you can find any **Spool service listening** inside the domain, you may be able to **abuse** is to **obtain new credentials** and **escalate privileges**.\
[**More information about how to abuse Spooler services here.**](printers-spooler-service-abuse.md)

### Third party sessions abuse

If **other users** **access** the **compromised** machine, it's possible to **gather credentials from memory** and even **inject beacons in their processes** to impersonate them.\
Usually users will access the system via RDP, so here you have how to performa couple of attacks over third party RDP sessions:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** allows you to **manage the local Administrator password** (which is **randomised**, unique, and **changed regularly**) on domain-joined computers. These passwords are centrally stored in Active Directory and restricted to authorised users using ACLs. If you have **enough permission to read these passwords you could move to other computers**.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Certificate Theft

Gathering certificates from the compromised machine could be a way to escalate privileges inside the environment:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Certificate Templates Abuse

If vulnerable templates are configured it's possible to abuse them to escalate privileges:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Once you get **Domain Admin** or even better **Enterprise Admin** privileges, you can **dump** the **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](broken-reference)

### Privesc as Persistence

Some of the techniques discussed before can be used for persistence.\
For example you could:

*   Make users vulnerable to [**Kerberoast**](kerberoast.md)

    ```powershell
    Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
    ```
*   Make users vulnerable to [**ASREPRoast**](asreproast.md)

    ```powershell
    Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
    ```
*   Grant [**DCSync**](./#dcsync) privileges to a user

    ```powershell
    Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
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

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** is a very good way to be able to persist in the users account (even if he changes the password):

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### AdminSDHolder Group

The Access Control List (ACL) of the **AdminSDHolder** object is used as a template to **copy** **permissions** to **all “protected groups”** in Active Directory and their members. Protected groups include privileged groups such as Domain Admins, Administrators, Enterprise Admins, and Schema Admins, Backup Operators and krbtgt.\
By default, the ACL of this group is copied inside all the "protected groups". This is done to avoid intentional or accidental changes to these critical groups. However, if an attacker **modifies the ACL** of the group **AdminSDHolder** for example, giving full permissions to a regular user, this user will have full permissions on all the groups inside the protected group (in an hour).\
And if someone tries to delete this user from the Domain Admins (for example) in an hour or less, the user will be back in the group.\
[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

There is a **local administrator** account inside each **DC**. Having admin privileges in this machine, you can use mimikatz to **dump the local Administrator hash**. Then, modifying a registry to **activate this password** so you can remotely access to this local Administrator user.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### ACL Persistence

You could **give** some **special permissions** to a **user** over some specific domain objects that will let the user **escalate privileges in the future**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
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
You can create you **own SSP** to **capture** in **clear text** the **credentials** used to access the machine.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

It registers a **new Domain Controller** in the AD and uses it to **push attributes** (SIDHistory, SPNs...) on specified objects **without** leaving any **logs** regarding the **modifications**. You **need DA** privileges and be inside the **root domain**.\
Note that if you use wrong data, pretty ugly logs will appear.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### LAPS Persistence

Previously we have discussed about how to escalate privileges if you have **enough permission to read LAPS passwords**. However, these passwords can also be used to **maintain persistence**.\
Check:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Forest Privilege Escalation - Domain Trusts

Microsoft considers that the **domain isn't a Security Boundary**, the **Forest is the security Boundary**. This means that **if you compromise a domain inside a Forest you might be able to compromise the entire Forest**.

### Basic Information

At a high level, a [**domain trust**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) establishes the ability for **users in one domain to authenticate** to resources or act as a [security principal](https://technet.microsoft.com/en-us/library/cc780957\(v=ws.10\).aspx) **in another domain**.

Essentially, all a trust does is **linking up the authentication systems of two domains** and allowing authentication traffic to flow between them through a system of referrals.\
When **2 domains trust each other they exchange keys**, these **keys** are going to be **saved** in the **DCs** of **each domains** (**2 keys per trust direction, latest and previous**) and the keys will be the base of the trust.

When a **user** tries to **access** a **service** on the **trusting domain** it will request an **inter-realm TGT** to the DC of its domain. The DC wills serve the client this **TGT** which would be **encrypted/signed** with the **inter-realm** **key** (the key both domains **exchanged**). Then, the **client** will **access** the **DC of the other domain** and will **request** a **TGS** for the service using the **inter-realm TGT**. The **DC** of the trusting domain will **check** the **key** used, if it's ok, it will **trust everything in that ticket** and will serve the TGS to the client.

![](<../../.gitbook/assets/image (166) (1).png>)

### Different trusts

It's important to notice that **a trust can be 1 way or 2 ways**. In the 2 ways options, both domains will trust each other, but in the **1 way** trust relation one of the domains will be the **trusted** and the other the **trusting** domain. In the last case, **you will only be able to access resources inside the trusting domain from the trusted one**.

If Domain A trusts Domain B, A is the trusting domain and B ins the trusted one. Moreover, in **Domain A**, this would be an **Outbound trust**; and in **Domain B**, this would be an **Inbound trust**.

**Different trusting relationships**

* **Parent-Child** – part of the same forest – a child domain retains an implicit two-way transitive trust with its parent. This is probably the most common type of trust that you’ll encounter.
* **Cross-link** – aka a “shortcut trust” between child domains to improve referral times. Normally referrals in a complex forest have to filter up to the forest root and then back down to the target domain, so for a geographically spread out scenario, cross-links can make sense to cut down on authentication times.
* **External** – an implicitly non-transitive trust created between disparate domains. “[External trusts provide access to resources in a domain outside of the forest that is not already joined by a forest trust.](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx)” External trusts enforce SID filtering, a security protection covered later in this post.
* **Tree-root** – an implicit two-way transitive trust between the forest root domain and the new tree root you’re adding. I haven’t encountered tree-root trusts too often, but from the [Microsoft documentation](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx), they’re created when you create a new domain tree in a forest. These are intra-forest trusts, and they [preserve two-way transitivity](https://technet.microsoft.com/en-us/library/cc757352\(v=ws.10\).aspx) while allowing the tree to have a separate domain name (instead of child.parent.com).
* **Forest** – a transitive trust between two forest root domain. Forest trusts also enforce SID filtering.
* **MIT** – a trust with a non-Windows [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domain. I hope to dive more into MIT trusts in the future.

#### Other differences in **trusting relationships**

* A trust relationship can also be **transitive** (A trust B, B trust C, then A trust C) or **non-transitive**.
* A trust relationship can be set up as **bidirectional trust** (both trust each other) or as **one-way trust** (only one of them trust the other).

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

```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```

{% hint style="warning" %}
There are **2 trusted keys**, one for _Child --> Parent_ and another one for _Parent_ --> _Child_.\
You can the one used by the current domain them with:

```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### SID-History Injection

Escalate as Enterprise admin to the child/parent domain abusing the trust with SID-History injection:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Exploit writeable Configuration NC

The Configuration NC is the primary repository for configuration information for a forest and is replicated to every DC in the forest. Additionally, every writable DC (not read-only DCs) in the forest holds a writable copy of the Configuration NC. Exploiting this require running as SYSTEM on a (child) DC.

It is possible to compromise the root domain in various ways covered below.

##### Link GPO to root DC site
The Sites container in Configuration NC contains all sites of the domain-joined computers in the AD forest. It is possible to link GPOs to sites when running as SYSTEM on any DC in the forest, including the site(s) of the forest root DCs, and thereby compromise these.

More details can be read here [Bypass SID filtering research](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

##### Compromise any gMSA in the forest
The attack depends on privileged gMSAs in the targeted domain.

The KDS Root key, which is used to calculate the password of gMSAs in the forest, is stored in the Configuration NC. When running as SYSTEM on any DC in the forest, one can read out the KDS Root key and calculate the password of any gMSA in the forest. 

More details can be read here: [Golden gMSA trust attack from child to parent](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

##### Schema change attack
The attack requires the attacker to wait for new privileged AD objects to be created.

When running as SYSTEM on any DC in the forest, one can grant any user full control over all classes in the AD Schema. That control can be abused to create an ACE in the default security descriptor of any AD object that grants full control to a compromised principal. All new instances of the modified AD object types will have this ACE. 

More details can be read here: [Schema change trust attack from child to parent](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

##### From DA to EA with ADCS ESC5
The ADCS ESC5 (Vulnerable PKI Object Access Control) attacks abuse control over PKI objects to create a vulnerable certificate template that can be abused to authenticate as any user in the forest. Since all the PKI objects are stored in the Configuration NC, one can execute ESC5 if they have compromised any writable (child) DC in the forest.

More details can be read here: [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)

In case the AD forest does not have ADCS, the attacker can create the necessary components as described here: [Escalating from child domain’s admins to enterprise admins in 5 minutes by abusing AD CS, a follow up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### External Forest Domain - One-Way (Inbound) or bidirectional

```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes : 
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```

In this scenario **your domain is trusted** by an external one giving you **undetermined permissions** over it. You will need to find **which principals of your domain have which access over the external domain** and then try to exploit it:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### External Forest Domain - One-Way (Outbound)

```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```

In this scenario **your domain** is **trusting** some **privileges** to principal from a **different domains**.

However, when a **domain is trusted** by the trusting domain, the trusted domain **creates a user** with a **predictable name** that uses as **password the trusted password**. Which means that it's possible to **access a user from the trusting domain to get inside the trusted one** to enumerate it and try to escalate more privileges:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Another way to compromise the trusted domain is to find a [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) created in the **opposite direction** of the domain trust (which isn't very common).

Another way to compromise the trusted domain is to wait in a machine where a **user from the trusted domain can access** to login via **RDP**. Then, the attacker could inject code in the RDP session process and **access the origin domain of the victim** from there.\
Moreover, if the **victim mounted his hard drive**, from the **RDP session** process the attacker could store **backdoors** in the **startup folder of the hard drive**. This technique is called **RDPInception.**

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Domain trust abuse mitigation

**SID Filtering:**

* Avoid attacks which abuse SID history attribute across forest trust.
* Enabled by default on all inter-forest trusts. Intra-forest trusts are assumed secured by default (MS considers forest and not the domain to be a security boundary).
* But, since SID filtering has potential to break applications and user access, it is often disabled.
* Selective Authentication
  * In an inter-forest trust, if Selective Authentication is configured, users between the trusts will not be automatically authenticated. Individual access to domains and servers in the trusting domain/forest should be given.
* Does not prevent writeable Configration NC exploitation and trust account attack.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Cloud & Cloud -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

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

## References

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
