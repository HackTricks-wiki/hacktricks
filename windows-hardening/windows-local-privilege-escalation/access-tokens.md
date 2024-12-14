# Access Tokens

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


## Access Tokens

Each **user logged** onto the system **holds an access token with security information** for that logon session. The system creates an access token when the user logs on. **Every process executed** on behalf of the user **has a copy of the access token**. The token identifies the user, the user's groups, and the user's privileges. A token also contains a logon SID (Security Identifier) that identifies the current logon session.

You can see this information executing `whoami /all`

```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

or using _Process Explorer_ from Sysinternals (select process and access"Security" tab):

![](<../../.gitbook/assets/image (772).png>)

### Local administrator

When a local administrator logins, **two access tokens are created**: One with admin rights and other one with normal rights. **By default**, when this user executes a process the one with **regular** (non-administrator) **rights is used**. When this user tries to **execute** anything **as administrator** ("Run as Administrator" for example) the **UAC** will be used to ask for permission.\
If you want to [**learn more about the UAC read this page**](../authentication-credentials-uac-and-efs/#uac)**.**

### Credentials user impersonation

If you have **valid credentials of any other user**, you can **create** a **new logon session** with those credentials :

```
runas /user:domain\username cmd.exe
```

The **access token** has also a **reference** of the logon sessions inside the **LSASS**, this is useful if the process needs to access some objects of the network.\
You can launch a process that **uses different credentials for accessing network services** using:

```
runas /user:domain\username /netonly cmd.exe
```

This is useful if you have useful credentials to access objects in the network but those credentials aren't valid inside the current host as they are only going to be used in the network (in the current host your current user privileges will be used).

### Types of tokens

There are two types of tokens available:

* **Primary Token**: It serves as a representation of a process's security credentials. The creation and association of primary tokens with processes are actions that require elevated privileges, emphasizing the principle of privilege separation. Typically, an authentication service is responsible for token creation, while a logon service handles its association with the user's operating system shell. It is worth noting that processes inherit the primary token of their parent process at creation.
* **Impersonation Token**: Empowers a server application to adopt the client's identity temporarily for accessing secure objects. This mechanism is stratified into four levels of operation:
  * **Anonymous**: Grants server access akin to that of an unidentified user.
  * **Identification**: Allows the server to verify the client's identity without utilizing it for object access.
  * **Impersonation**: Enables the server to operate under the client's identity.
  * **Delegation**: Similar to Impersonation but includes the ability to extend this identity assumption to remote systems the server interacts with, ensuring credential preservation.

#### Impersonate Tokens

Using the _**incognito**_ module of metasploit if you have enough privileges you can easily **list** and **impersonate** other **tokens**. This could be useful to perform **actions as if you where the other user**. You could also **escalate privileges** with this technique.

### Token Privileges

Learn which **token privileges can be abused to escalate privileges:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

Take a look to [**all the possible token privileges and some definitions on this external page**](https://github.com/gtworek/Priv2Admin).

## References

Learn more about tokens in this tutorials: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) and [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)


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

