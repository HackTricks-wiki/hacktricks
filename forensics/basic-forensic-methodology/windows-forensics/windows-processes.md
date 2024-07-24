

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


## smss.exe

**Session Manager**.\
Session 0 starts **csrss.exe** and **wininit.exe** (**OS** **services**) while Session 1 starts **csrss.exe** and **winlogon.exe** (**User** **session**). However, you should see **only one process** of that **binary** without children in the processes tree.

Also, sessions apart from 0 and 1 may mean that RDP sessions are occurring.


## csrss.exe

**Client/Server Run Subsystem Process**.\
It manages **processes** and **threads**, makes the **Windows** **API** available for other processes and also **maps drive letters**, create **temp files**, and handles the **shutdown** **process**.

There is one **running in Session 0 and another one in Session 1** (so **2 processes** in the processes tree). Another one is created **per new Session**.


## winlogon.exe

**Windows Logon Process**.\
It's responsible for user **logon**/**logoffs**. It launches **logonui.exe** to ask for username and password and then calls **lsass.exe** to verify them.

Then it launches **userinit.exe** which is specified in **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** with key **Userinit**.

Mover over, the previous registry should have **explorer.exe** in the **Shell key** or it might be abused as a **malware persistence method**.


## wininit.exe

**Windows Initialization Process**. \
It launches **services.exe**, **lsass.exe**, and **lsm.exe** in Session 0. There should only be 1 process.


## userinit.exe

**Userinit Logon Application**.\
Loads the **ntduser.dat in HKCU** and initialises the **user** **environment** and runs **logon** **scripts** and **GPO**.

It launches **explorer.exe**.


## lsm.exe

**Local Session Manager**.\
It works with smss.exe to manipulate user sessions: Logon/logoff, shell start, lock/unlock desktop, etc.

After W7 lsm.exe was transformed into a service (lsm.dll).

There should only be 1 process in W7 and from them a service running the DLL.


## services.exe

**Service Control Manager**.\
It **loads** **services** configured as **auto-start** and **drivers**.

It's the parent process of **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** and many more.

Services are defined in `HKLM\SYSTEM\CurrentControlSet\Services` and this process maintains a DB in memory of service info that can be queried by sc.exe.

Note how **some** **services** are going to be running in a **process of their own** and others are going to be **sharing a svchost.exe process**.

There should only be 1 process.


## lsass.exe

**Local Security Authority Subsystem**.\
It's responsible for the user **authentication** and create the **security** **tokens**. It uses authentication packages located in `HKLM\System\CurrentControlSet\Control\Lsa`.

It writes to the **Security** **event** **log** and there should only be 1 process.

Keep in mind that this process is highly attacked to dump passwords.


## svchost.exe

**Generic Service Host Process**.\
It hosts multiple DLL services in one shared process.

Usually, you will find that **svchost.exe** is launched with the `-k` flag. This will launch a query to the registry **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** where there will be a key with the argument mentioned in -k that will contain the services to launch in the same process.

For example: `-k UnistackSvcGroup` will launch: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

If the **flag `-s`** is also used with an argument, then svchost is asked to **only launch the specified service** in this argument.

There will be several processes of `svchost.exe`. If any of them is **not using the `-k` flag**, then that's very suspicious. If you find that **services.exe is not the parent**, that's also very suspicious.


## taskhost.exe

This process act as a host for processes running from DLLs. It also loads the services that are running from DLLs.

In W8 this is called taskhostex.exe and in W10 taskhostw.exe.


## explorer.exe

This is the process responsible for the **user's desktop** and launching files via file extensions.

**Only 1** process should be spawned **per logged on user.**

This is run from **userinit.exe** which should be terminated, so **no parent** should appear for this process.


# Catching Malicious Processes

* Is it running from the expected path? (No Windows binaries run from temp location)
* Is it communicating with weird IPs?
* Check digital signatures (Microsoft artifacts should be signed)
* Is it spelled correctly?
* Is running under the expected SID?
* Is the parent process the expected one (if any)?
* Are the children processes the expecting ones? (no cmd.exe, wscript.exe, powershell.exe..?)


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


