# Integrity Levels

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

## Integrity Levels

In Windows Vista and later versions, all protected items come with an **integrity level** tag. This setup mostly assigns a "medium" integrity level to files and registry keys, except for certain folders and files that Internet Explorer 7 can write to at a low integrity level. The default behavior is for processes initiated by standard users to have a medium integrity level, whereas services typically operate at a system integrity level. A high-integrity label safeguards the root directory.

A key rule is that objects can't be modified by processes with a lower integrity level than the object's level. The integrity levels are:

* **Untrusted**: This level is for processes with anonymous logins. %%%Example: Chrome%%%
* **Low**: Mainly for internet interactions, especially in Internet Explorer's Protected Mode, affecting associated files and processes, and certain folders like the **Temporary Internet Folder**. Low integrity processes face significant restrictions, including no registry write access and limited user profile write access.
* **Medium**: The default level for most activities, assigned to standard users and objects without specific integrity levels. Even members of the Administrators group operate at this level by default.
* **High**: Reserved for administrators, allowing them to modify objects at lower integrity levels, including those at the high level itself.
* **System**: The highest operational level for the Windows kernel and core services, out of reach even for administrators, ensuring protection of vital system functions.
* **Installer**: A unique level that stands above all others, enabling objects at this level to uninstall any other object.

You can get the integrity level of a process using **Process Explorer** from **Sysinternals**, accessing the **properties** of the process and viewing the "**Security**" tab:

![](<../../.gitbook/assets/image (824).png>)

You can also get your **current integrity level** using `whoami /groups`

![](<../../.gitbook/assets/image (325).png>)

### Integrity Levels in File-system

A object inside the file-system may need an **minimum integrity level requirement** and if a process doesn't have this integrity process it won't be able to interact with it.\
For example, lets **create a regular from a regular user console file and check the permissions**:

```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
        DESKTOP-IDJHTKP\user:(I)(F)
        NT AUTHORITY\SYSTEM:(I)(F)
        NT AUTHORITY\INTERACTIVE:(I)(M,DC)
        NT AUTHORITY\SERVICE:(I)(M,DC)
        NT AUTHORITY\BATCH:(I)(M,DC)
```

Now, lets assign a minimum integrity level of **High** to the file. This **must be done from a console** running as **administrator** as a **regular console** will be running in Medium Integrity level and **won't be allowed** to assign High Integrity level to an object:

```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
        DESKTOP-IDJHTKP\user:(I)(F)
        NT AUTHORITY\SYSTEM:(I)(F)
        NT AUTHORITY\INTERACTIVE:(I)(M,DC)
        NT AUTHORITY\SERVICE:(I)(M,DC)
        NT AUTHORITY\BATCH:(I)(M,DC)
        Mandatory Label\High Mandatory Level:(NW)
```

This is where things get interesting. You can see that the user `DESKTOP-IDJHTKP\user` has **FULL privileges** over the file (indeed this was the user that created the file), however, due to the minimum integrity level implemented he won't be able to modify the file anymore unless he is running inside a High Integrity Level (note that he will be able to read it):

```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```

{% hint style="info" %}
**Therefore, when a file has a minimum integrity level, in order to modify it you need to be running at least in that integrity level.**
{% endhint %}

### Integrity Levels in Binaries

I made a copy of `cmd.exe` in `C:\Windows\System32\cmd-low.exe` and set it an **integrity level of low from an administrator console:**

```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
                                BUILTIN\Administrators:(I)(F)
                                BUILTIN\Users:(I)(RX)
                                APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
                                Mandatory Label\Low Mandatory Level:(NW)
```

Now, when I run `cmd-low.exe` it will **run under a low-integrity level** instead of a medium one:

![](<../../.gitbook/assets/image (313).png>)

For curious people, if you assign high integrity level to a binary (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) it won't run with high integrity level automatically (if you invoke it from a medium integrity level --by default-- it will run under a medium integrity level).

### Integrity Levels in Processes

Not all files and folders have a minimum integrity level, **but all processes are running under an integrity level**. And similar to what happened with the file-system, **if a process wants to write inside another process it must have at least the same integrity level**. This means that a process with low integrity level can’t open a handle with full access to a process with medium integrity level.

Due to the restrictions commented in this and the previous section, from a security point of view, it's always **recommended to run a process in the lower level of integrity possible**.


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

