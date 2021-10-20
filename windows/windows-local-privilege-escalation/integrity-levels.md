# Integrity Levels

## Integrity Levels

From Windows Vista, all **protected objects are labeled with an integrity level**. Most user and system files and registry keys on the system have a default label of “medium” integrity. The primary exception is a set of specific folders and files writeable by Internet Explorer 7 at Low integrity. **Most processes** run by **standard users** are labeled with **medium integrity **(even the ones started by a user inside the administrators group), and most **services **are labeled with **System integrity**. The root directory is protected by a high-integrity label.\
Note that** a process with a lower integrity level can’t write to an object with a higher integrity level.**\
There are several levels of integrity:

* **Untrusted** – processes that are logged on anonymously are automatically designated as Untrusted. _Example: Chrome_
* **Low** – The Low integrity level is the level used by default for interaction with the Internet. As long as Internet Explorer is run in its default state, Protected Mode, all files and processes associated with it are assigned the Low integrity level. Some folders, such as the **Temporary Internet Folder**, are also assigned the **Low integrity **level by default. However,  note that a** low integrity process** is very **restricted**, it **cannot **write to the **registry **and it’s limited from writing to **most locations **in the current user’s profile.  _Example: Internet Explorer or Microsoft Edge_
* **Medium** – Medium is the context that **most objects will run in**. Standard users receive the Medium integrity level, and any object not explicitly designated with a lower or higher integrity level is Medium by default. Not that a user inside the Administrators group by default will use medium integrity levels.
* **High** – **Administrators **are granted the High integrity level. This ensures that Administrators are capable of interacting with and modifying objects assigned Medium or Low integrity levels, but can also act on other objects with a High integrity level, which standard users can not do. _Example: "Run as Administrator"_
* **System** – As the name implies, the System integrity level is reserved for the system. The Windows kernel and core services are granted the System integrity level. Being even higher than the High integrity level of Administrators protects these core functions from being affected or compromised even by Administrators. Example: Services
* **Installer** – The Installer integrity level is a special case and is the highest of all integrity levels. By virtue of being equal to or higher than all other WIC integrity levels, objects assigned the Installer integrity level are also able to uninstall all other objects.

You can get the integrity level of a process using **Process Explorer** from **Sysinternals**, accessing the **properties **of the process and viewing the "**Security**" tab:

![](<../../.gitbook/assets/image (318).png>)

You can also get your **current integrity level **using `whoami /groups`

![](<../../.gitbook/assets/image (319).png>)

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

Now, lets assign a minimum integrity level of **High **to the file. This **must be done from a console** running as **administrator **as a **regular console **will be running in Medium Integrity level and **won't be allowed** to assign High Integrity level to an object:

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

I made a copy of `cmd.exe` in `C:\Windows\System32\cmd-low.exe` and set it an** integrity level of low from an administrator console:**

```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
                                BUILTIN\Administrators:(I)(F)
                                BUILTIN\Users:(I)(RX)
                                APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
                                Mandatory Label\Low Mandatory Level:(NW)
```

Now, when I run `cmd-low.exe` it will** run under a low-integrity level** instead of a medium one:

![](<../../.gitbook/assets/image (320).png>)

For curious people, if you assign high integrity level to a binary (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) it won't run with high integrity level automatically (if you invoke it from a medium integrity level --by default-- it will run under a medium integrity level).

### Integrity Levels in Processes

Not all files and folders have a minimum integrity level, **but all processes are running under an integrity level**. And similar to what happened with the file-system, **if a process wants to write inside another process it must have at least the same integrity level**. This means that a process with low integrity level can’t open a handle with full access to a process with medium integrity level.

Due to the restrictions commented in this and the previous section, from a security point of view, it's always** recommended to run a process in the lower level of integrity possible**.
