# Privilege Escalation Abusing Tokens

## Tokens

If you **don't know what are Windows Access Tokens** read this page before continuing:

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

**Maybe you could be able to escalate privileges abusing the tokens you already have**

### SeImpersonatePrivilege (3.1.1)

Any process holding this privilege can **impersonate** (but not create) any **token** for which it is able to gethandle. You can get a **privileged token** from a **Windows service** (DCOM) making it perform an **NTLM authentication** against the exploit, then execute a process as **SYSTEM**. Exploit it with [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM ](https://github.com/antonioCoco/RogueWinRM)(needs winrm disabled), [SweetPotato](https://github.com/CCob/SweetPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

### SeAssignPrimaryPrivilege (3.1.2)

It is very similar to **SeImpersonatePrivilege**, it will use the **same method** to get a privileged token.\
Then, this privilege allows **to assign a primary token** to a new/suspended process. With the privileged impersonation token you can derivate a primary token (DuplicateTokenEx).\
With the token, you can create a **new process** with 'CreateProcessAsUser' or create a process suspended and **set the token** (in general, you cannot modify the primary token of a running process).

### SeTcbPrivilege (3.1.3)

If you have enabled this token you can use **KERB\_S4U\_LOGON** to get an **impersonation token** for any other user without knowing the credentials, **add an arbitrary group** (admins) to the token, set the **integrity level** of the token to "**medium**", and assign this token to the **current thread** (SetThreadToken).

### SeBackupPrivilege (3.1.4)

This privilege causes the system to **grant all read access** control to any file (only read).\
Use it to **read the password hashes of local Administrator** accounts from the registry and then use "**psexec**" or "**wmicexec**" with the hash (PTH).\
&#x20;This attack won't work if the Local Administrator is disabled, or if it is configured that a Local Admin isn't admin if he is connected remotely.\
You can **abuse this privilege** with: [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1) or with [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug) or following IppSec in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)

### SeRestorePrivilege (3.1.5)

**Write access** control to any file on the system, regardless of the files ACL.\
You can **modify services**, DLL Hijacking, set **debugger** (Image File Execution Options)… A lot of options to escalate.

### SeCreateTokenPrivilege (3.1.6)

This token **can be used** as EoP method **only** if the user **can impersonate** tokens (even without SeImpersonatePrivilege).\
&#x20;In a possible scenario, a user can impersonate the token if it is for the same user and the integrity level is less or equal to the current process integrity level.\
&#x20;In this case, the user could **create an impersonation token** and add to it a privileged group SID.

### SeLoadDriverPrivilege (3.1.7)

**Load and unload device drivers.**\
****You need to create an entry in the registry with values for ImagePath and Type.\
As you don't have access to write to HKLM, you have to **use HKCU**. But HKCU doesn't mean anything for the kernel, the way to guide the kernel here and use the expected path for a driver config is to use the path: "\Registry\User\S-1-5-21-582075628-3447520101-2530640108-1003\System\CurrentControlSet\Services\DriverName" (the ID is the **RID** of the current user).\
&#x20;So, you have to **create all that path inside HKCU and set the ImagePath** (path to the binary that is going to be executed) **and Type** (SERVICE\_KERNEL\_DRIVER 0x00000001).\
[**Learn how to exploit it here.**](../active-directory-methodology/privileged-accounts-and-token-privileges.md#seloaddriverprivilege)****

### SeTakeOwnershipPrivilege (3.1.8)

This privilege is very similar to **SeRestorePrivilege**.\
It allows a process to “**take ownership of an object** without being granted discretionary access” by granting the WRITE\_OWNER access right.\
First, you have to **take ownership of the registry key** that you are going to write on and **modify the DACL** so you can write on it.

### SeDebugPrivilege (3.1.9)

It allows the holder to **debug another process**, this includes reading and **writing** to that **process' memory.**\
There are a lot of various **memory injection** strategies that can be used with this privilege that evade a majority of AV/HIPS solutions.

## Check privileges

```
whoami /priv
```

The **tokens that appear as **_**Disabled**_** can be enable**, you you actually can abuse _Enabled_ and _Disabled_ tokens.

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.\


| Privilege              | Impact       | Tool                     | Execution path                                                                                                                                                                                                                                                                                                                                      | Remarks                                                                                                                                                                                                                                                                                                                         |
| ---------------------- | ------------ | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SeAssignPrimaryToken` |  _**Admin**_ | 3rd party tool           |  _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      |  Thank you [Aurélien Chalot](https://twitter.com/Defte\_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                        |
| `SeBackup`             |  **Threat**  |  _**Built-in commands**_ |  Read sensitve files with `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p> - May be more interesting if you can read %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (and robocopy) is not helpful when it comes to open files.<br><br>- Robocopy requires both SeBackup and SeRestore to work with /b parameter.</p>                                                                      |
| `SeCreateToken`        |  _**Admin**_ | 3rd party tool           |  Create arbitrary token including local admin rights with `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                 |
| `SeDebug`              |  _**Admin**_ |  **PowerShell**          |  Duplicate the `lsass.exe` token.                                                                                                                                                                                                                                                                                                                   |  Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| `SeLoadDriver`         |  _**Admin**_ | 3rd party tool           | <p> 1. Load buggy kernel driver such as <code>szkg64.sys</code><br>2. Exploit the driver vulnerability<br><br>Alternatively, the privilege may be used to unload security-related drivers with <code>ftlMC</code> builtin command. i.e.: <code>fltMC sysmondrv</code></p>                                                                           | <p> 1. The <code>szkg64</code> vulnerability is listed as <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. The <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> was created by <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| `SeRestore`            |  _**Admin**_ |  **PowerShell**          | <p> 1. Launch PowerShell/ISE with the SeRestore privilege present.<br>2. Enable the privilege with <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rename utilman.exe to utilman.old<br>4. Rename cmd.exe to utilman.exe<br>5. Lock the console and press Win+U</p> | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege</p>                                                                                                                                                             |
| `SeTakeOwnership`      |  _**Admin**_ |  _**Built-in commands**_ | <p> 1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rename cmd.exe to utilman.exe<br>4. Lock the console and press Win+U</p>                                                                                                                                       | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.</p>                                                                                                                                                            |
| `SeTcb`                |  _**Admin**_ | 3rd party tool           | <p>Manipulate tokens to have local admin rights included. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                      |                                                                                                                                                                                                                                                                                                                                 |

## Reference

* Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) about privesc with tokens**.**
