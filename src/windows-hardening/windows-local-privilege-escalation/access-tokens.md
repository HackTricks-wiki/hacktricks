# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Every process has a **primary access token** that defines its security context. A thread normally uses that token, but it can temporarily have an **impersonation token** as well. Tokens contain the user SID, group SIDs, privileges, integrity information, and a logon SID for the logon session. Processes generally inherit a reference to the parent's primary token; they do not receive an independent copy of its contents.<sup>[[4]](#references)</sup>

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

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Local administrator

When **UAC Admin Approval Mode** applies to an administrator, the interactive logon creates a full administrator token and a filtered token. Explorer and ordinary child processes use the filtered token by default. An elevation request such as **Run as administrator** asks UAC to start the program with the full token. The exact behavior differs for the built-in Administrator account and when Admin Approval Mode is disabled.<sup>[[5]](#references)</sup>

Read the dedicated [**UAC page**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) for bypass techniques and policy details.

In practice, this means a **non-elevated admin shell usually runs with a filtered token**. That is why `whoami /groups` often shows **`BUILTIN\Administrators` as `Deny only`** until the process is elevated. Internally, Windows keeps a **linked elevated token** (`TokenLinkedToken`) and tracks the state with fields such as `TokenElevationType`.

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

#### `runas /netonly` details

`runas /netonly` (and C2 helpers such as `make_token`) creates a **`LOGON32_LOGON_NEW_CREDENTIALS`** token. This is very useful to understand during lateral movement because:<sup>[[3]](#references)</sup>

- **Locally**, the new process keeps the **same local identity**, groups, integrity level, and most of the same access decisions as the current token.
- **Remotely**, outbound authentication can use the **supplied credentials** for SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Therefore `whoami` may still show the **original local user** while network access happens as the **alternate account**.

This is a great option when the credentials are valid in the domain or in another host, but the user **cannot or should not log on locally** to the current machine.

### Types of tokens

There are two types of tokens available:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**: Represents a process security context. A child normally inherits its parent's primary token, while the explicit-token process-creation APIs impose their own token-access and caller-privilege requirements.
- **Impersonation token**: Lets a server thread temporarily use a client's security context for access checks. Its four levels are:
  - **Anonymous**: Grants server access akin to that of an unidentified user.
  - **Identification**: Allows the server to verify the client's identity without utilizing it for object access.
  - **Impersonation**: Enables the server to operate under the client's identity.
  - **Delegation**: Lets the server impersonate the client on remote systems when the authentication mechanism and account configuration support delegation.

#### Triage a captured token before using it

Do not select a token by username alone. The same account can have several tokens with different logon sessions, service SIDs, privileges, integrity levels, restrictions, and network credentials.<sup>[[9]](#references)</sup> Query at least **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`**, and **`TokenStatistics.AuthenticationId`** with `GetTokenInformation`.<sup>[[7]](#references)</sup>

A restricted token can contain deny-only SIDs, removed privileges, and restricting SIDs. When restricting SIDs exist, Windows performs one access check with the enabled SIDs and another with the restricting SIDs; **both checks must allow access**. Therefore, an attractive user SID or an enabled group in the output does not by itself prove that the token can reach the target object.<sup>[[8]](#references)</sup>

Use this decision flow for the documented token and process-creation requirements:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. A **primary token** needs a handle with `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` before it can be supplied to `CreateProcessWithTokenW` or `CreateProcessAsUserW`.
2. Convert an **impersonation token** with `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Identification-level tokens can expose identity data but cannot perform access checks as that client.
3. `CreateProcessWithTokenW` needs `SeImpersonatePrivilege` and starts the child in the caller's session. `CreateProcessAsUserW` instead uses the token's session but normally needs `SeIncreaseQuotaPrivilege` and can need `SeAssignPrimaryTokenPrivilege`. If credentials are available and these privileges are missing, `CreateProcessWithLogonW` is the documented alternative.

#### Hunt token handles, not only process owners

Opening each process primary token can miss **impersonation tokens retained as ordinary handles** inside services and broker processes. A reusable handle-table workflow is to enumerate system handles, filter token objects, open each owner with `PROCESS_DUP_HANDLE`, duplicate the candidate handle into the current process, then query the fields above. Confirm the duplicated handle includes `TOKEN_QUERY` and `TOKEN_DUPLICATE`; seeing a token handle does not mean it can be duplicated into a usable primary token. Protected processes and process DACLs can still block the owner-process handle.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` automates both process-primary-token and retained-token-handle enumeration. `list_token` keeps one preferred candidate per username, while `list_all_token` prints every candidate. A PID limits enumeration to one owner process.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

For manual inspection and access checking, **TokenUniverse** can open process/thread tokens, search existing token handles, inspect restrictions and logon sessions, duplicate tokens, and test several process-creation methods.<sup>[[13]](#references)</sup> For the underlying cross-process handle primitive, see:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Impersonate Tokens

Using the _**incognito**_ module of metasploit if you have enough privileges you can easily **list** and **impersonate** other **tokens**. This could be useful to perform **actions as if you where the other user**. You could also **escalate privileges** with this technique.

Some practical notes that are easy to forget while operating:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** requires **`SeImpersonatePrivilege`** in the caller and the new process will run in the **caller's session**.
- **`CreateProcessAsUserW`** is a possible fallback when `CreateProcessWithTokenW` fails with `1314` only if the caller satisfies its privilege requirements. It is also the correct choice when the child must run in the **session referenced by the token**.<sup>[[9]](#references)[[10]](#references)</sup>
- If a token comes from **`LogonUser(LOGON32_LOGON_NETWORK)`**, it is usually an **impersonation token**, so you need **`DuplicateTokenEx(..., TokenPrimary, ...)`** before trying to spawn a process with it.
- Not every impersonation token is equally useful: **`SecurityIdentification`** lets you inspect the user but **not act as them**. If a coercion primitive or pipe/RPC client gives you only an identification-level token, check **`TokenImpersonationLevel`** and switch to a primitive that yields **`SecurityImpersonation`** or better.

#### Token theft without touching LSASS

If you already have a **service** or **SYSTEM** context and a **privileged user is logged on**, stealing or duplicating that user's token is often quieter than dumping **LSASS**. In many real intrusions this is enough to:<sup>[[2]](#references)</sup>

- run local actions as that user
- access remote resources as that user
- perform AD operations without extracting reusable credentials first

For examples of **session/user token hijacking** from a privileged context, check [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Remember that APIs such as **`WTSQueryUserToken`** are meant for **highly trusted services** and normally require **`LocalSystem` + `SeTcbPrivilege`**, so they are primarily useful once you already control a service-level context. For privilege-specific ways to obtain **SYSTEM** first, check the pages below.

### Token Privileges

Learn which **token privileges can be abused to escalate privileges:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Take a look to [**all the possible token privileges and some definitions on this external page**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Understanding and Abusing Access Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Demystifying Cobalt Strike's "make_token" Command](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Access Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [How User Account Control works - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Impersonation Levels - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [TOKEN_INFORMATION_CLASS enumeration - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Restricted Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [CreateProcessWithTokenW function - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [CreateProcessAsUserW function - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [DuplicateHandle function - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)

{{#include ../../banners/hacktricks-training.md}}
