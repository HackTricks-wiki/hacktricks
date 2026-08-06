# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

У новіших збірках Windows з'явилася **підтримка SMB-клієнтом альтернативних TCP-портів**. Цю функцію можна використати для перетворення **локальної NTLM-аутентифікації** на **локальне підвищення привілеїв до SYSTEM**, якщо зловмисник може:<sup>[[1]](#references)</sup>

1. Відкрити SMB-з'єднання зі слухачем під контролем зловмисника на **порту, відмінному від 445**
2. Підтримувати це TCP-з'єднання активним
3. Примусити **привілейований локальний клієнт** отримати доступ до **того самого шляху SMB-шари**
4. Виконати relay отриманої **локальної NTLM-аутентифікації** назад до справжньої SMB-служби машини

Це primitive, що лежить в основі **CVE-2026-24294**, виправленої у **березні 2026 року**.<sup>[[1]](#references)[[4]](#references)</sup>

## Чому це працює

Старіший трюк reflection через CMTI / serialized-SPN описаний тут:

{{#ref}}
../ntlm/README.md
{{#endref}}

Цей новіший варіант **не потребує marshalled hostname**. Натомість він використовує дві особливості поведінки SMB-клієнта:<sup>[[1]](#references)</sup>

- **Підтримку альтернативних портів** у **Windows 11 24H2** та **Windows Server 2025**, доступну користувачам через `net use \\host\share /tcpport:<port>`
- **Повторне використання / мультиплексування SMB-з'єднань**, коли кілька аутентифікованих сесій можуть використовувати одне TCP-з'єднання

Це означає, що користувач із низькими привілеями спочатку може створити TCP-з'єднання з SMB-клієнта до SMB-сервера зловмисника на високому порту, а потім примусити привілейовану службу отримати доступ до **абсолютно того самого UNC-шляху**. Якщо Windows вирішить повторно використати наявне TCP-з'єднання, привілейований NTLM-обмін буде надіслано через транспорт під контролем зловмисника та його можна буде relay до локального SMB-сервера.<sup>[[1]](#references)</sup>

## Передумови

- Target підтримує альтернативні порти SMB:<sup>[[2]](#references)</sup>
- **Windows 11 24H2** або новіша версія
- **Windows Server 2025** або новіша версія
- Зловмисник може запустити локальний або віддалений SMB-сервер на вибраному високому порту
- Зловмисник може примусити привілейовану службу отримати доступ до UNC-шляху
- Для привілейованої аутентифікації має використовуватися **локальна NTLM-аутентифікація**
- Target має бути придатним для relay:<sup>[[1]](#references)</sup>
- Synacktiv повідомили, що за замовчуванням це працювало на **Windows Server 2025**
- Їхній ланцюжок **не працював на Windows 11 24H2**, оскільки вихідне SMB-підписування там типово примусово увімкнене

## Userland та internals

З командного рядка ця функція виглядає просто:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Програмно клієнт використовує `WNetAddConnection4W` із недокументованими даними `lpUseOptions`. Відповідна опція — `TraP` (параметри транспорту), яка зрештою передається до kernel SMB client через FSCTL і розбирається `mrxsmb`.<sup>[[1]](#references)[[3]](#references)</sup>

Важливі практичні примітки:<sup>[[1]](#references)</sup>

- **Синтаксис UNC усе ще не містить поля порту**
- **`net use` працює в межах окремої logon-сесії**
- Обхід усе ще працює, оскільки **TCP-з'єднання та SMB-сесія є окремими об'єктами**
- Повторне використання **того самого шляху до share** є обов'язковим, якщо exploit залежить від повторного використання SMB client раніше створеного TCP-з'єднання

## Потік exploitation

### 1. Створення контрольованого attacker-ом SMB transport

Запустіть SMB server на високому порту та змусьте Windows підключитися до нього:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Сервер може прийняти будь-яку пару облікових даних, якою ви керуєте, наприклад `user:user`. Мета цього кроку — ще не підвищення привілеїв, а лише змусити Windows SMB client відкрити та підтримувати повторно використовуване TCP-з'єднання з вашим listener.<sup>[[1]](#references)</sup>

### 2. Примусити привілейовану службу використати той самий UNC-шлях

Використайте coercion primitive, наприклад **PetitPotam**, проти **того самого** шляху `\\192.168.56.3\share`. Якщо coerced client має привілеї, а цільове ім'я є локальним (`localhost` або локальна IP-адреса/назва хоста), Windows виконує **NTLM local authentication**.

Оскільки TCP-з'єднання повторно використовується, цей привілейований NTLM-обмін надходить до SMB service атакувальника, а не безпосередньо до справжнього локального SMB-сервера.<sup>[[1]](#references)</sup>

### 3. Relay привілейованої автентифікації назад до локального SMB

Контрольований атакувальником SMB service пересилає привілейований NTLM-обмін до `ntlmrelayx.py`, який виконує relay до справжнього SMB listener машини та отримує сесію від імені `NT AUTHORITY\SYSTEM`.<sup>[[1]](#references)</sup>

Типові інструменти з публічного writeup:<sup>[[1]](#references)</sup>

- `smbserver.py` на custom port для отримання привілейованої автентифікації через повторно використане TCP-з'єднання
- `ntlmrelayx.py` для relay перехопленого NTLM до локального SMB
- `PetitPotam.exe` або інший coercion primitive для примусового виконання привілейованої автентифікації

## Нотатки оператора

- Це техніка **local privilege escalation**, а не загальний remote relay trick<sup>[[1]](#references)</sup>
- Контрольований атакувальником SMB service має обробити привілейовану автентифікацію в **тому самому TCP-з'єднанні**, яке спочатку використовувалося для підключення до share<sup>[[1]](#references)</sup>
- Якщо coerced access звертається до **іншого шляху share**, Windows може встановити інше з'єднання, і ланцюжок буде перервано<sup>[[1]](#references)</sup>
- Вимоги SMB signing можуть зупинити relay, навіть якщо крок із довільним портом працює<sup>[[1]](#references)</sup>
- Якщо у вас є лише матеріал Kerberos або ви не можете примусити локальний NTLM, цього exact variant недостатньо<sup>[[1]](#references)</sup>

## Виявлення та hardening

- Встановіть patch для **CVE-2026-24294** з **March 2026 Patch Tuesday**<sup>[[4]](#references)</sup>
- Слідкуйте за використанням `net use` або `New-SmbMapping` із **нестандартними SMB-портами**<sup>[[1]](#references)</sup>
- Створюйте сповіщення про незвичайний вихідний SMB від робочих станцій або серверів до **високих TCP-портів**<sup>[[1]](#references)</sup>
- Перевіряйте можливості coercion, зокрема тригери на кшталт **EFSRPC / PetitPotam**<sup>[[1]](#references)</sup>
- Увімкніть SMB signing, де це можливо; Synacktiv окремо зазначає, що це заблокувало їхній relay у Windows 11 24H2<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Обхід mitigation для Windows authentication reflection для SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [2] [Microsoft Learn - Налаштування альтернативних SMB-портів для Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [3] [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [4] [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
