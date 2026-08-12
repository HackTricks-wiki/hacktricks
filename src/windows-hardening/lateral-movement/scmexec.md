# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Як це працює

Service Control Manager Remote Protocol (SCMR) — це протокол на основі RPC для налаштування та керування Windows services на віддаленому комп'ютері. За наявності достатніх дозволів оператор може створити або переналаштувати service, шлях до бінарного файлу якого містить команду, а потім запустити цей service для віддаленого виконання команди.<sup>[[1]](#references)</sup>

Якщо обліковий запис service не вказано, `CreateService` використовує `LocalSystem`, який має широкі локальні привілеї. Це пояснює значний вплив успішного SCM execution. Він не вимикає UAC або Microsoft Defender автоматично: викликачеві все одно потрібні права віддаленого доступу до SCM, а засоби захисту endpoint можуть перевіряти або блокувати service чи payload.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

## Інструменти

**SharpMove** підтримує автентифіковане віддалене виконання через SCM та кілька інших механізмів Windows. У наведеному прикладі вибирається його SCM action, створюється service з назвою `WindowsDebug`, а як його ціль указується payload, який уже присутній на віддаленому хості.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Огляд протоколу Remote Service Control Manager](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [3] [Microsoft Learn - Обліковий запис LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [4] [Microsoft Learn - Функція `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
