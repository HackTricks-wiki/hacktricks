# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Як це працює

Service Control Manager Remote Protocol (SCMR) — це протокол на основі RPC для налаштування та керування службами Windows на віддаленому комп’ютері. Маючи достатні дозволи, оператор може створити або переналаштувати службу, шлях до бінарного файлу якої містить команду, а потім запустити цю службу для віддаленого виконання команди.<sup>[[1]](#references)</sup>

## Інструменти

**SharpMove** підтримує автентифіковане віддалене виконання через SCM та кілька інших механізмів Windows. У наведеному прикладі вибирається дія SCM, створюється служба з назвою `WindowsDebug`, а як її ціль указується payload, який уже присутній на віддаленому хості.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - огляд Remote Protocol Service Control Manager](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
{{#include ../../banners/hacktricks-training.md}}
