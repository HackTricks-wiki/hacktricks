# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Cómo funciona

El Service Control Manager Remote Protocol (SCMR) es un protocolo basado en RPC para configurar y controlar servicios de Windows en un equipo remoto. Con permisos suficientes, un operador puede crear o reconfigurar un servicio cuya ruta binaria contenga un comando y, después, iniciar ese servicio para ejecutar el comando de forma remota.<sup>[[1]](#references)</sup>

Si no se especifica ninguna cuenta de servicio, `CreateService` usa `LocalSystem`, que tiene amplios privilegios locales. Esto explica el gran impacto de una ejecución de SCM exitosa. No deshabilita UAC ni Microsoft Defender de forma inherente: el usuario que realiza la llamada sigue necesitando permisos de SCM remotos, y los controles del endpoint pueden inspeccionar o bloquear el servicio o el payload.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

## Herramientas

**SharpMove** admite la ejecución remota autenticada mediante SCM y varios otros mecanismos de Windows. El siguiente ejemplo selecciona su acción SCM, crea un servicio llamado `WindowsDebug` y lo apunta a un payload que ya está presente en el host remoto.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Descripción general del protocolo remoto del Service Control Manager](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [3] [Microsoft Learn - cuenta LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [4] [Microsoft Learn - función `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
