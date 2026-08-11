# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Cómo funciona

El Service Control Manager Remote Protocol (SCMR) es un protocolo basado en RPC para configurar y controlar servicios de Windows en un equipo remoto. Con permisos suficientes, un operador puede crear o reconfigurar un servicio cuya ruta binaria contenga un comando y, a continuación, iniciar ese servicio para ejecutar el comando de forma remota.<sup>[[1]](#references)</sup>

## Herramientas

**SharpMove** admite la ejecución remota autenticada mediante SCM y varios mecanismos de Windows adicionales. En el siguiente ejemplo, selecciona su acción SCM, crea un servicio denominado `WindowsDebug` y lo apunta a un payload que ya está presente en el host remoto.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Descripción general del protocolo remoto del Service Control Manager](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
{{#include ../../banners/hacktricks-training.md}}
