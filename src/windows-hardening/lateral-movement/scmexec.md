# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Como funciona

O Service Control Manager Remote Protocol (SCMR) é um protocolo baseado em RPC para configurar e controlar serviços do Windows em um computador remoto. Com permissões suficientes, um operador pode criar ou reconfigurar um serviço cujo caminho do binário contenha um comando e, em seguida, iniciar esse serviço para executar o comando remotamente.<sup>[[1]](#references)</sup>

Se nenhuma conta de serviço for especificada, `CreateService` usará `LocalSystem`, que possui amplos privilégios locais. Isso explica o alto impacto de uma execução SCM bem-sucedida. Ela não desabilita inerentemente o UAC ou o Microsoft Defender: o chamador ainda precisa de direitos SCM remotos, e os controles do endpoint podem inspecionar ou bloquear o serviço ou o payload.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

## Ferramentas

**SharpMove** oferece execução remota autenticada por meio do SCM e de vários outros mecanismos do Windows. O exemplo a seguir seleciona sua ação SCM, cria um serviço chamado `WindowsDebug` e aponta esse serviço para um payload já presente no host remoto.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - visão geral do protocolo remoto do Service Control Manager](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [3] [Microsoft Learn - conta LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [4] [Microsoft Learn - função `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
