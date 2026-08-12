# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## 工作原理

Service Control Manager Remote Protocol (SCMR) 是一种基于 RPC 的协议，用于配置和控制远程计算机上的 Windows 服务。拥有足够权限时，operator 可以创建或重新配置一个服务，使其二进制路径包含一条命令，然后启动该服务，从而远程执行该命令。<sup>[[1]](#references)</sup>

如果未指定服务账户，`CreateService` 会使用 `LocalSystem`，该账户拥有广泛的本地权限。这解释了 SCM execution 成功后的高影响。它不会自动禁用 UAC 或 Microsoft Defender：调用方仍然需要远程 SCM 权限，并且 endpoint controls 可以检查或阻止该服务或 payload。<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

## 工具

**SharpMove** 支持通过 SCM 以及其他几种 Windows 机制进行经过身份验证的远程执行。以下示例选择其 SCM action，创建名为 `WindowsDebug` 的服务，并将其指向远程主机上已经存在的 payload。<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Service Control Manager Remote Protocol 概述](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [3] [Microsoft Learn - LocalSystem 账户](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [4] [Microsoft Learn - `CreateService` 函数](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
