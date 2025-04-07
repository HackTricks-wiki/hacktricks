# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** ist eine Technik, um Befehle auf entfernten Systemen auszuführen, indem der Service Control Manager (SCM) verwendet wird, um einen Dienst zu erstellen, der den Befehl ausführt. Diese Methode kann einige Sicherheitskontrollen umgehen, wie z.B. die Benutzerkontensteuerung (UAC) und Windows Defender.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

{{#include ../../banners/hacktricks-training.md}}
