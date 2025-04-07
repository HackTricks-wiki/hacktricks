# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** è una tecnica per eseguire comandi su sistemi remoti utilizzando il Service Control Manager (SCM) per creare un servizio che esegue il comando. Questo metodo può eludere alcuni controlli di sicurezza, come il Controllo Account Utente (UAC) e Windows Defender.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

{{#include ../../banners/hacktricks-training.md}}
