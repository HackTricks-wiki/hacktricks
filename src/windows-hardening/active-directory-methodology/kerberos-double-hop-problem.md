# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Introduction

Kerberos "Double Hop" 문제는 공격자가 **두 개의** **홉**을 통해 **Kerberos 인증**을 사용하려고 할 때 발생합니다. 예를 들어 **PowerShell**/**WinRM**을 사용하는 경우입니다.

**Kerberos**를 통해 **인증**이 발생할 때, **자격 증명**이 **메모리**에 캐시되지 않습니다. 따라서 사용자가 프로세스를 실행하고 있더라도 mimikatz를 실행하면 해당 사용자의 **자격 증명**을 찾을 수 없습니다.

Kerberos로 연결할 때의 단계는 다음과 같습니다:

1. User1이 자격 증명을 제공하고 **도메인 컨트롤러**가 User1에게 Kerberos **TGT**를 반환합니다.
2. User1이 **TGT**를 사용하여 **Server1**에 연결하기 위한 **서비스 티켓**을 요청합니다.
3. User1이 **Server1**에 **연결**하고 **서비스 티켓**을 제공합니다.
4. **Server1**은 User1의 **자격 증명**이나 User1의 **TGT**를 캐시하지 않습니다. 따라서 Server1에서 User1이 두 번째 서버에 로그인하려고 할 때, 그는 **인증할 수 없습니다**.

### Unconstrained Delegation

PC에서 **제한 없는 위임**이 활성화되어 있으면, **서버**는 접근하는 각 사용자의 **TGT**를 **얻습니다**. 게다가, 제한 없는 위임이 사용되면 **도메인 컨트롤러**를 **타격할 수** 있습니다.\
[**제한 없는 위임 페이지에서 더 많은 정보**](unconstrained-delegation.md).

### CredSSP

이 문제를 피하는 또 다른 방법은 [**상당히 안전하지 않은**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) **Credential Security Support Provider**입니다. Microsoft에서:

> CredSSP 인증은 로컬 컴퓨터에서 원격 컴퓨터로 사용자 자격 증명을 위임합니다. 이 관행은 원격 작업의 보안 위험을 증가시킵니다. 원격 컴퓨터가 손상되면 자격 증명이 전달될 때, 자격 증명을 사용하여 네트워크 세션을 제어할 수 있습니다.

보안 문제로 인해 **CredSSP**는 프로덕션 시스템, 민감한 네트워크 및 유사한 환경에서 비활성화하는 것이 강력히 권장됩니다. **CredSSP**가 활성화되어 있는지 확인하려면 `Get-WSManCredSSP` 명령을 실행할 수 있습니다. 이 명령은 **CredSSP 상태를 확인**할 수 있으며, **WinRM**이 활성화되어 있는 경우 원격으로도 실행할 수 있습니다.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Workarounds

### Invoke Command

더블 홉 문제를 해결하기 위해 중첩된 `Invoke-Command`를 포함하는 방법이 제시됩니다. 이는 문제를 직접적으로 해결하지는 않지만 특별한 구성이 필요 없는 우회 방법을 제공합니다. 이 접근 방식은 초기 공격 머신에서 실행된 PowerShell 명령어를 통해 또는 첫 번째 서버와 이전에 설정된 PS-Session을 통해 보조 서버에서 명령어(`hostname`)를 실행할 수 있게 합니다. 방법은 다음과 같습니다:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
대안으로, 첫 번째 서버와 PS-Session을 설정하고 `$cred`를 사용하여 `Invoke-Command`를 실행하는 것이 작업을 중앙 집중화하는 데 권장됩니다.

### PSSession 구성 등록

더블 홉 문제를 우회하는 솔루션은 `Enter-PSSession`과 함께 `Register-PSSessionConfiguration`을 사용하는 것입니다. 이 방법은 `evil-winrm`과는 다른 접근 방식을 요구하며, 더블 홉 제한이 없는 세션을 허용합니다.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

중간 대상의 로컬 관리자에게 포트 포워딩은 요청을 최종 서버로 전송할 수 있게 해줍니다. `netsh`를 사용하여 포트 포워딩을 위한 규칙을 추가할 수 있으며, 포워딩된 포트를 허용하기 위해 Windows 방화벽 규칙도 추가해야 합니다.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe`는 WinRM 요청을 전달하는 데 사용할 수 있으며, PowerShell 모니터링이 우려되는 경우 덜 감지 가능한 옵션으로 사용할 수 있습니다. 아래 명령은 그 사용을 보여줍니다:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

첫 번째 서버에 OpenSSH를 설치하면 더블 홉 문제에 대한 우회 방법이 가능해지며, 특히 점프 박스 시나리오에 유용합니다. 이 방법은 Windows용 OpenSSH의 CLI 설치 및 설정이 필요합니다. 비밀번호 인증을 위해 구성되면, 중간 서버가 사용자를 대신하여 TGT를 얻을 수 있습니다.

#### OpenSSH 설치 단계

1. 최신 OpenSSH 릴리스 zip 파일을 다운로드하여 대상 서버로 이동합니다.
2. 압축을 풀고 `Install-sshd.ps1` 스크립트를 실행합니다.
3. 포트 22를 열기 위해 방화벽 규칙을 추가하고 SSH 서비스가 실행 중인지 확인합니다.

`Connection reset` 오류를 해결하려면 OpenSSH 디렉토리에 대해 모든 사용자가 읽기 및 실행 권한을 갖도록 권한을 업데이트해야 할 수 있습니다.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## References

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
