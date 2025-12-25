# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## 소개

Kerberos "Double Hop" 문제는 공격자가 **Kerberos authentication across two** **hops**을 사용하려 할 때, 예를 들어 **PowerShell**/**WinRM**을 사용할 때 발생합니다.

Kerberos를 통한 **authentication**이 발생하면 **credentials**은 **memory**에 캐시되지 않습니다. 따라서 mimikatz를 실행해도 사용자가 프로세스를 실행 중이더라도 머신에서 해당 사용자의 **credentials**를 찾을 수 없습니다.

이는 Kerberos로 연결할 때 절차가 다음과 같기 때문입니다:

1. User1가 credentials를 제공하면 **domain controller**는 Kerberos **TGT**를 User1에게 반환합니다.
2. User1는 **TGT**를 사용해 **service ticket**을 요청하여 **connect**하기 위해 **Server1**에 접근합니다.
3. User1는 **Server1**에 **connect**하고 **service ticket**을 제공합니다.
4. **Server1**에는 User1의 **credentials**이나 User1의 **TGT**가 캐시되어 있지 않습니다. 따라서 Server1에서 User1가 두 번째 서버에 로그인하려 할 때 그는 **not able to authenticate**합니다.

### Unconstrained Delegation

만약 PC에 **unconstrained delegation**이 활성화되어 있다면, **Server**는 접근하는 각 사용자에 대한 **TGT**를 **get**하므로 이러한 문제가 발생하지 않습니다. 또한 unconstrained delegation이 사용되는 경우 이를 통해 **compromise the Domain Controller**할 수 있는 가능성이 있습니다.\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md).

### CredSSP

이 문제를 피하는 또 다른 방법으로 [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7)한 것은 **Credential Security Support Provider**입니다. Microsoft에 따르면:

> CredSSP authentication delegates the user credentials from the local computer to a remote computer. This practice increases the security risk of the remote operation. If the remote computer is compromised, when credentials are passed to it, the credentials can be used to control the network session.

보안상의 우려로 인해 프로덕션 시스템, 민감한 네트워크 및 유사한 환경에서는 **CredSSP**를 비활성화하는 것이 강력히 권장됩니다. **CredSSP**가 활성화되어 있는지 확인하려면 `Get-WSManCredSSP` 명령을 실행하면 됩니다. 이 명령은 **checking of CredSSP status**를 가능하게 하며, **WinRM**이 활성화되어 있으면 원격으로도 실행할 수 있습니다.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard**는 사용자의 TGT를 원래 워크스테이션에 유지하면서도 RDP 세션이 다음 홉에서 새로운 Kerberos 서비스 티켓을 요청할 수 있도록 허용합니다. **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers**를 활성화하고 **Require Remote Credential Guard**를 선택한 다음, CredSSP로 되돌아가지 않도록 `mstsc.exe /remoteGuard /v:server1`로 연결하세요.

Microsoft는 Windows 11 22H2+에서 멀티홉 액세스용 RCG를 **2024년 4월 누적 업데이트** (KB5036896/KB5036899/KB5036894)가 적용되기 전까지 동작하지 않게 만들었습니다. 클라이언트와 중간 서버를 패치하지 않으면 두 번째 홉이 여전히 실패합니다. 간단한 핫픽스 확인:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
해당 빌드들이 설치되어 있으면, RDP hop은 첫 번째 서버에서 재사용 가능한 비밀을 노출하지 않고도 하위 Kerberos 요청을 충족할 수 있습니다.

## 우회 방법

### Invoke Command

double hop 문제를 해결하기 위해, 중첩된 `Invoke-Command`를 이용한 방법이 제시됩니다. 이 방법은 문제를 직접적으로 해결하지는 못하지만, 특별한 구성 없이 우회책을 제공합니다. 이 접근법은 초기 공격 머신에서 실행된 PowerShell 명령이나 첫 번째 서버와 미리 수립된 PS-Session을 통해 보조 서버에서 `hostname` 같은 명령을 실행할 수 있게 합니다. 방법은 다음과 같습니다:
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
대안으로, 첫 번째 서버에 PS-Session을 설정하고 `$cred`를 사용하여 `Invoke-Command`를 실행하는 것이 작업을 중앙화하는 데 권장됩니다.

### Register PSSession 구성

double hop 문제를 우회하는 한 가지 해결책은 `Register-PSSessionConfiguration`을 `Enter-PSSession`과 함께 사용하는 것입니다. 이 방법은 `evil-winrm`과는 다른 접근을 요구하며, double hop 제한의 영향을 받지 않는 세션을 허용합니다.
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

중간 대상의 로컬 관리자에게 port forwarding은 요청을 최종 서버로 전송할 수 있게 해준다. `netsh`를 사용하면 port forwarding을 위한 규칙을 추가하고, 전달되는 포트를 허용하기 위한 Windows firewall rule을 함께 만들 수 있다.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe`는 WinRM 요청을 전달하는 데 사용할 수 있으며, PowerShell 모니터링이 우려되는 경우 탐지 가능성이 더 낮은 옵션이 될 수 있습니다. 아래 명령은 그 사용 예를 보여줍니다:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

첫 번째 서버에 OpenSSH를 설치하면 특히 jump box 시나리오에서 double-hop 문제에 대한 우회가 가능합니다. 이 방법은 Windows용 OpenSSH를 CLI로 설치하고 설정해야 합니다. Password Authentication으로 구성하면 중간 서버가 사용자 대신 TGT를 얻을 수 있습니다.

#### OpenSSH 설치 단계

1. 최신 OpenSSH 릴리스 zip을 다운로드하여 대상 서버로 옮깁니다.
2. 압축을 풀고 `Install-sshd.ps1` 스크립트를 실행합니다.
3. 포트 22를 열도록 방화벽 규칙을 추가하고 SSH 서비스가 실행 중인지 확인합니다.

`Connection reset` 오류를 해결하려면 OpenSSH 디렉터리에 대해 Everyone에게 읽기 및 실행 권한을 부여하도록 권한을 업데이트해야 할 수 있습니다.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (고급)

**LSA Whisperer** (2024)은 `msv1_0!CacheLogon` 패키지 호출을 노출시켜, 새로운 세션을 `LogonUser`로 생성하는 대신 알려진 NT hash로 기존 *네트워크 로그온*을 시드할 수 있게 합니다. WinRM/PowerShell이 이미 홉 #1에서 연 로그온 세션에 해시를 주입하면, 해당 호스트는 명시적 자격증명 저장이나 추가 4624 이벤트 생성 없이 홉 #2에 인증할 수 있습니다.

1. LSASS 내에서 코드 실행을 얻습니다(예: PPL을 비활성화/악용하거나 자신이 제어하는 실습 VM에서 실행).
2. 로그온 세션을 열거합니다(예: `lsa.exe sessions`) 그리고 원격 컨텍스트에 해당하는 LUID를 캡처합니다.
3. NT hash를 사전 계산하여 `CacheLogon`에 제공한 뒤, 완료되면 지웁니다.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
캐시 시드 후, hop #1에서 `Invoke-Command`/`New-PSSession`를 다시 실행하면: LSASS는 주입된 해시를 재사용하여 두 번째 홉의 Kerberos/NTLM 챌린지를 충족시키므로 double hop 제약을 깔끔하게 우회합니다. 단점은 더 많은 telemetry(LSASS에서의 코드 실행)가 발생한다는 점이므로 CredSSP/RCG가 금지된 마찰이 큰 환경에서만 사용하세요.

## References

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [https://specterops.io/blog/2024/04/17/lsa-whisperer/](https://specterops.io/blog/2024/04/17/lsa-whisperer/)


{{#include ../../banners/hacktricks-training.md}}
