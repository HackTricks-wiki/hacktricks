# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## Introduction

Kerberos의 "Double Hop" 문제는 공격자가 **두 개의** **hop**을 거쳐 **Kerberos authentication**을 사용하려고 할 때 발생합니다. 예를 들어 **PowerShell**/**WinRM**을 사용하는 경우입니다.

**Kerberos**를 통한 **authentication**이 발생하면 **credentials**는 **memory**에 캐시되지 **않습니다.** 따라서 mimikatz를 실행하더라도 해당 사용자가 프로세스를 실행 중인 경우에도 시스템에서 사용자의 **credentials**를 **찾을 수 없습니다.**

이는 Kerberos로 연결할 때 다음 단계가 수행되기 때문입니다:<sup>[[1]](#references)</sup>

1. User1이 credentials를 제공하면 **domain controller**가 User1에게 Kerberos **TGT**를 반환합니다.
2. User1은 **TGT**를 사용하여 Server1에 **connect**하기 위한 **service ticket**을 요청합니다.
3. User1은 Server1에 **connect**하고 **service ticket**을 제공합니다.
4. **Server1**에는 User1의 **credentials**나 User1의 **TGT**가 캐시되어 있지 **않습니다.** 따라서 User1이 Server1에서 두 번째 서버에 로그인을 시도하면 **authenticate할 수 없습니다.**

### Unconstrained Delegation

PC에서 **unconstrained delegation**이 활성화되어 있다면 **Server**가 해당 서버에 액세스하는 각 사용자의 **TGT**를 **가져오기** 때문에 이 문제가 발생하지 않습니다. 또한 unconstrained delegation이 사용되는 경우 해당 서버에서 **Domain Controller를 compromise**할 수 있을 가능성이 높습니다.\
[**unconstrained delegation 페이지에서 더 많은 정보 확인**](unconstrained-delegation.md).

### CredSSP

이 문제를 피하는 또 다른 방법은 [**특히 안전하지 않은**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) **Credential Security Support Provider**를 사용하는 것입니다. Microsoft에 따르면:

> CredSSP authentication은 로컬 컴퓨터의 사용자 credentials를 원격 컴퓨터로 위임합니다. 이 방식은 원격 작업의 보안 위험을 증가시킵니다. 원격 컴퓨터가 compromise된 경우, credentials가 전달되면 해당 credentials를 사용하여 network session을 제어할 수 있습니다.

보안 문제로 인해 운영 시스템, 민감한 네트워크 및 이와 유사한 환경에서는 **CredSSP**를 비활성화하는 것이 강력히 권장됩니다. **CredSSP**가 활성화되어 있는지 확인하려면 `Get-WSManCredSSP` 명령을 실행할 수 있습니다. 이 명령을 사용하면 **CredSSP status를 확인**할 수 있으며, **WinRM**이 활성화되어 있다면 원격으로도 실행할 수 있습니다.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard**는 사용자의 TGT를 원래 workstation에 유지하면서도 RDP session이 다음 hop에서 새로운 Kerberos service ticket을 요청할 수 있도록 합니다. **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers**를 활성화하고 **Require Remote Credential Guard**를 선택한 다음, CredSSP로 fallback하지 말고 `mstsc.exe /remoteGuard /v:server1`로 연결합니다.

Microsoft는 **April 2024 cumulative updates**(KB5036896/KB5036899/KB5036894)가 적용되기 전까지 Windows 11 22H2+에서 multi-hop access에 대한 RCG를 중단시켰습니다. Client와 intermediary server에 patch를 적용하지 않으면 second hop은 계속 실패합니다.<sup>[[5]](#references)</sup> 빠른 hotfix 확인 방법:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
해당 빌드가 설치되어 있으면 RDP hop에서 첫 번째 서버에 재사용 가능한 secret을 노출하지 않고 downstream Kerberos challenge를 처리할 수 있습니다.

## Workarounds

### Invoke Command

double hop 문제를 해결하기 위해 중첩된 `Invoke-Command`를 사용하는 방법이 제시됩니다. 이 방법은 문제를 직접 해결하지는 않지만, special configuration 없이 workaround를 제공합니다. 이 접근 방식을 사용하면 초기 attacking machine에서 실행한 PowerShell command 또는 첫 번째 서버와 기존에 설정된 PS-Session을 통해 secondary server에서 command(`hostname`)를 실행할 수 있습니다. 방법은 다음과 같습니다:<sup>[[2]](#references)</sup>
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
또는 첫 번째 서버와 PS-Session을 설정하고 `$cred`를 사용해 `Invoke-Command`를 실행하여 작업을 중앙화하는 방법이 제안됩니다.

### PSSession Configuration 등록

Double hop problem을 우회하는 한 가지 해결 방법은 `Enter-PSSession`과 함께 `Register-PSSessionConfiguration`을 사용하는 것입니다. 이 방법은 `evil-winrm`과는 다른 접근 방식이 필요하며, double hop 제한의 영향을 받지 않는 세션을 사용할 수 있습니다.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

중간 대상의 로컬 관리자에게 port forwarding을 사용하면 최종 서버로 요청을 전송할 수 있습니다. `netsh`를 사용하면 port forwarding을 위한 rule을 추가하고, 전달된 port를 허용하도록 Windows firewall rule도 추가할 수 있습니다.<sup>[[2]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe`는 WinRM 요청을 전달하는 데 사용할 수 있으며, PowerShell 모니터링이 우려되는 경우 탐지 가능성이 더 낮은 옵션이 될 수 있습니다.<sup>[[2]](#references)</sup> 아래 명령은 사용 방법을 보여 줍니다:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

첫 번째 서버에 OpenSSH를 설치하면 double-hop 문제에 대한 workaround를 사용할 수 있으며, 특히 jump box 시나리오에서 유용합니다. 이 방법을 사용하려면 Windows용 OpenSSH를 CLI로 설치하고 설정해야 합니다. Password Authentication으로 구성하면 중간 서버가 사용자를 대신하여 TGT를 가져올 수 있습니다.<sup>[[2]](#references)</sup>

#### OpenSSH 설치 단계

1. 최신 OpenSSH release zip을 다운로드하여 대상 서버로 이동합니다.
2. 압축을 해제하고 `Install-sshd.ps1` 스크립트를 실행합니다.
3. 포트 22를 열도록 firewall rule을 추가하고 SSH services가 실행 중인지 확인합니다.

`Connection reset` 오류를 해결하려면 OpenSSH 디렉터리에 대한 everyone의 read 및 execute access를 허용하도록 permissions를 업데이트해야 할 수 있습니다.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (고급)

**LSA Whisperer** (2024)는 `msv1_0!CacheLogon` package call을 노출하므로, `LogonUser`로 새 session을 생성하는 대신 알려진 NT hash를 사용해 기존 *network logon*을 seed할 수 있습니다. WinRM/PowerShell이 hop #1에서 이미 연 logon session에 hash를 주입하면, 해당 host는 명시적인 credentials를 저장하거나 추가 4624 event를 생성하지 않고 hop #2에 authenticate할 수 있습니다.<sup>[[6]](#references)</sup>

1. LSASS 내부에서 code execution을 확보합니다(PPL을 disable/abuse하거나 직접 제어하는 lab VM에서 실행).
2. logon session을 enumerate하고(예: `lsa.exe sessions`), remoting context에 해당하는 LUID를 확보합니다.
3. NT hash를 pre-compute하여 `CacheLogon`에 전달한 다음, 작업이 끝나면 clear합니다.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
캐시 시드 후 hop #1에서 `Invoke-Command`/`New-PSSession`을 다시 실행하면 LSASS가 주입된 hash를 재사용하여 두 번째 hop의 Kerberos/NTLM challenge에 응답하므로 double hop 제약을 깔끔하게 우회할 수 있습니다. 단점은 더 많은 telemetry(code execution이 LSASS에서 발생)가 남는다는 것이므로, CredSSP/RCG가 허용되지 않는 마찰이 큰 환경에서 사용하세요.

## References

- [1] [Kerberos Double Hop 이해하기 - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [2] [Kerberos Double-Hop Workarounds](https://posts.slayerlabs.com/double-hop/)
- [3] [Another solution to multi-hop PowerShell remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [4] [Solve the PowerShell multi-hop problem without using CredSSP](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [5] [April 9, 2024—KB5036896 (OS Build 17763.5696)](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [6] [LSA Whisperer](https://specterops.io/blog/2024/04/17/lsa-whisperer/)

{{#include ../../banners/hacktricks-training.md}}
